import socket
import threading
import random
import time
import string
import hashlib
import argparse

# reserved messages for system control
CONTROL_MESSAGES = ["JOIN", "JOINED", "OK", "DONE", "DC", "DROPPED",
                    "CHECK", "AUTH_FAIL"]
MAX_ATTEMPTS = 3            # maximum number of attempts for checking if a peer is alive
STATUS_CHECK_INTERVAL = 10  # interval for sending peer status checks (in seconds)

participants = [] # list of participants excluding self (total number of participants = len(participants) + 1)
password_hash = None

def join(sock, addr):
    print("Attempting to join chat - contacting", addr, "...")
    
    # send join request
    join_msg = b"JOIN"
    if password_hash is not None:
        join_msg += b" " + str.encode(password_hash)
    sock.sendto(join_msg, addr)
    
    message, address = sock.recvfrom(1024)
    message = message.decode()
    
    if "OK" in message:
        n_of_participants = int(message.split()[1]) # get number of addresses to receive
        print("Join accepted. Receiving participant addresses...")
        print("Expecting", n_of_participants, "addresses.")
        
        # receive the addresses of current participants
        while True:
            message, _ = sock.recvfrom(1024)
            message = message.decode()
            
            if message == "DONE":
                break
            
            received_ip, received_port = message.split(":")
            received_port = int(received_port)
            
            participants.append((received_ip, received_port))
        
        print("Received addresses of", len(participants), "participants.")
        participants.append(address)
        print("Total number of participants:", len(participants)+1)
        
        print("Join successful. Listening at ", sock.getsockname())
        return 0
    
    elif "AUTH_FAIL" in message:
        print("Failed to join chat: password authentication failed.")
    
    return 1


def receive_join_request(sock, address, join_message):
    
    print("User at", address, "is attempting to join...")
    
    auth_successful = True
    
    # check if the correct password is provided
    if password_hash is not None:
        auth_successful = False
        try:
            received_pw_hash = join_message.split()[1]
            if received_pw_hash == password_hash:
                print("Password authentication successful.")
                auth_successful = True
            else:
                print(address, "failed password authentication: wrong password.")
        except IndexError:
            print(address, "failed password authentication: no password provided.")
    
    if not auth_successful:
        sock.sendto(b"AUTH_FAIL", address)
        return
    
    # accept request
    msg = "OK {}".format(len(participants))
    sock.sendto(str.encode(msg), address)
    
    print("Sending list of", len(participants), "participants.")
    
    # send participant addresses
    for participant_address in participants:
        msg = "{}:{}".format(participant_address[0], participant_address[1])
        sock.sendto(str.encode(msg), address)
    
    sock.sendto(b"DONE", address)
    
    # inform other peers of join event
    msg = str.encode("JOINED {}:{}".format(address[0], address[1]))
    send_to_all(sock, msg)
    
    # update local list of participants
    participants.append(address)
    
    print(address, "succesfully joined. Current participants:", participants)

def send_to_all(sock, message):
    # sends a message (chat or control) to all participants in byte format
    if type(message) is not bytes:
        message = str.encode(message)
    
    for participant_address in participants:
        sock.sendto(message, participant_address)

def chat_send(sock, message):
    for reserved_string in CONTROL_MESSAGES:
        if reserved_string in message:
            print("Message could not be sent - contains reserved communication primitive.")
            return
    
    send_to_all(sock, message)

def disconnect(sock):
    print("Disconnecting from chat...")
    send_to_all(sock, b"DC")

def remove_participant(address):
    # safe removal of a participant address to account for the case
    # in which multiple peers discover the same dropped peer
    try:
        participants.remove(address)
    except ValueError:
        print("Failed to remove", address,
                "from participants. Already removed.")

def check_neighbor_status(stop_event, sock):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", 0))
    s.settimeout(2)
    
    while not stop_event.is_set():
        if len(participants) > 0:
            idx = random.randrange(len(participants))
            
            check_address = participants[idx]
            
            print("Checking status of peer number", idx,
                  "at", check_address)
            
            attempts = 0
            while attempts < MAX_ATTEMPTS:
                s.sendto(b"CHECK", check_address)
                
                try:
                    message, address = s.recvfrom(1024)
                except socket.timeout:
                    attempts += 1
                    print("Failed attempt number", attempts)
                else:
                    print("Check successful. Peer is alive.")
                    break
            
            if attempts == MAX_ATTEMPTS:
                print("Peer at", check_address, "not responding after",
                      MAX_ATTEMPTS, "attempts. Informing peers of dropped connection.")
                send_to_all(sock, "DROPPED {}:{}".format(check_address[0], check_address[1]))
                
                remove_participant(check_address)
        
        # wait until the next status check
        stop_event.wait(STATUS_CHECK_INTERVAL)
    
    print("Stopped checking peer statuses...")
    s.close()

def receive_message(stop_event, sock):
    
    while not stop_event.is_set():
        message, address = sock.recvfrom(1024)
        
        if len(message) > 0:
            message = message.decode()
            
            if address in participants:
                
                # user disconnecting
                if message == "DC":
                    remove_participant(address)
                    print(address, "has disconnected. Current participants:",
                          participants)
                
                # a new user has joined
                elif "JOINED" in message:
                    received_address = message.split()[1]
                    received_ip, received_port = received_address.split(":")
                    received_port = int(received_port)
                    
                    participants.append((received_ip, received_port))
                    
                    print(received_address, "has joined. Current participants:",
                          participants)
                
                # a user has lost connection
                elif "DROPPED" in message:
                    received_address = message.split()[1]
                    received_ip, received_port = received_address.split(":")
                    received_port = int(received_port)
                    
                    remove_participant((received_ip, received_port))
                    
                    print(received_address, "has dropped from the chat. Current participants:",
                          participants)
                
                # received a chat message
                else:
                    print("{}:{} says: {}".format(address[0], address[1], message))
            
            # a new user is trying to join
            elif "JOIN" in message:
                receive_join_request(sock, address, message)
            
            # status check messages are sent from a different socket
            # (not in list of participants)
            elif message == "CHECK":
                print("Received status check request from", address,
                      "responding with OK...")
                sock.sendto(b"OK", address)
            
            else:
                print("Received invalid message from", address, ":", message)
    
    print("Stopped listening for messages...")

def send_messages(sock):
    while True:
        msg = input()
        
        if msg == "exit":
            break
        
        chat_send(sock, msg)

def run_test(stop_event, sock, messages_per_second, message_length):
    
    alphabet = string.ascii_letters + string.digits + string.punctuation
    
    # send random messages to chat
    while not stop_event.is_set():
        random_message = "".join(random.choice(alphabet) for i in range(message_length))
        chat_send(sock, random_message)
        print("Sent message:", random_message)
        stop_event.wait(1 / messages_per_second)
    
    print("Stopped sending test messages...")

def get_ip_port_input():
    while True:
        try:
            addr = input("Enter address to connect to: ")
            ip, port = addr.split(":")
            port = int(port)
        except:
            print("Please enter a valid IP address and port in the format IP:PORT, e.g., 192.168.1.101:12345")
        else:
            return (ip, port)

def main(host, addr=("", 0) , local_port=0, test_messages_per_second=0.0, test_message_length=256):
    global password_hash
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", local_port))
    print("Application port:", sock.getsockname()[1])
    
    password = input("Enter chat password (leave blank for no password): ")
    if len(password) > 0:
        password_hash = hashlib.sha256(str.encode(password)).hexdigest()
    else:
        print("Continuing without password authentication.")
    
    if host:
        print("Starting new chat at address", sock.getsockname())
        print("Waiting for participants...")
    else:
        join_failed = join(sock, addr)
        if join_failed:
            print("Exiting after failed join attempt...")
            return
    
    # start thread for receiving messages
    stop_event = threading.Event()
    th = threading.Thread(target=receive_message,
                          args=[stop_event, sock])
    th.start()
    
    # start thread for checking that neighbors are alive
    status_checking_thread = threading.Thread(target=check_neighbor_status,
                                              args=[stop_event, sock])
    status_checking_thread.start()
    
    
    if test_messages_per_second:
        print("Starting test scenario with", test_messages_per_second,
              "messages per second after 5 seconds. Press enter to stop.")
        time.sleep(5)
        
        # start thread for sending test messages
        test_thread = threading.Thread(target=run_test,
                                       args=[stop_event, sock, test_messages_per_second, test_message_length])
        test_thread.start()
        
        input()
    else:
        print("\nType text and press Enter to chat. Type 'exit' to leave.")
        # send messages to chat
        send_messages(sock)
    
    
    # disconnect from chat
    disconnect(sock)
    
    # stop listening for messages
    sock.sendto(b"", sock.getsockname())
    stop_event.set()
    th.join()
    status_checking_thread.join()
    if test_messages_per_second:
        test_thread.join()
    sock.close()

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    
    ap.add_argument("-ho", "--host", action='store_true', help="Flag for starting a new chat room. Default: False")
    ap.add_argument("-j", "--join", required=False, help="Address (IP:PORT) of the chat to join.")
    ap.add_argument("-p", "--port", type=int, default=0, help="Local port number to use for chat communication. Set to 0 to use a random available port. Default: 0")
    ap.add_argument("-t", "--test", type=float, default=0, help="Run a test scenario by sending random strings. Determines the number of messages per second.")
    ap.add_argument("-tmlen", "--test_message_length", type=int, default=256, help="Length of the messages to be sent in a test scenario in characters. Default: 256")
    
    args = vars(ap.parse_args())
    
    if args["join"] is not None:
        try:
            ip, port = args["join"].split(":")
            port = int(port)
        except:
            print("Please enter a valid IP address and port in the format IP:PORT, e.g., 192.168.1.101:12345")
        else:
            main(False, (ip, port), args["port"], test_messages_per_second=args["test"],
                 test_message_length=args["test_message_length"])
    elif args["host"]:
        main(True, local_port=args["port"], test_messages_per_second=args["test"],
             test_message_length=args["test_message_length"])
    else:
        print("Please determine whether to join or host a chat. Use flag -h to see available command arguments.")
    
    
