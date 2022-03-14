# Based on https://github.com/vahidmohsseni/vagrant-nfs-mpi

# Install tools for tracking network activity
$installNetworkTools = <<SCRIPT
apt update
apt install bmon tcptrack -y
SCRIPT


Vagrant.configure("2") do |config|
  (1..4).each do |i|
    config.vm.define "peer#{i}" do |node|
      
      node.vm.box = "ubuntu/bionic64"
      node.vm.hostname = "peer#{i}"
      node.vm.network "private_network", ip: "192.168.56.1#{i}", hostname: true
      
      # Add temporary private and public key to server
      # CAUTION: The keys should be removed after initial configuration
      node.vm.provision "CopySSHKeys", type: "file", source: "ssh_keys/id_rsa.pub", destination: "/home/vagrant/"
      node.vm.provision "ConfigSSH", type: "shell", inline: <<-SCRIPT
      cat id_rsa.pub >> .ssh/authorized_keys
      SCRIPT

      # Copy the code to the peer
      node.vm.provision "CopyClientPy", type:"file", source: "p2p_chat/p2p_chat.py", destination: "/home/vagrant/", run: "always"

      # Install network tracking tools
      node.vm.provision "InstallTcptrack", type: "shell", run: "once", inline: $installNetworkTools

    end

  end

end
