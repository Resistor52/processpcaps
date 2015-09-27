# Install Script for "ProcessPCAPs"
This is the installation instructions for the "ProcessPCAPs" pcap file analyzer.  The Kali Linux distribution was selected to simplify the installation of the security tools, nonetheless only the required software will be installed.

Follow these steps:

Step 1 - Install Kali Linux on a new Virtual Machine using this image: [http://cdimage.kali.org/kali-2.0/kali-linux-mini-2.0-amd64.iso](http://cdimage.kali.org/kali-2.0/kali-linux-mini-2.0-amd64.iso).  At the Software Selection screen, choose only the following options:

* SSH Server
* Standard System Utilities

Step 2 - Enter the following commands into the local console as root:

    wget https://raw.githubusercontent.com/Resistor52/processpcaps/master/install/install.sh
    chmod 744 install.sh
	./install.sh

Once the install is done, type ######## to see ProcessPCAPs in action
