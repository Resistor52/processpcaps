# Install Script for "ProcessPCAPs"
This is the installation instructions for the "ProcessPCAPs" pcap file analyzer.  The Kali Linux distribution was selected to simplify the installation of the security tools, nonetheless only the required software will be installed.

Follow these steps:

**Step 1** - Install Kali Linux on a new Virtual Machine using this image: [http://cdimage.kali.org/kali-2.0/kali-linux-mini-2.0-amd64.iso](http://cdimage.kali.org/kali-2.0/kali-linux-mini-2.0-amd64.iso).  At the Software Selection screen, choose only the following options:

* SSH Server
* Standard System Utilities

**Step 2** - Enter the following commands into the local console as root:

    wget https://raw.githubusercontent.com/Resistor52/processpcaps/master/install/install.sh
    chmod 744 install.sh
	./install.sh

**Step 3** - Once the install is done, you will probably want to SSH in versus work from the console.  Connect via SSH using the **'manager'** account created by the install script.  The default password is **'manager99'**.

**Step 4** - Use the `passwd` command to change the default password for manager account.

**Step 5** - Next, you will need some PCAP files to process.  The [netresec.com](http://www.netresec.com/?page=PcapFiles) site has several examples.  For your convenience, you can run the following command to download several:
```
/usr/local/processpcaps/downloadSamplePCAPS.sh &
``` 
The script downloads 8 files simultaneously in the background, but it is suggested that you use the `&` to run the script itself in the background. (You may need to hit another carriage return to get back to the prompt.)

When all of the sample files have been downloaded, you will get a "Downloads Complete" Message on the terminal. (You may need to hit another carriage return to get back to the prompt.)

**Step 6** - To see ProcessPCAPs in action...