#!/bin/bash

# This scripts assumes a fresh install onto a Debian virtual machine from 
# http://cdimage.kali.org/kali-2.0/kali-linux-mini-2.0-amd64.iso

#Test to ensure expected OS Distribution and Version
OSTEST=$(grep "Kali GNU/Linux 2.0 (sana)" /etc/*release | wc -c)
if [ $OSTEST == 0 ]
then
echo "Incorrect Operating System - Kali Linux 2.0 Expected"
exit 1
fi

#Test to ensure script is run as root
USERTEST=$(whoami)
if [ $USERTEST != "root" ]
then
echo "Incorrect Permissions - Run this script as root"
#exit 1
fi

# Install required packages
apt-get update
apt-get upgrade
DEBIAN_FRONTEND=noninteractive apt-get -y install tshark 
apt-get -y install tcpflow p0f dsniff chkconfig git vim
apt-get -y install flex bison gcc g++ libnet1 libnet1-dev libpcre3 libpcre3-dev 

#Install Snort Pre-Requisites
## Install libpcap
cd /usr/src
wget http://www.tcpdump.org/release/libpcap-1.6.1.tar.gz
tar -zxf libpcap-1.6.1.tar.gz 
cd libpcap-1.6.1
./configure --prefix=/usr
make; make install

## Install libdnet
cd /usr/src
wget http://libdnet.googlecode.com/files/libdnet-1.12.tgz
tar -zxf libdnet-1.12.tgz
cd libdnet-1.12
./configure --prefix=/usr --enable-shared
make; make install

## Install daq:
cd /usr/src
wget https://snort.org/downloads/snort/daq-2.0.6.tar.gz
tar xvfz daq-2.0.6.tar.gz
cd daq-2.0.6
./configure
make; make install

## Install zlib
cd /usr/src
wget http://zlib.net/zlib-1.2.8.tar.gz
tar xvfz zlib-1.2.8.tar.gz
cd zlib-1.2.8
./configure
make; make install

## Update Shared Library Path
echo >> /etc/ld.so.conf /usr/lib
echo >> /etc/ld.so.conf /usr/local/lib
ldconfig

# Install Snort
/usr/src
wget wget https://snort.org/downloads/snort/snort-2.9.7.5.tar.gz
tar xvfz snort-2.9.7.5.tar.gz
cd snort-2.9.7.5
./configure --enable-sourcefire
make; make install

# Add the user "manager" and password "manager99"
# Give the manager account sudo priv
# Don't forget to change the default password!!
useradd -m manager
echo 'manager:manager99' | chpasswd
usermod -a -G sudo manager

# Add the user "upload."  This user has only the minimum privileges
# to upload a file to its home directory
# Don't forget to change the default password!!
useradd -m upload
echo 'upload:upload33' | chpasswd

# Change SSH keys
update-rc.d -f ssh remove
update-rc.d -f ssh defaults
chkconfig ssh
cd /etc/ssh
mkdir /etc/ssh/default_kali_keys
mv /etc/ssh/ssh_host_* /etc/ssh/default_kali_keys/
dpkg-reconfigure openssh-server
md5sum /etc/ssh/ssh_host_* > /tmp/hash_newkeys
md5sum /etc/ssh/default_kali_keys/ssh_host_* > /tmp/hash_oldkeys
if [ $(diff /tmp/hash_oldkeys /tmp/hash_newkeys | wc -m ) -eq 0 ]; then 
	echo '*******************************'
	echo 'WARNING Keys were not updated'
	echo 'install script has been aborted'
	echo '*******************************'
	exit
fi
rm /tmp/hash_*
rm -r /etc/ssh/default_kali_keys/ 

# Modify the Message of the Day
echo ' ' > /etc/motd
echo 'Welcome to Kali-System-1' >> /etc/motd
echo ' ' >> /etc/motd
echo 'Unauthorized access is prohibited' >> /etc/motd
echo ' ' >> /etc/motd

service ssh restart

# Pull down the ProcessPCAPs code

cd /usr/local/
git clone https://github.com/Resistor52/processpcaps.git
chmod 550 /usr/local/processpcaps/check4upload.sh
chmod 550 /usr/local/processpcaps/downloadSamplePCAPS.sh


# Create the directories for PCAP processing
mkdir /usr/local/processpcaps/pcap_files/
mkdir /usr/local/processpcaps/pcap_files/in/
mkdir /usr/local/processpcaps/pcap_files/processed/
mkdir /usr/local/processpcaps/snort_configs/
mkdir /usr/local/processpcaps/generated_scripts/
mkdir /usr/local/processpcaps/snort_logs/
mkdir /usr/local/processpcaps/artifacts/
mkdir /usr/local/processpcaps/output/

# Schedule the script to check for uploaded *.PCAP files.  This script will run every minute and
# if it finds a packet capture will move it to the "in" directory to be processed 
echo '0/1 0 0 0 0 root /usr/local/processpcaps/check4upload.sh' >> /etc/crontab

