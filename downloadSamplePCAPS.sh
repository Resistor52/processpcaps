#!/bin/bash
# This script downloads some sample PCAP files
# For Testing the ProcessPCAPs framework
# https://github.com/Resistor52/processpcaps
# Get more PCAPS at http://www.netresec.com/?page=PcapFiles

wall -n "NOTE: Some of these files are large, so this may take a new moments"
wall -n "Downloading each in the background, but you will be notified when they are done."
cd /home/upload
wget -b -a log.txt http://www.snaketrap.co.uk/pcaps/Ncapture.pcap | 
wget -b -a log.txt http://www.snaketrap.co.uk/pcaps/hbot.pcap
wget -b -a log.txt http://www.snaketrap.co.uk/pcap/hptcp.pcap
wget -b -a log.txt http://panda.gtisc.gatech.edu/malrec/pcap/00e8051b-5793-4180-9def-31306bc010e0.pcap
wget -b -a log.txt http://panda.gtisc.gatech.edu/malrec/pcap/709efbe4-3914-440e-a468-b63f88e4ce63.pcap 
wget -b -a log.txt http://panda.gtisc.gatech.edu/malrec/pcap/4ec30df6-ee8f-4cd7-89b7-64c2d1fce607.pcap
wget -b -a log.txt http://holisticinfosec.org/toolsmith/files/nov2k6/toolsmith.pcap
wget -b -a log.txt http://barracudalabs.com/downloads/5f810408ddbbd6d349b4be4766f41a37.pcap

DLTEST=$(ps aux | grep "wget.*pcapx$" | wc -c)
while [ $DLTEST -gt 0 ]
do
DLTEST=$(ps aux | grep "wget.*pcap$" | wc -c)
done
wall -n "Downloads Complete"
