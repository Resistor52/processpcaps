#!/usr/bin/python
#
# Author: Kenneth G. Hartman
# Site: www.KennethGHartman.com
#
# ======================================================================

#IDEA iterate through a directory to get the tests to import
import proc_snort, proc_p0f, proc_tcpflow

#Variables
PCAP_ID = "P001"
TEST_ID = "T0001"
stuff = proc_snort.processpcap(PCAP_ID, TEST_ID, "/root/pcap_files/in/Skype-2.pcap")
#stuff = proc_snort.processpcap(PCAP_ID, TEST_ID, "/root/pcap_files/in/pcap_2012_1123_0900.pcap")

#Variables
PCAP_ID = "P001"
TEST_ID = "T0002"
stuff = proc_p0f.processpcap(PCAP_ID, TEST_ID, "/root/pcap_files/in/Skype-2.pcap")
#stuff = proc_p0f.processpcap(PCAP_ID, TEST_ID, "/root/pcap_files/in/pcap_2012_1123_0900.pcap")

#Variables
PCAP_ID = "P001"
TEST_ID = "T0003"
stuff = proc_tcpflow.processpcap(PCAP_ID, TEST_ID, "/root/pcap_files/in/Skype-2.pcap")
#stuff = proc_tcpflow.processpcap(PCAP_ID, TEST_ID, "/root/pcap_files/in/pcap_2012_1123_0900.pcap")


#print stuff
#print "\n"
print("Execution complete")

