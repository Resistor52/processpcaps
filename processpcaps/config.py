#!/usr/bin/python
#
# File: config.py
#
# Description: 
#
# Author: Kenneth G. Hartman
# Site: www.KennethGHartman.com
#
# ======================================================================

# General parameters
generated_scripts = "/usr/local/processpcaps/generated_scripts/"
artifacts = "/usr/local/processpcaps/artifacts/"
mainlog = "processpcaps.log"
scriptout =  "processpcap.sh"
hashfile_suffix = "_hash"
outputlogsuffix = ".log"
output = "/usr/local/processpcaps/output/"

# snort parameters
snort_configs = "/usr/local/processpcaps/snort_configs/"
snort_logs = "/root/snort_logs/"  #TODO Replace with output
snortconfig = "snort.conf"
alertfile = "alert"

# p0f parameters
p0f_output = "p0fOutput.txt"

# tcpflow parameters
tcpflow_dir = "output/"
tcpflow_filelist = "tcpflow_files.txt"
hashes_dir = "output_hashes/"



	
if __name__ == "__main__":
	print("This is the configuration file.  It doesn't do anything")
        print("except load the global parameters into calling modules")
	
	
