#!/usr/bin/python
#
# File: proc_tcpflow.py
#
# Description: 
#
# Author: Kenneth G. Hartman
# Site: www.KennethGHartman.com
#
# Ideas: Pass in config.snortconfig or iterate through a directory
#    or read from XML file
#
#
# ======================================================================

import os, sys, glob, subprocess, shutil, datetime  # Standard python modules
import config, hash                                 # Custom modules

# Other Variables
scriptout_wpath = config.generated_scripts + config.scriptout


def processpcap(pcapno, testno, name):
        print(pcapno + "-" + testno +":  " + __file__) # Status update to console
        if (name[-5:].lower() <> ".pcap"):
                raise Exception("Error - the last argumant should be a filename with a PCAP extension")
        pcapsample = name.split("/")
        pcapsample = pcapsample[-1]
                
        # Create a shell script and execute it
        cmdstring = ("cd $HOME/output\ntcpflow -r " + name + " > /dev/null")
        f = open(scriptout_wpath,'w')
        f.write("#!/bin/bash\n" + cmdstring + '\n')
        f.close()
        p = subprocess.Popen(["chmod", "u+x", scriptout_wpath], stderr=subprocess.PIPE)
        output, err = p.communicate()
        if (len(err) <> 0):
                raise Exception("Error: " + err)
        p = subprocess.Popen([scriptout_wpath], stderr=subprocess.PIPE)
        output, err = p.communicate()
        if (len(err) <> 0):
                raise Exception("Error: " + err)

        # Create a subdirectory and move/copy artifacts there
        directory = config.artifacts + pcapno + "-" + testno + "/"
        if not os.path.exists(directory):
                os.makedirs(directory)
        os.rename(scriptout_wpath, directory + config.scriptout)
        shutil.copytree(config.output, directory + config.tcpflow_dir)
        shutil.copyfile(name, directory + pcapsample)

        # Create a file that lists all of the tcpflow output files
        outpath = directory + config.tcpflow_dir
        outfiles = [ f for f in os.listdir(outpath) if os.path.isfile(os.path.join(outpath,f)) ]
        myfile = directory + config.tcpflow_filelist
        f = open(myfile,'w')
        for fileitem in outfiles:
                f.write(fileitem + '\n')
        f.close()
        
        # Create a Hash File for each artifact
        script_hashes = hash.calc_hash(directory + config.scriptout)
        hash.write_hash(directory + config.scriptout, script_hashes, config.hashfile_suffix)
        pcap_hashes = hash.calc_hash(directory + pcapsample)
        hash.write_hash(directory + pcapsample, pcap_hashes, config.hashfile_suffix)
        filelist_hashes = hash.calc_hash(directory + config.tcpflow_filelist)
        hash.write_hash(directory + config.tcpflow_filelist, filelist_hashes, config.hashfile_suffix)
        # Create a Hash File for each output file in the subdirectory
        hashlist = []
        destdir = directory + config.hashes_dir
        if not os.path.exists(destdir):
                os.makedirs(destdir)
        for fileitem in outfiles:
                my_hashes = hash.calc_hash(directory + config.tcpflow_dir + fileitem)
                myfile2hash = directory + config.tcpflow_dir + fileitem
                hash.write_hash(myfile2hash, my_hashes, config.hashfile_suffix, destdir)
                hashlist.append(my_hashes)

        # Generate logs of the artifacts
        logtime = datetime.datetime.now().time().isoformat()
        logdate = datetime.datetime.now().date().isoformat()
        outputlog = pcapno + "-" + testno + config.outputlogsuffix
        logmsg = "Sample ID: " + pcapno + "\nTest ID: " + testno + "\n\n"
        logmsg += "On " + logdate + " at " + logtime + " the following command was executed:\n\n"
        logmsg += cmdstring + "\n\nto produce the following output files listed in:\n\n"
        logmsg += pcapno + "-" + testno + "/" + config.tcpflow_dir
        logmsg += "\n\n" + "*" * 100 + "\n\n"
        logmsg += "The PCAP is saved as:   '" + pcapsample + "'\n"
        logmsg += "The hashes of '" + pcapsample + "' have been saved as '"
        logmsg += pcapsample + config.hashfile_suffix + "'\n"
        logmsg += "MD5:    " + pcap_hashes[0] + "\n"
        logmsg += "SHA1:   " + pcap_hashes[1] + "\n"
        logmsg += "SHA256: " + pcap_hashes[2] + "\n"
        logmsg += "\nThe command is saved as:   '" + config.scriptout + "'\n"
        logmsg += "The hashes of '" + config.scriptout + "' have been saved as '"
        logmsg += config.scriptout + config.hashfile_suffix + "'\n"
        logmsg += "MD5:    " + script_hashes[0] + "\n"
        logmsg += "SHA1:   " + script_hashes[1] + "\n"
        logmsg += "SHA256: " + script_hashes[2] + "\n"
        logmsg += "\nThe list of output files is saved as:   '" + config.tcpflow_filelist + "'\n"
        logmsg += "The hashes of '" + config.tcpflow_filelist + "' have been saved as '"
        logmsg += config.tcpflow_filelist + config.hashfile_suffix + "'\n"
        logmsg += "MD5:    " + filelist_hashes[0] + "\n"
        logmsg += "SHA1:   " + filelist_hashes[1] + "\n"
        logmsg += "SHA256: " + filelist_hashes[2] + "\n"        
        logmsg += "\nThe hashes for every file output by tcpflow have been saved in the following"
        logmsg += " directory:\n" + pcapno + "-" + testno + "/" + config.hashes_dir + "\n"
        logmsg += "\nThis log file is saved as:   " + outputlog + "\n"
        logmsg += "The hashes of '" + outputlog + "' have been saved as '"
        logmsg += outputlog + config.hashfile_suffix + "'\n"        
        f = open(directory + outputlog,'w')
        f.write(logmsg)
        f.write("\n\n")
        f.close()
        testlog_hashes = hash.calc_hash(directory + outputlog)
        hash.write_hash(directory + outputlog, testlog_hashes, config.hashfile_suffix)
        f = open(config.artifacts + config.mainlog,'a')
        logmsg += "MD5:    " + testlog_hashes[0] + "\n"
        logmsg += "SHA1:   " + testlog_hashes[1] + "\n"
        logmsg += "SHA256: " + testlog_hashes[2] + "\n"
        f.write(logmsg)
        f.write("\n\n")
        f.write("=" * 40 + "  END  OF  RECORD  " + "=" * 40 + "=\n\n")
        f.close()

        # Housekeeping
        files = glob.glob(config.output + '*')
        for f in files:
                os.remove(f)

        results = {
                'directory': directory,
                'pcap': pcapsample,
                'pcap_hash': pcap_hashes,
                'pcap_hashfile': pcapsample + config.hashfile_suffix,
                'shellcmd': config.scriptout,
                'shellcmd_hash': script_hashes,
                'shellcmd_hashfile': config.scriptout + config.hashfile_suffix,
                'output_filelist': config.tcpflow_filelist,
                'filelist_hash': filelist_hashes,
                'filelist_hashfile': config.tcpflow_filelist + config.hashfile_suffix,
                'list_hashes': hashlist,
                'testlog': outputlog,
                'testlog_hash': testlog_hashes,
                'testlog_hashfile': outputlog + config.hashfile_suffix
                }
        
        return(results)
	
if __name__ == "__main__":
        if (len(sys.argv) <> 4):
                print("Proper syntax is: python "+ __file__ + " pcapID testID pcapfile") 
        processpcap(sys.argv[1], sys.argv[2], sys.argv[3])
