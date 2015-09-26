#!/usr/bin/python
#
# File: proc_p0f.py
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

import os, sys, subprocess, shutil, datetime  # Standard python modules
import config, hash                           # Custom modules

# Other Variables
scriptout_wpath = config.generated_scripts + config.scriptout
config.snortconfig_wpath = config.snort_configs + config.snortconfig


def processpcap(pcapno, testno, name):
        print(pcapno + "-" + testno +":  " + __file__) # Status update to console
        if (name[-5:].lower() <> ".pcap"):
                raise Exception("Error - the last argumant should be a filename with a PCAP extension")
        pcapsample = name.split("/")
        pcapsample = pcapsample[-1]
                
        # Create a shell script and execute it
        cmdstring = ("snort -r " + name + " -q -K none -l " +
                     config.snort_logs + " -c " + config.snortconfig_wpath)
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
        shutil.copyfile(config.snortconfig_wpath, directory + config.snortconfig)
        os.rename(config.snort_logs + config.alertfile, directory + config.alertfile)
        shutil.copyfile(name, directory + pcapsample)
        
        # Create a Hash File for each artifact
        script_hashes = hash.calc_hash(directory + config.scriptout)
        hash.write_hash(directory + config.scriptout, script_hashes, config.hashfile_suffix)
        snortcfg_hashes = hash.calc_hash(directory + config.snortconfig)
        hash.write_hash(directory + config.snortconfig, snortcfg_hashes, config.hashfile_suffix)
        alert_hashes = hash.calc_hash(directory + config.alertfile)
        hash.write_hash(directory + config.alertfile, alert_hashes, config.hashfile_suffix)
        pcap_hashes = hash.calc_hash(directory + pcapsample)
        hash.write_hash(directory + pcapsample, pcap_hashes, config.hashfile_suffix)


        # Generate logs of the artifacts
        logtime = datetime.datetime.now().time().isoformat()
        logdate = datetime.datetime.now().date().isoformat()
        outputlog = pcapno + "-" + testno + config.outputlogsuffix
        logmsg = "Sample ID: " + pcapno + "\nTest ID: " + testno + "\n\n"
        logmsg += "On " + logdate + " at " + logtime + " the following command was executed:\n\n"
        logmsg += cmdstring + "\n\nto produce the following alert file :\n\n" + config.alertfile 
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
        logmsg += "\nThe snort alert is saved as:   '" + config.alertfile + "'\n"
        logmsg += "The hashes of '" + config.alertfile + "' have been saved as '"
        logmsg += config.alertfile + config.hashfile_suffix + "'\n"
        logmsg += "MD5:    " + alert_hashes[0] + "\n"
        logmsg += "SHA1:   " + alert_hashes[1] + "\n"
        logmsg += "SHA256: " + alert_hashes[2] + "\n"
        logmsg += "\nThe snort config file is saved as:   '" + config.snortconfig + "'\n"
        logmsg += "The hashes of '" + config.snortconfig + "' have been saved as '"
        logmsg += config.snortconfig + config.hashfile_suffix + "'\n\n"
        logmsg += "MD5:    " + snortcfg_hashes[0] + "\n"
        logmsg += "SHA1:   " + snortcfg_hashes[1] + "\n"
        logmsg += "SHA256: " + snortcfg_hashes[2] + "\n"
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

        results = {
                'directory': directory,
                'pcap': pcapsample,
                'pcap_hash': pcap_hashes,
                'pcap_hashfile': pcapsample + config.hashfile_suffix,
                'shellcmd': config.scriptout,
                'shellcmd_hash': script_hashes,
                'shellcmd_hashfile': config.scriptout + config.hashfile_suffix,
                'snortconf': config.snortconfig,
                'snortconf_hash': snortcfg_hashes,
                'snortconf_hashfile': config.snortconfig + config.hashfile_suffix,
                'alertfile': config.alertfile,
                'alert_hash': alert_hashes,
                'alert_hashfile': config.alertfile + config.hashfile_suffix,
                'testlog': outputlog,
                'testlog_hash': testlog_hashes,
                'testlog_hashfile': outputlog + config.hashfile_suffix
                }
        
        return(results)
	
if __name__ == "__main__":
        if (len(sys.argv) <> 4):
                print("Proper syntax is: python "+ __file__ + " pcapID testID pcapfile") 
        processpcap(sys.argv[1], sys.argv[2], sys.argv[3])
