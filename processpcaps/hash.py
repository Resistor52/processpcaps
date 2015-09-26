# File: 
#
# Description: 
#
# Author: Kenneth G. Hartman
# Site: www.KennethGHartman.com
#
# ======================================================================

import subprocess

def calc_hash(myfile):
    hash_md5 = do_hash("md5sum",myfile)
    hash_sha1 = do_hash("sha1sum",myfile)
    hash_sha256 = do_hash("sha256sum",myfile)
    return(hash_md5, hash_sha1, hash_sha256)


def do_hash(algo, thefile):
    p = subprocess.Popen([algo, thefile], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, err = p.communicate()
    if (len(err) <> 0):
        raise Exception("Error: " + err)
    return_hash = output.split(" ")
    return(return_hash[0])

def write_hash(file2hash, hashset, suffix, *path):
    # Provide the path if hashfile is to be written to alt location
    myfile = file2hash.split("/")[-1]
    if len(path)<>0:
        fullpath = path[0] + myfile + suffix
    else:
        fullpath = file2hash + suffix
    f = open(fullpath,'w')
    f.write("MD5:    " + hashset[0] + '\n')
    f.write("SHA1:   " + hashset[1] + '\n')
    f.write("SHA256: " + hashset[2] + '\n')
    f.close()

if __name__ == "__main__":
    errormsg = """Error - This module needs to be called by another program
        Call it by passing in a file name with path and it will return
        the MD5, the SHA1, and SHA256 hashes of the file"""
    print(errormsg)

