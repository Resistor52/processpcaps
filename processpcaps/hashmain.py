# File: 
#
# Description: 
#
# Author: Kenneth G. Hartman
# Site: www.KennethGHartman.com
#
# ======================================================================

import hash

# Test the calc_hash function
result = hash.calc_hash("/root/cleanup.sh")

print("MD5:    " + result[0])
print("SHA1:   " + result[1])
print("SHA256: " + result[2])

# Test the write_hash function, write to same folder
hash.write_hash("/root/processpcaps/config.py", result, "_hash1" ) 

# Test the write_hash function, write to different folder 
hash.write_hash("/root/processpcaps/config.py", result, "_hash2", "/root/output/" )
