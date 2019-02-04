"""
Bhavik Dhandhalya
M.E. Computer Science student at BITS Pilani
Subject: Network Security G513
Homework 2: "Encryption for fun"
"""

#!/usr/bin/env python
###  Call syntax:
###
###   python    Encrypt.py  plain.txt  cipher.txt

import sys
from BitVector import *                                                       

if len(sys.argv) is not 3:                                                    
    sys.exit('''Needs two command-line arguments, one for '''
             '''the input plaintext file and the other for the '''
             '''encrypted output file''')

PassPhrase = "I want to learn network security and cryptography"                            

BLOCKSIZE = 64                                                                
numbytes = BLOCKSIZE // 8                                                     

# Reduce the passphrase to a bit array of size BLOCKSIZE:
bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)

for i in range(0,len(PassPhrase) // numbytes):                                
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]                          
    bv_iv ^= BitVector( textstring = textstr )                           

# Get key from user:
# key = None
# if sys.version_info[0] == 3:                                                  
#     key = input("\nEnter key: ")                                             
# else:                                                                         
#     key = raw_input("\nEnter key: ")   
key = "bhavikdhandhalya"                                       
key = key.strip()                                                             

# Reduce the key to a bit array of size BLOCKSIZE:
key_bv = BitVector(bitlist = [0]*BLOCKSIZE)                                   
for i in range(0,len(key) // numbytes):                                       
    keyblock = key[i*numbytes:(i+1)*numbytes]                                 
    key_bv ^= BitVector( textstring = keyblock )                              

# Create a bitvector for storing the ciphertext bit array:
msg_encrypted_bv = BitVector( size = 0 )                                      

# Carry out differential XORing of bit blocks and encryption:
previous_block = bv_iv                                                        
bv = BitVector( filename = sys.argv[1] )   

while (bv.more_to_read):                                                      
    bv_read = bv.read_bits_from_file(BLOCKSIZE)                               
    if len(bv_read) < BLOCKSIZE:                                              
        bv_read += BitVector(size = (BLOCKSIZE - len(bv_read)))              
    bv_read ^= key_bv                                                         
    bv_read ^= previous_block                                                 
    previous_block = bv_read.deep_copy()                                      
    msg_encrypted_bv += bv_read                                               

# Convert the encrypted bitvector into a hex string:    
outputhex = msg_encrypted_bv.get_hex_string_from_bitvector()                

# Write ciphertext bitvector to the output file:
FILEOUT = open(sys.argv[2], 'w')                                              
FILEOUT.write(outputhex)                                                      
FILEOUT.close()                                                               