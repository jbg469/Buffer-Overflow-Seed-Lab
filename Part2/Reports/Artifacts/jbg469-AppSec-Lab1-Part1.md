after typing make we see the following commands execute 
gcc -m32 -z execstack -o a32.out call_shellcode.c
gcc -z execstack -o a64.out call_shellcode.c
The output files are visible locally but not on the github repo. 
