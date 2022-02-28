
all: 
	gcc -m32 -o a32.out call_shellcode.c
	gcc -o a64.out call_shellcode.c

setuid:
	gcc -m32 -o a32.out call_shellcode.c
	gcc -o a64.out call_shellcode.c
	sudo chown root a32.out a64.out
	sudo chmod 4755 a32.out a64.out

clean:
	rm -f a32.out a64.out *.o

