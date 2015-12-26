obj-m += sys_xcrypt.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: xcipher xcrypt

xcipher: xcipher.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi xcipher.c -o xcipher -lssl -lcrypto 

xcrypt:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xcipher
