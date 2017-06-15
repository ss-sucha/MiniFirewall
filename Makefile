obj-m += mfw_module.o

oall:	mfw mfwmod

mfw:	mfw.c mfw.h
	gcc -Wall -o mfw mfw.c

mfwmod:	
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm mfw
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
