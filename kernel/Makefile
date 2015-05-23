.PHONY: all clean install uninstall
obj-m+=domain_hash.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install:
	insmod domain_hash.ko
uninstall:
	rmmod domain_hash.ko
