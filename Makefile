.PHONY: all clean kernel userspace
all: kernel userspace
kernel:
	make -C kernel/  all
clean:
	make -C kernel/ clean
