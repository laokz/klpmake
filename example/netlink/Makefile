modulename := netlinkfix
obj-m := $(modulename).o
$(modulename)-y := af_netlink.o diag.o

all:
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

