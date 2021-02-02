
# vim: tabstop=8


all:

# prep
prep:
	# commands needed to prep kernel
	sudo apt install raspberrypi-kernel-headers

# build usb_f_mdlm.ko
build:
	# commands to configure and build

# test load usb_f_mdlm.ko
load:
	sudo insmod drivers/usb/gadget/function/usb_f_mdlm.ko


config:
	gadgetconfig --verbose --add /etc/gadgetservice/mdlm-15ec-f101.json ;
	sysfstree --gadget


test:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

