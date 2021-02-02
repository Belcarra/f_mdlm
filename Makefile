
# vim: tabstop=8

obj-m := f_mdlm.o

all:

# prep
prep:
	# commands needed to prep kernel
	sudo apt install raspberrypi-kernel-headers
	#sudo apt update
	#sudo apt install raspberrypi-kernel
	#sudo apt install linux-image-rpi-rpfv linux-headers-rpi-rpfv

# build usb_f_mdlm.ko
build:
	# commands to configure and build

# test load usb_f_mdlm.ko
load:
	sudo insmod f_mdlm.ko


config:
	gadgetconfig --verbose --add /etc/gadgetservice/mdlm-15ec-f101.json ;
	sysfstree --gadget


test:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

