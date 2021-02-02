
# vim: tabstop=8

usb_f_mdlm-y := f_mdlm.o
obj-m := usb_f_mdlm.o

all:

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

install:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules_install
	
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	




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

unload:
	gadgetconfig --verbose --disable --remove-all

