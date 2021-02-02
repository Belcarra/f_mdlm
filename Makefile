
# vim: tabstop=8


all:

# prep
prep:
	# commands needed to prep kernel

# build usb_f_mdlm.ko
build:
	# commands to configure and build

# test load usb_f_mdlm.ko
load:
	insmod drivers/usb/gadget/function/usb_f_mdlm.ko


config:
	gadgetconfig --verbose --add /etc/gadgetservice/mdlm-15ec-f101.json ;
	sysfstree --gadget


