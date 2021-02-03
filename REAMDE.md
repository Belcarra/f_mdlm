# Gadget MDLM
## Tue Feb 02 18:10:00 PST 2021 
## Stuart.Lynne@belcarra.com

This is a Gadget implementation of the SAFE (and BLAN variant) of the 
*MDLM Semantic Model for SAFE Communications Devices*.


## Overview

The SAFE protocol was defined to support *Networking over USB* on
USB Client devices that had limited endpoints or interfaces available.

It collapsed the semantic model to a single data plane and added some
additional options to help with implementation or verify correct operation.

See this document for details: 

    *MCCI-950198-2002-01-27-SAFE.pdf*


## f_mdlm.c

This was derived from the gadget *f_ecm.c* which had incomplete
support for some of the SAFE protocol.

This adds the additional MDLM GUID's to the descriptor block
and implements some additional device requests and supports
CRC.

## Installation

Generally:


```
make prep
make modules
make install
depmod usb_f_mdlm
```


## Sample

See this script to load a test configuration: 

    *mdlm-safe-15ec-f101.sh*



## Contents

``
f_mdlm.c
Makefile
MCCI-950198-2002-01-27-SAFE.pdf
mdlm-safe-15ec-f101.sh
REAMDE.md
u_ether_configfs.h
u_ether.h
u_mdlm.h
```

*N.B. the two files: u_ether_configfs.h and u_ether.h are copies from the
*drivers/usb/gadget/functions* directory of the Linux kernel. They are
included as a convience so this module can be build by installing
the kernel headers only without the entire kernel source tree.*


