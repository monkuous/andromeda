#pragma once

#define KERN_PHYS_BASE 0x7000

#define KERN_VIRT_BASE 0xc0000000
#define PTBL_VIRT_BASE 0xffc00000

#define KERN_TO_PHYS(x) ((x) - KERN_VIRT_BASE)
