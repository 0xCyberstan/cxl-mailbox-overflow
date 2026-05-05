# cxl-mailbox-overflow
PoC for three guest-triggerable bugs in QEMU's CXL Type 3 mailbox emulation (hw/cxl/cxl-mailbox-utils.c). OOB read, heap overflow, and write-what-where chain into a full guest-to-host escape with ASLR bypass. Tested against QEMU v11.0.0-rc2.
