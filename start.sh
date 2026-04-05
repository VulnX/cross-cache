#!/bin/sh

set -e

make
cp vuln.ko initramfs/

gcc -static -o initramfs/exploit exploit.c kpwn/*.c

cd initramfs
find . | cpio -H newc -o | gzip > ../initramfs.cpio.gz
cd ..

qemu-system-x86_64 \
	-kernel bzImage \
	-initrd initramfs.cpio.gz \
	-nographic \
	-append "console=ttyS0 nokaslr quite loglevel=3" \
	-monitor /dev/null \
	-s
