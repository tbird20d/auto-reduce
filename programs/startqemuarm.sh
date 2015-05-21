#!/bin/sh

# copied originally from ~/work/yocto/danny-test1
yoctoroot=/a/home/tbird/work/yocto/danny-test1


###### RUNQEMU STUFF
#kimage=/a/home/tbird/work/yocto/danny-test1/tmp/deploy/images/zImage-qemuarm.bin
#netstuff= "-net nic,vlan=0 -net tap,vlan=0,ifname=tap0,script=no,downscript=no"
machine="versatilepb"
#kcmd="root=/dev/sda rw console=ttyAMA0,115200 console=tty ip=192.168.7.2::192.168.7.1:255.255.255.0 mem=128M highres=off "

###### MY STUFF
#kimage=${yoctoroot}/tmp/deploy/images/bzImage-qemux86.bin
kimage=${KBUILD_OUTPUT}/arch/arm/boot/zImage
rootfs=${yoctoroot}/tmp/deploy/images/core-image-minimal-qemuarm-20130104010142.rootfs.cpio.gz


#kcmd="console=ttyAMA0,115200 mem=24M highres=off "
kcmd="console=ttyAMA0,115200 mem=24M "

${yoctoroot}/tmp/sysroots/x86_64-linux/usr/bin/qemu-system-arm \
	-kernel ${kimage} \
	-initrd ${rootfs} \
	-nographic \
	-M ${machine} \
	-append "${kcmd}"
