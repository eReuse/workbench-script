test_pxe:
	qemu-system-x86_64 -m 1G -boot n -netdev user,id=mynet0,tftp=/srv/pxe-tftp,bootfile=pxelinux.0 -device virtio-net,netdev=mynet0
