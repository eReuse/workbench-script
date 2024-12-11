.PHONY: test_pxe
test_pxe:
	qemu-system-x86_64 -m 1G -boot n -netdev user,id=mynet0,tftp=/srv/pxe-tftp,bootfile=pxelinux.0 -device virtio-net,netdev=mynet0

# TODO not very convinced on having this, but ok right now
.PHONY: install_pxe_debug
install_pxe_debug:
	DEBUG=true ./install-pxe.sh
