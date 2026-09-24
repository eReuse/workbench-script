.PHONY: test_pxe
test_pxe:
	qemu-system-x86_64 -m 1G -boot n -netdev user,id=mynet0,tftp=/srv/pxe-tftp,bootfile=pxelinux.0 -device virtio-net,netdev=mynet0

# TODO not very convinced on having this, but ok right now
.PHONY: install_pxe_debug
install_pxe_debug:
	DEBUG=true ./pxe-reset.sh

# Test locally the TFTP files generated
#  (obviously, this cannot work with NFS)
test_pxe_tftp:
	sudo qemu-system-x86_64 \
		-enable-kvm -m 2G -vga qxl \
		-netdev user,id=lan,tftp=./docker-data/pxe-tftp/,bootfile=pxelinux.0 \
		-device virtio-net,netdev=lan,id=nic1 \
		-boot n
