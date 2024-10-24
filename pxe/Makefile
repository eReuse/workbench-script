include .env
export $(shell sed 's/=.*//' .env)

.PHONY: test_pxe

clean:
	@if [ ! -f .env ]; then \
		echo ".env file not found!."; \
		exit 1; \
	fi

	@echo "Purging PXE files & packages -- THIS DOES NOT DELETE /SNAPSHOTS"

	@echo "Deleting NFS directory: $(nfs_path)"
	@rm -rf $(nfs_path)

	@echo "Deleting TFTP directory: $(tftp_path)"
	@rm -rf $(tftp_path)

	@echo "Deleting NFS directory: $(nfs_path)"

	#TODO: all pxe packages on one same place
	@echo "purging PXE packages: "

	@sudo apt-get remove --purge dnsmasq nfs-kernel-server syslinux
	@echo "Cleaning up package leftovers..."
	@sudo apt-get autoremove -y
	@sudo apt-get clean

	@echo "clean done"


test_pxe:
	qemu-system-x86_64 -m 1G -boot n -netdev user,id=mynet0,tftp=/srv/pxe-tftp,bootfile=pxelinux.0 -device virtio-net,netdev=mynet0

install_qemu:
	sudo apt-get install qemu-system

install_pxe_debug:
	DEBUG=true ./install-pxe.sh
