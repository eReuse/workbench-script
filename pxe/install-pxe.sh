#!/bin/sh

# Copyright (c) 2024 Pedro <copyright@cas.cat>
# SPDX-License-Identifier: AGPL-3.0-or-later

set -e
set -u
# DEBUG
set -x

install_dependencies() {
        apt update
        apt install -y wget dnsmasq nfs-kernel-server
}

backup_file() {
        target="${1}"
        ts="$(date +'%Y-%m-%d_%H-%M-%S')"
        if [ -f "${target}" ]; then
                cp -a "${target}" "${target}_bak_${ts}"
        fi
}

install_nfs() {
        backup_file /etc/exports
        cat > /etc/exports <<END
${nfs_path} ${nfs_allowed_lan}(rw,sync,no_subtree_check,no_root_squash)
END
}

install_tftp() {

        cat > /etc/dnsmasq.d/pxe-tftp <<END
port=0
dhcp-range=${nfs_allowed_lan%/*},proxy
dhcp-boot=pxelinux.0
pxe-service=x86PC,"Network Boot",pxelinux
enable-tftp
tftp-root=${tftp_path}
END
}

install_netboot() {
        # if you want to refresh install, remove or move dir
        if [ ! -d "${tftp_path}" ]; then
                mkdir -p "${tftp_path}"
                cd "${tftp_path}"
                wget http://ftp.debian.org/debian/dists/${VERSION_CODENAME}/main/installer-amd64/current/images/netboot/netboot.tar.gz
                tar xvf netboot.tar.gz
                cat > "${tftp_path}/pxelinux.cfg/default" <<END
default wb

label wb
        KERNEL vmlinuz
        INITRD initd.img
        APPEND ip=dhcp netboot=nfs nfsroot=${server_ip}:${nfs_path}/ boot=live text forcepae
END
        fi
}

init_config() {

        # get where the script is
        cd "$(dirname "${0}")"

        if [ -f ./.env ]; then
                . ./.env
        else
                echo 'PXE: WARNING: .env does not exist yet, cannot read config from there. You can take inspiration with file .env.example'
        fi
        VERSION_CODENAME="${VERSION_CODENAME:-bookworm}"
        tftp_path="${tftp_path:-/srv/pxe-tftp}"
        server_ip="${server_ip}"
        nfs_path="${nfs_path:-/srv/pxe-images}"
}

main() {
        init_config
        install_dependencies
        install_netboot
        install_tftp
        install_nfs
        echo "PXE: Installation finished"
}

main "${@}"

# written in emacs
# -*- mode: shell-script; -*-
