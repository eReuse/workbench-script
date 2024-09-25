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
        # append live directory, which is expected by the debian live env
        mkdir -p "${nfs_path}/live"
        mkdir -p "${nfs_path}/snapshots"

        if [ ! -f "${nfs_path}/settings.ini" ]; then
                if [ -f "settings.ini" ]; then
                        ln -sv "$(pwd)/settings.ini"" ${nfs_path}/settings.ini"
                else
                        echo "ERROR: ../settings.ini does not exist yet, cannot read config from there. You can take inspiration with file ../settings.ini.example"
                        exit 1
                fi
        fi
}

install_tftp() {

        # from https://wiki.debian.org/PXEBootInstall#Simple_way_-_using_Dnsmasq
        cat > /etc/dnsmasq.d/pxe-tftp <<END
port=0
dhcp-range=${nfs_allowed_lan%/*},proxy
dhcp-boot=pxelinux.0
pxe-service=x86PC,"Network Boot",pxelinux
enable-tftp
tftp-root=${tftp_path}
END
}

extract_live_parts_for_tftp() {
        # this is slow, so it is not enforced, reboot or remove the
        #   file to redownload the live iso
        if [ ! -f /tmp/live.iso ]; then
        # src https://www.debian.org/CD/faq/#newest
                DEBIAN_VERSION="$(wget https://www.debian.org/CD/ -O- \
                        | grep -o '<strong>[0-9.]*</strong>' \
                        | grep -o '[0-9.]*')"
                url="https://cdimage.debian.org/debian-cd/current-live/amd64/iso-hybrid/debian-live-${DEBIAN_VERSION}-amd64-standard.iso"
                wget "${url}" -O /tmp/live.iso
        fi
        mount -o loop /tmp/live.iso /mnt/
        cp /mnt/live/vmlinuz "${tftp_path}/"
        cp /mnt/live/initrd.img "${tftp_path}/"
        umount /mnt
}

install_netboot() {
        # if you want to refresh install, remove or move dir
        if [ ! -d "${tftp_path}" ] || [ "${FORCE:-}" ]; then
                mkdir -p "${tftp_path}"
                cd "${tftp_path}"
                extract_live_parts_for_tftp

                cat > "${tftp_path}/pxelinux.cfg/default" <<END
default wb

label wb
        KERNEL vmlinuz
        INITRD initrd.img
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
        nfs_path="${nfs_path:-/srv/pxe-nfs}"
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
