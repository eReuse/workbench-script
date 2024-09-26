#!/bin/sh

# Copyright (c) 2024 Pedro <copyright@cas.cat>
# SPDX-License-Identifier: AGPL-3.0-or-later

set -e
set -u
# DEBUG
set -x

install_dependencies() {
        apt update
        apt install -y wget dnsmasq nfs-kernel-server rsync
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

        # debian live nfs path is readonly, do a trick
        #   to make snapshots subdir readwrite
        if ! grep -q "/snapshots" /proc/mounts; then
                mkdir -p "/snapshots"
                mount --bind "${nfs_path}/snapshots" "/snapshots"
        fi

        cat > /etc/exports <<END
${nfs_path} ${nfs_allowed_lan}(rw,sync,no_subtree_check,no_root_squash)
/snapshots ${nfs_allowed_lan}(rw,sync,no_subtree_check,no_root_squash)
END
        # reload nfs exports
        exportfs -vra

        # append live directory, which is expected by the debian live env
        mkdir -p "${nfs_path}/live"
        mkdir -p "${nfs_path}/snapshots"

        if [ ! -f "${nfs_path}/settings.ini" ]; then
                if [ -f "settings.ini" ]; then
                        cp settings.ini "${nfs_path}/settings.ini"
                else
                        echo "ERROR: $(pwd)/settings.ini does not exist yet, cannot read config from there. You can take inspiration with file $(pwd)/settings.ini.example"
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

install_netboot() {
        # if you want to refresh install, remove or move dir
        if [ ! -d "${tftp_path}" ] || [ "${FORCE:-}" ]; then
                mkdir -p "${tftp_path}/pxelinux.cfg"
                cd "${tftp_path}"
                if [ ! -f "${tftp_path}/netboot.tar.gz" ]; then
                        wget http://ftp.debian.org/debian/dists/${VERSION_CODENAME}/main/installer-amd64/current/images/netboot/netboot.tar.gz
                        tar xvf netboot.tar.gz || true
                        rm -rf "${tftp_path}/pxelinux.cfg"
                        mkdir -p "${tftp_path}/pxelinux.cfg"
                fi

                cp -fv "${PXE_DIR}/../iso/staging/live/vmlinuz" "${tftp_path}/"
                cp -fv "${PXE_DIR}/../iso/staging/live/initrd" "${tftp_path}/"
                rsync -av "${PXE_DIR}/../iso/staging/live/filesystem.squashfs" "${nfs_path}/live/"

                cat > "${tftp_path}/pxelinux.cfg/default" <<END
default wb

label wb
        KERNEL vmlinuz
        INITRD initrd
        APPEND ip=dhcp netboot=nfs nfsroot=${server_ip}:${nfs_path}/ boot=live text forcepae
END
                cd -
        fi
}

init_config() {
        # get where the script is
        cd "$(dirname "${0}")"
        PXE_DIR="$(pwd)"

        if [ -f ./.env ]; then
                . ./.env
        else
                echo "PXE: WARNING: $(pwd)/.env does not exist yet, cannot read config from there. You can take inspiration with file $(pwd)/.env.example"
        fi
        VERSION_CODENAME="${VERSION_CODENAME:-bookworm}"
        tftp_path="${tftp_path:-/srv/pxe-tftp}"
        server_ip="${server_ip}"
        nfs_path="${nfs_path:-/srv/pxe-nfs}"
}

main() {
        init_config
        install_dependencies
        install_tftp
        install_nfs
        install_netboot
        echo "PXE: Installation finished"
}

main "${@}"

# written in emacs
# -*- mode: shell-script; -*-
