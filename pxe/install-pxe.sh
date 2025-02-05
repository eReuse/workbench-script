#!/bin/sh

# Copyright (c) 2024 pangea.org Associació Pangea - Coordinadora Comunicació per a la Cooperació
# SPDX-License-Identifier: AGPL-3.0-or-later

set -e
set -u
# DEBUG
set -x

detect_user() {
        userid="$(id -u)"
        # detect non root user without sudo
        if [ ! "${userid}" = 0 ] && id ${USER} | grep -qv sudo; then
                echo "ERROR: this script needs root or sudo permissions (current user is not part of sudo group)"
                exit 1
                # detect user with sudo or already on sudo src https://serverfault.com/questions/568627/can-a-program-tell-it-is-being-run-under-sudo/568628#568628
        elif [ ! "${userid}" = 0 ] || [ -n "${SUDO_USER}" ]; then
                SUDO='sudo'
                # working directory to build the iso
                ISO_PATH="iso"
                # detect pure root
        elif [ "${userid}" = 0 ]; then
                SUDO=''
                ISO_PATH="/opt/workbench"
        fi
}

install_dependencies() {
        ${SUDO} apt update
        ${SUDO} apt install -y wget dnsmasq nfs-kernel-server rsync syslinux
}

backup_file() {
        target="${1}"
        ts="$(date +'%Y-%m-%d_%H-%M-%S')"

        if [ -f "${target}" ]; then
                if ! grep -q 'we should do a backup' "${target}"; then
                        ${SUDO} cp -v -a "${target}" "${target}-bak_${ts}"
                fi
        fi
}

install_nfs() {
        # append live directory, which is expected by the debian live env
        ${SUDO} mkdir -p "${nfs_path}/live"
        ${SUDO} mkdir -p "${nfs_path}/snapshots"

        # debian live nfs path is readonly, do a trick
        #   to make snapshots subdir readwrite
        if ! grep -q "/snapshots" /proc/mounts; then
                ${SUDO} mkdir -p "/snapshots"
                ${SUDO} mount --bind "${nfs_path}/snapshots" "/snapshots"
        fi

        backup_file /etc/exports

        if [ "${DEBUG:-}" ]; then
                nfs_debug=' 127.0.0.1(rw,sync,no_subtree_check,no_root_squash,insecure)'
        fi

        ${SUDO} tee /etc/exports <<END
${script_header}
#   we assume that if you remove this line from the file, we should do a backup
${nfs_path} ${nfs_allowed_lan}(rw,sync,no_subtree_check,no_root_squash)${nfs_debug:-}
/snapshots ${nfs_allowed_lan}(rw,sync,no_subtree_check,no_root_squash)${nfs_debug:-}
END
        # reload nfs exports
        ${SUDO} exportfs -vra

        if [ ! -f ./settings.ini ]; then
                cp -v ./settings.ini.example ./settings.ini
                echo "WARNING: settings.ini was not there, settings.ini.example was copied, this only happens once"
        fi

        if [ ! -f "${nfs_path}/settings.ini" ]; then
                ${SUDO} cp -v settings.ini "${nfs_path}/settings.ini"
                echo "WARNING: ${nfs_path}/settings.ini was not there, ./settings.ini was copied, this only happens once"
        fi
}

install_tftp() {

        # from https://wiki.debian.org/PXEBootInstall#Simple_way_-_using_Dnsmasq
        ${SUDO} tee /etc/dnsmasq.d/pxe-tftp <<END
${script_header}
port=0
# info: https://wiki.archlinux.org/title/Dnsmasq#Proxy_DHCP
dhcp-range=${nfs_allowed_lan%/*},proxy
dhcp-boot=pxelinux.0
pxe-service=x86PC,"Network Boot",pxelinux
enable-tftp
tftp-root=${tftp_path}
END
        sudo systemctl restart dnsmasq || true
}

install_netboot() {
        # if you want to refresh install, remove or move dir
        if [ ! -d "${tftp_path}" ] || [ "${FORCE:-}" = 'true' ]; then
                ${SUDO} mkdir -p "${tftp_path}/pxelinux.cfg"
                if [ ! -f "${tftp_path}/netboot.tar.gz" ]; then
                        url="http://ftp.debian.org/debian/dists/${VERSION_CODENAME}/main/installer-amd64/current/images/netboot/netboot.tar.gz"
                        ${SUDO} wget -P "${tftp_path}" "${url}"
                        ${SUDO} tar xvf "${tftp_path}/netboot.tar.gz" -C "${tftp_path}"
                        ${SUDO} rm -rf "${tftp_path}/pxelinux.cfg"
                        ${SUDO} mkdir -p "${tftp_path}/pxelinux.cfg"
                fi

                ${SUDO} cp -fv "${PXE_DIR}/../iso/staging/live/vmlinuz" "${tftp_path}/"
                ${SUDO} cp -fv "${PXE_DIR}/../iso/staging/live/initrd" "${tftp_path}/"

                ${SUDO} cp -v /usr/lib/syslinux/memdisk "${tftp_path}/"
                ${SUDO} cp -v /usr/lib/syslinux/modules/bios/* "${tftp_path}/"
                if [ ! -f ./pxe-menu.cfg ]; then
                        ${SUDO} cp -v ./pxe-menu.cfg.example pxe-menu.cfg
                        echo "WARNING: pxe-menu.cfg was not there, pxe-menu.cfg.example was copied, this only happens once"
                fi
                envsubst < ./pxe-menu.cfg | ${SUDO} tee "${tftp_path}/pxelinux.cfg/default"
        fi

        ${SUDO} rsync -av "${PXE_DIR}/../iso/staging/live/filesystem.squashfs" "${nfs_path}/live/"
}

init_config() {

        # jump to current dir where the script is so relative links work
        cd "$(dirname "${0}")"

        # this is what we put in the files we modity
        script_header='# configuration done through workbench install-pxe script'

        PXE_DIR="$(pwd)"

        if [ ! -f ./.env ]; then
                cp -v ./.env.example ./.env
                echo "WARNING: .env was not there, .env.example was copied, this only happens once"
        fi
        . ./.env
        VERSION_CODENAME="${VERSION_CODENAME:-bookworm}"
        tftp_path="${tftp_path:-/srv/pxe-tftp}"
        # vars used in envsubst require to be exported:
        export server_ip="${server_ip}"
        export nfs_path="${nfs_path:-/srv/pxe-nfs}"
}

main() {
        detect_user
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
