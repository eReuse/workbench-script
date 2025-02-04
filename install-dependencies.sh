#!/bin/sh

# Copyright (c) 2024 pangea.org Associació Pangea - Coordinadora Comunicació per a la Cooperació
# SPDX-License-Identifier: AGPL-3.0-or-later

set -e
set -u
# DEBUG
set -x

main() {
        sudo apt update

        # system dependencies
        host_deps='sudo'
        # thanks https://stackoverflow.com/questions/23513045/how-to-check-if-a-process-is-running-inside-docker-container
        if [ ! "${DOCKER_BUILD}" ]; then
                host_deps="${host_deps} qemu-system"
        fi

        # workbench deploy/builder image dependencies
        image_deps='debootstrap
                    squashfs-tools
                    xorriso
                    mtools
                    dosfstools'

        # workbench deploy/builder bootloader dependencies
        #   thanks https://willhaley.com/blog/custom-debian-live-environment/
        #   secureboot:
        #     -> extra src https://wiki.debian.org/SecureBoot/
        #     -> extra src https://wiki.debian.org/SecureBoot/VirtualMachine
        #     -> extra src https://wiki.debian.org/GrubEFIReinstall
        bootloader_deps='isolinux
                         syslinux-efi
                         syslinux-common
                         grub-pc-bin
                         grub-efi-amd64-bin
                         ovmf
                         shim-signed
                         grub-efi-amd64-signed'

        # workbench-script client dependencies
        client_deps='smartmontools
                     lshw
                     hwinfo
                     dmidecode
                     inxi
                     python3
                     pipenv
                     qrencode'

        # install all
        sudo apt install --no-install-recommends -y \
             ${host_deps} \
             ${image_deps} \
             ${bootloader_deps} \
             ${client_deps}
}

main "${@}"

# written in emacs
# -*- mode: shell-script; -*-
