#!/bin/sh

# Copyright (c) 2024 pangea.org Associació Pangea - Coordinadora Comunicació per a la Cooperació
# SPDX-License-Identifier: AGPL-3.0-or-later

set -e
set -u
# DEBUG
set -x

main() {
        sudo apt update

        # workbench deploy/builder image dependencies
        pxe_deps='wget
                  ca-certificates
                  dnsmasq
                  nfs-kernel-server
                  rpcbind
                  rsync
                  syslinux
                  syslinux-common
                  gettext-base'

        # install all
        sudo apt install --no-install-recommends -y \
             ${pxe_deps}
}

main "${@}"

# written in emacs
# -*- mode: shell-script; -*-
