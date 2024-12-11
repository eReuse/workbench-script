#!/bin/sh

# Copyright (c) 2024 Pedro <copyright@cas.cat>
# SPDX-License-Identifier: AGPL-3.0-or-later

set -e
set -u
# DEBUG
set -x

main() {
        sudo apt update && \
                apt install -y \
                    smartmontools \
                    lshw \
                    hwinfo \
                    dmidecode \
                    inxi \
                    python3 \
                    pipenv \
                    sudo \
                    debootstrap \
                    qemu-system
}

main "${@}"

# written in emacs
# -*- mode: shell-script; -*-
