#!/bin/sh

# Copyright (c) 2024 Pedro <copyright@cas.cat>
# SPDX-License-Identifier: AGPL-3.0-or-later

set -e
set -u
# DEBUG
set -x

main() {
        sudo apt install smartmontools lshw hwinfo dmidecode
}

main "${@}"

# written in emacs
# -*- mode: shell-script; -*-
