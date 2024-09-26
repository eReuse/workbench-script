#!/bin/sh

# Copyright (c) 2022 pangea.org Associació Pangea - Coordinadora Comunicació per a la Cooperació
# SPDX-License-Identifier: AGPL-3.0-or-later
# Description: This program attaches workbench-script to a ISO

# debug
set -x
# exit on failure
set -e
# fail and exit when it cannot substitute a variable
set -u

# inspired from Ander in https://code.ungleich.ch/ungleich-public/cdist/issues/4
# this is a way to reuse a function used inside and outside of chroot
# this function is used both in shell and chroot
decide_if_update_str="$(cat <<END
decide_if_update() {
        if [ ! -d /var/lib/apt/lists ] \
                   || [ -n "\$( find /etc/apt -newer /var/lib/apt/lists )" ] \
                   || [ ! -f /var/cache/apt/pkgcache.bin ] \
                   || [ "\$( stat --format %Y /var/cache/apt/pkgcache.bin )" -lt "\$( date +%s -d '-1 day' )" ]
        then
                if [ -d /var/lib/apt/lists ]; then
                        \${SUDO} touch /var/lib/apt/lists
                fi
                apt_opts="-o Acquire::AllowReleaseInfoChange::Suite=true -o Acquire::AllowReleaseInfoChange::Version=true"
                # apt update could have problems such as key expirations, proceed anyway
                \${SUDO} apt-get "\${apt_opts}" update || true
        fi
}
END
)"

create_iso() {
        # Copy kernel and initramfs
        vmlinuz="$(ls -1v "${ISO_PATH}"/chroot/boot/vmlinuz-* | tail -n 1)"
        initrd="$(ls -1v "${ISO_PATH}"/chroot/boot/initrd.img-* | tail -n 1)"
        ${SUDO} cp ${vmlinuz} "${ISO_PATH}"/staging/live/vmlinuz
        ${SUDO} cp ${initrd} "${ISO_PATH}"/staging/live/initrd
        # Creating ISO
        iso_path=""${ISO_PATH}"/${iso_name}.iso"

        # 0x14 is FAT16 Hidden FAT16 <32, this is the only format detected in windows10 automatically when using a persistent volume of 10 MB
        ${SUDO} xorrisofs \
                -verbose \
                -iso-level 3 \
                -o "${iso_path}" \
                -full-iso9660-filenames \
                -volid "${iso_name}" \
                -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin \
                -eltorito-boot \
                isolinux/isolinux.bin \
                -no-emul-boot \
                -boot-load-size 4 \
                -boot-info-table \
                --eltorito-catalog isolinux/isolinux.cat \
                -eltorito-alt-boot \
                -e /EFI/boot/efiboot.img \
                -no-emul-boot \
                -isohybrid-gpt-basdat \
                -append_partition 2 0xef "${ISO_PATH}"/staging/EFI/boot/efiboot.img \
                -append_partition 3 0x14 "${rw_img_path}" \
                "${ISO_PATH}/staging"

        printf "\n\n  Image generated in ${iso_path}\n\n"
}

isolinux_boot() {
        isolinuxcfg_str="$(cat <<END
UI vesamenu.c32

MENU TITLE Boot Menu
DEFAULT linux
TIMEOUT 10
MENU RESOLUTION 640 480
MENU COLOR border       30;44   #40ffffff #a0000000 std
MENU COLOR title        1;36;44 #9033ccff #a0000000 std
MENU COLOR sel          7;37;40 #e0ffffff #20ffffff all
MENU COLOR unsel        37;44   #50ffffff #a0000000 std
MENU COLOR help         37;40   #c0ffffff #a0000000 std
MENU COLOR timeout_msg  37;40   #80ffffff #00000000 std
MENU COLOR timeout      1;37;40 #c0ffffff #00000000 std
MENU COLOR msg07        37;40   #90ffffff #a0000000 std
MENU COLOR tabmsg       31;40   #30ffffff #00000000 std

LABEL linux
  MENU LABEL workbench
  MENU DEFAULT
  KERNEL /live/vmlinuz
  APPEND initrd=/live/initrd boot=live net.ifnames=0 biosdevname=0 persistence

LABEL linux
  MENU LABEL workbench (nomodeset)
  MENU DEFAULT
  KERNEL /live/vmlinuz
  APPEND initrd=/live/initrd boot=live net.ifnames=0 biosdevname=0 persistence nomodeset
END
)"
        #   TIMEOUT 60 means 6 seconds :)
        ${SUDO} tee "${ISO_PATH}/staging/isolinux/isolinux.cfg" <<EOF
${isolinuxcfg_str}
EOF
        ${SUDO} cp /usr/lib/ISOLINUX/isolinux.bin "${ISO_PATH}/staging/isolinux/"
        ${SUDO} cp /usr/lib/syslinux/modules/bios/* "${ISO_PATH}/staging/isolinux/"
}

grub_boot() {
        grubcfg_str="$(cat <<END
search --set=root --file /${iso_name}

set default="0"
set timeout=1

# If X has issues finding screens, experiment with/without nomodeset.

menuentry "workbench" {
    linux (\$root)/live/vmlinuz boot=live net.ifnames=0 biosdevname=0 persistence
    initrd (\$root)/live/initrd
}

menuentry "workbench (nomodeset)" {
    linux (\$root)/live/vmlinuz boot=live net.ifnames=0 biosdevname=0 persistence nomodeset
    initrd (\$root)/live/initrd
}
END
)"
        ${SUDO} tee "${ISO_PATH}/staging/boot/grub/grub.cfg" <<EOF
${grubcfg_str}
EOF

        ${SUDO} tee "${ISO_PATH}/tmp/grub-standalone.cfg" <<EOF
search --set=root --file /${iso_name}
set prefix=(\$root)/boot/grub/
configfile /boot/grub/grub.cfg
EOF
        ${SUDO} cp -r /usr/lib/grub/x86_64-efi/* "${ISO_PATH}/staging/boot/grub/x86_64-efi/"

        ${SUDO} grub-mkstandalone \
                --format=x86_64-efi \
                --output="${ISO_PATH}"/tmp/bootx64.efi \
                --locales="" \
                --fonts="" \
                "boot/grub/grub.cfg=${ISO_PATH}/tmp/grub-standalone.cfg"

  # prepare uefi secureboot files
  #   bootx64 is the filename is looking to boot, and we force it to be the shimx64 file for uefi secureboot
  #   shimx64 redirects to grubx64 -> src https://askubuntu.com/questions/874584/how-does-secure-boot-actually-work
  #   grubx64 looks for a file in /EFI/debian/grub.cfg -> src src https://unix.stackexchange.com/questions/648089/uefi-grub-not-finding-config-file
        ${SUDO} cp /usr/lib/shim/shimx64.efi.signed /tmp/bootx64.efi
        ${SUDO} cp /usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed /tmp/grubx64.efi
        ${SUDO} cp "${ISO_PATH}/tmp/grub-standalone.cfg" "${ISO_PATH}/staging/EFI/debian/grub.cfg"

        (
                cd "${ISO_PATH}/staging/EFI/boot"
                ${SUDO} dd if=/dev/zero of=efiboot.img bs=1M count=20
                ${SUDO} mkfs.vfat efiboot.img
                ${SUDO} mmd -i efiboot.img efi efi/boot
                ${SUDO} mcopy -vi efiboot.img \
                        /tmp/bootx64.efi \
                        /tmp/grubx64.efi \
                        ::efi/boot/
        )
}

create_boot_system() {
        # both boots disable predicted names -> src https://michlstechblog.info/blog/linux-disable-assignment-of-new-names-for-network-interfaces/
        isolinux_boot
        grub_boot
}

compress_chroot_dir() {
        # Faster squashfs when debugging -> src https://forums.fedoraforum.org/showthread.php?284366-squashfs-wo-compression-speed-up
        if [ "${DEBUG:-}" ]; then
                DEBUG_SQUASHFS_ARGS='-noI -noD -noF -noX'
        fi

        # why squashfs -> https://unix.stackexchange.com/questions/163190/why-do-liveusbs-use-squashfs-and-similar-file-systems
        # noappend option needed to avoid this situation -> https://unix.stackexchange.com/questions/80447/merging-preexisting-source-folders-in-mksquashfs
        ${SUDO} mksquashfs \
                "${ISO_PATH}/chroot" \
                "${ISO_PATH}/staging/live/filesystem.squashfs" \
                ${DEBUG_SQUASHFS_ARGS:-} \
                -noappend -e boot
}

create_persistence_partition() {
        # persistent partition
        rw_img_name="workbench_vfat.img"
        rw_img_path="${ISO_PATH}/staging/${rw_img_name}"
        if [ ! -f "${rw_img_path}" ] || [ "${DEBUG:-}" ] || [ "${FORCE:-}" ]; then
                persistent_volume_size_MB=100
                ${SUDO} dd if=/dev/zero of="${rw_img_path}" bs=1M count=${persistent_volume_size_MB}
                ${SUDO} mkfs.vfat "${rw_img_path}"

                # generate structure on persistent partition
                tmp_rw_mount="/tmp/${rw_img_name}"
                ${SUDO} umount -f -l "${tmp_rw_mount}" >/dev/null 2>&1 || true
                mkdir -p "${tmp_rw_mount}"
                ${SUDO} mount "$(pwd)/${rw_img_path}" "${tmp_rw_mount}"
                ${SUDO} mkdir -p "${tmp_rw_mount}/settings"
                if [ -f "settings.ini" ]; then
                        ${SUDO} cp -v settings.ini "${tmp_rw_mount}/settings/settings.ini"
                else
                        echo "ERROR: settings.ini does not exist yet, cannot read config from there. You can take inspiration with file settings.ini.example"
                        exit 1
                fi
                ${SUDO} umount "${tmp_rw_mount}"

                uuid="$(blkid "${rw_img_path}" | awk '{ print $3; }')"
                # no fail on boot -> src https://askubuntu.com/questions/14365/mount-an-external-drive-at-boot-time-only-if-it-is-plugged-in/99628#99628
                # use tee instead of cat -> src https://stackoverflow.com/questions/2953081/how-can-i-write-a-heredoc-to-a-file-in-bash-script/17093489#17093489
                ${SUDO} tee "${ISO_PATH}/chroot/etc/fstab" <<END
# next three lines originally appeared on fstab, we preserve them
# UNCONFIGURED FSTAB FOR BASE SYSTEM
overlay / overlay rw 0 0
tmpfs /tmp tmpfs nosuid,nodev 0 0
${uuid} /mnt vfat defaults,nofail 0 0
END
  fi
        # src https://manpages.debian.org/testing/open-infrastructure-system-boot/persistence.conf.5.en.html
        echo "/ union" | ${SUDO} tee "${ISO_PATH}/chroot/persistence.conf"
}


chroot_netdns_conf_str="$(cat<<END
###################
# configure network
mkdir -p /etc/network/
cat > /etc/network/interfaces <<END2
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
END2

###################
# configure dns
cat > /etc/resolv.conf <<END2
nameserver 8.8.8.8
nameserver 1.1.1.1
END2

###################
# configure hosts
cat > /etc/hosts <<END2
127.0.0.1    localhost workbench
::1          localhost ip6-localhost ip6-loopback
ff02::1      ip6-allnodes
ff02::2      ip6-allrouters
END2
END
)"

prepare_app() {
        # prepare app during prepare_chroot_env
        # Install hardware_metadata module
        workbench_dir="${ISO_PATH}/chroot/opt/workbench"
        ${SUDO} mkdir -p "${workbench_dir}"
        ${SUDO} cp workbench-script.py "${workbench_dir}/"
        ${SUDO} cp requirements.txt "${workbench_dir}/"

        # startup script execution
        cat > "${ISO_PATH}/chroot/root/.profile" <<END
set -x

stty -echo # Do not show what we type in terminal so it does not meddle with our nice output
dmesg -n 1 # Do not report *useless* system messages to the terminal
# clearly specify the right working directory, used in the python script as os.getcwd()
cd /mnt
# detect pxe env
if [ -d /run/live/medium ]; then
        config_path='/run/live/medium/settings.ini'
        # debian live nfs path is readonly, do a trick
        #   to make snapshots subdir readwrite
        nfs_host="\$(df -hT | grep nfs | cut -f1 -d: | head -n1)"
        mount \${nfs_host}:/snapshots /run/live/medium/snapshots
else
        config_path='/mnt/settings.ini'
fi
pipenv run python /opt/workbench/workbench-script.py --config "\${config_path}"
stty echo

set +x
END
        #TODO add some useful commands
        cat > "${ISO_PATH}/chroot/root/.bash_history" <<END
poweroff
END

        # sequence of commands to install app in function run_chroot
        install_app_str="$(cat<<END
echo 'Install requirements'

# Install debian requirements
apt-get install -y --no-install-recommends \
  sudo \
  python3 python3-dev python3-pip pipenv \
  dmidecode smartmontools hwinfo pciutils lshw < /dev/null
  # Install python requirements using apt instead of pip
  #python3-dateutils python3-decouple python3-colorlog

# Install lshw B02.19 utility using backports (DEPRECATED in Debian 12)
#apt install -y -t ${VERSION_CODENAME}-backports lshw  < /dev/null

echo 'Install sanitize requirements'

# Install sanitize debian requirements
apt-get install -y --no-install-recommends \
  hdparm nvme-cli < /dev/null

pipenv run pip install -r /opt/workbench/requirements.txt
END
)"
}

run_chroot() {
        # non interactive chroot -> src https://stackoverflow.com/questions/51305706/shell-script-that-does-chroot-and-execute-commands-in-chroot
        # stop apt-get from greedily reading the stdin -> src https://askubuntu.com/questions/638686/apt-get-exits-bash-script-after-installing-packages/638754#638754
        ${SUDO} chroot ${ISO_PATH}/chroot <<CHROOT
set -x
set -e

echo workbench > /etc/hostname

# check what linux images are available on the system
# Figure out which Linux Kernel you want in the live environment.
#   apt-cache search linux-image

backports_path="/etc/apt/sources.list.d/backports.list"
if [ ! -f "\${backports_path}" ]; then
  backports_repo='deb http://deb.debian.org/debian ${VERSION_CODENAME}-backports main contrib'
  printf "\${backports_repo}" > "\${backports_path}"
fi

# this env var confuses sudo detection
unset SUDO_USER
${detect_user_str}
detect_user

# Installing packages
${decide_if_update_str}
decide_if_update

apt-get install -y --no-install-recommends \
  linux-image-amd64 \
  live-boot \
  systemd-sysv

# Install app
${install_app_str}

# Autologin root user
# src https://wiki.archlinux.org/title/getty#Automatic_login_to_virtual_console
mkdir -p /etc/systemd/system/getty@tty1.service.d/
cat > /etc/systemd/system/getty@tty1.service.d/override.conf <<END2
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I \$TERM
END2

systemctl enable getty@tty1.service

# other debian utilities
apt-get install -y --no-install-recommends \
  iproute2 iputils-ping ifupdown isc-dhcp-client \
  fdisk parted \
  curl openssh-client \
  less \
  jq \
  nano vim-tiny \
  < /dev/null

${chroot_netdns_conf_str}

# Set up root user
#   this is the root password
#   Method3: Use echo
#     src https://www.systutorials.com/changing-linux-users-password-in-one-command-line/
printf '${root_passwd}\n${root_passwd}' | passwd root

# general cleanup if production image
if [ -z "${DEBUG:-}" ]; then
  apt-get clean < /dev/null
fi

# cleanup bash history
history -c

CHROOT
}

prepare_chroot_env() {
        # version of debian the bootstrap is going to build
        #   if no VERSION_CODENAME is specified we assume that the bootstrap is going to
        #   be build with the same version of debian being executed because some files
        #   are copied from our root system
        if [ -z "${VERSION_CODENAME:-}" ]; then
                . /etc/os-release
                echo "TAKING OS-RELEASE FILE"
                if [ ! "${ID}" = "debian" ]; then
                        echo "ERROR: ubuntu detected, then you are enforced to specify debian variant"
                        echo "  use for example \`VERSION_CODENAME='bookworm'\` or similar"
                        exit 1
                fi
        fi

        chroot_path="${ISO_PATH}/chroot"
        if [ ! -d "${chroot_path}" ]; then
                ${SUDO} debootstrap --arch=amd64 --variant=minbase ${VERSION_CODENAME} ${ISO_PATH}/chroot http://deb.debian.org/debian/
                ${SUDO} chown -R "${USER}:" ${ISO_PATH}/chroot
        fi

        prepare_app
}

# thanks https://willhaley.com/blog/custom-debian-live-environment/
install_requirements() {
        # Install requirements
        eval "${decide_if_update_str}" && decide_if_update
        image_deps='debootstrap
                    squashfs-tools
                    xorriso
                    mtools
                    dosfstools'
        # secureboot:
        #   -> extra src https://wiki.debian.org/SecureBoot/
        #   -> extra src https://wiki.debian.org/SecureBoot/VirtualMachine
        #   -> extra src https://wiki.debian.org/GrubEFIReinstall
        bootloader_deps='isolinux
                         syslinux-efi
                         grub-pc-bin
                         grub-efi-amd64-bin
                         ovmf
                         grub-efi-amd64-signed'
        ${SUDO} apt-get install -y \
                ${image_deps} \
                ${bootloader_deps}
}

# thanks https://willhaley.com/blog/custom-debian-live-environment/
create_base_dirs() {
        mkdir -p "${ISO_PATH}"
        mkdir -p "${ISO_PATH}/staging/EFI/boot"
        mkdir -p "${ISO_PATH}/staging/boot/grub/x86_64-efi"
        mkdir -p "${ISO_PATH}/staging/isolinux"
        mkdir -p "${ISO_PATH}/staging/live"
        mkdir -p "${ISO_PATH}/tmp"
        # usb name
        ${SUDO} touch "${ISO_PATH}/staging/${iso_name}"

        # for uefi secure boot grub config file
        mkdir -p "${ISO_PATH}/staging/EFI/debian"
}

# this function is used both in shell and chroot
detect_user_str="$(cat <<END
detect_user() {
        userid="\$(id -u)"
        # detect non root user without sudo
        if [ ! "\${userid}" = 0 ] && id \${USER} | grep -qv sudo; then
                echo "ERROR: this script needs root or sudo permissions (current user is not part of sudo group)"
                exit 1
                # detect user with sudo or already on sudo src https://serverfault.com/questions/568627/can-a-program-tell-it-is-being-run-under-sudo/568628#568628
        elif [ ! "\${userid}" = 0 ] || [ -n "\${SUDO_USER}" ]; then
                SUDO='sudo'
                # jump to current dir where the script is so relative links work
                cd "\$(dirname "\${0}")"
                # working directory to build the iso
                ISO_PATH="iso"
                # detect pure root
        elif [ "\${userid}" = 0 ]; then
                SUDO=''
                ISO_PATH="/opt/workbench"
        fi
}
END
)"

main() {

        if [ "${DEBUG:-}" ]; then
                VERSION_ISO='debug'
        else
                VERSION_ISO='production'
        fi
        iso_name="workbench_${VERSION_ISO}"
        hostname='workbench'
        root_passwd='workbench'

        eval "${detect_user_str}" && detect_user

        create_base_dirs

        install_requirements

        prepare_chroot_env

        run_chroot

        create_persistence_partition

        compress_chroot_dir

        create_boot_system

        create_iso
}

main "${@}"
