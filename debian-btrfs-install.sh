#!/usr/bin/env bash
set -euo pipefail

# Simple Debian Btrfs installer bootstrap script
# Review and test in a VM before using on real hardware.

# Config
DEBIAN_RELEASE="trixie"
EFI_SIZE_MIB=512
ROOT_SUBVOL="@"
HOME_SUBVOL="@home"
MOUNT_POINT="/mnt"

# Helper
log() { printf '\n[install] %s\n' "$1"; }
die() { printf '\n[install] ERROR: %s\n' "$1" >&2; exit 1; }

# 1) Host dependency check
log "Checking host tools"
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends debootstrap btrfs-progs gdisk parted dosfstools
elif command -v pacman >/dev/null 2>&1; then
  sudo pacman -Sy --needed --noconfirm debootstrap btrfs-progs gptfdisk parted dosfstools
else
  die "Unsupported live environment: apt-get or pacman required"
fi

# 2) Select disk
lsblk
read -rp "Target drive (e.g., /dev/nvme0n1 or /dev/sda): " DISK
[[ -b "$DISK" ]] || die "Block device $DISK not found"

read -rp "This will erase $DISK. Type YES to continue: " CONFIRM
[[ "$CONFIRM" == "YES" ]] || die "Aborted by user"

# 3) Unmount any mounted partitions on the disk (lazy)
log "Unmounting any mounted partitions on $DISK"
DISK_BASENAME=$(basename "$DISK")
mapfile -t MOUNTS < <(lsblk -ln -o NAME,MOUNTPOINT | awk -v d="$DISK_BASENAME" '$1 ~ "^"d { if ($2!="") print $2 }')
for mp in "${MOUNTS[@]:-}"; do
  if [[ -n "$mp" ]]; then
    log "Lazy unmount $mp"
    umount -l "$mp" || true
  fi
done

# 4) Partitioning (GPT with EFI)
log "Creating partition table and partitions on $DISK"
sgdisk --zap-all "$DISK"
sgdisk -n1:0:+${EFI_SIZE_MIB}M -t1:ef00 -c1:"EFI System" "$DISK"
sgdisk -n2:0:0 -t2:8300 -c2:"Linux filesystem" "$DISK"
partprobe "$DISK"

# 5) Partition device names (nvme vs sd)
if [[ "$(basename "$DISK")" =~ ^nvme ]]; then
  PART_EFI="${DISK}p1"
  PART_ROOT="${DISK}p2"
else
  PART_EFI="${DISK}1"
  PART_ROOT="${DISK}2"
fi
log "EFI partition: $PART_EFI"
log "Root partition: $PART_ROOT"

# 6) Format partitions
log "Formatting EFI as FAT32"
mkfs.fat -F32 -n EFI "$PART_EFI"

log "Formatting root as btrfs"
mkfs.btrfs -f -L DEBIAN "$PART_ROOT"

# 7) Create btrfs subvolumes
log "Creating Btrfs subvolumes"
mkdir -p "$MOUNT_POINT"
mount "$PART_ROOT" "$MOUNT_POINT"
SUBVOLS=( "$ROOT_SUBVOL" "$HOME_SUBVOL" "@opt" "@cache" "@varlib" "@log" "@spool" "@tmp" )
for sv in "${SUBVOLS[@]}"; do
  log "Creating subvolume $sv"
  btrfs subvolume create "${MOUNT_POINT}/${sv}"
done
umount "$MOUNT_POINT"

# 8) Mount subvolumes for debootstrap
MOUNT_OPTS="compress=zstd:3,noatime,space_cache=v2,ssd"
log "Mounting root subvolume"
mount -o "${MOUNT_OPTS},subvol=${ROOT_SUBVOL}" "$PART_ROOT" "$MOUNT_POINT"

# Ensure directories exist before mounting nested subvolumes
mkdir -p "$MOUNT_POINT"/{home,opt,var/cache,var/lib,boot/efi,var/log,var/spool,tmp}
# Mount other subvolumes
mount -o "${MOUNT_OPTS},subvol=${HOME_SUBVOL}" "$PART_ROOT" "$MOUNT_POINT/home"
mount -o "${MOUNT_OPTS},subvol=@opt" "$PART_ROOT" "$MOUNT_POINT/opt"
mount -o "${MOUNT_OPTS},subvol=@cache" "$PART_ROOT" "$MOUNT_POINT/var/cache"
mount -o "${MOUNT_OPTS},subvol=@varlib" "$PART_ROOT" "$MOUNT_POINT/var/lib"
mount -o "${MOUNT_OPTS},subvol=@log" "$PART_ROOT" "$MOUNT_POINT/var/log"
mount -o "${MOUNT_OPTS},subvol=@spool" "$PART_ROOT" "$MOUNT_POINT/var/spool"
mount -o "${MOUNT_OPTS},subvol=@tmp" "$PART_ROOT" "$MOUNT_POINT/tmp"

log "Mounting EFI partition"
mkdir -p "$MOUNT_POINT/boot/efi"
mount "$PART_EFI" "$MOUNT_POINT/boot/efi"

# 9) Debootstrap
log "Running debootstrap for ${DEBIAN_RELEASE}"
debootstrap --arch amd64 "${DEBIAN_RELEASE}" "$MOUNT_POINT" "http://deb.debian.org/debian/"

# 10) Prepare chroot binds and minimal config to avoid locale/dbus issues
for d in dev proc sys dev/pts run; do
  mount --bind "/$d" "$MOUNT_POINT/$d"
done
cp /etc/resolv.conf "$MOUNT_POINT/etc/resolv.conf"

# Create minimal locale and prevent services starting in chroot
cat > "$MOUNT_POINT/etc/default/locale" <<EOF
LANG=en_US.UTF-8
EOF

cat > "$MOUNT_POINT/usr/sbin/policy-rc.d" <<'POL'
#!/bin/sh
exit 101
POL
chmod +x "$MOUNT_POINT/usr/sbin/policy-rc.d"

# 11) Write a minimal fstab so the installed system can boot
ROOT_UUID=$(blkid -s UUID -o value "$PART_ROOT" || true)
EFI_UUID=$(blkid -s UUID -o value "$PART_EFI" || true)
if [[ -n "$ROOT_UUID" ]]; then
  ROOT_FSTAB="UUID=${ROOT_UUID}"
else
  ROOT_FSTAB="${PART_ROOT}"
fi
if [[ -n "$EFI_UUID" ]]; then
  EFI_FSTAB="UUID=${EFI_UUID}"
else
  EFI_FSTAB="${PART_EFI}"
fi

cat > "$MOUNT_POINT/etc/fstab" <<FSTAB
# <file system> <mount point> <type> <options> <dump> <pass>
${ROOT_FSTAB} / btrfs ${MOUNT_OPTS},subvol=${ROOT_SUBVOL} 0 0
${ROOT_FSTAB} /home btrfs ${MOUNT_OPTS},subvol=${HOME_SUBVOL} 0 0
${EFI_FSTAB} /boot/efi vfat umask=0077 0 1
FSTAB

log "Minimal /etc/fstab written"

# 12) Final instructions and chroot
cat <<EOF

Bootstrap complete. Next steps inside chroot (run these after the prompt):

  # chroot into the new system
  chroot $MOUNT_POINT /bin/bash

  # inside chroot
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y linux-image-amd64 grub-efi-amd64 shim-signed btrfs-progs cryptsetup initramfs-tools
  # if using LUKS, ensure /etc/crypttab is correct and then:
  update-initramfs -u -k all
  update-grub
  grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=debian --recheck

  # remove policy-rc.d so services can start on first boot
  rm -f /usr/sbin/policy-rc.d

EOF

chroot "$MOUNT_POINT" /bin/bash
