#!/usr/bin/env bash
#
# one-shot-debian-btrfs-install.sh
# Partition -> Btrfs subvolumes -> debootstrap -> interactive chroot automation
# Includes network fixes and improved firmware handling (uses nala in-chroot to fetch non-free).
#
# Usage: sudo ./one-shot-debian-btrfs-install.sh /dev/sdX
#
set -euo pipefail
IFS=$'\n\t'

# -------------------- Defaults --------------------
DEBOOTSTRAP_ARCH="amd64"
DEBIAN_RELEASE="trixie"
EFI_SIZE_MB=512
ROOT_SUBVOL="@"
HOME_SUBVOL="@home"
MOUNTPOINT="/mnt/target"
BTRFS_OPTS_BASE="noatime,ssd,space_cache=v2"
REQUIRED_PACKAGES=(apt-utils debootstrap gdisk btrfs-progs cryptsetup wget gnupg ca-certificates dosfstools netselect-apt shim-signed parted zstd)

log() { printf '\n[install] %s\n' "$1"; }
err() { printf '\n[install][ERROR] %s\n' "$1" >&2; exit 1; }
confirm() { read -rp "$1 [y/N]: " ans; [[ "${ans,,}" == "y" ]]; }

# -------------------- 0. Preflight: show drives --------------------
if [[ $EUID -ne 0 ]]; then
  err "Run as root: sudo $0"
fi

echo
echo "Available block devices (name, size, model, type, mountpoint):"
lsblk -o NAME,SIZE,MODEL,TYPE,MOUNTPOINT -e 7
echo

read -rp "Enter the target disk (example /dev/nvme0n1 or /dev/sda): " TARGET_DISK
[[ -b "$TARGET_DISK" ]] || err "Block device $TARGET_DISK not found."

cat <<WARN
===========================================================================
WARNING: This will ERASE ALL DATA on ${TARGET_DISK}.
Make sure you selected the correct disk above.
===========================================================================

WARN
if ! confirm "Type 'y' to continue"; then
  err "User aborted."
fi

# -------------------- 1. Ensure required packages in live environment --------------------
log "Checking required packages in live environment"
MISSING=()
for pkg in "${REQUIRED_PACKAGES[@]}"; do
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    MISSING+=("$pkg")
  fi
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
  log "Installing missing packages: ${MISSING[*]}"
  apt-get update -y || true
  apt-get install -y --no-install-recommends "${MISSING[@]}" || err "Failed to install required packages"
else
  log "All required packages present."
fi

# -------------------- 2. zstd check for compression option --------------------
if command -v zstd >/dev/null 2>&1; then
  COMPRESS_OPT="compress=zstd:3"
  log "zstd available; using ${COMPRESS_OPT}"
else
  COMPRESS_OPT="compress=gzip:1"
  log "zstd not available; falling back to ${COMPRESS_OPT}"
fi
BTRFS_OPTS="${BTRFS_OPTS_BASE},${COMPRESS_OPT}"

# -------------------- 3. Unmount any mounted partitions on target disk --------------------
log "Unmounting any mounted partitions on ${TARGET_DISK} (lazy)"
DISK_BASENAME=$(basename "$TARGET_DISK")
mapfile -t MOUNTS < <(lsblk -ln -o NAME,MOUNTPOINT | awk -v d="$DISK_BASENAME" '$1 ~ "^"d { if ($2!="") print $2 }')
for mp in "${MOUNTS[@]:-}"; do
  if [[ -n "$mp" ]]; then
    log "umount -l $mp"
    umount -l "$mp" || true
  fi
done

# -------------------- 4. Partition table type --------------------
echo
echo "Partition table type:"
echo "  1) GPT (UEFI recommended)"
echo "  2) MBR (legacy BIOS)"
read -rp "Choose 1 or 2 [1]: " PART_CHOICE
PART_CHOICE=${PART_CHOICE:-1}
if [[ "$PART_CHOICE" == "2" ]]; then
  PART_TABLE="msdos"
else
  PART_TABLE="gpt"
fi
log "Using partition table: ${PART_TABLE}"

# -------------------- 5. Partitioning --------------------
log "Wiping partition table on ${TARGET_DISK}"
if [[ "$PART_TABLE" == "gpt" ]]; then
  sgdisk --zap-all "$TARGET_DISK"
  sgdisk -n1:0:+${EFI_SIZE_MB}M -t1:ef00 -c1:"EFI System" "$TARGET_DISK"
  sgdisk -n2:0:0 -t2:8300 -c2:"Linux filesystem" "$TARGET_DISK"
else
  parted -s "$TARGET_DISK" mklabel msdos
  parted -s "$TARGET_DISK" mkpart primary fat32 1MiB ${EFI_SIZE_MB}MiB
  parted -s "$TARGET_DISK" set 1 boot on
  parted -s "$TARGET_DISK" mkpart primary ext4 ${EFI_SIZE_MB}MiB 100%
fi
partprobe "$TARGET_DISK" || true
sleep 1

# partition device names
if [[ "$(basename "$TARGET_DISK")" =~ ^nvme ]]; then
  EFI_PART="${TARGET_DISK}p1"
  MAIN_PART="${TARGET_DISK}p2"
else
  EFI_PART="${TARGET_DISK}1"
  MAIN_PART="${TARGET_DISK}2"
fi
log "EFI partition: ${EFI_PART}"
log "Main partition: ${MAIN_PART}"

# -------------------- 6. Format partitions --------------------
log "Formatting ${EFI_PART} as FAT32"
mkfs.vfat -F32 -n EFI "${EFI_PART}"

log "Formatting ${MAIN_PART} as Btrfs"
mkfs.btrfs -f -L DEBIAN "${MAIN_PART}"

# -------------------- 7. Create Btrfs subvolumes --------------------
log "Creating Btrfs subvolumes"
mkdir -p "${MOUNTPOINT}"
mount "${MAIN_PART}" "${MOUNTPOINT}"
SUBVOLS=( "${ROOT_SUBVOL}" "${HOME_SUBVOL}" "@opt" "@cache" "@varlib" "@log" "@spool" "@tmp" )
for sv in "${SUBVOLS[@]}"; do
  log "btrfs subvolume create ${MOUNTPOINT}/${sv}"
  btrfs subvolume create "${MOUNTPOINT}/${sv}"
done
umount "${MOUNTPOINT}"

# -------------------- 8. Mount subvolumes for debootstrap --------------------
log "Mounting root subvolume"
mkdir -p "${MOUNTPOINT}"
mount -o "${BTRFS_OPTS},subvol=${ROOT_SUBVOL}" "${MAIN_PART}" "${MOUNTPOINT}"

mkdir -p "${MOUNTPOINT}"/{home,opt,var/cache,var/lib,boot/efi,var/log,var/spool,tmp}
mount -o "${BTRFS_OPTS},subvol=${HOME_SUBVOL}" "${MAIN_PART}" "${MOUNTPOINT}/home"
mount -o "${BTRFS_OPTS},subvol=@opt" "${MAIN_PART}" "${MOUNTPOINT}/opt"
mount -o "${BTRFS_OPTS},subvol=@cache" "${MAIN_PART}" "${MOUNTPOINT}/var/cache"
mount -o "${BTRFS_OPTS},subvol=@varlib" "${MAIN_PART}" "${MOUNTPOINT}/var/lib"
mount -o "${BTRFS_OPTS},subvol=@log" "${MAIN_PART}" "${MOUNTPOINT}/var/log"
mount -o "${BTRFS_OPTS},subvol=@spool" "${MAIN_PART}" "${MOUNTPOINT}/var/spool"
mount -o "${BTRFS_OPTS},subvol=@tmp" "${MAIN_PART}" "${MOUNTPOINT}/tmp"

log "Mounting EFI partition at ${MOUNTPOINT}/boot/efi"
mkdir -p "${MOUNTPOINT}/boot/efi"
mount "${EFI_PART}" "${MOUNTPOINT}/boot/efi"

# -------------------- 9. Debootstrap --------------------
log "Bootstrapping Debian ${DEBIAN_RELEASE}"
DEBOOTSTRAP_MIRROR="http://deb.debian.org/debian"
apt-get update -y || true
apt-get install -y --no-install-recommends debootstrap ca-certificates wget gnupg || true
debootstrap --arch "${DEBOOTSTRAP_ARCH}" "${DEBIAN_RELEASE}" "${MOUNTPOINT}" "${DEBOOTSTRAP_MIRROR}"

# -------------------- 10. Prepare chroot environment --------------------
log "Preparing chroot environment (bind mounts, resolv, tmp, locale stub)"
mount --bind /dev "${MOUNTPOINT}/dev"
mount --bind /dev/pts "${MOUNTPOINT}/dev/pts"
mount --bind /proc "${MOUNTPOINT}/proc"
mount --bind /sys "${MOUNTPOINT}/sys"
cp /etc/resolv.conf "${MOUNTPOINT}/etc/resolv.conf" || true

mkdir -p "${MOUNTPOINT}/tmp" "${MOUNTPOINT}/tmp/user/0"
chmod 1777 "${MOUNTPOINT}/tmp" "${MOUNTPOINT}/tmp/user/0"

cat > "${MOUNTPOINT}/etc/default/locale" <<EOF
LANG=en_AU.UTF-8
EOF
echo "Australia/Sydney" > "${MOUNTPOINT}/etc/timezone" || true
ln -sf /usr/share/zoneinfo/Australia/Sydney "${MOUNTPOINT}/etc/localtime" || true

# Prevent services from starting during chroot installs
cat > "${MOUNTPOINT}/usr/sbin/policy-rc.d" <<'POL'
#!/bin/sh
exit 101
POL
chmod +x "${MOUNTPOINT}/usr/sbin/policy-rc.d"

# Ensure zstd inside chroot (so initramfs can use it)
chroot "${MOUNTPOINT}" /bin/bash -c "
export DEBIAN_FRONTEND=noninteractive
apt-get update -y || true
apt-get install -y --no-install-recommends zstd || true
"

# Minimal locale generation inside chroot to avoid post-install failures
chroot "${MOUNTPOINT}" /bin/bash -c "
export DEBIAN_FRONTEND=noninteractive
apt-get update -y || true
apt-get install -y --no-install-recommends locales || true
if ! locale -a | grep -qi 'en_AU.utf8'; then
  echo 'en_AU.UTF-8 UTF-8' >> /etc/locale.gen || true
  locale-gen en_AU.UTF-8 || true
fi
echo 'LANG=en_AU.UTF-8' > /etc/default/locale || true
dpkg --configure -a || true
apt-get -f install -y || true
"

# -------------------- 11. Write /etc/fstab --------------------
log "Writing /etc/fstab in installed system"
BTRFS_UUID=$(blkid -s UUID -o value "${MAIN_PART}" || true)
EFI_UUID=$(blkid -s UUID -o value "${EFI_PART}" || true)
if [[ -n "${BTRFS_UUID}" ]]; then BTRFS_DEV="UUID=${BTRFS_UUID}"; else BTRFS_DEV="${MAIN_PART}"; fi
if [[ -n "${EFI_UUID}" ]]; then EFI_DEV="UUID=${EFI_UUID}"; else EFI_DEV="${EFI_PART}"; fi

cat > "${MOUNTPOINT}/etc/fstab" <<FSTAB
# <file system> <mount point> <type> <options> <dump> <pass>
${BTRFS_DEV} / btrfs ${BTRFS_OPTS},subvol=${ROOT_SUBVOL} 0 0
${BTRFS_DEV} /home btrfs ${BTRFS_OPTS},subvol=${HOME_SUBVOL} 0 0
${EFI_DEV} /boot/efi vfat umask=0077 0 1
FSTAB

# -------------------- 12. Create interactive chroot script (with nala fetch and firmware fallbacks) --------------------
log "Creating interactive chroot script (prompts for root password and user creation, installs network stack and firmware)"
cat > "${MOUNTPOINT}/root/interactive-setup.sh" <<'CHROOT'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export TMPDIR=/tmp

log() { printf "\n[chroot] %s\n" "$1"; }
err() { printf "\n[chroot][ERROR] %s\n" "$1" >&2; exit 1; }

log "Ensure apt sources include contrib and non-free"
# Add contrib and non-free to sources.list if missing
if ! grep -q "contrib" /etc/apt/sources.list 2>/dev/null; then
  sed -i 's/main/main contrib non-free/g' /etc/apt/sources.list || true
fi

log "Install nala and fetch non-free packages for AU mirror (best-effort)"
apt-get update -y || true
apt-get install -y --no-install-recommends nala || true

# Use nala to fetch best AU mirror and enable https-only non-free
if command -v nala >/dev/null 2>&1; then
  # This command may prompt; run non-interactively where possible
  nala fetch -c AU --https-only --non-free || true
fi

log "Updating package lists"
apt-get update -y || true

log "Install kernel, grub, btrfs-progs, cryptsetup, initramfs-tools and network packages"
apt-get install -y --no-install-recommends \
  linux-image-amd64 grub-efi-amd64 shim-signed btrfs-progs cryptsetup initramfs-tools \
  ca-certificates wget gnupg sudo zstd

log "Install NetworkManager and common firmware packages (attempt multiple candidates)"
# Try to install common firmware packages; some names vary by release.
# Use nala if available for better mirror selection; fall back to apt-get.
FIRMWARE_PKGS=( firmware-misc-nonfree firmware-ath9k-htc firmware-iwlwifi firmware-realtek firmware-linux-nonfree firmware-linux )
if command -v nala >/dev/null 2>&1; then
  for p in "${FIRMWARE_PKGS[@]}"; do
    log "Attempting to install ${p} via nala (best-effort)"
    nala install -y "${p}" || true
  done
  nala install -y network-manager wpasupplicant wireless-tools dnsutils || true
else
  for p in "${FIRMWARE_PKGS[@]}"; do
    log "Attempting to install ${p} via apt-get (best-effort)"
    apt-get install -y --no-install-recommends "${p}" || true
  done
  apt-get install -y --no-install-recommends network-manager wpasupplicant wireless-tools dnsutils || true
fi

# Ensure efivars mounted (for UEFI systems)
if [[ -d /sys/firmware/efi/efivars ]]; then
  if ! mountpoint -q /sys/firmware/efi/efivars; then
    mount -t efivarfs none /sys/firmware/efi/efivars || true
    log "Mounted efivars"
  fi
fi

# Prompt to set root password interactively
echo
echo "Set root password now:"
passwd root

# Create a new user interactively
read -rp "Enter username to create (leave blank to skip): " NEWUSER
if [[ -n "$NEWUSER" ]]; then
  adduser "$NEWUSER"
  usermod -aG sudo "$NEWUSER" || true
  log "User $NEWUSER created and added to sudo group"
fi

# If LUKS present, try to write crypttab (best-effort)
if blkid | grep -qi crypto_LUKS; then
  if [[ ! -f /etc/crypttab ]]; then
    LUKS_DEV=$(blkid -t TYPE=crypto_LUKS -o device | head -n1 || true)
    if [[ -n "$LUKS_DEV" ]]; then
      LUKS_UUID=$(blkid -s UUID -o value "$LUKS_DEV" || true)
      if [[ -n "$LUKS_UUID" ]]; then
        echo "cryptroot UUID=${LUKS_UUID} none luks,discard" > /etc/crypttab || true
        log "Wrote /etc/crypttab for cryptroot (UUID=${LUKS_UUID})"
      fi
    fi
  fi
fi

log "Updating initramfs"
update-initramfs -u -k all || true

log "Installing GRUB to EFI and generating grub.cfg"
if [[ -d /boot/efi ]] && mountpoint -q /boot/efi; then
  grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=debian --recheck || true
else
  log "Warning: /boot/efi not mounted. Mount the ESP at /boot/efi and run grub-install manually."
fi

update-grub || true

# Network service enablement and resolver setup
log "Enabling NetworkManager and systemd-resolved"
systemctl enable NetworkManager || true
systemctl enable systemd-resolved || true
systemctl start NetworkManager || true
systemctl start systemd-resolved || true

# Ensure /etc/resolv.conf points to systemd-resolved stub
if [[ -d /run/systemd/resolve ]]; then
  ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf || true
fi

# Unblock rfkill
rfkill unblock all || true

# Remove policy-rc.d so services start on first boot
rm -f /usr/sbin/policy-rc.d || true

log "Interactive chroot setup complete. Exit to continue host cleanup."
CHROOT

chmod +x "${MOUNTPOINT}/root/interactive-setup.sh"

# -------------------- 13. Run interactive chroot script (so it can prompt) --------------------
log "Entering chroot to run interactive setup. You will be prompted for root password and user creation."
chroot "${MOUNTPOINT}" /bin/bash -ic "/root/interactive-setup.sh"

# -------------------- 14. Verification checks --------------------
log "Running verification checks before cleanup"
fail=0

if [[ ! -b "${EFI_PART}" ]]; then echo "[check] EFI partition ${EFI_PART} not found" >&2; fail=1; else echo "[check] EFI partition exists: ${EFI_PART}"; fi
if [[ ! -b "${MAIN_PART}" ]]; then echo "[check] Main partition ${MAIN_PART} not found" >&2; fail=1; else echo "[check] Main partition exists: ${MAIN_PART}"; fi

if mountpoint -q "${MOUNTPOINT}/boot/efi"; then
  if [[ -f "${MOUNTPOINT}/boot/efi/EFI/debian/shimx64.efi" || -f "${MOUNTPOINT}/boot/efi/EFI/debian/grubx64.efi" ]]; then
    echo "[check] EFI binaries present"
  else
    echo "[check] EFI binaries missing in /boot/efi/EFI/debian" >&2; fail=1
  fi
else
  echo "[check] /boot/efi is not mounted in target" >&2; fail=1
fi

if [[ -f "${MOUNTPOINT}/boot/grub/grub.cfg" ]]; then echo "[check] grub.cfg present"; else echo "[check] grub.cfg missing" >&2; fail=1; fi

if chroot "${MOUNTPOINT}" bash -lc 'ls /boot/initrd.img-* 2>/dev/null | wc -l' | grep -q '[1-9]'; then echo "[check] initramfs images present"; else echo "[check] initramfs images missing" >&2; fail=1; fi

if grep -q "subvol=${ROOT_SUBVOL}" "${MOUNTPOINT}/etc/fstab" 2>/dev/null; then echo "[check] fstab contains root subvol entry"; else echo "[check] fstab missing root subvol entry" >&2; fail=1; fi
if grep -q "subvol=${HOME_SUBVOL}" "${MOUNTPOINT}/etc/fstab" 2>/dev/null; then echo "[check] fstab contains home subvol entry"; else echo "[check] fstab missing home subvol entry" >&2; fail=1; fi

if [[ "$fail" -ne 0 ]]; then
  echo
  echo "[install] One or more verification checks failed. Inspect ${MOUNTPOINT} and fix issues before rebooting."
  echo "Helpful commands from live environment:"
  echo "  lsblk -o NAME,SIZE,FSTYPE,MODEL,MOUNTPOINT"
  echo "  blkid"
  echo "  efibootmgr -v || true"
  echo "  sudo mount ${EFI_PART} /mnt/efi && ls -la /mnt/efi/EFI || true"
  exit 2
fi

# -------------------- 15. Cleanup and unmount --------------------
log "Cleaning up and unmounting"
rm -f "${MOUNTPOINT}/root/interactive-setup.sh" || true
rm -f "${MOUNTPOINT}/usr/sbin/policy-rc.d" || true

for d in dev/pts dev proc sys run; do
  umount -l "${MOUNTPOINT}/${d}" >/dev/null 2>&1 || true
done
umount -l "${MOUNTPOINT}/boot/efi" || true
umount -l "${MOUNTPOINT}/home" || true
umount -l "${MOUNTPOINT}" || true

log "Installation complete. Reboot when ready."
echo "If you want to reboot now, run: sudo reboot"
