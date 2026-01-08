#!/usr/bin/env bash
#
# debian-btrfs-install.sh
#
# Automated Debian installer with Btrfs subvolumes, optional LUKS, EFI, snapper, deb-multimedia.
# - Verifies and installs required packages in the live environment
# - Option to use GPT or MBR partition table
# - Unmounts any mounted partitions on the target disk (uses umount -l)
# - Prepares chroot to avoid dbus/systemd/localectl calls (policy-rc.d, /etc/default/locale)
# - Adds deb-multimedia repo and verifies keyring checksum
# - Writes /etc/fstab with subvol entries
# - Creates snapper configs and package hooks, enables timers by symlink
# - Performs verification checks before reboot
#
# WARNING: This script WILL ERASE ALL DATA on the target disk. Test in a VM first.
set -euo pipefail
IFS=$'\n\t'

# -------------------- Configurable defaults --------------------
EFI_SIZE_MB=512
ROOT_SUBVOL="@"
HOME_SUBVOL="@home"
MOUNTPOINT="/mnt"
DEBOOTSTRAP_ARCH="amd64"
DEFAULT_LOCALE="en_AU.UTF-8"
DEFAULT_TIMEZONE="Australia/Sydney"
DEFAULT_KEYMAP="us"
SNAPPER_GUI_SCRIPT="snapper_restore_type_then_list.py"
DESKTOP_LAUNCHER_NAME="snapshot-restore.desktop"
DMO_KEY_PKG="deb-multimedia-keyring_2024.9.1_all.deb"
DMO_URL="https://www.deb-multimedia.org/pool/main/d/deb-multimedia-keyring/${DMO_KEY_PKG}"
DMO_SHA256="8dc6cbb266c701cfe58bd1d2eb9fe2245a1d6341c7110cfbfe3a5a975dcf97ca"

# -------------------- Required packages in live environment (user requested) --------------------
REQUIRED_PACKAGES=(apt-utils debootstrap gdisk btrfs-progs cryptsetup wget gnupg ca-certificates \
dosfstools netselect-apt shim-signed gdisk parted)

# -------------------- Helpers --------------------
log() { printf '\n[install] %s\n' "$1"; }
err() { printf '\n[install] ERROR: %s\n' "$1" >&2; exit 1; }

# -------------------- Preconditions --------------------
if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0 /dev/sdX" >&2
  exit 1
fi
if [[ $# -lt 1 ]]; then
  echo "Usage: sudo $0 /dev/sdX" >&2
  exit 1
fi
TARGET_DISK="$1"
if [[ ! -b "$TARGET_DISK" ]]; then
  echo "Target $TARGET_DISK is not a block device. Aborting." >&2
  exit 1
fi

cat <<'WARN'
===========================================================================
WARNING: This script WILL ERASE ALL DATA on the target disk you specify.
Type the confirmation token to continue:
  y
===========================================================================
WARN
read -r CONFIRM
if [[ "$CONFIRM" != "y" ]]; then
  echo "Confirmation token not provided. Aborting." >&2
  exit 1
fi

# -------------------- Ensure live environment packages --------------------
check_and_install_live_packages() {
  if ! command -v apt-get >/dev/null 2>&1; then
    err "This installer requires apt-get in the live environment. Use a Debian-based live image."
  fi

  log "Checking required packages in live environment"
  MISSING=()
  for pkg in "${REQUIRED_PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      MISSING+=("$pkg")
    fi
  done

  if [[ ${#MISSING[@]} -gt 0 ]]; then
    log "Missing packages: ${MISSING[*]}"
    apt-get update -y || true
    apt-get install -y --no-install-recommends "${MISSING[@]}" || err "Failed to install required packages: ${MISSING[*]}"
    log "Required packages installed."
  else
    log "All required packages are present in the live environment."
  fi
}
check_and_install_live_packages

# -------------------- Unmount any mounted partitions on target disk --------------------
log "Checking for mounted partitions on ${TARGET_DISK} and unmounting them (lazy)"
TARGET_BASENAME=$(basename "$TARGET_DISK")
# Find mountpoints for partitions whose device name starts with the target disk basename
mapfile -t MOUNTS < <(lsblk -ln -o NAME,MOUNTPOINT | awk -v disk="$TARGET_BASENAME" '$1 ~ "^"disk { if ($2!="") print $2 }')
if [[ ${#MOUNTS[@]} -gt 0 ]]; then
  for mp in "${MOUNTS[@]}"; do
    if [[ -n "$mp" ]]; then
      log "Unmounting $mp"
      umount -l "$mp" || true
    fi
  done
else
  log "No mounted partitions on ${TARGET_DISK} found."
fi

# -------------------- Partition table type option --------------------
echo
echo "Choose partition table type for ${TARGET_DISK}:"
echo "  1) GPT (recommended for UEFI)"
echo "  2) MBR (msdos)"
read -rp "Select 1 or 2 [1]: " PART_TYPE_CHOICE
PART_TYPE_CHOICE=${PART_TYPE_CHOICE:-1}
if [[ "$PART_TYPE_CHOICE" == "2" ]]; then
  PART_TABLE="msdos"
else
  PART_TABLE="gpt"
fi
log "Selected partition table: ${PART_TABLE}"

# -------------------- Partitioning --------------------
log "Wiping partition table on $TARGET_DISK"
if [[ "$PART_TABLE" == "gpt" ]]; then
  sgdisk --zap-all "$TARGET_DISK"
  log "Creating GPT partitions: EFI (${EFI_SIZE_MB}MiB) + main"
  sgdisk -n1:0:+${EFI_SIZE_MB}M -t1:ef00 -c1:"EFI System" "$TARGET_DISK"
  sgdisk -n2:0:0 -t2:8300 -c2:"Linux filesystem" "$TARGET_DISK"
else
  # create msdos table with parted
  parted -s "$TARGET_DISK" mklabel msdos
  # create primary FAT32 EFI partition at beginning
  parted -s "$TARGET_DISK" mkpart primary fat32 1MiB ${EFI_SIZE_MB}MiB
  parted -s "$TARGET_DISK" set 1 boot on
  # create rest as primary linux
  parted -s "$TARGET_DISK" mkpart primary ext4 ${EFI_SIZE_MB}MiB 100%
fi

partprobe "$TARGET_DISK" || true
sleep 1

# Determine partition device names (handle /dev/sdX and /dev/nvmeXn1)
if [[ "$(basename "$TARGET_DISK")" =~ ^nvme ]]; then
  EFI_PART="${TARGET_DISK}p1"
  MAIN_PART="${TARGET_DISK}p2"
else
  EFI_PART="${TARGET_DISK}1"
  MAIN_PART="${TARGET_DISK}2"
fi

log "Formatting EFI partition ${EFI_PART} as FAT32"
mkfs.vfat -F32 -n EFI "${EFI_PART}"

# -------------------- LUKS (optional) --------------------
read -rp "Install with LUKS encryption for root partition? [y/N]: " LUKS_ANS
LUKS_ANS=${LUKS_ANS:-N}
if [[ "${LUKS_ANS,,}" =~ ^y ]]; then
  LUKS_ENABLED=1
  read -rsp "Enter LUKS passphrase: " LUKS_PW
  echo
  log "Formatting main partition with LUKS2"
  printf '%s\n' "$LUKS_PW" | cryptsetup luksFormat --type luks2 "$MAIN_PART" -q
  printf '%s\n' "$LUKS_PW" | cryptsetup open "$MAIN_PART" cryptroot
  FS_DEVICE="/dev/mapper/cryptroot"
else
  LUKS_ENABLED=0
  FS_DEVICE="$MAIN_PART"
fi

# -------------------- Btrfs and subvolumes --------------------
log "Creating btrfs on $FS_DEVICE and subvolumes"
mkfs.btrfs -f "$FS_DEVICE"
mkdir -p "${MOUNTPOINT}"
mount "$FS_DEVICE" "${MOUNTPOINT}"
btrfs subvolume create "${MOUNTPOINT}/${ROOT_SUBVOL}"
btrfs subvolume create "${MOUNTPOINT}/${HOME_SUBVOL}"
mkdir -p "${MOUNTPOINT}/${HOME_SUBVOL}/.snapshots"
umount "${MOUNTPOINT}"

# Mount subvolumes for debootstrap
mkdir -p /mnt/target
mount -o noatime,compress=zstd:3,ssd,space_cache=v2,subvol=${ROOT_SUBVOL} "$FS_DEVICE" /mnt/target
mkdir -p /mnt/target/home
mount -o noatime,compress=zstd:3,ssd,space_cache=v2,subvol=${HOME_SUBVOL} "$FS_DEVICE" /mnt/target/home

# Mount EFI inside target
mkdir -p /mnt/target/boot/efi
mount "${EFI_PART}" /mnt/target/boot/efi

# -------------------- Mirror selection and debootstrap --------------------
choose_release_and_mirror() {
  MIRROR=""
  if command -v netselect-apt >/dev/null 2>&1; then
    pushd /tmp >/dev/null
    netselect-apt -n -s -o /tmp netselect "$RELEASE" >/dev/null 2>&1 || true
    if [[ -f /tmp/sources.list ]]; then MIRROR=$(awk '/^deb / {print $2; exit}' /tmp/sources.list || true); fi
    popd >/dev/null
  else
    apt-get update -y || true
    apt-get install -y netselect-apt >/dev/null 2>&1 || true
    if command -v netselect-apt >/dev/null 2>&1; then
      pushd /tmp >/dev/null
      netselect-apt -n -s -o /tmp netselect "$RELEASE" >/dev/null 2>&1 || true
      if [[ -f /tmp/sources.list ]]; then MIRROR=$(awk '/^deb / {print $2; exit}' /tmp/sources.list || true); fi
      popd >/dev/null
    fi
  fi
  MIRROR=${MIRROR:-"http://deb.debian.org/debian"}
  DEBOOTSTRAP_MIRROR="$MIRROR"
  log "Using mirror: $DEBOOTSTRAP_MIRROR"
}

echo
echo "Select Debian release:"
echo "  1) bullseye"
echo "  2) bookworm"
echo "  3) trixie"
echo "  4) testing"
echo "  5) sid"
read -rp "Choose 1-5 [2]: " rel_choice
rel_choice=${rel_choice:-2}
case "$rel_choice" in
  1) RELEASE="bullseye" ;;
  2) RELEASE="bookworm" ;;
  3) RELEASE="trixie" ;;
  4) RELEASE="testing" ;;
  5) RELEASE="sid" ;;
  *) RELEASE="bookworm" ;;
esac
choose_release_and_mirror

# Write live sources so debootstrap uses same mirror
cat > /etc/apt/sources.list <<EOF
deb ${DEBOOTSTRAP_MIRROR} ${RELEASE} main contrib non-free
deb ${DEBOOTSTRAP_MIRROR} ${RELEASE}-updates main contrib non-free
deb http://security.debian.org/ ${RELEASE}-security main contrib non-free
EOF
apt-get update -y || true

log "Bootstrapping Debian base system (${RELEASE}) using mirror ${DEBOOTSTRAP_MIRROR}"
apt-get install -y debootstrap ca-certificates wget gnupg || true
debootstrap --arch "${DEBOOTSTRAP_ARCH}" "${RELEASE}" /mnt/target "${DEBOOTSTRAP_MIRROR}"

# -------------------- Prepare chroot (binds, resolv, /tmp, locale) --------------------
log "Preparing chroot environment and ensuring /tmp and locale are present"
mount --bind /dev /mnt/target/dev
mount --bind /dev/pts /mnt/target/dev/pts
mount --bind /proc /mnt/target/proc
mount --bind /sys /mnt/target/sys
cp /etc/resolv.conf /mnt/target/etc/resolv.conf

mkdir -p /mnt/target/tmp /mnt/target/tmp/user/0
chmod 1777 /mnt/target/tmp /mnt/target/tmp/user/0

# Pre-create /etc/default/locale and timezone to avoid localectl/dbus calls
cat > /mnt/target/etc/default/locale <<EOF
LANG=${DEFAULT_LOCALE}
EOF
echo "${DEFAULT_TIMEZONE}" > /mnt/target/etc/timezone
ln -sf /usr/share/zoneinfo/"${DEFAULT_TIMEZONE}" /mnt/target/etc/localtime || true

# Create policy-rc.d inside chroot to prevent services from starting during package installs
cat > /mnt/target/usr/sbin/policy-rc.d <<'POLICY'
#!/bin/sh
# Prevent init scripts from running inside chroot during package install
exit 101
POLICY
chmod +x /mnt/target/usr/sbin/policy-rc.d

# Minimal locale setup BEFORE installing packages that rely on locales
log "Bootstrapping locales inside chroot"
chroot /mnt/target /bin/bash -c "
export DEBIAN_FRONTEND=noninteractive
export LANG=${DEFAULT_LOCALE}
export LC_ALL=${DEFAULT_LOCALE}
export TMPDIR=/tmp
apt-get update -y || true
apt-get install -y --no-install-recommends locales || true
if ! locale -a | grep -q '${DEFAULT_LOCALE}'; then
  echo '${DEFAULT_LOCALE} UTF-8' >> /etc/locale.gen || true
  locale-gen ${DEFAULT_LOCALE} || true
fi
echo 'LANG=${DEFAULT_LOCALE}' > /etc/default/locale || true
dpkg --configure -a || true
apt-get -f install -y || true
"

# -------------------- Write chroot sources.list (security.debian.org) --------------------
cat > /mnt/target/etc/apt/sources.list <<EOF
deb ${DEBOOTSTRAP_MIRROR} ${RELEASE} main contrib non-free
deb ${DEBOOTSTRAP_MIRROR} ${RELEASE}-updates main contrib non-free
deb http://security.debian.org/ ${RELEASE}-security main contrib non-free
EOF

# -------------------- Chroot setup script (no systemd/dbus calls) --------------------
cat > /mnt/target/root/chroot-setup.sh <<'CHROOT'
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export TMPDIR=/tmp
export LANG=en_AU.UTF-8
export LC_ALL=en_AU.UTF-8
# Prevent services from starting during package installs
if [[ ! -x /usr/sbin/policy-rc.d ]]; then
  cat > /usr/sbin/policy-rc.d <<'POL'
#!/bin/sh
exit 101
POL
  chmod +x /usr/sbin/policy-rc.d
fi

USERNAME_PLACEHOLDER="__USERNAME__"
USER_PW_PLACEHOLDER="__USERPW__"
ROOT_PW_PLACEHOLDER="__ROOTPW__"
HOSTNAME_PLACEHOLDER="__HOSTNAME__"
TIMEZONE_PLACEHOLDER="__TIMEZONE__"
LOCALE_PLACEHOLDER="__LOCALE__"
KEYMAP_PLACEHOLDER="__KEYMAP__"

apt-get update -y
apt-get install -y --no-install-recommends linux-image-amd64 btrfs-progs snapper acl sudo cryptsetup ca-certificates locales wget gnupg grub-efi-amd64 shim-signed efibootmgr parted

# Ensure locale exists and write /etc/default/locale
if ! locale -a | grep -q "${LOCALE_PLACEHOLDER}"; then
  echo "${LOCALE_PLACEHOLDER} UTF-8" >> /etc/locale.gen || true
  locale-gen "${LOCALE_PLACEHOLDER}" || true
fi
echo "LANG=${LOCALE_PLACEHOLDER}" > /etc/default/locale || true

# Keyboard: write /etc/default/keyboard
cat > /etc/default/keyboard <<KEY
XKBMODEL="pc105"
XKBLAYOUT="${KEYMAP_PLACEHOLDER}"
XKBVARIANT=""
XKBOPTIONS=""
BACKSPACE="guess"
KEY

# Timezone: write /etc/timezone and link /etc/localtime
echo "${TIMEZONE_PLACEHOLDER}" > /etc/timezone
ln -sf /usr/share/zoneinfo/"${TIMEZONE_PLACEHOLDER}" /etc/localtime || true

# Create user and set passwords
useradd -m -s /bin/bash -G sudo "${USERNAME_PLACEHOLDER}"
echo "${USERNAME_PLACEHOLDER}:${USER_PW_PLACEHOLDER}" | chpasswd
if [[ -n "${ROOT_PW_PLACEHOLDER}" ]]; then
  echo "root:${ROOT_PW_PLACEHOLDER}" | chpasswd
fi

# Hostname
echo "${HOSTNAME_PLACEHOLDER}" > /etc/hostname
sed -i "1s/.*/127.0.1.1 ${HOSTNAME_PLACEHOLDER}/" /etc/hosts || true

# Remove policy-rc.d to allow services to start on first boot
rm -f /usr/sbin/policy-rc.d || true

CHROOT

# Replace placeholders in chroot script
read -rp "Enter username for the new system [test]: " USERNAME
USERNAME=${USERNAME:-test}
read -rsp "Enter password for user ${USERNAME} (leave blank to set later): " USER_PW
echo
read -rsp "Enter root password (leave blank to disable root login): " ROOT_PW
echo
read -rp "Enter hostname (PC name) [user]: " HOSTNAME
HOSTNAME=${HOSTNAME:-user}
read -rp "Enter timezone [${DEFAULT_TIMEZONE}]: " TIMEZONE
TIMEZONE=${TIMEZONE:-$DEFAULT_TIMEZONE}
read -rp "Enter locale [${DEFAULT_LOCALE}]: " LOCALE
LOCALE=${LOCALE:-$DEFAULT_LOCALE}
read -rp "Enter keyboard layout [${DEFAULT_KEYMAP}]: " KEYMAP
KEYMAP=${KEYMAP:-$DEFAULT_KEYMAP}

sed -i "s|__USERNAME__|${USERNAME}|g" /mnt/target/root/chroot-setup.sh
USER_PW_ESCAPED=$(printf '%s' "$USER_PW" | sed -e 's/[\/&]/\\&/g')
ROOT_PW_ESCAPED=$(printf '%s' "$ROOT_PW" | sed -e 's/[\/&]/\\&/g')
sed -i "s|__USERPW__|${USER_PW_ESCAPED}|g" /mnt/target/root/chroot-setup.sh
sed -i "s|__ROOTPW__|${ROOT_PW_ESCAPED}|g" /mnt/target/root/chroot-setup.sh
sed -i "s|__HOSTNAME__|${HOSTNAME}|g" /mnt/target/root/chroot-setup.sh
sed -i "s|__TIMEZONE__|${TIMEZONE}|g" /mnt/target/root/chroot-setup.sh
sed -i "s|__LOCALE__|${LOCALE}|g" /mnt/target/root/chroot-setup.sh
sed -i "s|__KEYMAP__|${KEYMAP}|g" /mnt/target/root/chroot-setup.sh
chmod +x /mnt/target/root/chroot-setup.sh

# -------------------- deb-multimedia repo + keyring inside chroot --------------------
cat > /mnt/target/etc/apt/sources.list.d/dmo.sources <<EOF
Types: deb
URIs: https://www.deb-multimedia.org
Suites: ${RELEASE}
Components: main non-free
Signed-By: /usr/share/keyrings/deb-multimedia-keyring.pgp
Enabled: yes
EOF

chroot /mnt/target /bin/bash -c "
export DEBIAN_FRONTEND=noninteractive
export LANG=${LOCALE}
export LC_ALL=${LOCALE}
export TMPDIR=/tmp
apt-get update -y || true
apt-get install -y --no-install-recommends wget gnupg ca-certificates || true
dpkg --configure -a || true
apt-get -f install -y || true
"

log "Downloading deb-multimedia keyring into chroot"
chroot /mnt/target bash -lc "cd /tmp && wget -q ${DMO_URL} -O ${DMO_KEY_PKG} || exit 1"
CHROOT_SHA=$(chroot /mnt/target bash -lc "cd /tmp && sha256sum ${DMO_KEY_PKG} | awk '{print \$1}'" || true)
if [[ "${CHROOT_SHA}" != "${DMO_SHA256}" ]]; then
  err "deb-multimedia keyring checksum mismatch: expected ${DMO_SHA256}, got ${CHROOT_SHA}"
fi
chroot /mnt/target bash -lc "cd /tmp && dpkg -i ${DMO_KEY_PKG} || apt-get -f install -y || true"
chroot /mnt/target bash -lc "export DEBIAN_FRONTEND=noninteractive; export LANG=${LOCALE}; export LC_ALL=${LOCALE}; export TMPDIR=/tmp; apt-get update -y && apt-get -y --allow-downgrades --allow-change-held-packages dist-upgrade || true"

# -------------------- Run chroot setup --------------------
log "Running chroot setup script"
chroot /mnt/target /root/chroot-setup.sh || true

# -------------------- Snapper configs and hooks --------------------
log "Creating snapper configs and package hooks inside chroot"
mkdir -p /mnt/target/etc/snapper/configs
chown root:root /mnt/target/etc/snapper
chmod 755 /mnt/target/etc/snapper

cat > /mnt/target/etc/snapper/configs/root <<'ROOTCFG'
SUBVOLUME="/"
FSTYPE="btrfs"
QGROUP=""
FREE_LIMIT="0.12"
ALLOW_USERS="__USERNAME__"
ALLOW_GROUPS="sudo"
SYNC_ACL="yes"
BACKGROUND_COMPARISON="no"
NUMBER_CLEANUP="yes"
NUMBER_MIN_AGE="3600"
NUMBER_LIMIT="50"
NUMBER_LIMIT_IMPORTANT="10"
TIMELINE_CREATE="yes"
TIMELINE_CLEANUP="yes"
TIMELINE_MIN_AGE="3600"
TIMELINE_LIMIT_HOURLY="12"
TIMELINE_LIMIT_DAILY="30"
TIMELINE_LIMIT_WEEKLY="12"
TIMELINE_LIMIT_MONTHLY="12"
TIMELINE_LIMIT_YEARLY="3"
EMPTY_PRE_POST_CLEANUP="yes"
ROOTCFG

cat > /mnt/target/etc/snapper/configs/home <<'HOMECFG'
SUBVOLUME="/home"
FSTYPE="btrfs"
QGROUP=""
SPACE_LIMIT="500G"
FREE_LIMIT="0.12"
ALLOW_USERS="__USERNAME__"
ALLOW_GROUPS="sudo"
SYNC_ACL="yes"
BACKGROUND_COMPARISON="no"
NUMBER_CLEANUP="yes"
NUMBER_MIN_AGE="3600"
NUMBER_LIMIT="4"
NUMBER_LIMIT_IMPORTANT="2"
TIMELINE_CREATE="yes"
TIMELINE_CLEANUP="yes"
TIMELINE_MIN_AGE="3600"
TIMELINE_LIMIT_HOURLY="0"
TIMELINE_LIMIT_DAILY="4"
TIMELINE_LIMIT_WEEKLY="0"
TIMELINE_LIMIT_MONTHLY="0"
TIMELINE_LIMIT_YEARLY="0"
EMPTY_PRE_POST_CLEANUP="yes"
HOMECFG

sed -i "s|__USERNAME__|${USERNAME}|g" /mnt/target/etc/snapper/configs/root
sed -i "s|__USERNAME__|${USERNAME}|g" /mnt/target/etc/snapper/configs/home

cat > /mnt/target/usr/local/bin/snapper-pkg-hook.sh <<'HOOK'
#!/usr/bin/env bash
set -euo pipefail
mode="${1:-}"
desc_pre="Before Program/Updates Installed"
desc_post="After Program/Updates Installed"
if [[ "$mode" == "pre" ]]; then
  /usr/bin/snapper -c root create --description "$desc_pre" --cleanup-algorithm number >/dev/null 2>&1 || true
elif [[ "$mode" == "post" ]]; then
  /usr/bin/snapper -c root create --description "$desc_post" --cleanup-algorithm number >/dev/null 2>&1 || true
fi
HOOK
chmod +x /mnt/target/usr/local/bin/snapper-pkg-hook.sh
chown root:root /mnt/target/usr/local/bin/snapper-pkg-hook.sh

if chroot /mnt/target bash -lc 'command -v apt-get >/dev/null 2>&1'; then
  cat > /mnt/target/etc/apt/apt.conf.d/80snapper <<'APT'
DPkg::Pre-Invoke { "/usr/local/bin/snapper-pkg-hook.sh pre"; };
DPkg::Post-Invoke { "/usr/local/bin/snapper-pkg-hook.sh post"; };
APT
fi

# -------------------- ACLs for /home/.snapshots --------------------
log "Applying ACLs for /home/.snapshots"
chroot /mnt/target bash -lc "mkdir -p /home/.snapshots; chown root:root /home/.snapshots; chmod 0750 /home/.snapshots"
if chroot /mnt/target bash -lc 'command -v setfacl >/dev/null 2>&1'; then
  chroot /mnt/target bash -lc "setfacl -R -m g:users:rx /home/.snapshots || true; setfacl -R -d -m g:users:rx /home/.snapshots || true"
fi

# -------------------- Enable timers by symlink and baseline snapshots --------------------
log "Enabling snapper timers by creating systemd symlinks (no systemctl calls)"
mkdir -p /mnt/target/etc/systemd/system/timers.target.wants
mkdir -p /mnt/target/etc/systemd/system/multi-user.target.wants
ln -sf /lib/systemd/system/snapper-timeline.timer /mnt/target/etc/systemd/system/timers.target.wants/snapper-timeline.timer || true
ln -sf /lib/systemd/system/snapper-cleanup.timer /mnt/target/etc/systemd/system/timers.target.wants/snapper-cleanup.timer || true
ln -sf /lib/systemd/system/snapperd.service /mnt/target/etc/systemd/system/multi-user.target.wants/snapperd.service || true

# If snapper exists in chroot, create baseline snapshots (best-effort)
if chroot /mnt/target bash -lc 'command -v snapper >/dev/null 2>&1'; then
  chroot /mnt/target bash -lc "snapper -c root create --description baseline-root-$(date +%F-%H%M) --cleanup-algorithm number || true" || true
  chroot /mnt/target bash -lc "snapper -c home create --description baseline-home-$(date +%F-%H%M) --cleanup-algorithm number || true" || true
else
  log "snapper not available in chroot to create baseline snapshots now."
fi

# -------------------- Desktop launcher and optional GUI embedding --------------------
log "Installing desktop launcher into chroot"
mkdir -p /mnt/target/usr/local/share/applications
cat > /mnt/target/usr/local/share/applications/${DESKTOP_LAUNCHER_NAME} <<DESKTOP
[Desktop Entry]
Type=Application
Name=Snapshot Restore
Comment=Open Snapshot Restore GUI (System / Personal files)
Exec=/usr/local/bin/${SNAPPER_GUI_SCRIPT}
Icon=utilities-system-monitor
Terminal=false
Categories=Utility;System;
StartupNotify=true
DESKTOP

read -rp "Copy local GUI script '${SNAPPER_GUI_SCRIPT}' into installed system's /usr/local/bin? [y/N]: " COPY_GUI_ANS
COPY_GUI_ANS=${COPY_GUI_ANS:-N}
if [[ "${COPY_GUI_ANS,,}" =~ ^y ]]; then
  if [[ -f "./${SNAPPER_GUI_SCRIPT}" ]]; then
    mkdir -p /mnt/target/usr/local/bin
    cp "./${SNAPPER_GUI_SCRIPT}" /mnt/target/usr/local/bin/ || true
    chmod +x /mnt/target/usr/local/bin/"${SNAPPER_GUI_SCRIPT}" || true
    log "GUI script copied into installed system."
  else
    log "Local GUI script not found; skipping copy."
  fi
fi

# -------------------- Write /etc/fstab for installed system --------------------
log "Writing /mnt/target/etc/fstab with btrfs subvol entries and EFI"
BTRFS_UUID=$(blkid -s UUID -o value "${FS_DEVICE}" || true)
EFI_UUID=$(blkid -s UUID -o value "${EFI_PART}" || true)
if [[ -z "${BTRFS_UUID}" ]]; then BTRFS_DEV="${FS_DEVICE}"; else BTRFS_DEV="UUID=${BTRFS_UUID}"; fi
if [[ -z "${EFI_UUID}" ]]; then EFI_DEV="${EFI_PART}"; else EFI_DEV="UUID=${EFI_UUID}"; fi

cat > /mnt/target/etc/fstab <<FSTAB
# <file system> <mount point> <type> <options> <dump> <pass>
${BTRFS_DEV} / btrfs noatime,compress=zstd:3,ssd,space_cache=v2,subvol=${ROOT_SUBVOL} 0 0
${BTRFS_DEV} /home btrfs noatime,compress=zstd:3,ssd,space_cache=v2,subvol=${HOME_SUBVOL} 0 0
${EFI_DEV} /boot/efi vfat umask=0077 0 1
FSTAB

log "/etc/fstab written."

# -------------------- Ensure crypttab for LUKS root --------------------
if [[ "${LUKS_ENABLED:-0}" -eq 1 ]]; then
  log "Writing /mnt/target/etc/crypttab for cryptroot"
  MAIN_UUID=$(blkid -s UUID -o value "${MAIN_PART}")
  echo "cryptroot UUID=${MAIN_UUID} none luks,discard" > /mnt/target/etc/crypttab
fi

# -------------------- Install GRUB/EFI and update initramfs --------------------
log "Installing GRUB/EFI into the installed system and updating initramfs"
chroot /mnt/target /bin/bash -c "
export DEBIAN_FRONTEND=noninteractive
export LANG=${LOCALE}
export LC_ALL=${LOCALE}
export TMPDIR=/tmp
apt-get update -y || true
apt-get install -y --no-install-recommends grub-efi-amd64 shim-signed efibootmgr || true
if command -v update-initramfs >/dev/null 2>&1; then
  update-initramfs -u -k all || true
fi
update-grub || true
grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=debian --recheck || true
"

# Create an EFI boot entry (best-effort)
if command -v efibootmgr >/dev/null 2>&1; then
  # determine partition number for EFI_PART
  if [[ "$(basename "$TARGET_DISK")" =~ ^nvme ]]; then
    PART_NUM=1
  else
    PART_NUM=1
  fi
  efibootmgr -c -d "${TARGET_DISK}" -p "${PART_NUM}" -L "debian" -l '\EFI\debian\shimx64.efi' >/dev/null 2>&1 || true
fi

# -------------------- Verification tests before reboot --------------------
log "Running verification checks before reboot"
fail=0

# 1) Check partitions exist
if [[ ! -b "${EFI_PART}" ]]; then echo "[check] EFI partition ${EFI_PART} not found" >&2; fail=1; else echo "[check] EFI partition exists: ${EFI_PART}"; fi
if [[ ! -b "${MAIN_PART}" ]]; then echo "[check] Main partition ${MAIN_PART} not found" >&2; fail=1; else echo "[check] Main partition exists: ${MAIN_PART}"; fi

# 2) Check EFI filesystem mounted and contains EFI files
if mountpoint -q /mnt/target/boot/efi; then
  if [[ -f /mnt/target/boot/efi/EFI/debian/shimx64.efi || -f /mnt/target/boot/efi/EFI/debian/grubx64.efi ]]; then
    echo "[check] EFI binaries present in /boot/efi/EFI/debian"
  else
    echo "[check] EFI binaries missing in /boot/efi/EFI/debian" >&2; fail=1
  fi
else
  echo "[check] /boot/efi is not mounted in target" >&2; fail=1
fi

# 3) Check grub.cfg
if [[ -f /mnt/target/boot/grub/grub.cfg ]]; then echo "[check] grub.cfg present"; else echo "[check] grub.cfg missing" >&2; fail=1; fi

# 4) efibootmgr entry (best-effort)
if command -v efibootmgr >/dev/null 2>&1; then
  if efibootmgr -v | grep -qi debian; then echo "[check] EFI boot entry for 'debian' exists"; else echo "[check] EFI boot entry for 'debian' not found (efibootmgr)"; fi
else
  echo "[check] efibootmgr not available on live system; cannot verify EFI boot entry"
fi

# 5) LUKS checks
if [[ "${LUKS_ENABLED:-0}" -eq 1 ]]; then
  if [[ -f /mnt/target/etc/crypttab ]]; then echo "[check] /etc/crypttab present"; else echo "[check] /etc/crypttab missing" >&2; fail=1; fi
  if chroot /mnt/target bash -lc 'ls /boot/initrd.img-* 2>/dev/null | wc -l' | grep -q '[1-9]'; then echo "[check] initramfs images present"; else echo "[check] initramfs images missing" >&2; fail=1; fi
fi

# 6) Snapper configs
if [[ -d /mnt/target/etc/snapper/configs ]]; then
  if [[ -f /mnt/target/etc/snapper/configs/root && -f /mnt/target/etc/snapper/configs/home ]]; then echo "[check] snapper configs present"; else echo "[check] snapper config files missing" >&2; fail=1; fi
else echo "[check] /etc/snapper/configs directory missing" >&2; fail=1; fi

# 7) Desktop launcher
if [[ -f /mnt/target/usr/local/share/applications/${DESKTOP_LAUNCHER_NAME} ]]; then echo "[check] Desktop launcher installed"; else echo "[check] Desktop launcher missing"; fi

# 8) fstab entries for root and home
if grep -q "subvol=${ROOT_SUBVOL}" /mnt/target/etc/fstab 2>/dev/null; then echo "[check] fstab contains root subvol entry"; else echo "[check] fstab missing root subvol entry" >&2; fail=1; fi
if grep -q "subvol=${HOME_SUBVOL}" /mnt/target/etc/fstab 2>/dev/null; then echo "[check] fstab contains home subvol entry"; else echo "[check] fstab missing home subvol entry" >&2; fail=1; fi

if [[ "$fail" -ne 0 ]]; then
  echo; echo "[install] One or more verification checks failed. The system will NOT reboot automatically."; echo "[install] Inspect /mnt/target and fix issues, then reboot manually."; exit 2
fi

# -------------------- Cleanup and unmount --------------------
log "All checks passed. Cleaning up and unmounting"
rm -f /mnt/target/root/chroot-setup.sh || true
rm -f /mnt/target/usr/sbin/policy-rc.d || true

for d in /mnt/target/dev/pts /mnt/target/dev /mnt/target/proc /mnt/target/sys; do umount -l "$d" >/dev/null 2>&1 || true; done
umount -l /mnt/target/boot/efi || true
umount -l /mnt/target/home || true
umount -l /mnt/target || true

log "Installation finished and verified. Rebooting now."
reboot
