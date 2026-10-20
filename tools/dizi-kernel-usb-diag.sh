#!/bin/sh
# Boot a dizi shim payload and capture the XNU live console over USB ECM.
#   tools/dizi-kernel-usb-diag.sh IMAGE LOG [SECONDS]
# Starts sweet-usbnet.sh (host 192.168.7.1, UDP 5140) before the temporary
# fastboot boot, then saves the UDP stream. Nothing is flashed. The kernel
# must have been built with the early USB hook (sweetearlyusb=1) or reach
# sweet_ufs_init(); otherwise no interface appears and the log stays empty.
set -eu
if [ $# -lt 2 ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
	echo "Usage: $0 IMAGE LOG [SECONDS]" >&2
	exit 2
fi
image=$1
log=$2
seconds=${3:-120}
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
adb="$root/../host-tools/platform-tools/adb"
fastboot="$root/../host-tools/platform-tools/fastboot"
[ -f "$image" ] || { echo "missing image: $image" >&2; exit 2; }
[ -x "$adb" ] && [ -x "$fastboot" ] || { echo "adb/fastboot missing" >&2; exit 2; }
mkdir -p "$(dirname "$log")"

# The UDP listener and its sudo children share this session so the cleanup
# below cannot leave a stale nc/socat bound to 5140.
setsid sudo -n "$root/tools/sweet-usbnet.sh" "$log" &
pid=$!
trap 'kill -- -$pid 2>/dev/null || true' EXIT INT TERM
sleep 1

if ! "$adb" devices | grep -q "device$"; then
	if ! "$fastboot" devices | grep -q .; then
		echo "No adb/fastboot device; connect the tablet" >&2
		exit 2
	fi
fi
if "$adb" devices | grep -q "device$"; then
	echo "rebooting Android to the bootloader..." >&2
	"$adb" reboot bootloader
	timeout 90 sh -c "until '$fastboot' devices 2>/dev/null | grep -q .; do sleep 1; done"
fi
echo "fastboot boot $image; listening for the kernel log..." >&2
"$fastboot" boot "$image"

sleep "$seconds"
kill -- -"$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
trap - EXIT INT TERM
if [ -s "$log" ]; then
	echo "saved $(wc -c < "$log") bytes to $log" >&2
	tail -40 "$log"
else
	echo "No kernel UDP log arrived." >&2
	echo "The shim payload may have failed before the USB probe; check the screen." >&2
fi
