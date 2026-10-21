#!/usr/bin/env bash
# Reproduce Renegade's pinned old TianoCore BaseTools build on newer GCC hosts.
# Scope: the explicitly provided EDK2 source *copy* and a private temporary
# wrapper directory. No git checkout/reset/clean, firmware packaging or device.
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo 'Usage: dizi-renegade-basetools.sh EDK2_SOURCE_DIR [--build]' >&2
    exit 2
fi
EDK2_DIR=$(realpath -e -- "$1")
if [ ! -f "$EDK2_DIR/edksetup.sh" ] || [ ! -d "$EDK2_DIR/BaseTools/Source/C" ]; then
    echo 'Not a complete pinned EDK2 source tree' >&2
    exit 2
fi
if [ "${2:-}" != '--build' ]; then
    echo 'Read-only check: EDK2 BaseTools source is present; pass --build to compile.'
    exit 0
fi
GCC_EXE=$(command -v gcc)
if [ -z "$GCC_EXE" ]; then
    echo 'Host GCC is missing' >&2
    exit 2
fi
GCC_EXE=$(realpath -e -- "$GCC_EXE")
BASE_TOOLS=$(realpath -e -- "$EDK2_DIR/BaseTools")
if [ "$BASE_TOOLS" = / ] || [ "$BASE_TOOLS" = "$PWD" ]; then
    echo 'Refusing invalid BaseTools destination' >&2
    exit 2
fi

WRAPPERS=$(mktemp -d "${TMPDIR:-/tmp}/dizi-edk2-gcc-XXXXXXXX")
trap 'rm -rf -- "$WRAPPERS"' EXIT
for name in cc gcc; do
    # CC command is deliberately absolute and quoted, so a test cannot
    # insert a shell fragment through the caller's PATH.
    printf '#!/bin/sh\nexec "%s" -std=gnu17 -Wno-error=unused-but-set-variable "$@"\n' \
        "$GCC_EXE" > "$WRAPPERS/$name"
    chmod 700 "$WRAPPERS/$name"
done
PATH="$WRAPPERS:$PATH" make -C "$BASE_TOOLS" -j4
echo 'BaseTools completed with host GCC GNU17 compatibility wrapper.'
echo 'This does NOT build SM7435 UEFI firmware or prove a safe boot image.'
