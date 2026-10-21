# Working on ios-sweet

- Read `NOTES.md` before starting; it contains the project goal, hardware facts,
  current blocker, local artifact locations and the next concrete action.
- **Current POCO Pad target is genuine macOS 27 Golden Gate**, tracked in
  `docs/DIZI_MACOS27_MIGRATION.md` and `boards/dizi-macos27.json` on branch
  `pocopad-macos27`. The prior XNU22/iPadOS16 GUI successes remain useful
  hardware evidence, not evidence of a macOS27 kernel or userspace boot.
- The user switches agents frequently. Update the active handoff in `NOTES.md`
  after each milestone and before stopping. Record commits, CI run IDs, exact
  build/boot results and unfinished work. Distinguish observations from guesses.
- Commit completed changes. Use `gh` for GitHub Actions kernel builds and logs.
  Local single-file cross-compiles are useful before spending a CI run.
- Device bring-up uses temporary `fastboot boot` images. Preserve the Android
  installation and partition backups. The user approved (2026-10-15) using
  internal UFS for iOS and said Android may be deleted: the iOS root goes
  into the existing `userdata` partition (no GPT changes). Keep bootloaders,
  recovery, modem, persist and the backups intact, and confirm each
  destructive step with the user before running it.
- **POCO Pad (`dizi`) update, 2026-10-21:** The user later explicitly
  authorized selected temporary boots of the 0099, 0116 and 0120 experimental
  iPadOS images, and confirmed the 0116 GUI. This does **not** authorize
  destructive flashing or an arbitrary new OS boot. There is currently NO
  verified Darwin26/macOS27 kernel, APFS root/SSV or boot chain. Keep macOS27
  work source-only until supported inputs are verified. Never relabel the old
  iPadOS kernel, use simulated DMA ownership, or claim a source-only check as
  real macOS boot success. Preserve all existing dizi images and original
  Android/firmware/Apple backups; never flash, erase or repartition without
  explicit approval of a concrete operation.
- Keep device dumps, serial numbers and downloaded Apple artifacts out of git.
