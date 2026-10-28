# APatch Strong Integrity Diagnostics (`apatch_strong_integrity_diag`)

An open-source, 6-layer diagnostic and 1-tap auto-remediation module (`v1.4.0`) with a built-in WebUI for **APatch** (and KernelSU) that audits and fixes every requirement for passing Google Play Integrity's `MEETS_DEVICE_INTEGRITY` and `MEETS_STRONG_INTEGRITY` verdicts.

## Key Capabilities

1. **Layer 1 — PIF Migration, Zygisk GMS Injection & RKP Audit**:
   - Detects the critical APatch + ReZygisk/ZygiskNext trap where enabling `Exclude Modifications` (`exclude=1` in `/data/adb/ap/package_config`) on `com.google.android.gms` puts GMS on the DenyList and unloads PlayIntegrityFork.
   - Audits `/data/adb/modules/playintegrityfix/custom.pif.prop` for PlayIntegrityFork v15+ `migrate.sh` formatting (`*.build.id`, `*.security_patch`, `*api_level`) and flags `DEVICE_INITIAL_SDK_INT >= 36` (Pixel 10/11 series) prints that require RKP.
2. **Layer 2 — Pure-BusyBox ASN.1 DER Keybox & Live Google CRL Check**:
   - Parses `/data/adb/tricky_store/keybox.xml` using pure BusyBox (`awk` + `base64 -d` + `od -An -tx1` — no `openssl` binary needed) to extract every X.509 certificate serial number.
   - Checks all extracted serials against Google's live Attestation CRL (`https://android.googleapis.com/attestation/status`) and distinguishes between unrevoked hardware keyboxes (`clean_unrevoked`), revoked keyboxes (`revoked_serial_...`), and default AOSP software keyboxes (`aosp_software_keybox`).
3. **Layer 3 — Verified Boot & Bootloader State**:
   - Audits `ro.boot.verifiedbootstate`, `ro.boot.flash.locked`, `ro.boot.vbmeta.device_state`, `ro.boot.veritymode`, `ro.debuggable`, and `ro.secure`.
4. **Layer 4 — Build Fingerprint & Security Patch Alignment**:
   - Verifies alignment between PIF `SECURITY_PATCH`, `ro.build.version.security_patch`, `ro.vendor.build.security_patch`, and `/data/adb/tricky_store/security_patch.txt`.
5. **Layer 5 — APatch & OverlayFS Footprint**:
   - Scans `/data/adb/modules/*` for active `/system` `OverlayFS` mounts missing `skip_mount`.
6. **Layer 6 — SELinux, Mount Namespace & Kernel Hygiene**:
   - Checks `getenforce`, `/proc/mounts` leaks, `ro.boot.warranty_bit`, and banned kernel release substrings (`uname -r`).

## Repository Structure

```text
apatch-strong-integrity-diag/
├── .github/workflows/
│   └── release.yml          # Automated CI syntax check + GitHub Release ZIP builder
├── META-INF/com/google/android/
│   ├── update-binary        # Standard APatch/Magisk module installer wrapper
│   └── updater-script       # #MAGISK
├── scripts/
│   ├── diag_engine.sh       # Read-only 6-layer diagnostic & DER/CRL engine (--json / --text)
│   └── apply_fix.sh         # Root auto-remediation engine (autopif4 -s -m, target.txt, resetprop)
├── webroot/
│   └── index.html           # Built-in APatch WebUI (window.ksu.exec bridge)
├── action.sh                # APatch Manager Action button entry point
├── build.sh                 # Local one-command syntax validator & ZIP builder
├── customize.sh             # Installer hook (enables skip_mount & sets 0755 permissions)
├── module.prop              # Module metadata
├── update.json              # OTA update metadata for APatch Manager
├── CHANGELOG.md             # Version history
└── LICENSE                  # GPL-3.0 License
```

## Quick Start: Push to Your Own GitHub Repository

```sh
unzip apatch_strong_integrity_diag_github_repo_v1.4.0.zip -d apatch-strong-integrity-diag
cd apatch-strong-integrity-diag

# Test local build
sh ./build.sh

# Initialize Git & push to GitHub (triggers GitHub Actions release on tag push)
git init
git add .
git commit -m "Initial release: APatch Strong Integrity Diagnostics v1.4.0"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/apatch-strong-integrity-diag.git
git push -u origin main

# Tag v1.4.0 to automatically publish a GitHub Release with the flashable ZIP
git tag v1.4.0
git push origin v1.4.0
```
