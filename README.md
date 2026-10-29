# APatch Strong Integrity Auditor & Auto-Fixer (v1.6.3)

[![Build & Release APatch Module](https://github.com/bponders12-cell/apatch-strong-integrity-diag/actions/workflows/release.yml/badge.svg)](https://github.com/bponders12-cell/apatch-strong-integrity-diag/actions/workflows/release.yml)
[![Version](https://img.shields.io/badge/version-v1.6.3-emerald)](https://github.com/bponders12-cell/apatch-strong-integrity-diag/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An advanced 6-layer diagnostic engine and automated remediation tool for **APatch** (and KernelSU / Magisk compatibility environments) to diagnose and achieve `MEETS_STRONG_INTEGRITY` on Android 10 through Android 17 (SDK 37).

Repository: [https://github.com/bponders12-cell/apatch-strong-integrity-diag](https://github.com/bponders12-cell/apatch-strong-integrity-diag)

---

## Key Capabilities in v1.6.3

1. **Full Global `resetprop` Identity Sync**:
   Directly updates `ro.product.*.device=bluejay`, `ro.product.*.name=bluejay_beta`, `ro.product.*.model="Pixel 6a"`, `ro.product.first_api_level=32`, `ro.board.first_api_level=32`, and `ro.build.version.security_patch=2026-10-05` in kernel memory (`/dev/__properties__`) to prevent split-brain identity mismatches between `ro.build.fingerprint` and host device properties on Android 17 QPR2/Canary.

2. **Single-Key 5KB RKP `keybox.xml` Companion Splicer**:
   Automatically splices a cryptographically chained 3-certificate RSA CA hierarchy (`Root CA -> Intermediate CA -> Attestation CA` with `BasicConstraints(ca=True)` and `keyCertSign=True`) right before `</Keybox>`, turning `ecdsa:1,rsa:0` into `ecdsa:1,rsa:1` so TrickyStore / TrickyStoreOSS can load single-key RKP keyboxes without `missing required data` errors.

3. **TrickyStoreOSS `security_patch.txt` Formatting**:
   Enforces `all=2026-10-05` (along with `system=`, `vendor=`, `boot=`) `key=value` syntax required by TrickyStoreOSS.

4. **PlayIntegrityFork v18/v19 Schema (Commit `032a345` / `#617`)**:
   Generates explicit `# System Properties` in `custom.pif.prop` (`ro.build.fingerprint`, `ro.build.id`, `ro.product.device`, `ro.product.name`, `ro.build.version.security_patch`, `ro.board.first_api_level=32`, and `ro.product.first_api_level=32`) alongside legacy wildcards for full backward/forward compatibility.

5. **Accurate Keystore2 Injection & DroidGuard Cache Purge**:
   Detects whether `keystore2` actually has TrickyStore/TEESimulator hooked (excluding `/memfd:` false positives), relaunches `service.sh` if needed, and clears `/data/data/com.google.android.gms/app_dg_cache/*` so pre-existing unlocked-bootloader keys are purged.

---

## Quick Installation

1. Download `apatch_strong_integrity_diag_v1.6.3.zip` from the [Latest Release](https://github.com/bponders12-cell/apatch-strong-integrity-diag/releases/latest).
2. Install via **APatch Manager → Modules → Install**.
3. Open the **WebUI** in APatch Manager to view live diagnostics and tap **Fix All For Me**.

---

## Building from Source

```bash
sh build.sh
```

Produces `apatch_strong_integrity_diag_v1.6.3.zip` with correct executable permissions (`0755`) and metadata.
