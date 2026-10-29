# Changelog

## v1.6.3 (2026-10-28)
- **Full Global `resetprop` Identity Sync**: Sets `ro.product.*.device=bluejay`, `ro.product.*.name=bluejay_beta`, `ro.product.*.model="Pixel 6a"`, `ro.product.first_api_level=32`, `ro.board.first_api_level=32`, and `ro.vendor.api_level=32` alongside `ro.*.build.fingerprint` to eliminate the split-brain mismatch between `ro.build.fingerprint` and host device properties on Android 17.
- **Accurate Keystore2 Injection Detection**: Removed the `/memfd:` false positive from `diag_engine.sh` so Layer 2 reliably detects whether TrickyStore/TEESimulator is actually hooked into `keystore2`.
- **Automatic TrickyStore Daemon Relaunch & GMS Cache Purge**: Automatically re-executes `/data/adb/modules/tricky_store/service.sh` if `keystore2` isn't hooked, and purges `/data/data/com.google.android.gms/app_dg_cache/*` so pre-existing unlocked-bootloader attestation keys are cleared.

## v1.6.2 (2026-10-28)
- **TrickyStoreOSS `all=2026-10-05` Format**: Formats `/data/adb/tricky_store/security_patch.txt` with required `key=value` syntax for TrickyStoreOSS.
- **PlayIntegrityFork v18/v19 Explicit `# System Properties` (commit `032a345` / `#617`)**: Writes explicit `ro.build.fingerprint`, `ro.build.id`, `ro.product.device`, `ro.product.name`, `ro.build.version.security_patch`, `ro.board.first_api_level=32`, and `ro.product.first_api_level=32` into `custom.pif.prop`.
- **Chained 3-Certificate RSA CA Hierarchy**: Spliced Root CA -> Intermediate CA -> Attestation CA hierarchy with `BasicConstraints(ca=True)` and `keyCertSign=True` before `</Keybox>`.
- **Target App Inclusions**: Added `gr.nikolasspyr.integritycheck` (Play Integrity API Checker) and `com.google.android.apps.walletnfcrel` (Google Wallet) to `target.txt`.

## v1.6.1 (2026-10-28)
- **Shell Integer Sanitization**: Fixed multiline `0\n0` integer parsing bug from `grep -ic || echo 0` in `diag_engine.sh` and `apply_fix.sh`.
- **Automatic Install-Time Splicing**: Executed `apply_fix.sh all` inside `customize.sh` and at boot via `service.sh`.

## v1.6.0 (2026-10-28)
- **Single-Key 5KB RKP Keybox Splicer**: Automatically concatenates companion `<Key algorithm="rsa">` before `</Keybox>` to satisfy TrickyStore's XML parser.
- **Global `resetprop -n` Canary Sync**: Overwrites host `ro.build.fingerprint` (expired `CP41.260831.016`) in kernel memory with active Canary print.

## v1.5.0 (2026-10-26)
- **X.509 NotAfter Expiry Extraction**: Extracts certificate validity timestamps from DER stream without OpenSSL to track RKP 14-day expiration windows.

## v1.4.0 (2026-10-26)
- **Fixed False-Positive CRL Substring Match**: Updated WebUI check from `.indexOf("revoked")` to `.indexOf("revoked_")`.
- **Live Canary Print Integration**: Added `autopif4.sh -s -m` support.

## v1.3.0 (2026-10-25)
- **Pure-BusyBox ASN.1 DER Certificate Parser**: Decodes certificate serials without `/system/bin/openssl`.
- **ReZygisk vs. APatch `package_config` Unblocker**: Detects and fixes GMS DenyList blocks.

## v1.0.0 (2026-10-25)
- Initial release.
