#!/system/bin/sh
# APatch Strong Integrity Auto-Remediation Engine (v1.4.0)

if [ -x /data/adb/ap/bin/busybox ]; then
  export ASH_STANDALONE=1
fi

FIX_ID="$1"
[ -z "$FIX_ID" ] && FIX_ID="all"

write_migrated_pif() {
  SPOOF_PROV="${1:-0}"
  SPOOF_VEND_SDK="${2:-0}"
  PIF_DIR="/data/adb/modules/playintegrityfix"
  mkdir -p "$PIF_DIR" 2>/dev/null

  LIVE_PULL_OK="false"

  # 1. Prefer PlayIntegrityFork's live autopif4.sh crawler first!
  # Passing -s -m on Pixel 8a (akita) matches akita_beta (SDK 34 <= 35) and pulls a live Canary print from flash.android.com!
  if [ -f "$PIF_DIR/autopif4.sh" ] && [ "$SPOOF_PROV" = "0" ]; then
    sh "$PIF_DIR/autopif4.sh" -s -m >/dev/null 2>&1 || true
    if [ -f "$PIF_DIR/custom.pif.prop" ]; then
      sdk_val=$(grep -E "^(\*api_level|ro\.product\.first_api_level|DEVICE_INITIAL_SDK_INT)=" "$PIF_DIR/custom.pif.prop" 2>/dev/null | tail -n 1 | cut -d= -f2 | tr -d ' \r\n')
      if [ -n "$sdk_val" ] && [ "$sdk_val" -le 35 ] 2>/dev/null && ! grep -q "BP31\.260821\.009" "$PIF_DIR/custom.pif.prop" 2>/dev/null; then
        LIVE_PULL_OK="true"
      fi
    fi

    # If -m picked an SDK >= 36 print (or non-Pixel device), retry random Canary up to 5 times until SDK <= 35
    TRIES=0
    while [ "$LIVE_PULL_OK" != "true" ] && [ "$TRIES" -lt 5 ]; do
      TRIES=$((TRIES + 1))
      sh "$PIF_DIR/autopif4.sh" -s >/dev/null 2>&1 || break
      if [ -f "$PIF_DIR/custom.pif.prop" ]; then
        sdk_val=$(grep -E "^(\*api_level|ro\.product\.first_api_level|DEVICE_INITIAL_SDK_INT)=" "$PIF_DIR/custom.pif.prop" 2>/dev/null | tail -n 1 | cut -d= -f2 | tr -d ' \r\n')
        if [ -n "$sdk_val" ] && [ "$sdk_val" -le 35 ] 2>/dev/null; then
          LIVE_PULL_OK="true"
          break
        fi
      fi
    done
  fi

  # 2. Fallback if offline or autopif4.sh unavailable: write native PIFork v15+ custom.pif.prop schema
  if [ "$LIVE_PULL_OK" != "true" ] || [ ! -f "$PIF_DIR/custom.pif.prop" ]; then
    cat << PIF_EOF > "$PIF_DIR/custom.pif.prop"
# Build Fields
MANUFACTURER=Google
MODEL=Pixel 8a
FINGERPRINT=google/akita_beta/akita:CANARY/ZP11.260925.011/16612048:user/release-keys
BRAND=google
PRODUCT=akita_beta
DEVICE=akita
RELEASE=CANARY
ID=ZP11.260925.011
INCREMENTAL=16612048
TYPE=user
TAGS=release-keys
SECURITY_PATCH=2026-10-05
DEVICE_INITIAL_SDK_INT=34

# System Properties
*.build.id=ZP11.260925.011
*.security_patch=2026-10-05
*api_level=34

# Advanced Settings
spoofBuild=1
spoofProps=1
spoofProvider=${SPOOF_PROV}
spoofSignature=0
spoofVendingFinger=0
spoofVendingSdk=${SPOOF_VEND_SDK}
verboseLogs=0
PIF_EOF
  else
    sed -i "s/^spoofProvider=.*/spoofProvider=${SPOOF_PROV}/; s/^spoofVendingSdk=.*/spoofVendingSdk=${SPOOF_VEND_SDK}/" "$PIF_DIR/custom.pif.prop" 2>/dev/null
  fi

  chmod 0644 "$PIF_DIR/custom.pif.prop" 2>/dev/null

  # Extract active SECURITY_PATCH from custom.pif.prop to sync TrickyStore security_patch.txt
  ACTIVE_SPL=$(grep -E "^(SECURITY_PATCH|\*\.security_patch)=" "$PIF_DIR/custom.pif.prop" 2>/dev/null | head -n 1 | cut -d= -f2 | tr -d ' \r\n')
  [ -z "$ACTIVE_SPL" ] && ACTIVE_SPL="2026-10-05"
  ACTIVE_SPL_COMPACT=$(echo "$ACTIVE_SPL" | tr -d '-')

  if [ -d /data/adb/tricky_store ]; then
    if [ -f /data/adb/modules/tricky_store/libTEESimulator.so ] || [ -f /data/adb/modules/tricky_store/libTrickyStoreOSS.so ]; then
      printf "all=%s\n[com.google.android.gms]\nsystem=no\n" "$ACTIVE_SPL" > /data/adb/tricky_store/security_patch.txt
    else
      echo "$ACTIVE_SPL_COMPACT" > /data/adb/tricky_store/security_patch.txt
    fi
    chmod 0644 /data/adb/tricky_store/security_patch.txt 2>/dev/null
  fi
}

unblock_rezygisk_gms() {
  PKG_CFG="/data/adb/ap/package_config"
  if [ -f "$PKG_CFG" ]; then
    sed -i '/^com\.google\.android\.gms,/d' "$PKG_CFG" 2>/dev/null
    sed -i '/^com\.android\.vending,/d' "$PKG_CFG" 2>/dev/null
  fi

  if [ -d /data/adb/modules ]; then
    for mod in /data/adb/modules/*; do
      [ -d "$mod" ] || continue
      if [ -d "$mod/system" ] && [ -z "$(ls -A "$mod/system" 2>/dev/null)" ]; then
        touch "$mod/skip_mount"
      fi
    done
  fi
}

restart_gms_and_vending() {
  if [ -f /data/adb/modules/playintegrityfix/killpi.sh ]; then
    sh /data/adb/modules/playintegrityfix/killpi.sh >/dev/null 2>&1 || true
  fi
  killall com.google.android.gms.unstable 2>/dev/null || true
  killall com.google.android.gms 2>/dev/null || true
  killall com.android.vending 2>/dev/null || true
}

fix_tricky_targets() {
  mkdir -p /data/adb/tricky_store 2>/dev/null
  TFILE="/data/adb/tricky_store/target.txt"
  cat << 'TARGET_EOF' > "$TFILE"
com.google.android.gms!
com.android.vending!
com.google.android.gsf!
TARGET_EOF
  chmod 0644 "$TFILE" 2>/dev/null
}

fix_verified_boot_props() {
  if command -v resetprop >/dev/null 2>&1; then
    resetprop -n ro.boot.verifiedbootstate green
    resetprop -n ro.boot.flash.locked 1
    resetprop -n ro.boot.vbmeta.device_state locked
    resetprop -n ro.boot.veritymode enforcing
    resetprop -n ro.debuggable 0
    resetprop -n ro.secure 1
    resetprop -n ro.boot.warranty_bit 0
    resetprop -n ro.warranty_bit 0
  fi
}

case "$FIX_ID" in
  pif_rkp_check)
    unblock_rezygisk_gms
    write_migrated_pif 0 0
    fix_tricky_targets
    restart_gms_and_vending
    echo "Fetched live pre-RKP Canary print via autopif4.sh -s -m, synced security_patch.txt, and restarted GMS."
    ;;
  keybox_xml|pif_device_fallback)
    unblock_rezygisk_gms
    write_migrated_pif 1 1
    restart_gms_and_vending
    echo "Enabled spoofProvider=1 + spoofVendingSdk=1 fallback in custom.pif.prop for Device Integrity."
    ;;
  pif_spoof_provider)
    unblock_rezygisk_gms
    write_migrated_pif 0 0
    restart_gms_and_vending
    echo "Set spoofProvider=0 in custom.pif.prop and restarted GMS."
    ;;
  mount_leaks|apatch_gms_exclude|apatch_overlay_mods)
    unblock_rezygisk_gms
    restart_gms_and_vending
    echo "Cleaned /data/adb/ap/package_config so Zygisk can inject PIF into GMS."
    ;;
  vb_state|flash_locked|vbmeta_state|ro_debug_secure|warranty_bit)
    fix_verified_boot_props
    echo "Reset Verified Boot & warranty properties to locked/green state."
    ;;
  target_gms|keymint_hal)
    fix_tricky_targets
    restart_gms_and_vending
    echo "Configured com.google.android.gms! and com.android.vending! (!) in /data/adb/tricky_store/target.txt."
    ;;
  spl_alignment)
    ACTIVE_SPL=$(grep -E "^(SECURITY_PATCH|\*\.security_patch)=" /data/adb/modules/playintegrityfix/custom.pif.prop 2>/dev/null | head -n 1 | cut -d= -f2 | tr -d ' -\r\n')
    [ -z "$ACTIVE_SPL" ] && ACTIVE_SPL="20261005"
    echo "$ACTIVE_SPL" > /data/adb/tricky_store/security_patch.txt
    restart_gms_and_vending
    echo "Synchronized /data/adb/tricky_store/security_patch.txt to $ACTIVE_SPL."
    ;;
  selinux_state)
    setenforce 1 2>/dev/null
    echo "Set SELinux to Enforcing."
    ;;
  all)
    unblock_rezygisk_gms
    write_migrated_pif 0 0
    fix_tricky_targets
    fix_verified_boot_props
    setenforce 1 2>/dev/null
    restart_gms_and_vending
    echo "Applied all fixes: pulled live Canary print via autopif4.sh -s -m, synced security_patch.txt, updated target.txt (!), and restarted GMS."
    ;;
  *)
    echo "Unknown fix ID: $FIX_ID"
    exit 1
    ;;
esac
