#!/system/bin/sh
# APatch Strong Integrity Boot Service (v1.6.1)
# Automatically splices RSA companion key into single-key RKP keyboxes and rewrites expired host ro.build.fingerprint (CP41.260831.016) at boot.

MODDIR=${0%/*}

if [ -x /data/adb/ap/bin/busybox ]; then
  export ASH_STANDALONE=1
fi

sh "$MODDIR/scripts/apply_fix.sh" all >/dev/null 2>&1
