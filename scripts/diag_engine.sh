#!/system/bin/sh
# APatch Strong Integrity Diagnostic Engine v1.6.3 (Read-Only Auditor)

MODDIR=${0%/*}/..
MODE="text"
[ "$1" = "--json" ] && MODE="json"

if [ -x /data/adb/ap/bin/busybox ]; then
  export ASH_STANDALONE=1
  BB="/data/adb/ap/bin/busybox"
else
  BB="busybox"
fi

get_prop() {
  val=$(getprop "$1" 2>/dev/null | tr -d '\r\n')
  echo "$val"
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/ /g' | tr -d '\r\n'
}

parse_pif_val() {
  key="$1"
  file="$2"
  [ -f "$file" ] || return 1
  case "$file" in
    *.prop)
      grep -E "^[[:space:]]*${key}=" "$file" 2>/dev/null | tail -n 1 | cut -d= -f2- | cut -d'#' -f1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr -d '\r\n'
      ;;
    *.json)
      grep -E "\"${key}\"[[:space:]]*:" "$file" 2>/dev/null | tail -n 1 | sed -E 's/.*"'"${key}"'"[[:space:]]*:[[:space:]]*//; s/[",[:space:]]*$//; s/^"//' | tr -d '\r\n'
      ;;
  esac
}

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")
TODAY_YMD=$(date -u +"%Y%m%d" 2>/dev/null || echo "20261028")
DEVICE_MODEL=$(get_prop ro.product.model)
DEVICE_BRAND=$(get_prop ro.product.brand)
HOST_DEVICE=$(get_prop ro.product.device)
HOST_FIRST_API=$(get_prop ro.product.first_api_level)
HOST_BOARD_API=$(get_prop ro.board.first_api_level)
ANDROID_VER=$(get_prop ro.build.version.release)
SDK_INT=$(get_prop ro.build.version.sdk)
KERNEL_REL=$(uname -r 2>/dev/null)

# 1. APatch Environment & ReZygisk package_config Conflict Check
APATCH_APD="missing"
[ -x /data/adb/apd ] && APATCH_APD=$(/data/adb/apd -V 2>/dev/null | head -n 1 | tr -d '\r\n')
[ -z "$APATCH_APD" ] && [ -e /data/adb/apd ] && APATCH_APD="present"

APATCH_BB="missing"
[ -x /data/adb/ap/bin/busybox ] && APATCH_BB="present"

ZYGISK_PROVIDER="none"
Z_COUNT=0
for zmod in rezygisk zygisksu neozygisk; do
  if [ -d "/data/adb/modules/$zmod" ] && [ ! -f "/data/adb/modules/$zmod/disable" ] && [ ! -f "/data/adb/modules/$zmod/remove" ]; then
    zver=$(grep '^version=' "/data/adb/modules/$zmod/module.prop" 2>/dev/null | cut -d= -f2 | tr -d '\r\n')
    zlabel="$zmod"
    [ -n "$zver" ] && zlabel="${zmod}(${zver})"
    if [ "$ZYGISK_PROVIDER" = "none" ]; then
      ZYGISK_PROVIDER="$zlabel"
    else
      ZYGISK_PROVIDER="${ZYGISK_PROVIDER}+${zlabel}_COLLISION"
    fi
    Z_COUNT=$((Z_COUNT + 1))
  fi
done

ROOT_HIDER="none"
for hmod in treat_wheel nohello shamiko zygisk_assistant; do
  if [ -d "/data/adb/modules/$hmod" ] && [ ! -f "/data/adb/modules/$hmod/disable" ]; then
    ROOT_HIDER="$hmod"
    break
  fi
done

GMS_EXCLUDED="not_listed"
if [ -f /data/adb/ap/package_config ]; then
  if grep -Eq "^com\.google\.android\.gms,1," /data/adb/ap/package_config 2>/dev/null; then
    if [ "$ZYGISK_PROVIDER" != "none" ] && [ "$ROOT_HIDER" = "none" ]; then
      GMS_EXCLUDED="denylist_blocks_zygisk_pif"
    else
      GMS_EXCLUDED="configured_with_hider"
    fi
  fi
fi

ACTIVE_OVERLAY_MODULES=0
OVERLAY_MOD_LIST=""
if [ -d /data/adb/modules ]; then
  for mod in /data/adb/modules/*; do
    [ -d "$mod" ] || continue
    [ -f "$mod/disable" ] && continue
    [ -f "$mod/remove" ] && continue
    if [ -d "$mod/system" ] && [ ! -f "$mod/skip_mount" ]; then
      ACTIVE_OVERLAY_MODULES=$((ACTIVE_OVERLAY_MODULES + 1))
      modname=$(basename "$mod")
      OVERLAY_MOD_LIST="${OVERLAY_MOD_LIST}${modname} "
    fi
  done
fi

# 2. Verified Boot & Bootloader State
VB_STATE=$(get_prop ro.boot.verifiedbootstate)
FLASH_LOCKED=$(get_prop ro.boot.flash.locked)
VBMETA_STATE=$(get_prop ro.boot.vbmeta.device_state)
VERITY_MODE=$(get_prop ro.boot.veritymode)
WARRANTY_BIT=$(get_prop ro.boot.warranty_bit)
[ -z "$WARRANTY_BIT" ] && WARRANTY_BIT=$(get_prop ro.warranty_bit)
RO_DEBUGGABLE=$(get_prop ro.debuggable)
RO_SECURE=$(get_prop ro.secure)

# 3. Build Fingerprint & Security Patch Consistency
BUILD_TAGS=$(get_prop ro.build.tags)
BUILD_TYPE=$(get_prop ro.build.type)
BUILD_FP=$(get_prop ro.build.fingerprint)
SYS_SPL=$(get_prop ro.build.version.security_patch)
VENDOR_SPL=$(get_prop ro.vendor.build.security_patch)
BOOT_SPL=$(get_prop ro.bootimage.build.security_patch)

# 4. PlayIntegrityFix / PlayIntegrityFork (.prop & .json) Deep Inspection
PIF_INSTALLED="false"
PIF_VERSION="none"
if [ -f /data/adb/modules/playintegrityfix/module.prop ]; then
  PIF_NAME=$(grep '^name=' /data/adb/modules/playintegrityfix/module.prop 2>/dev/null | cut -d= -f2 | tr -d '\r\n')
  PIF_VER=$(grep '^version=' /data/adb/modules/playintegrityfix/module.prop 2>/dev/null | cut -d= -f2 | tr -d '\r\n')
  PIF_VERSION="${PIF_NAME} ${PIF_VER}"
fi

PIF_PATH=""
for ppath in \
  /data/adb/modules/playintegrityfix/custom.pif.prop \
  /data/adb/modules/playintegrityfix/custom.pif.json \
  /data/adb/modules/playintegrityfix/pif.prop \
  /data/adb/modules/playintegrityfix/pif.json \
  /data/adb/pif.prop \
  /data/adb/pif.json; do
  if [ -f "$ppath" ]; then
    PIF_INSTALLED="true"
    PIF_PATH="$ppath"
    break
  fi
done

PIF_FINGERPRINT=""
PIF_DEVICE=""
PIF_MODEL=""
PIF_SPL=""
PIF_INITIAL_SDK=""
PIF_SPOOF_PROVIDER="not_set"
PIF_SPOOF_PROPS="not_set"
PIF_SPOOF_VENDING_SDK="not_set"
PIF_SPOOF_VENDING_FINGER="0"
PIF_RKP_CONFLICT="none"

if [ -n "$PIF_PATH" ] && [ -f "$PIF_PATH" ]; then
  PIF_FINGERPRINT=$(parse_pif_val "FINGERPRINT" "$PIF_PATH")
  [ -z "$PIF_FINGERPRINT" ] && PIF_FINGERPRINT=$(parse_pif_val "ro.build.fingerprint" "$PIF_PATH")
  PIF_DEVICE=$(parse_pif_val "DEVICE" "$PIF_PATH")
  [ -z "$PIF_DEVICE" ] && PIF_DEVICE=$(parse_pif_val "ro.product.device" "$PIF_PATH")
  PIF_MODEL=$(parse_pif_val "MODEL" "$PIF_PATH")
  [ -z "$PIF_MODEL" ] && PIF_MODEL=$(parse_pif_val "ro.product.model" "$PIF_PATH")
  PIF_SPL=$(parse_pif_val "SECURITY_PATCH" "$PIF_PATH")
  [ -z "$PIF_SPL" ] && PIF_SPL=$(parse_pif_val "ro.build.version.security_patch" "$PIF_PATH")
  [ -z "$PIF_SPL" ] && PIF_SPL=$(parse_pif_val "\*\.security_patch" "$PIF_PATH")
  PIF_INITIAL_SDK=$(parse_pif_val "ro.product.first_api_level" "$PIF_PATH")
  [ -z "$PIF_INITIAL_SDK" ] && PIF_INITIAL_SDK=$(parse_pif_val "\*api_level" "$PIF_PATH")
  [ -z "$PIF_INITIAL_SDK" ] && PIF_INITIAL_SDK=$(parse_pif_val "DEVICE_INITIAL_SDK_INT" "$PIF_PATH")

  raw_sp=$(parse_pif_val "spoofProvider" "$PIF_PATH")
  case "$raw_sp" in
    1|true|TRUE) PIF_SPOOF_PROVIDER="true" ;;
    0|false|FALSE) PIF_SPOOF_PROVIDER="false" ;;
  esac

  raw_pr=$(parse_pif_val "spoofProps" "$PIF_PATH")
  case "$raw_pr" in
    1|true|TRUE) PIF_SPOOF_PROPS="true" ;;
    0|false|FALSE) PIF_SPOOF_PROPS="false" ;;
  esac

  raw_vs=$(parse_pif_val "spoofVendingSdk" "$PIF_PATH")
  [ -n "$raw_vs" ] && PIF_SPOOF_VENDING_SDK="$raw_vs"

  raw_vf=$(parse_pif_val "spoofVendingFinger" "$PIF_PATH")
  [ -n "$raw_vf" ] && PIF_SPOOF_VENDING_FINGER="$raw_vf"

  # 4A. Check PlayIntegrityFork v18/v19 (commit 032a345 / #617) explicit System Properties requirement!
  case "$PIF_PATH" in
    *custom.pif.prop)
      if ! grep -Eq "^ro\.product\.first_api_level=" "$PIF_PATH" 2>/dev/null || ! grep -Eq "^ro\.board\.first_api_level=" "$PIF_PATH" 2>/dev/null; then
        PIF_RKP_CONFLICT="missing_v19_explicit_sys_props (missing ro.board.first_api_level / ro.product.first_api_level)"
      fi
      ;;
  esac

  # 4B. Detect expired Canary builds (>6 weeks old)
  if echo "$PIF_FINGERPRINT" | grep -Eq "ZP11\.260[1-8]|BP31\.260821\.009"; then
    PIF_RKP_CONFLICT="expired_canary_print (${PIF_FINGERPRINT##*/})"
  fi

  # 4C. Detect if host ro.product.device or ro.board.first_api_level mismatches PIF_DEVICE (split-brain identity!)
  if echo "$BUILD_FP" | grep -Eq ":(16|17)/[BC]P[1-4]1\.260[1-9]"; then
    PIF_RKP_CONFLICT="host_ro_build_fingerprint_still_expired_CP41"
  elif [ -n "$PIF_DEVICE" ] && [ "$HOST_DEVICE" != "$PIF_DEVICE" ]; then
    PIF_RKP_CONFLICT="split_brain_identity (host ro.product.device=${HOST_DEVICE} != pif=${PIF_DEVICE}; tap Fix for Me)"
  elif [ -n "$HOST_BOARD_API" ] && [ "$HOST_BOARD_API" -gt 32 ] 2>/dev/null; then
    PIF_RKP_CONFLICT="board_first_api_level_gt_32 (ro.board.first_api_level=${HOST_BOARD_API} > 32; tap Fix for Me)"
  fi
fi

# 5. Hardware KeyMint / TEE Stack & Pure-BusyBox ASN.1 DER Keybox Audit
KEYMINT_SVC=$(getprop 2>/dev/null | grep -E "init\.svc\..*(keymint|keymaster)" | tr '\n' ';' | sed 's/;$//')
STRONGBOX_SVC=$(getprop 2>/dev/null | grep -E "init\.svc\..*strongbox" | tr '\n' ';' | sed 's/;$//')

TS_DIR="/data/adb/tricky_store"
[ ! -d "$TS_DIR" ] && [ -d "/data/adb/teesim" ] && TS_DIR="/data/adb/teesim"

TS_INSTALLED="false"
TS_VERSION="none"
if [ -d "/data/adb/tricky_store" ] || [ -d "/data/adb/modules/tricky_store" ] || [ -d "/data/adb/teesim" ] || [ -d "/data/adb/modules/teesimulator" ]; then
  TS_INSTALLED="true"
  for tsmp in /data/adb/modules/tricky_store/module.prop /data/adb/modules/teesimulator/module.prop; do
    if [ -f "$tsmp" ]; then
      tsn=$(grep '^name=' "$tsmp" 2>/dev/null | cut -d= -f2 | tr -d '\r\n')
      tsv=$(grep '^version=' "$tsmp" 2>/dev/null | cut -d= -f2 | tr -d '\r\n')
      TS_VERSION="${tsn} ${tsv}"
      break
    fi
  done
fi

TEE_BROKEN_STATUS="unknown"
if [ -f "/data/adb/tricky_store/tee_status" ]; then
  TEE_BROKEN_STATUS=$(tr '\n' ' ' < /data/adb/tricky_store/tee_status 2>/dev/null | sed 's/ $//')
fi

# Accurately check if keystore2 has TrickyStore/TEESimulator injected (WITHOUT matching /memfd:jit-cache false positives!)
TS_DAEMON="stopped"
KS2_PID=$(pidof keystore2 2>/dev/null | awk '{print $1}')
if [ -n "$KS2_PID" ] && grep -Eiq "tricky|teesim|lsplt" "/proc/$KS2_PID/maps" 2>/dev/null; then
  TS_DAEMON="injected_keystore2 (${TS_VERSION}, ${TEE_BROKEN_STATUS})"
elif pidof tricky_store >/dev/null 2>&1 || ps -ef 2>/dev/null | grep -Eiq "[t]ricky_store|[t]eesim|tricky_store/service"; then
  TS_DAEMON="running_daemon_only (${TS_VERSION}, ${TEE_BROKEN_STATUS})"
elif [ -d "/data/adb/modules/tricky_store" ] && [ ! -f "/data/adb/modules/tricky_store/disable" ]; then
  TS_DAEMON="not_injected_in_keystore2 (${TS_VERSION}, ${TEE_BROKEN_STATUS})"
fi

TS_LOGCAT=$(logcat -d -t 500 2>/dev/null | grep -Ei "TrickyStore|KeyBox|CertHack|PIF|PlayIntegrityFork" | tail -n 4 | tr '\n' ' | ' | sed 's/ | $//')
[ -z "$TS_LOGCAT" ] && TS_LOGCAT="no_recent_log_entries"

KEYBOX_FILE=""
for kbpath in /data/adb/tricky_store/keybox.xml /data/adb/teesim/keybox.xml /data/misc/keystore/omk/keybox.xml; do
  if [ -f "$kbpath" ]; then
    KEYBOX_FILE="$kbpath"
    break
  fi
done

KEYBOX_STATUS="missing"
KEYBOX_CERTS=0
KEYBOX_ALGOS=""
KEYBOX_SERIALS=""
KEYBOX_CRL_STATUS="not_checked"
KEYBOX_SHA256="none"
MIN_CERT_EXPIRY_YMD="99991231"
MIN_CERT_EXPIRY_FMT="unknown"

if [ -n "$KEYBOX_FILE" ] && [ -f "$KEYBOX_FILE" ]; then
  if [ -s "$KEYBOX_FILE" ]; then
    KEYBOX_SHA256=$(sha256sum "$KEYBOX_FILE" 2>/dev/null | cut -c1-12)
    KEYBOX_CERTS=$(grep -ic "<Certificate[[:space:]>]" "$KEYBOX_FILE" 2>/dev/null | head -n 1 | tr -cd '0-9')
    [ -z "$KEYBOX_CERTS" ] && KEYBOX_CERTS=0
    HAS_ECDSA=$(grep -ic "<Key[^>]*ecdsa" "$KEYBOX_FILE" 2>/dev/null | head -n 1 | tr -cd '0-9')
    [ -z "$HAS_ECDSA" ] && HAS_ECDSA=0
    HAS_RSA=$(grep -ic "<Key[^>]*rsa" "$KEYBOX_FILE" 2>/dev/null | head -n 1 | tr -cd '0-9')
    [ -z "$HAS_RSA" ] && HAS_RSA=0
    KEYBOX_ALGOS="ecdsa:${HAS_ECDSA},rsa:${HAS_RSA}"

    TMP_CERT_DIR="/data/local/tmp/apatch_kb_certs_$$"
    mkdir -p "$TMP_CERT_DIR" 2>/dev/null
    awk '
      /<Certificate[ \t>]/ { in_cert=1; idx++; file=sprintf("'"$TMP_CERT_DIR"'/c_%d.b64", idx) }
      in_cert {
        line=$0
        gsub(/<[^>]*>/, "", line)
        gsub(/-----BEGIN CERTIFICATE-----/, "", line)
        gsub(/-----END CERTIFICATE-----/, "", line)
        gsub(/[ \t\r\n]/, "", line)
        if (length(line) > 0) printf "%s", line >> file
      }
      /<\/Certificate>/ {
        if (in_cert) { close(file); in_cert=0 }
      }
    ' "$KEYBOX_FILE" 2>/dev/null

    IS_AOSP_SW="false"
    HAS_UNCHAINED_RSA="false"
    if grep -qi "OEM Hardware RSA Leaf" "$KEYBOX_FILE" 2>/dev/null; then
      HAS_UNCHAINED_RSA="true"
    fi

    for bfile in "$TMP_CERT_DIR"/c_*.b64; do
      [ -f "$bfile" ] || continue
      asc=$(base64 -d < "$bfile" 2>/dev/null | tr -cd '\11\12\15\40-\176')
      if echo "$asc" | grep -Eiq "Software Attestation|Android Keystore Software|aosp-test|Google Software Attestation"; then
        IS_AOSP_SW="true"
      fi

      exp_info=$(printf '%s' "$asc" | grep -Eo '[0-9]{12,14}Z' 2>/dev/null | awk '
        NR == 2 {
          s = $0
          sub(/Z$/, "", s)
          if (length(s) == 12) {
            yy = substr(s, 1, 2)
            mm = substr(s, 3, 2)
            dd = substr(s, 5, 2)
            yyyy = (yy + 0 < 50) ? ("20" yy) : ("19" yy)
          } else {
            yyyy = substr(s, 1, 4)
            mm = substr(s, 5, 2)
            dd = substr(s, 7, 2)
          }
          printf "%s%s%s|%s-%s-%s", yyyy, mm, dd, yyyy, mm, dd
        }')
      if [ -n "$exp_info" ]; then
        exp_ymd=$(echo "$exp_info" | cut -d'|' -f1)
        exp_fmt=$(echo "$exp_info" | cut -d'|' -f2)
        if [ -n "$exp_ymd" ] && [ "$exp_ymd" -lt "$MIN_CERT_EXPIRY_YMD" ] 2>/dev/null; then
          MIN_CERT_EXPIRY_YMD="$exp_ymd"
          MIN_CERT_EXPIRY_FMT="$exp_fmt"
        fi
      fi

      hex=$(base64 -d < "$bfile" 2>/dev/null | od -An -tx1 | tr -d ' \t\r\n')
      ser=$(printf '%s' "$hex" | awk '
      {
        idx = index($0, "a00302010202")
        if (idx > 0) {
          len_hex = substr($0, idx + 12, 2)
          h1 = index("0123456789abcdef", substr(len_hex, 1, 1)) - 1
          h2 = index("0123456789abcdef", substr(len_hex, 2, 1)) - 1
          blen = h1 * 16 + h2
          raw_ser = substr($0, idx + 14, blen * 2)
          sub(/^0+/, "", raw_ser)
          if (raw_ser == "") raw_ser = "0"
          print raw_ser
        }
      }')
      if [ -n "$ser" ]; then
        case "$ser" in
          7f000101|7f000102|7f000103) ;;
          *)
            case ",$KEYBOX_SERIALS," in
              *,"$ser",*) ;;
              *) KEYBOX_SERIALS="${KEYBOX_SERIALS}${ser}," ;;
            esac
            ;;
        esac
      fi
    done
    rm -rf "$TMP_CERT_DIR" 2>/dev/null
    KEYBOX_SERIALS=$(echo "$KEYBOX_SERIALS" | sed 's/,$//')

    if [ "$IS_AOSP_SW" = "true" ] || grep -Eiq "aosp-test|Software Attestation|MIIEpAIBAAKCAQEA3" "$KEYBOX_FILE" 2>/dev/null; then
      KEYBOX_STATUS="aosp_software_keybox"
      KEYBOX_CRL_STATUS="aosp_software_root"
    elif [ "$HAS_UNCHAINED_RSA" = "true" ]; then
      KEYBOX_STATUS="unchained_rsa_companion_needs_v162_resplice"
      KEYBOX_CRL_STATUS="tap_fix_for_me_to_resplice_chained_rsa_ca (valid_until_${MIN_CERT_EXPIRY_FMT})"
    elif [ "$MIN_CERT_EXPIRY_YMD" != "99991231" ] && [ "$MIN_CERT_EXPIRY_YMD" -lt "$TODAY_YMD" ] 2>/dev/null; then
      KEYBOX_STATUS="expired_rkp_certificate (expired ${MIN_CERT_EXPIRY_FMT})"
      KEYBOX_CRL_STATUS="expired_not_after_${MIN_CERT_EXPIRY_FMT}"
    elif [ "$KEYBOX_CERTS" -ge 3 ] && [ "$HAS_ECDSA" -ge 1 ] && [ "$HAS_RSA" -eq 0 ] 2>/dev/null; then
      KEYBOX_STATUS="rkp_ecdsa_only_missing_rsa_key"
      KEYBOX_CRL_STATUS="clean_unrevoked_needs_rsa_splice (valid_until_${MIN_CERT_EXPIRY_FMT})"
    elif [ "$KEYBOX_CERTS" -ge 3 ] && [ "$HAS_ECDSA" -ge 1 ] && [ "$HAS_RSA" -ge 1 ] 2>/dev/null; then
      KEYBOX_STATUS="present_valid_structure"
    else
      KEYBOX_STATUS="present_incomplete_chain"
    fi

    if [ -n "$KEYBOX_SERIALS" ] && [ "$KEYBOX_STATUS" = "present_valid_structure" ]; then
      CRL_CACHE="/data/local/tmp/apatch_google_crl.json"
      if [ ! -s "$CRL_CACHE" ]; then
        if command -v curl >/dev/null 2>&1; then
          curl -sL --max-time 6 "https://android.googleapis.com/attestation/status" -o "$CRL_CACHE" 2>/dev/null
        elif [ -x /data/adb/ap/bin/busybox ]; then
          /data/adb/ap/bin/busybox wget -q -T 6 --no-check-certificate -O "$CRL_CACHE" "https://android.googleapis.com/attestation/status" 2>/dev/null
        elif command -v wget >/dev/null 2>&1; then
          wget -q -T 6 --no-check-certificate -O "$CRL_CACHE" "https://android.googleapis.com/attestation/status" 2>/dev/null
        fi
      fi
      if [ -s "$CRL_CACHE" ]; then
        if [ "$MIN_CERT_EXPIRY_FMT" != "unknown" ]; then
          KEYBOX_CRL_STATUS="clean_unrevoked (valid_until_${MIN_CERT_EXPIRY_FMT})"
        else
          KEYBOX_CRL_STATUS="clean_unrevoked"
        fi
        OLD_IFS="$IFS"
        IFS=","
        for s in $KEYBOX_SERIALS; do
          [ -z "$s" ] && continue
          [ "$s" = "f92009e853b6b045" ] && continue
          [ "$s" = "84a9d0297b0eb58ae7ff0e80de760605" ] && continue
          [ "$s" = "1" ] && continue
          if grep -iq "\"$s\"" "$CRL_CACHE" 2>/dev/null; then
            KEYBOX_CRL_STATUS="revoked_serial_${s}"
            KEYBOX_STATUS="revoked_on_google_crl"
            break
          fi
        done
        IFS="$OLD_IFS"
      else
        KEYBOX_CRL_STATUS="crl_unreachable (valid_until_${MIN_CERT_EXPIRY_FMT})"
      fi
    fi
  else
    KEYBOX_STATUS="empty_file"
  fi
fi

TS_TARGET_GMS="missing"
TS_TARGET_VENDING="missing"
TS_TARGET_MODE="standard"
if [ -f "$TS_DIR/target.txt" ]; then
  if grep -q "^com\.google\.android\.gms!" "$TS_DIR/target.txt" 2>/dev/null; then
    TS_TARGET_GMS="present"
    TS_TARGET_MODE="generate_cert_exclamation"
  elif grep -q "^com\.google\.android\.gms?" "$TS_DIR/target.txt" 2>/dev/null; then
    TS_TARGET_GMS="present"
    TS_TARGET_MODE="leaf_hack_question"
  elif grep -q "^com\.google\.android\.gms" "$TS_DIR/target.txt" 2>/dev/null; then
    TS_TARGET_GMS="present"
    TS_TARGET_MODE="auto"
  fi
  if grep -q "^com\.android\.vending" "$TS_DIR/target.txt" 2>/dev/null; then
    TS_TARGET_VENDING="present"
  fi
elif [ -f "/data/adb/teesim/config.json" ]; then
  if grep -q "com.google.android.gms" "/data/adb/teesim/config.json" 2>/dev/null; then
    TS_TARGET_GMS="present"
    TS_TARGET_VENDING="present"
    TS_TARGET_MODE="teesim_json"
  fi
fi

TS_SPL_OVERRIDE="none"
if [ -f "$TS_DIR/security_patch.txt" ]; then
  TS_SPL_OVERRIDE=$(grep -v '^#' "$TS_DIR/security_patch.txt" 2>/dev/null | tr '\n' ' ' | sed 's/ $//')
  [ -z "$TS_SPL_OVERRIDE" ] && TS_SPL_OVERRIDE="empty_file"
fi

SPL_MISMATCH="false"
PIF_SPL_DIGITS=$(echo "$PIF_SPL" | tr -cd '0-9')
TS_SPL_DIGITS=$(echo "$TS_SPL_OVERRIDE" | grep -Eo '[0-9]{4}-?[0-9]{2}-?[0-9]{2}' | head -n 1 | tr -cd '0-9')
if [ -n "$PIF_SPL_DIGITS" ] && [ -n "$TS_SPL_DIGITS" ] && [ "$PIF_SPL_DIGITS" != "$TS_SPL_DIGITS" ]; then
  SPL_MISMATCH="true"
fi
if echo "$TS_VERSION" | grep -Eiq "OSS" && ! echo "$TS_SPL_OVERRIDE" | grep -Eq "(all|system)="; then
  SPL_MISMATCH="true"
  TS_SPL_OVERRIDE="${TS_SPL_OVERRIDE}_missing_key_value_for_TS_OSS"
fi

# 6. SELinux, Mount Leaks & Kernel Hygiene
SELINUX_STATE=$(getenforce 2>/dev/null | tr -d '\r\n')
[ -z "$SELINUX_STATE" ] && SELINUX_STATE="unknown"

MOUNT_LEAKS=0
OVERLAY_LEAKS="$ACTIVE_OVERLAY_MODULES"

KERNEL_FLAGGED="clean"
echo "$KERNEL_REL" | grep -Eiq "(dirty|lineage|kali|nethunter|arter97|elementalx)" && KERNEL_FLAGGED="flagged_keyword"

ADB_STATE=$(get_prop init.svc.adbd)

SCORE=100
CRITICAL_COUNT=0
WARN_COUNT=0

if [ "$GMS_EXCLUDED" = "denylist_blocks_zygisk_pif" ]; then
  SCORE=$((SCORE - 30))
  CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
fi

if [ "$VB_STATE" != "green" ] || [ "$FLASH_LOCKED" != "1" ] || [ "$VBMETA_STATE" != "locked" ]; then
  SCORE=$((SCORE - 25))
  CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
fi

if [ "$BUILD_TAGS" != "release-keys" ] || [ "$BUILD_TYPE" != "user" ] || [ "$RO_DEBUGGABLE" = "1" ]; then
  SCORE=$((SCORE - 15))
  CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
fi

if [ "$KEYBOX_STATUS" != "present_valid_structure" ]; then
  SCORE=$((SCORE - 35))
  CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
fi

if [ "$PIF_RKP_CONFLICT" != "none" ]; then
  SCORE=$((SCORE - 30))
  CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
fi

if [ "$SPL_MISMATCH" = "true" ]; then
  SCORE=$((SCORE - 25))
  CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
fi

case "$TS_DAEMON" in
  stopped*|not_injected*)
    SCORE=$((SCORE - 25))
    CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
    ;;
esac

if [ "$TS_TARGET_GMS" != "present" ]; then
  SCORE=$((SCORE - 15))
  CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
fi

if [ "$PIF_SPOOF_PROVIDER" = "true" ] && [ "$TS_INSTALLED" = "true" ] && [ "$KEYBOX_STATUS" = "present_valid_structure" ]; then
  SCORE=$((SCORE - 20))
  CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
fi

if [ "$SELINUX_STATE" != "Enforcing" ]; then
  SCORE=$((SCORE - 25))
  CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
fi

if [ "${OVERLAY_LEAKS:-0}" -gt 0 ]; then
  SCORE=$((SCORE - 10))
  WARN_COUNT=$((WARN_COUNT + 1))
fi

[ "$SCORE" -lt 0 ] && SCORE=0

PREDICTED_VERDICT="MEETS_STRONG_INTEGRITY"
if [ "$CRITICAL_COUNT" -gt 0 ]; then
  if [ "$SELINUX_STATE" != "Enforcing" ] || [ "$BUILD_TAGS" != "release-keys" ]; then
    PREDICTED_VERDICT="FAILS_BASIC_INTEGRITY"
  elif [ "$GMS_EXCLUDED" = "denylist_blocks_zygisk_pif" ] || [ "$PIF_RKP_CONFLICT" != "none" ] || [ "$SPL_MISMATCH" = "true" ] || [ "$KEYBOX_STATUS" != "present_valid_structure" ]; then
    PREDICTED_VERDICT="CAPS_AT_BASIC_INTEGRITY"
  else
    PREDICTED_VERDICT="FAILS_STRONG_INTEGRITY"
  fi
fi

if [ "$MODE" = "json" ]; then
  cat <<JSON_EOF
{
  "timestamp": "$(json_escape "$TIMESTAMP")",
  "device": {
    "model": "$(json_escape "$DEVICE_MODEL")",
    "brand": "$(json_escape "$DEVICE_BRAND")",
    "host_device": "$(json_escape "$HOST_DEVICE")",
    "host_first_api_level": "$(json_escape "$HOST_FIRST_API")",
    "host_board_api_level": "$(json_escape "$HOST_BOARD_API")",
    "android_version": "$(json_escape "$ANDROID_VER")",
    "sdk_int": "$(json_escape "$SDK_INT")",
    "kernel": "$(json_escape "$KERNEL_REL")"
  },
  "summary": {
    "score": $SCORE,
    "critical_issues": $CRITICAL_COUNT,
    "warnings": $WARN_COUNT,
    "predicted_verdict": "$(json_escape "$PREDICTED_VERDICT")"
  },
  "apatch": {
    "apd_version": "$(json_escape "$APATCH_APD")",
    "busybox": "$(json_escape "$APATCH_BB")",
    "gms_package_config": "$(json_escape "$GMS_EXCLUDED")",
    "root_hider": "$(json_escape "$ROOT_HIDER")",
    "active_overlay_modules": $ACTIVE_OVERLAY_MODULES,
    "overlay_module_names": "$(json_escape "$OVERLAY_MOD_LIST")"
  },
  "verified_boot": {
    "verifiedbootstate": "$(json_escape "$VB_STATE")",
    "flash_locked": "$(json_escape "$FLASH_LOCKED")",
    "vbmeta_device_state": "$(json_escape "$VBMETA_STATE")",
    "veritymode": "$(json_escape "$VERITY_MODE")",
    "warranty_bit": "$(json_escape "$WARRANTY_BIT")",
    "ro_debuggable": "$(json_escape "$RO_DEBUGGABLE")",
    "ro_secure": "$(json_escape "$RO_SECURE")"
  },
  "build_props": {
    "tags": "$(json_escape "$BUILD_TAGS")",
    "type": "$(json_escape "$BUILD_TYPE")",
    "fingerprint": "$(json_escape "$BUILD_FP")",
    "sys_security_patch": "$(json_escape "$SYS_SPL")",
    "vendor_security_patch": "$(json_escape "$VENDOR_SPL")",
    "boot_security_patch": "$(json_escape "$BOOT_SPL")"
  },
  "tee_attestation": {
    "keymint_services": "$(json_escape "$KEYMINT_SVC")",
    "strongbox_services": "$(json_escape "$STRONGBOX_SVC")",
    "tricky_store_installed": $TS_INSTALLED,
    "tricky_store_version": "$(json_escape "$TS_VERSION")",
    "tee_broken_status": "$(json_escape "$TEE_BROKEN_STATUS")",
    "tricky_store_daemon": "$(json_escape "$TS_DAEMON")",
    "tricky_store_logcat": "$(json_escape "$TS_LOGCAT")",
    "keybox_status": "$(json_escape "$KEYBOX_STATUS")",
    "keybox_cert_count": $KEYBOX_CERTS,
    "keybox_algorithms": "$(json_escape "$KEYBOX_ALGOS")",
    "keybox_serials": "$(json_escape "$KEYBOX_SERIALS")",
    "keybox_crl_status": "$(json_escape "$KEYBOX_CRL_STATUS")",
    "keybox_sha256": "$(json_escape "$KEYBOX_SHA256")",
    "target_gms": "$(json_escape "$TS_TARGET_GMS")",
    "target_vending": "$(json_escape "$TS_TARGET_VENDING")",
    "target_mode": "$(json_escape "$TS_TARGET_MODE")",
    "security_patch_override": "$(json_escape "$TS_SPL_OVERRIDE")"
  },
  "module_conflicts": {
    "zygisk_provider": "$(json_escape "$ZYGISK_PROVIDER")",
    "pif_installed": $PIF_INSTALLED,
    "pif_version": "$(json_escape "$PIF_VERSION")",
    "pif_path": "$(json_escape "$PIF_PATH")",
    "pif_fingerprint": "$(json_escape "$PIF_FINGERPRINT")",
    "pif_device": "$(json_escape "$PIF_DEVICE")",
    "pif_model": "$(json_escape "$PIF_MODEL")",
    "pif_security_patch": "$(json_escape "$PIF_SPL")",
    "pif_initial_sdk_int": "$(json_escape "$PIF_INITIAL_SDK")",
    "pif_rkp_conflict": "$(json_escape "$PIF_RKP_CONFLICT")",
    "pif_spoof_provider": "$(json_escape "$PIF_SPOOF_PROVIDER")",
    "pif_spoof_props": "$(json_escape "$PIF_SPOOF_PROPS")",
    "pif_spoof_vending_sdk": "$(json_escape "$PIF_SPOOF_VENDING_SDK")",
    "pif_spoof_vending_finger": "$(json_escape "$PIF_SPOOF_VENDING_FINGER")"
  },
  "mount_selinux": {
    "selinux": "$(json_escape "$SELINUX_STATE")",
    "root_mount_leaks": ${MOUNT_LEAKS:-0},
    "overlay_mount_leaks": ${OVERLAY_LEAKS:-0},
    "kernel_string_check": "$(json_escape "$KERNEL_FLAGGED")",
    "adbd_state": "$(json_escape "$ADB_STATE")"
  }
}
JSON_EOF
else
  echo "========================================================"
  echo "  APatch Strong Integrity Diagnostic Report v1.6.3      "
  echo "  Timestamp: $TIMESTAMP"
  echo "  Device: $DEVICE_BRAND $DEVICE_MODEL (Android $ANDROID_VER / SDK $SDK_INT)"
  echo "========================================================"
  echo ""
  echo "[SUMMARY]"
  echo "  Readiness Score   : ${SCORE}/100"
  echo "  Predicted Verdict : ${PREDICTED_VERDICT}"
  echo "  Critical Blockers : ${CRITICAL_COUNT} | Warnings: ${WARN_COUNT}"
  echo "========================================================"
fi
