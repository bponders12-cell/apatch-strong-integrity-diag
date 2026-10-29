#!/system/bin/sh
# APatch Strong Integrity Auto-Remediation Engine (v1.6.3)

if [ -x /data/adb/ap/bin/busybox ]; then
  export ASH_STANDALONE=1
fi

FIX_ID="$1"
[ -z "$FIX_ID" ] && FIX_ID="all"

splice_rsa_into_rkp_keybox() {
  for KB_FILE in /data/adb/tricky_store/keybox.xml /data/adb/teesim/keybox.xml /data/misc/keystore/omk/keybox.xml; do
    [ -f "$KB_FILE" ] || continue

    if [ -s "${KB_FILE}.rkp_bak" ] && grep -qi "OEM Hardware RSA Leaf" "$KB_FILE" 2>/dev/null; then
      cat "${KB_FILE}.rkp_bak" > "$KB_FILE" 2>/dev/null
    fi

    HAS_ECDSA=$(grep -ic "<Key[^>]*ecdsa" "$KB_FILE" 2>/dev/null | head -n 1 | tr -cd '0-9')
    [ -z "$HAS_ECDSA" ] && HAS_ECDSA=0
    HAS_RSA=$(grep -ic "<Key[^>]*rsa" "$KB_FILE" 2>/dev/null | head -n 1 | tr -cd '0-9')
    [ -z "$HAS_RSA" ] && HAS_RSA=0

    if [ "$HAS_ECDSA" -ge 1 ] && [ "$HAS_RSA" -eq 0 ] 2>/dev/null; then
      [ ! -s "${KB_FILE}.rkp_bak" ] && cp -f "$KB_FILE" "${KB_FILE}.rkp_bak" 2>/dev/null
      KB_DIR=$(dirname "$KB_FILE")
      RSA_TMP="${KB_DIR}/.apatch_rsa_companion_$$.xml"
      KB_TMP="${KB_DIR}/.keybox_spliced_$$.xml"

      cat << 'RSA_EOF' > "$RSA_TMP"
    <Key algorithm="rsa">
      <PrivateKey format="pem">
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEArAkZEmzkn3uu5Nb4CLTy2I7wrydBxIESFUMtZdlFw7hENNYt
Y5DDjheH/gxuU9EO/TsQFjD8LltJ0kAlZG44XB5x0w6yy1nKwK7DRgIMWscSEVag
E1E/LmA+BykpxOuk4CxSHGS9NQzVLitdHcNeUXI+PhM+6aLDjKB3oxOjTPAlx40g
lreK5Xs+BL8i/P6H71d9rLAAf7ni4dQcbRYQhtvLGpBhK9PecD0BQdAY1m88E8RF
/HMXD2VWu4h9BCsE78+D1vGjUs2dIMsF24iAaJt9Sc5Au1seCuDdQ5mEEA14Iupe
MNP3GznsZwAb9pW7Z7VhGCMiMPR84DJudQU3HwIDAQABAoIBAAJBeZ4E5i0z1qPo
MFxniFT6mtamccr9KPA1GfVJ7LZCRkgDFEPynqh6+oIu8OC8ebEsWGunZ3HG1KhN
xa++xOfAURxusZLPse7mMRKhQumLJAYs1/B+POaDcIzGJ2a48vKAN5tpCWoWqaeZ
/fXpR+VS1X9u39ZPF2Kn//7talNp6oZCpU/OtXTyU0ZlxYs5C+qPciM2378Zilbl
08aVv4S+J/mnGaLilFAwzBavtkjDYfph/opkvHt2RHODrJXhGUqZ+G3zZ8KkH6kx
IpcdCxUN+c3LlM9qtTeAhto8GN5j6Sg4NsDIfmrMDwUcJbtIEfKNXSKmE7WmFZZ7
tpJupPECgYEA4C76YtGY6Lz7NxqAXXsbuJBcRz8mn2fxXI/OJISTL2Lt6OGG22TB
UdBfLBiQqXY3aCz6zBKxzL8e+fZt4ay4tm0qH2I26mYOr5fhfOZ7VWdoKawj7zMx
JnEowWfGbS6t02U+ssTQkWxWO564ZPzAWls3vlvgC3Pk8KYLlNla99UCgYEAxHN7
odSax/7bt0IdBsASVYuolY+X/QEoBX6o0j/XDnls+YQvquu/+G95QY3M8uiPMOr3
RvR/F88oZitY8EdBTM/slSMnDCA3/G9z0/SQldMCBAtHbqC8WQ1iAgMQU+eyAA9J
EjM9CCdMzmxgShzYyVQxdwnzvUAAe5Lv63BngSMCgYEA1y1AN0lmsz1xAtr1CsT3
PpeRevEqaSajjGybOIHnpDwYjsapYju7MoQGVZTehUlqtRs3PllTP2rSmKnnngzi
3na5T5Y9j46V2gS18eRnzPmMCTOo6hcAvh0vOTQaSQHc5mLvYzd12Z9axa763jOb
jR6wyo305gk/XZyC0UQvBGECgYEArmReAgE8DgJ+haZZIh7rp6k81NgN8nlOT+Jq
d4pYnO7KAI6Jyk9RsXczyy/YGmK8io5rST/OexJZKKmeYF7A5zFFMfdsuGT5jkxa
JHRczcPtbC2fEeP6j4tDz8lsey+ZYlgvY8q8iTpqAm1O5TvKbp8g8i2RhBUG2KxN
81FrcMUCgYAi6f7edoFLsp2irxN/UQl5rFZvpiLmTazIrbMBnsiaStUt4xOynwFK
syX0Ud9meqRq2srPcxW3kdmsZ34JfT75aVWIzYXpZimVy0Xgr3duqhU2Y2Ys5dPQ
RpuWHD9mOVei9b8I8luZPDY3xK0OS8R/YDM7TxjViyp8JAb9uaosmQ==
-----END RSA PRIVATE KEY-----
      </PrivateKey>
      <CertificateChain>
        <NumberOfCertificates>3</NumberOfCertificates>
        <Certificate format="pem">
-----BEGIN CERTIFICATE-----
MIIC9jCCAd6gAwIBAgIEfwABATANBgkqhkiG9w0BAQsFADApMQwwCgYDVQQMDANU
RUUxGTAXBgNVBAUTEGUxYjJjM2Q0ZTVmNjA3MTgwHhcNMjYxMDAxMDAwMDAwWhcN
MzYxMDAxMDAwMDAwWjApMQwwCgYDVQQMDANURUUxGTAXBgNVBAUTEGExYjJjM2Q0
ZTVmNjA3MTkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCsCRkSbOSf
e67k1vgItPLYjvCvJ0HEgRIVQy1l2UXDuEQ01i1jkMOOF4f+DG5T0Q79OxAWMPwu
W0nSQCVkbjhcHnHTDrLLWcrArsNGAgxaxxIRVqATUT8uYD4HKSnE66TgLFIcZL01
DNUuK10dw15Rcj4+Ez7posOMoHejE6NM8CXHjSCWt4rlez4EvyL8/ofvV32ssAB/
ueLh1BxtFhCG28sakGEr095wPQFB0BjWbzwTxEX8cxcPZVa7iH0EKwTvz4PW8aNS
zZ0gywXbiIBom31JzkC7Wx4K4N1DmYQQDXgi6l4w0/cbOexnABv2lbtntWEYIyIw
9HzgMm51BTcfAgMBAAGjJjAkMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/
BAQDAgGmMA0GCSqGSIb3DQEBCwUAA4IBAQBktZ2dJLuTHXh5mEkqe8xJIwBEjvPR
svao3gmdieGiG2h7xB5P5lnTP81um35CQKOUpC/FNwEnOfMXfB6eE+/gRA+m+4Oa
pjtE57OHyJO9nl0dOXexb1PONJEICpml3+kza+ayhaISFXY7KT31qZIHVq0C2pkZ
CZKwHHPCLVnyB5AO06tFCDAibIS1pSL/ZPhn/GS3jExD/aHymrwxU89/t5FxImbk
wGJPahAhYKCdDJR0VnQ5hz7i8HGm7V/0QgNH9pLURFVhgOAa5foEXX65HDUEISk1
MRd0T7D35rKjt+hDlGQ9AgX32xSRIlxJEztIVfhX7OLzmvh6MjPyb4z0
-----END CERTIFICATE-----
        </Certificate>
        <Certificate format="pem">
-----BEGIN CERTIFICATE-----
MIIC9jCCAd6gAwIBAgIEfwABAjANBgkqhkiG9w0BAQsFADApMQwwCgYDVQQMDANU
RUUxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjYxMDAxMDAwMDAwWhcN
MzYxMDAxMDAwMDAwWjApMQwwCgYDVQQMDANURUUxGTAXBgNVBAUTEGUxYjJjM2Q0
ZTVmNjA3MTgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvZIQpTrHA
3HvOV6RSFH6mdSzGjGxK1hreLB6Ks4Hxf+gRVPyzosfa4t/wAEXkUN9Cbfk1AeuG
S/zXSh45TS1h6TG7tou63+b5kV0C4XKAq6ivDJ1ES3B/OwaxVqK4mld1/fThCJlv
5Pn9/7txGD1mQrQRsJb9DtutQrlXNWXS2Atf2IdVUqG98PnhCiUhQk7mMCutCwJv
nkjZ6Fvhiszdox8/zadcTSWeiCXmx+QVe5/hJvpuj8ZgETpZ+eN2AdC1yjAe6BKt
flvsWKkj9vBV4jeIFKCJidyIqup2ibEj+NzfFBzWaelYnK/+aLpLawDpl5w2brEA
aWwqnmaU8u+7AgMBAAGjJjAkMBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/
BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4IBAQAmazh+vwj2eZsk9s24W5+4cbWlxnON
Rqc1H/vmcamy7nYD/XPA4SAwGeU+PxG8vK4g5qZR/En4k5gdS2+qVbZTrb70tZei
GHM5TRagxo6nZmGHYE6ghbSwBLPL38vQCgG/n4kZ1NRHYPInQ4oFhkSTl/YHOaEj
MzQqsQA5Om5xYDu1WC1cpqS/iV92AvVeaoEfHBTWHw9n4SVS+fBfqxyAnmyW4GoZ
QfH+Q7iDIZw1VGS6Qj4QO6GP2MktW5Yf71uX6ZSGsTqLjMOjYn1sV+IfKn/aHzlE
rObLDAiW870xw1nwSdViIQ0jDFD1Z/7S01+jl4NOw1sfjDTeyCSYBA4F
-----END CERTIFICATE-----
        </Certificate>
        <Certificate format="pem">
-----BEGIN CERTIFICATE-----
MIIC8zCCAdugAwIBAgIEfwABAzANBgkqhkiG9w0BAQsFADApMQwwCgYDVQQMDANU
RUUxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjYxMDAxMDAwMDAwWhcN
MzYxMDAxMDAwMDAwWjApMQwwCgYDVQQMDANURUUxGTAXBgNVBAUTEGY5MjAwOWU4
NTNiNmIwNDUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCkIFGbbBDn
xquXX7AehQTzKWbaGpyx4tOgnZJs4kw26QSSVHew9gsPE/iul1dotU+s+Un8Qwqb
FCy/588LA6xLNZgsOFW0/arnqJTALJQkyDW25Q4yztJsAwqEAN8I275Hs8UCSTR2
TQKyyDGLJcalMp2SeivQpi5WsuPF5IW8EXH7puqTJVtOu3iCS4clLYgggddhkboh
diWOzmEMVt+3mikAIstefHwx+gHcbvSrzb2DLcn5k8IfIR7jdlUaUm5lSqREWSuN
hK0pgLUccWutuqJnU1I5F+GUSwDtEFu6LrKU3ln4FfWuuYWtJYs92As/aXaM5pTN
hRFoLoSjf8z9AgMBAAGjIzAhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD
AgGGMA0GCSqGSIb3DQEBCwUAA4IBAQAaJyVf5QlUgrt8jrAEpXfAvDQdbu6oTjty
i9njJggERHemKXu2lsy4/JCZ6/N/VS/I3Gw365y8tXhUXqZjcm1dVH0vvZNIEU74
Qn9GLTfDkaowJ2+05hk5/3hi7I2Z86cL567Wg3y7GlGeggR42e1aw1Bpz3yQLprl
1uCI2WnYNYJoC6g8UhTy8T8IIFdYoVU2NVihGxvE2Dbt1B/r1LaaSSq5tpJf58nH
9BVEp0bkvCUUtpMNoBbDvdkm4kXONVdLITRqEzeEBAjDpXLKqKe4P9P7TuJK2yhz
739CGxfsZ79ZoE7j5kGVJzlwYbCiv2ZGvl1a1dE5N7J6dbxnqxdx
-----END CERTIFICATE-----
        </Certificate>
      </CertificateChain>
    </Key>
RSA_EOF

      tr -d '\r' < "$KB_FILE" | awk -v rsa_file="$RSA_TMP" '
      {
        idx = index(tolower($0), "</keybox>")
        if (idx > 0 && !done) {
          prefix = substr($0, 1, idx - 1)
          suffix = substr($0, idx)
          if (length(prefix) > 0) print prefix
          while ((getline rline < rsa_file) > 0) {
            print rline
          }
          close(rsa_file)
          print suffix
          done = 1
        } else {
          print $0
        }
      }' > "$KB_TMP"

      if [ -s "$KB_TMP" ] && grep -qi "<Key[^>]*rsa" "$KB_TMP" 2>/dev/null && grep -qi "<Key[^>]*ecdsa" "$KB_TMP" 2>/dev/null; then
        cat "$KB_TMP" > "$KB_FILE"
        chmod 0644 "$KB_FILE" 2>/dev/null
        chown 0:0 "$KB_FILE" 2>/dev/null
      fi
      rm -f "$KB_TMP" "$RSA_TMP" 2>/dev/null
    fi
  done
}

resetprop_global_canary_identity() {
  # Complete global resetprop synchronization for bluejay_beta (ZP11.260918.007, SDK 32)
  # Fixes the split-brain mismatch where ro.build.fingerprint was bluejay_beta while ro.product.device was still akita (Pixel 8a, SDK 34)!
  NEW_FP="google/bluejay_beta/bluejay:CANARY/ZP11.260918.007/16484274:user/release-keys"
  RP_BIN="resetprop"
  [ -x /data/adb/ap/bin/resetprop ] && RP_BIN="/data/adb/ap/bin/resetprop"
  if command -v "$RP_BIN" >/dev/null 2>&1; then
    for prop in \
      ro.build.fingerprint \
      ro.system.build.fingerprint \
      ro.system_ext.build.fingerprint \
      ro.product.build.fingerprint \
      ro.vendor.build.fingerprint \
      ro.odm.build.fingerprint \
      ro.bootimage.build.fingerprint; do
      "$RP_BIN" -n "$prop" "$NEW_FP" 2>/dev/null
    done

    for dprop in \
      ro.product.device \
      ro.product.system.device \
      ro.product.system_ext.device \
      ro.product.product.device \
      ro.product.vendor.device \
      ro.product.odm.device \
      ro.build.product; do
      "$RP_BIN" -n "$dprop" "bluejay" 2>/dev/null
    done

    for nprop in \
      ro.product.name \
      ro.product.system.name \
      ro.product.system_ext.name \
      ro.product.product.name \
      ro.product.vendor.name \
      ro.product.odm.name; do
      "$RP_BIN" -n "$nprop" "bluejay_beta" 2>/dev/null
    done

    for mprop in \
      ro.product.model \
      ro.product.system.model \
      ro.product.system_ext.model \
      ro.product.product.model \
      ro.product.vendor.model \
      ro.product.odm.model; do
      "$RP_BIN" -n "$mprop" "Pixel 6a" 2>/dev/null
    done

    for bprop in \
      ro.product.brand \
      ro.product.system.brand \
      ro.product.system_ext.brand \
      ro.product.product.brand \
      ro.product.vendor.brand \
      ro.product.odm.brand; do
      "$RP_BIN" -n "$bprop" "google" 2>/dev/null
    done

    for mfprop in \
      ro.product.manufacturer \
      ro.product.system.manufacturer \
      ro.product.system_ext.manufacturer \
      ro.product.product.manufacturer \
      ro.product.vendor.manufacturer \
      ro.product.odm.manufacturer; do
      "$RP_BIN" -n "$mfprop" "Google" 2>/dev/null
    done

    "$RP_BIN" -n ro.build.id "ZP11.260918.007" 2>/dev/null
    "$RP_BIN" -n ro.build.version.incremental "16484274" 2>/dev/null
    "$RP_BIN" -n ro.build.version.security_patch "2026-10-05" 2>/dev/null
    "$RP_BIN" -n ro.vendor.build.security_patch "2026-10-05" 2>/dev/null
    "$RP_BIN" -n ro.bootimage.build.security_patch "2026-10-05" 2>/dev/null
    "$RP_BIN" -n ro.product.first_api_level "32" 2>/dev/null
    "$RP_BIN" -n ro.board.first_api_level "32" 2>/dev/null
    "$RP_BIN" -n ro.board.api_level "32" 2>/dev/null
    "$RP_BIN" -n ro.vendor.api_level "32" 2>/dev/null
  fi
}

write_tricky_security_patch() {
  if [ -d /data/adb/tricky_store ]; then
    cat << 'SPL_EOF' > /data/adb/tricky_store/security_patch.txt
all=2026-10-05
system=2026-10-05
vendor=2026-10-05
boot=2026-10-05
SPL_EOF
    chmod 0644 /data/adb/tricky_store/security_patch.txt 2>/dev/null
    chown 0:0 /data/adb/tricky_store/security_patch.txt 2>/dev/null
  fi
}

write_migrated_pif() {
  SPOOF_PROV="${1:-0}"
  SPOOF_VEND_SDK="${2:-0}"
  PIF_DIR="/data/adb/modules/playintegrityfix"
  mkdir -p "$PIF_DIR" 2>/dev/null

  cat << PIF_EOF > "$PIF_DIR/custom.pif.prop"
# Build Fields
MANUFACTURER=Google
MODEL=Pixel 6a
FINGERPRINT=google/bluejay_beta/bluejay:CANARY/ZP11.260918.007/16484274:user/release-keys
BRAND=google
PRODUCT=bluejay_beta
DEVICE=bluejay
RELEASE=CANARY
ID=ZP11.260918.007
INCREMENTAL=16484274
TYPE=user
TAGS=release-keys
SECURITY_PATCH=2026-10-05
DEVICE_INITIAL_SDK_INT=32

# System Properties
ro.build.fingerprint=google/bluejay_beta/bluejay:CANARY/ZP11.260918.007/16484274:user/release-keys
ro.build.id=ZP11.260918.007
ro.product.device=bluejay
ro.product.name=bluejay_beta
ro.build.version.security_patch=2026-10-05
ro.board.first_api_level=32
ro.product.first_api_level=32
*.build.id=ZP11.260918.007
*.security_patch=2026-10-05
*api_level=32

# Advanced Settings
spoofBuild=1
spoofProps=1
spoofProvider=${SPOOF_PROV}
spoofSignature=0
spoofVendingFinger=1
spoofVendingSdk=${SPOOF_VEND_SDK}
verboseLogs=0
PIF_EOF

  chmod 0644 "$PIF_DIR/custom.pif.prop" 2>/dev/null

  rm -f /data/adb/pif.prop /data/adb/pif.json /data/adb/tricky_store/pif.prop /data/adb/tricky_store/custom.pif.prop 2>/dev/null

  resetprop_global_canary_identity
  write_tricky_security_patch
}

unblock_rezygisk_gms() {
  PKG_CFG="/data/adb/ap/package_config"
  if [ -f "$PKG_CFG" ]; then
    sed -i '/^com\.google\.android\.gms,/d' "$PKG_CFG" 2>/dev/null
    sed -i '/^com\.android\.vending,/d' "$PKG_CFG" 2>/dev/null
  fi

  if [ -d /data/adb/modules/rezygisk ] && [ ! -f /data/adb/modules/rezygisk/disable ] && \
     [ -d /data/adb/modules/zygisksu ] && [ ! -f /data/adb/modules/zygisksu/disable ]; then
    touch /data/adb/modules/zygisksu/disable 2>/dev/null
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

ensure_tricky_daemon_and_clear_dg_cache() {
  # 1. Check if keystore2 actually has TrickyStore / TEESimulator injected (excluding /memfd:jit-cache false positives!)
  KS2_PID=$(pidof keystore2 2>/dev/null | awk '{print $1}')
  IS_INJECTED="false"
  if [ -n "$KS2_PID" ] && grep -Eiq "tricky|teesim|lsplt" "/proc/$KS2_PID/maps" 2>/dev/null; then
    IS_INJECTED="true"
  fi

  if [ "$IS_INJECTED" = "false" ]; then
    for sfile in /data/adb/modules/tricky_store/service.sh /data/adb/modules/teesimulator/service.sh; do
      if [ -f "$sfile" ]; then
        nohup sh "$sfile" >/dev/null 2>&1 &
        sleep 1
        break
      fi
    done
  fi

  # 2. Clear cached DroidGuard / Play Integrity attestation blobs in GMS & Play Store so pre-existing unlocked-bootloader keys are purged
  rm -rf /data/data/com.google.android.gms/app_dg_cache/* 2>/dev/null
  rm -rf /data/data/com.google.android.gms/cache/* 2>/dev/null
  rm -rf /data/data/com.android.vending/cache/* 2>/dev/null
  rm -rf /data/data/gr.nikolasspyr.integritycheck/cache/* 2>/dev/null
}

restart_gms_and_vending() {
  ensure_tricky_daemon_and_clear_dg_cache
  if [ -f /data/adb/modules/playintegrityfix/killpi.sh ]; then
    sh /data/adb/modules/playintegrityfix/killpi.sh >/dev/null 2>&1 || true
  fi
  killall com.google.android.gms.unstable 2>/dev/null || true
  killall com.google.android.gms 2>/dev/null || true
  killall com.android.vending 2>/dev/null || true
  killall gr.nikolasspyr.integritycheck 2>/dev/null || true
  killall io.github.vvb2060.keyattestation 2>/dev/null || true
}

fix_tricky_targets() {
  mkdir -p /data/adb/tricky_store 2>/dev/null
  TFILE="/data/adb/tricky_store/target.txt"
  SUFFIX=""
  if [ -f /data/adb/tricky_store/tee_status ] && grep -qi "teeBroken=true" /data/adb/tricky_store/tee_status 2>/dev/null; then
    SUFFIX="!"
  fi

  cat << TARGET_EOF > "$TFILE"
com.google.android.gms${SUFFIX}
com.android.vending${SUFFIX}
com.google.android.gsf${SUFFIX}
com.google.android.apps.walletnfcrel${SUFFIX}
gr.nikolasspyr.integritycheck${SUFFIX}
io.github.vvb2060.keyattestation${SUFFIX}
io.github.vvb2060.mahoshojo${SUFFIX}
com.henrikherzig.playintegritychecker${SUFFIX}
TARGET_EOF
  chmod 0644 "$TFILE" 2>/dev/null
  chown 0:0 "$TFILE" 2>/dev/null
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
    splice_rsa_into_rkp_keybox
    write_migrated_pif 0 0
    fix_tricky_targets
    restart_gms_and_vending
    echo "Synced full bluejay_beta identity via resetprop -n (device, model, board/product first_api_level=32, fingerprint), purged GMS cache, and restarted GMS."
    ;;
  keybox_xml)
    unblock_rezygisk_gms
    splice_rsa_into_rkp_keybox
    write_migrated_pif 0 0
    fix_tricky_targets
    restart_gms_and_vending
    echo "Spliced chained RSA CA hierarchy into RKP keybox.xml, verified TrickyStore daemon injection, purged GMS cache, and restarted GMS."
    ;;
  pif_device_fallback)
    unblock_rezygisk_gms
    write_migrated_pif 1 0
    fix_tricky_targets
    restart_gms_and_vending
    echo "Enabled spoofProvider=1 (Device Integrity Mode) with full resetprop bluejay_beta identity (SDK 32) and restarted GMS/Play Store."
    ;;
  pif_spoof_provider)
    unblock_rezygisk_gms
    splice_rsa_into_rkp_keybox
    write_migrated_pif 0 0
    fix_tricky_targets
    restart_gms_and_vending
    echo "Set spoofProvider=0 + full resetprop bluejay_beta identity and restarted GMS."
    ;;
  mount_leaks|apatch_gms_exclude|apatch_overlay_mods|zygisk_bridge)
    unblock_rezygisk_gms
    restart_gms_and_vending
    echo "Cleaned /data/adb/ap/package_config and resolved any duplicate Zygisk modules."
    ;;
  vb_state|flash_locked|vbmeta_state|ro_debug_secure|warranty_bit)
    fix_verified_boot_props
    echo "Reset Verified Boot & warranty properties to locked/green state."
    ;;
  target_gms|keymint_hal|tee_daemon)
    fix_tricky_targets
    restart_gms_and_vending
    echo "Verified TrickyStore daemon injection, updated target.txt, purged GMS cache, and restarted GMS."
    ;;
  spl_alignment)
    write_tricky_security_patch
    resetprop_global_canary_identity
    restart_gms_and_vending
    echo "Synchronized /data/adb/tricky_store/security_patch.txt to TrickyStoreOSS key=value format (all=2026-10-05)."
    ;;
  selinux_state)
    setenforce 1 2>/dev/null
    echo "Set SELinux to Enforcing."
    ;;
  all)
    unblock_rezygisk_gms
    splice_rsa_into_rkp_keybox
    write_migrated_pif 0 0
    fix_tricky_targets
    fix_verified_boot_props
    setenforce 1 2>/dev/null
    restart_gms_and_vending
    echo "Applied all v1.6.3 fixes: full resetprop bluejay_beta identity (device=bluejay, model=Pixel 6a, board/product first_api_level=32), TrickyStoreOSS all=2026-10-05, chained RSA CA splice, and GMS cache purge."
    ;;
  *)
    echo "Unknown fix ID: $FIX_ID"
    exit 1
    ;;
esac
