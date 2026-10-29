#!/usr/bin/env sh
# Local Builder & Syntax Validator for APatch Strong Integrity Diagnostics
set -e

echo "==> Validating POSIX shell syntax..."
sh -n customize.sh
sh -n action.sh
sh -n scripts/diag_engine.sh
sh -n scripts/apply_fix.sh
sh -n service.sh

VER=$(grep '^version=' module.prop | cut -d= -f2 | tr -d '\r\n')
OUT_DIR="dist"
OUT_ZIP="${OUT_DIR}/apatch_strong_integrity_diag_${VER}.zip"

mkdir -p "$OUT_DIR"
rm -f "$OUT_ZIP"

chmod 0755 action.sh customize.sh service.sh scripts/diag_engine.sh scripts/apply_fix.sh

if command -v zip >/dev/null 2>&1; then
  zip -r9 "$OUT_ZIP" META-INF scripts webroot module.prop customize.sh action.sh README.md LICENSE
else
  python3 - "$OUT_ZIP" << 'EOF'
import os, sys, zipfile
out_zip = sys.argv[1]
include = ["META-INF", "scripts", "webroot", "module.prop", "customize.sh", "action.sh", "service.sh", "README.md", "LICENSE"]
with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as zf:
    for item in include:
        if os.path.isfile(item):
            zf.write(item, item)
        elif os.path.isdir(item):
            for root, dirs, files in os.walk(item):
                dirs.sort()
                files.sort()
                for file in files:
                    full = os.path.join(root, file)
                    zf.write(full, full)
EOF
fi

echo "==> Built flashable APatch module: $OUT_ZIP"
