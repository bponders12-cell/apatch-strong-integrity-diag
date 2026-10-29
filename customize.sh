# APatch Strong Integrity Diagnostics v1.6.3 - Module Installer Hook
ui_print "------------------------------------------------"
ui_print "  APatch Strong Integrity Diagnostics v1.6.3    "
ui_print "------------------------------------------------"

if [ "$APATCH" = "true" ] || [ "$KERNELPATCH" = "true" ]; then
  ui_print "- Detected APatch environment"
  ui_print "  APatch Version: ${APATCH_VER:-unknown} (${APATCH_VER_CODE:-0})"
  ui_print "  KernelPatch Version: ${KERNELPATCH_VERSION:-unknown}"
elif [ "$KSU" = "true" ]; then
  ui_print "- Detected KernelSU compatibility environment (${KSU_VER:-unknown})"
fi

touch "$MODPATH/skip_mount"
ui_print "- Enabled skip_mount (zero OverlayFS footprint)"

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/action.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755 2>/dev/null
set_perm "$MODPATH/scripts/diag_engine.sh" 0 0 0755
set_perm "$MODPATH/scripts/apply_fix.sh" 0 0 0755

ui_print "- Syncing full bluejay_beta identity, purging GMS cache & checking keystore2..."
sh "$MODPATH/scripts/apply_fix.sh" all >/dev/null 2>&1
sh "$MODPATH/scripts/diag_engine.sh" --json > "$MODPATH/last_report.json" 2>/dev/null
ui_print "- Done! Open WebUI in APatch Manager to verify Strong Integrity."
ui_print "------------------------------------------------"
