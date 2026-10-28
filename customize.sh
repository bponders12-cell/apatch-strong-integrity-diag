# APatch Strong Integrity Diagnostics v1.4.0 - Module Installer Hook
ui_print "------------------------------------------------"
ui_print "  APatch Strong Integrity Diagnostics v1.4.0    "
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
set_perm "$MODPATH/scripts/diag_engine.sh" 0 0 0755
set_perm "$MODPATH/scripts/apply_fix.sh" 0 0 0755

ui_print "- Running baseline DER keybox, CRL & PIF check..."
sh "$MODPATH/scripts/diag_engine.sh" --json > "$MODPATH/last_report.json" 2>/dev/null
ui_print "- Done! Open WebUI in APatch Manager to view results & use Fix for Me."
ui_print "------------------------------------------------"
