#!/system/bin/sh
# APatch Manager Action Button Handler (v1.6.3)
MODDIR=${0%/*}
REPORT_JSON="/data/local/tmp/apatch_strong_integrity_report.json"
REPORT_TXT="/data/local/tmp/apatch_strong_integrity_report.txt"

echo "========================================================"
echo "  APatch Strong Integrity Auditor & Auto-Fixer v1.6.3   "
echo "========================================================"

sh "$MODDIR/scripts/apply_fix.sh" all
sh "$MODDIR/scripts/diag_engine.sh" --text | tee "$REPORT_TXT"
sh "$MODDIR/scripts/diag_engine.sh" --json > "$REPORT_JSON"

echo ""
echo "[+] Saved JSON telemetry to: $REPORT_JSON"
echo "[+] Saved text summary to  : $REPORT_TXT"
echo "[+] Tip: Tap the WebUI button in APatch Manager for interactive 1-tap fixes."
exit 0
