#!/system/bin/sh
# APatch Manager Action Button Entry Point
MODDIR=${0%/*}
REPORT_TXT="/sdcard/Download/apatch_strong_integrity_report.txt"
REPORT_JSON="$MODDIR/last_report.json"

echo "- Running APatch Strong Integrity Diagnostics v1.4.0..."
sh "$MODDIR/scripts/diag_engine.sh" --json > "$REPORT_JSON" 2>/dev/null
sh "$MODDIR/scripts/diag_engine.sh" --text | tee "$REPORT_TXT"
echo ""
echo "- Saved JSON snapshot to: $REPORT_JSON"
echo "- Saved text report to  : $REPORT_TXT"
sleep 2
