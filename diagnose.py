"""Run in the project folder from an ADMINISTRATOR PowerShell:   python diagnose.py
Optional:  python diagnose.py --test-block   (disables the first USB drive found, then re-enables it)"""
import sys
import enforcement

print("== 1. Environment ==")
print("Windows:", enforcement.is_windows(), "| Administrator:", enforcement.is_admin())
if not enforcement.is_admin():
    print("   -> NOT elevated. Blocking cannot work. Open PowerShell with 'Run as administrator'.")

print("\n== 2. What Windows (WMI) reports ==")
from monitor import USBMonitor
mon = USBMonitor()
snap = mon.snapshot()
if snap is None:
    print("WMI failed (see error above). Run: pip install WMI pywin32")
elif not snap:
    print("No USB storage drives found. Is the pendrive plugged in (and not already disabled)?")
else:
    for key, d in snap.items():
        print(f"- {d['device_name']}  drive={d['drive_letter'] or '-'}")
        print(f"    id={key}")
        print("    ID accepted by blocker:", bool(enforcement.SAFE_INSTANCE_ID.match(key)))

print("\n== 3. What the database says ==")
try:
    from database import get_db, get_setting
    print("Protection mode:", get_setting("enforcement_mode", "monitor"))
    db = get_db(); cur = db.cursor(dictionary=True)
    cur.execute("SELECT device_name, device_id, connected, auth_status, is_blocked FROM usb_devices")
    for r in cur.fetchall():
        print(f"- {r['device_name']}: auth_status={r['auth_status']} is_blocked={r['is_blocked']} connected={r['connected']}")
        if snap and r["device_id"] not in snap and r["connected"]:
            print("    ! stored device_id differs from what WMI reports now")
    cur.close(); db.close()
except Exception as e:
    print("Database problem:", e, "\n   -> if a column such as auth_status is missing, you are running the OLD code; use this project's app.py/database.py.")

if "--test-block" in sys.argv and snap:
    d = next(iter(snap.values()))
    print(f"\n== 4. Test block of {d['device_name']} ==")
    ok, msg = enforcement.block_device(d); print("block ->", ok, msg)
    input("Check File Explorer, then press Enter to re-enable the device... ")
    ok, msg = enforcement.unblock_device(d); print("unblock ->", ok, msg)
