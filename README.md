# Smart USB Activity & Device Monitor

A Windows desktop-hosted full-stack project: Flask dashboard + MySQL database + WMI USB storage monitoring,
now with **USB device authorization and blocking**.

## Setup
1. Install Python 3.10+ and MySQL.
2. Run `schema.sql` in MySQL Workbench (or just start the app: it creates and upgrades the tables itself).
3. Open **PowerShell as Administrator** in this folder (needed for blocking, see below):
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   $env:DB_PASSWORD="your_mysql_password"
   $env:SECRET_KEY="a-long-random-string"
   python app.py
   ```
4. Visit http://127.0.0.1:5000
5. Login: `admin` / `admin123` (change before real use).

Upgrading from the old version: nothing to run. On start, `init_db()` adds the new columns and the `settings` table.

## Authorization and blocking

Every USB storage device has an authorization state:

| State | Meaning |
|---|---|
| **Pending** | Seen, no decision yet (the default for every new device) |
| **Authorized** | Trusted. Never blocked |
| **Blocked** (shown as *Denied*) | Always blocked, in every mode |

The dashboard has a **protection mode** switch:

- **Monitor only** (default): everything is logged; only devices you explicitly blocked are disabled.
- **Enforce**: any device that is not authorized is disabled as soon as it is detected.

**Recommended first run:** plug in your own drives in Monitor mode, click *Authorize* on each, then switch to Enforce.

### How blocking works
The monitor thread (every 4 seconds) compares each connected device with the policy. To block, it disables the
device's PnP instance with `pnputil /disable-device` (falls back to PowerShell `Disable-PnpDevice`). Authorizing or
resetting a device re-enables it within a few seconds. Events recorded: `CONNECTED`, `BLOCKED`, `UNBLOCKED`,
`AUTHORIZED`, `DENIED`, `RESET`, `POLICY`, `BLOCK_FAILED`, `UNBLOCK_FAILED`.

### Safety rules built in
- Blocking only works when the app runs **as Administrator**. Otherwise devices are logged, a banner is shown, and a
  `BLOCK_FAILED` event is recorded once.
- It never blocks the drive Windows is running from, and only accepts `USBSTOR\...` device IDs.
- All forms are CSRF-protected.

### Recovery
If a device stays disabled and you cannot re-enable it from the dashboard: Device Manager > Disk drives > right-click
the device > Enable device. Or in an Administrator terminal: `pnputil /enable-device "<Device ID from the Devices page>"`.

## Troubleshooting: "I clicked Block and nothing happened"
1. Make sure only **one** copy of the app is running (an old, non-Administrator instance on port 5000 will keep answering):
   `netstat -ano | findstr :5000`, then close old Python/PyCharm windows.
2. Start the app from an **Administrator** PowerShell. The dashboard must not show the yellow Administrator banner.
3. Check **Activity Logs** for `BLOCKED` or `BLOCK_FAILED` (its details give the reason).
4. Run `python diagnose.py` from the Administrator window. Add `--test-block` to test the blocking itself.

## Limitations
- Monitors USB storage drives only (not keyboards, webcams, phones in MTP mode, and so on).
- Polling means a new drive may be readable for a few seconds before it is disabled. For hard prevention use Group
  Policy / endpoint security software; this app is an educational monitor.
- If a blocked device is physically unplugged, the log cannot tell it apart from the block, so no `DISCONNECTED` event is written for it.
- Run locally on Windows. Do not expose the dashboard publicly. Change the default admin password and set `SECRET_KEY`.
