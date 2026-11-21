"""Windows-side enforcement: enable / disable a USB storage device by its PnP instance ID.

Uses `pnputil /disable-device` (Windows 10 2004+) and falls back to PowerShell's
Disable-PnpDevice. Both need the app to run as Administrator.
"""
import ctypes
import os
import platform
import re
import subprocess

# Only USB mass-storage disk instances (e.g. USBSTOR\DISK&VEN_...\SERIAL&0) are accepted.
SAFE_INSTANCE_ID = re.compile(r"^USBSTOR\\[\w&.\-\\{}#]+$")
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def is_windows():
    return platform.system() == "Windows"


def is_admin():
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def should_block(auth_status, mode):
    """Policy decision. authorized -> never; blocked -> always; pending -> only in enforce mode."""
    if auth_status == "authorized":
        return False
    if auth_status == "blocked":
        return True
    return mode == "enforce"


def _run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, creationflags=NO_WINDOW)
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def _set_state(instance_id, enable):
    if not is_windows():
        return False, "Blocking needs Windows."
    if not is_admin():
        return False, "Not running as Administrator, so the device cannot be changed."
    if not SAFE_INSTANCE_ID.match(instance_id or ""):
        return False, "Unsupported device ID, skipped."
    verb = "/enable-device" if enable else "/disable-device"
    ok, out = _run(["pnputil", verb, instance_id])
    if ok:
        return True, "OK"
    cmdlet = "Enable-PnpDevice" if enable else "Disable-PnpDevice"
    ok, out2 = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     f"{cmdlet} -InstanceId '{instance_id}' -Confirm:$false -ErrorAction Stop"])
    return (True, "OK") if ok else (False, (out2 or out or "Windows refused the change.")[:300])


def block_device(device):
    letter = (device.get("drive_letter") or "").upper()
    if letter and letter == os.environ.get("SystemDrive", "C:").upper():
        return False, "Refusing to block the drive Windows is running from."
    return _set_state(device.get("device_id"), enable=False)


def unblock_device(device):
    return _set_state(device.get("device_id"), enable=True)
