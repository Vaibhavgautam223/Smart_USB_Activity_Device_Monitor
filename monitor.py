import threading, time, platform, json
from database import get_db, get_setting
import enforcement

RETRY_SECONDS = 30   # wait this long before retrying a failed block/unblock

class USBMonitor:
    """Windows USB storage monitor (periodic WMI snapshots) that also enforces the authorization policy."""
    def __init__(self,interval=4):
        self.interval=interval; self._stop=threading.Event(); self._thread=None
        self._previous=set(); self._next_try={}; self._failed=set()

    # ---------- detection (unchanged logic) ----------
    def snapshot(self):
        """Return {device_key: info}, or None if WMI failed (so a glitch is not read as 'everything unplugged')."""
        if platform.system()!="Windows": return {}
        com=None
        try:
            try:
                import pythoncom
                pythoncom.CoInitialize(); com=pythoncom   # WMI in a background thread needs COM initialised
            except Exception: pass
            import wmi
            c=wmi.WMI()
            result={}
            # Win32_DiskDrive identifies physical drives; InterfaceType USB filters USB disks.
            for d in c.Win32_DiskDrive(InterfaceType="USB"):
                key=(d.PNPDeviceID or d.DeviceID or d.Model or "USB-unknown").strip()
                result[key]={"device_id":key,"device_name":d.Caption or d.Model or "USB Storage",
                    "manufacturer":d.Manufacturer or "Unknown","serial_number":d.SerialNumber or "",
                    "drive_letter":""}
            # Associate drive letters where possible.
            for disk in c.Win32_DiskDrive(InterfaceType="USB"):
                try:
                    for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                        for logical in partition.associators("Win32_LogicalDiskToPartition"):
                            key=(disk.PNPDeviceID or disk.DeviceID or disk.Model or "USB-unknown").strip()
                            if key in result: result[key]["drive_letter"]=logical.DeviceID
                except Exception: pass
            return result
        except Exception as e:
            print("USB snapshot error:",e); return None
        finally:
            if com:
                try: com.CoUninitialize()
                except Exception: pass

    # ---------- small DB helpers ----------
    def _query(self,sql,args=()):
        db=get_db(); cur=db.cursor(dictionary=True)
        try: cur.execute(sql,args); return cur.fetchall()
        finally: cur.close(); db.close()

    def _execute(self,sql,args=()):
        db=get_db(); cur=db.cursor()
        try: cur.execute(sql,args); db.commit()
        finally: cur.close(); db.close()

    def _device(self,key):
        rows=self._query("SELECT * FROM usb_devices WHERE device_id=%s",(key,))
        return rows[0] if rows else None

    def _log(self,key,name,event,message):
        self._execute("INSERT INTO usb_events(device_id,device_name,event_type,details) VALUES(%s,%s,%s,%s)",
            (key,name,event,json.dumps({"message":message},ensure_ascii=False)))

    def record(self,key,item,event,connected):
        db=get_db(); cur=db.cursor()
        cur.execute("""INSERT INTO usb_devices(device_id,device_name,manufacturer,serial_number,drive_letter,connected,first_seen,last_seen)
          VALUES(%s,%s,%s,%s,%s,%s,NOW(),NOW()) ON DUPLICATE KEY UPDATE device_name=VALUES(device_name),
          manufacturer=VALUES(manufacturer),serial_number=VALUES(serial_number),drive_letter=VALUES(drive_letter),
          connected=VALUES(connected),last_seen=IF(VALUES(connected)=1,NOW(),last_seen)""",
          (key,item.get("device_name"),item.get("manufacturer"),item.get("serial_number"),item.get("drive_letter"),connected))
        cur.execute("INSERT INTO usb_events(device_id,device_name,event_type,details) VALUES(%s,%s,%s,%s)",
          (key,item.get("device_name"),event,json.dumps(item,ensure_ascii=False)))
        db.commit(); cur.close(); db.close()

    def mark_disconnected(self,key):
        row=self._device(key)
        # Update only the flag so manufacturer/serial/drive details are kept.
        self._execute("UPDATE usb_devices SET connected=0 WHERE device_id=%s",(key,))
        if row and row["is_blocked"]:
            return  # we disabled it ourselves: the BLOCKED event already explains why it vanished
        self._log(key,row["device_name"] if row else "USB Device","DISCONNECTED","Device removed")

    # ---------- enforcement ----------
    def _apply_block(self,row):
        key=row["device_id"]
        if time.time()<self._next_try.get(("block",key),0): return
        ok,msg=enforcement.block_device(row)
        if ok:
            self._next_try.pop(("block",key),None); self._failed.discard(("block",key))
            self._execute("UPDATE usb_devices SET is_blocked=1 WHERE id=%s",(row["id"],))
            why="blocked by an administrator" if row["auth_status"]=="blocked" else "device is not authorized"
            self._log(key,row["device_name"],"BLOCKED","Device disabled: "+why)
        else:
            self._next_try[("block",key)]=time.time()+RETRY_SECONDS
            if ("block",key) not in self._failed:   # log a failure once, not every retry
                self._failed.add(("block",key))
                self._log(key,row["device_name"],"BLOCK_FAILED",msg)

    def _apply_unblock(self,row):
        key=row["device_id"]
        if time.time()<self._next_try.get(("unblock",key),0): return
        ok,msg=enforcement.unblock_device(row)
        if ok:
            self._next_try.pop(("unblock",key),None); self._failed.discard(("unblock",key))
            self._execute("UPDATE usb_devices SET is_blocked=0 WHERE id=%s",(row["id"],))
            self._log(key,row["device_name"],"UNBLOCKED","Device re-enabled")
        else:
            self._next_try[("unblock",key)]=time.time()+RETRY_SECONDS
            if ("unblock",key) not in self._failed:
                self._failed.add(("unblock",key))
                self._log(key,row["device_name"],"UNBLOCK_FAILED",msg)

    def enforce(self,key,mode,newly_connected):
        row=self._device(key)
        if not row or not enforcement.should_block(row["auth_status"],mode): return
        # Already disabled: only re-apply when the device was just (re)plugged in.
        if row["is_blocked"] and not newly_connected: return
        self._apply_block(row)

    def release_pass(self,mode):
        """Re-enable devices that are disabled but no longer should be (authorized, or mode switched to monitor).
        Runs over the database, because a disabled device may no longer show up in the WMI snapshot."""
        for row in self._query("SELECT * FROM usb_devices WHERE is_blocked=1"):
            if not enforcement.should_block(row["auth_status"],mode): self._apply_unblock(row)

    # ---------- main loop ----------
    def cycle(self):
        current=self.snapshot()
        if current is None: return
        mode=get_setting("enforcement_mode","monitor")
        for key,item in current.items():
            is_new=key not in self._previous
            if is_new: self.record(key,item,"CONNECTED",1)
            self.enforce(key,mode,is_new)
        for key in self._previous-current.keys():
            self.mark_disconnected(key)
        self._previous=set(current.keys())
        self.release_pass(mode)

    def run(self):
        while not self._stop.is_set():
            try: self.cycle()
            except Exception as e: print("USB monitor error:",e)   # e.g. MySQL briefly unavailable
            self._stop.wait(self.interval)

    def start(self):
        if platform.system()!="Windows":
            print("Warning: USB monitoring requires Windows/WMI.")
        elif not enforcement.is_admin():
            print("Warning: not running as Administrator. USB devices will be logged but cannot be blocked.")
        self._thread=threading.Thread(target=self.run,daemon=True); self._thread.start()
