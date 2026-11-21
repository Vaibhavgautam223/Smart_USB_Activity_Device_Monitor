import os, mysql.connector
from werkzeug.security import generate_password_hash

def get_db():
    return mysql.connector.connect(host=os.getenv("DB_HOST","localhost"),port=int(os.getenv("DB_PORT","3306")),
      user=os.getenv("DB_USER","root"),password=os.getenv("DB_PASSWORD","Vaibhav@123"),
      database=os.getenv("DB_NAME","smart_usb_db"),charset="utf8mb4")

# Columns added for authorization/blocking. init_db() adds them to databases created by the old version.
AUTH_COLUMNS = {
    "auth_status": "VARCHAR(20) NOT NULL DEFAULT 'pending'",   # pending | authorized | blocked
    "is_blocked": "TINYINT(1) NOT NULL DEFAULT 0",             # 1 while Windows has the device disabled
    "decided_by": "VARCHAR(50) NULL",
    "decided_at": "DATETIME NULL",
}

def _ensure_column(cur, table, column, ddl):
    cur.execute("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s AND COLUMN_NAME=%s",(table,column))
    if cur.fetchone()[0]==0:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

def init_db():
    db=get_db(); c=db.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS admins(id INT AUTO_INCREMENT PRIMARY KEY,username VARCHAR(50) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS usb_devices(id INT AUTO_INCREMENT PRIMARY KEY,device_id VARCHAR(255) UNIQUE NOT NULL,
      device_name VARCHAR(255),manufacturer VARCHAR(255),serial_number VARCHAR(255),drive_letter VARCHAR(20),
      connected TINYINT(1) DEFAULT 0,first_seen DATETIME,last_seen DATETIME,updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)""")
    c.execute("""CREATE TABLE IF NOT EXISTS usb_events(id INT AUTO_INCREMENT PRIMARY KEY,device_id VARCHAR(255),
      device_name VARCHAR(255),event_type VARCHAR(30),event_time DATETIME DEFAULT CURRENT_TIMESTAMP,details TEXT)""")
    c.execute("CREATE TABLE IF NOT EXISTS settings(name VARCHAR(50) PRIMARY KEY,value VARCHAR(255) NOT NULL)")
    for col, ddl in AUTH_COLUMNS.items():
        _ensure_column(c, "usb_devices", col, ddl)
    # Safe default: log everything, only block devices the admin explicitly blocked.
    c.execute("INSERT IGNORE INTO settings(name,value) VALUES('enforcement_mode','monitor')")
    c.execute("SELECT id FROM admins WHERE username='admin'")
    if not c.fetchone(): c.execute("INSERT INTO admins(username,password_hash) VALUES(%s,%s)",("admin",generate_password_hash("admin123")))
    db.commit(); c.close(); db.close()

def get_setting(name, default=None):
    db=get_db(); c=db.cursor()
    try:
        c.execute("SELECT value FROM settings WHERE name=%s",(name,))
        row=c.fetchone()
        return row[0] if row else default
    finally:
        c.close(); db.close()

def set_setting(name, value):
    db=get_db(); c=db.cursor()
    try:
        c.execute("INSERT INTO settings(name,value) VALUES(%s,%s) ON DUPLICATE KEY UPDATE value=VALUES(value)",(name,value))
        db.commit()
    finally:
        c.close(); db.close()
