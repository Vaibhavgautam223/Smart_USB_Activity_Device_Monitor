CREATE DATABASE IF NOT EXISTS smart_usb_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE smart_usb_db;
CREATE TABLE IF NOT EXISTS admins(id INT AUTO_INCREMENT PRIMARY KEY,username VARCHAR(50) UNIQUE NOT NULL,password_hash VARCHAR(255) NOT NULL,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS usb_devices(
  id INT AUTO_INCREMENT PRIMARY KEY,
  device_id VARCHAR(255) UNIQUE NOT NULL,
  device_name VARCHAR(255),
  manufacturer VARCHAR(255),
  serial_number VARCHAR(255),
  drive_letter VARCHAR(20),
  connected TINYINT(1) DEFAULT 0,
  first_seen DATETIME,
  last_seen DATETIME,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  auth_status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending | authorized | blocked
  is_blocked TINYINT(1) NOT NULL DEFAULT 0,            -- 1 while Windows has the device disabled
  decided_by VARCHAR(50) NULL,
  decided_at DATETIME NULL
);
CREATE TABLE IF NOT EXISTS usb_events(id INT AUTO_INCREMENT PRIMARY KEY,device_id VARCHAR(255),device_name VARCHAR(255),event_type VARCHAR(30),event_time DATETIME DEFAULT CURRENT_TIMESTAMP,details TEXT);
CREATE TABLE IF NOT EXISTS settings(name VARCHAR(50) PRIMARY KEY,value VARCHAR(255) NOT NULL);
INSERT IGNORE INTO settings(name,value) VALUES('enforcement_mode','monitor');
-- Already have a database from the old version? You do not need to run anything:
-- init_db() adds the new columns automatically the next time the app starts.
