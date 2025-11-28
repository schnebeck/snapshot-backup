# snapshot-backup
A robust, rsnapshot-inspired backup solution optimized for modern Linux laptops and roaming devices.
## **✨ Key Features**

* **Laptop-First Design:**  
  * **Smart Rotation:** Promotes backups based on time deltas, not fixed weekdays.  
  * **Gap-Closing:** Keeps snapshot indices (daily.0, daily.1) contiguous even if runs are missed.  
  * **Location Aware:** Auto-backup when connecting to trusted Home WiFi (via NetworkManager).  
  * **Power Aware:** Pauses/Skips on battery power.  
* **Modern Linux Support:**  
  * Handles **Snap** and **Flatpak** mounts correctly (avoids backup bloat).  
  * Generates **Software Manifests** (dpkg, snap, flatpak, AppImage) for disaster recovery.  
* **Robustness:**  
  * **Auto-Repair:** Runs fsck on the backup drive before mounting.  
  * **Anti-Recursion:** Auto-detects if backup destination is within source.  
  * **Atomic:** Uses temporary directories for consistency.

## **🚀 Installation**

### **1\. Clone & Install**

git clone \[https://github.com/yourname/snapshot-backup.git\](https://github.com/yourname/snapshot-backup.git)  
cd snapshot-backup  
sudo ./install.sh \--startup=auto

The installer will:

1. Install the binary to /usr/local/sbin/snapshot-backup.  
2. Install the manpage (man snapshot-backup).  
3. Detect if you are on a Laptop (Battery) or Server.  
   * **Laptop:** Installs NetworkManager dispatcher.  
   * **Server:** Installs Cron job.

### **2\. Configure**

**Main Config:** /etc/snapshot-backup.conf  
BACKUP\_ROOT="/backup"  
SOURCE\_DIRS=("/")  
\# ... adjust excludes and retention ...

**Dispatcher Config (Laptops):** /etc/snapshot-backup-dispatcher.conf  
HOME\_NETWORKS=("MyWiFi\_5GHz" "Office\_LAN")  
MOUNT\_POINT="/backup"  
BACKUP\_PROTOCOL="iscsi" \# or nfs

## **🖥 Usage**

**Check Status:**  
sudo snapshot-backup \--status

**Emergency Stop:**  
sudo snapshot-backup \--kill

**Desktop Notification Check:**  
sudo snapshot-backup \--desktop

## **🔧 Disaster Recovery**

The system automatically generates inventory lists in /etc/backup-manifests/ inside the backup:

* dpkg.list: Apt packages.  
* snap.list / flatpak.list: Container apps.  
* appimage.list: Found AppImages in user home.

Use these to rebuild your system environment after a fresh install.

## **📝 License**
GPL-3
