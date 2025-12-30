#  OBLIVION – Educational Network Scanner

**OBLIVION** is an educational, multi-threaded TCP network scanner written in C.  
It demonstrates core cybersecurity concepts such as socket programming, multithreading, concurrency control, banner grabbing, CIDR scanning, and structured data export.

> ⚠️ **Educational Use Only:** Scan only systems you own or have explicit permission to test.

---

## 📝 Features

- IPv4 & IPv6 support  
- Multi-threaded TCP connect scanning with semaphore-controlled concurrency  
- Real-time scanning progress (% completed)  
- Service identification and safe banner grabbing  
- Scans individual IPs or ranges using CIDR notation  
- Export results to **TXT** or **JSON**  
- Error handling for all user inputs  
- ASCII-based tool branding for educational flair  

---

## 💻 Prerequisites

- Linux or WSL (Windows Subsystem for Linux)  
- GCC compiler  
- POSIX threads (`pthread`)  

Install required build tools:

```bash
sudo apt update
sudo apt install build-essential -y

