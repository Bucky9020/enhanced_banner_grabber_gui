# Enhanced Banner Grabber 🔍

A lightweight **Python network reconnaissance tool** that performs **banner grabbing** and **port scanning** (with both CLI and GUI modes).  
It uses only the Python standard library — **no external dependencies** — and works offline on **Linux, Parrot OS, or Kali**.

---

## ✨ Features
- ✅ **Fast multi-threaded scanning**  
- ✅ **Banner grabbing** for FTP, SSH, SMTP, HTTP, MySQL, and more  
- ✅ **Smart timeout detection**  
- ✅ **Clean CLI output + optional GUI interface (Tkinter)**  
- ✅ Works **without root privileges** (except for low ports)  
- ✅ **No API keys**, no dependencies

---

## 🧠 Usage (CLI Mode)

```bash
python3 enhanced_banner_grabber_gui.py -t example.com
-t, --target      Target domain or IP
-p, --ports       Comma-separated ports (default: 21,22,25,53,80,110,143,443,587,993,995,3306,8080)
-o, --output      Save results to a text file
--threads         Number of threads (default: 10)
--timeout         Timeout seconds (default: 2)

💻 GUI Mode (Optional)
python3 enhanced_banner_grabber_gui.py --gui
A Tkinter-based window will appear allowing you to input the target and ports interactively.

Requirements
Python 3.8+

Works natively on:

Linux / Kali / Parrot OS

macOS

Windows (tested via WSL)

No installation needed — just run the file directly.

Disclaimer
This tool is built for educational and ethical purposes only.
Use it only on systems you own or have explicit permission to test.
Unauthorized scanning is strictly prohibited.

🧑‍💻 Author
Bucky — Cybersecurity Researcher & Red Team Learner
🚀 Focused on ethical offensive tools and educational projects.
