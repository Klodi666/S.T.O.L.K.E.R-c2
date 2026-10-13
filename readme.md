# STOLKER: Secure Training & Offensive Lab Knowledge Engine

> **Author:** DeepHat (Kindo)  
> **Version:** 1.1.0  
> **Type:** Single-File Python 3 CLI  
> **License:** MIT (Educational / Lab Use)

**STOLKER** (Secure Training & Offensive Lab Knowledge Engine) is a portable, single-file Python utility designed for cybersecurity professionals, students, and red-teamers to simulate offensive lab environments. It generates executable artifacts (`.bat` and `.exe`) that mimic real-world post-exploitation beaconing and command execution, while providing a local mock listener to observe the traffic.

## ✨ Features

- **Zero Dependencies:** Runs on Python 3.6+ using only the standard library.
- **Portable Payload Generation:**
  - **Windows `.bat`:** Self-contained batch scripts with CRLF endings, ANSI coloring, and PowerShell beaconing.
  - **Standalone `.exe`:** If PyInstaller is installed, STOLKER compiles a native executable. If not, it generates a pure Python payload.
- **Interactive CLI:** Guided workflow to select profiles, listener parameters, and save locations.
- **Built-in Mock Listener:** A background TCP server that logs connections, echoes beacons, and provides real-time feedback on the console.
- **Modular Profiles:** Pre-configured simulation profiles for Recon, Web, Network (Active Directory), and Cloud scenarios.
- **Debug Mode:** Toggleable verbose logging for development and troubleshooting.

## 📥 Installation

### Option 1: Direct Download
1. Clone this repository or download the `stolker.py` file.
2. Ensure Python 3 is installed on your system.
3. (Optional) Install PyInstaller for `.exe` generation:
   ```bash
   pip install pyinstaller