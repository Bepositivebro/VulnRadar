# 🔐 VulnRadar — VS Code Extension

Real-time vulnerability scanner that detects CVEs **as you type** in VS Code.
Works on `requirements.txt` files AND `.py` files with `import` statements.

---

## 📁 Folder Structure

```
vulnradar-vscode/
├── src/
│   └── extension.js     ← All extension logic
├── package.json          ← Extension manifest
└── README.md
```

---

## 🚀 How to Install & Run (Step by Step)

### Prerequisites
- **VS Code** installed
- **Node.js** v16+ installed → https://nodejs.org

---

### Step 1 — Install VS Code Extension Tools

Open terminal and run:
```bash
npm install -g @vscode/vsce
```

---

### Step 2 — Open Project in VS Code

```bash
cd vulnradar-vscode
code .
```

---

### Step 3 — Run the Extension (Dev Mode)

Press **`F5`** in VS Code.

This opens a new VS Code window called **"Extension Development Host"**.

That new window IS your extension running live.

---

### Step 4 — Test It

In the **Extension Development Host** window:

**Test with requirements.txt:**
1. Create a new file → `test_requirements.txt`
2. Type:
   ```
   django==1.2
   requests==2.0.0
   flask==0.10.0
   ```
3. Wait ~1 second...
4. You will see:
   - 🔴 Red squiggles under vulnerable packages
   - ⚠️ Alert popup in bottom-right corner
   - Status bar shows `VulnRadar: 3 vulnerable (2 critical)`
5. Click **"Open Dashboard"** in the popup → Dashboard opens on the right side

**Test with Python file:**
1. Create a new file → `test_app.py`
2. Type:
   ```python
   import django
   import flask
   import requests
   ```
3. Wait ~1 second → same alerts appear

---

## ✨ Features

| Feature | How It Works |
|---|---|
| **Real-time scanning** | Scans 1 second after you stop typing |
| **Red squiggles** | Shows on the vulnerable package name |
| **Alert popup** | Bottom-right notification with risk level |
| **Click → Dashboard** | Sidebar panel opens with full CVE analysis |
| **requirements.txt** | Detects `package==version` patterns |
| **Python imports** | Detects `import X` / `from X import Y` |
| **Status bar** | Shows scan status at all times |
| **OSV API** | Live CVE data from osv.dev |

---

## 🎯 How to Trigger Alerts

These patterns are detected:

**In requirements.txt / .txt files:**
```
django==1.2          ← CRITICAL
flask>=0.10.0        ← HIGH  
requests==2.31.0     ← SAFE (no alert)
pyyaml==3.11         ← HIGH
cryptography==0.1    ← CRITICAL
```

**In .py files:**
```python
import django        ← scans latest django (no version = checks for any vulns)
from flask import Flask
import yaml          ← maps to PyYAML package
import PIL           ← maps to Pillow package
```

---

## ⚙️ Settings

Open VS Code Settings (`Ctrl+,`) and search for `vulnradar`:

| Setting | Default | Description |
|---|---|---|
| `vulnradar.enabled` | `true` | Turn scanning on/off |
| `vulnradar.debounceMs` | `1000` | Delay before scanning (ms) |

---

## 🔧 Commands

Open Command Palette (`Ctrl+Shift+P`) and type:

| Command | Action |
|---|---|
| `VulnRadar: Scan Current File` | Force scan now |
| `VulnRadar: Open Dashboard` | Open dashboard with last results |

---

## 🐛 Troubleshooting

**Extension not activating?**
- Make sure file is `.py` or `.txt`
- Check VS Code Output panel → select "VulnRadar" from dropdown

**No alerts showing?**
- Check internet connection (needs OSV API)
- Try `Ctrl+Shift+P` → "VulnRadar: Scan Current File"

**F5 not working?**
- Make sure you opened the `vulnradar-vscode/` folder directly in VS Code
- Check there are no errors in the Debug Console

---

## 📦 Package as .vsix (Optional)

To install permanently:
```bash
npm install -g @vscode/vsce
cd vulnradar-vscode
vsce package
# Creates vulnradar-1.0.0.vsix
code --install-extension vulnradar-1.0.0.vsix
```
