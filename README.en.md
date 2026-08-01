# 🧠 Frida GG GUI

A Frida-based memory editor GUI — a Cheat Engine / GameGuardian analogue with support for Android (over USB) and local processes on PC.

Lets you scan a running process's memory, find and change values (HP, coins, ammo, etc.), freeze them, and save ready-made "cheat tables" for reuse.

> 🇬🇧 This is an English translation. Original README (Russian): [`README.md`](README.md).

---

## ✨ Features

- 🔍 **Exact value scan** — search a specific value across all accessible memory (`rw-` regions).
- ❓ **Unknown value scan** — snapshot all numbers in a bounded memory region (~8 MB), then narrow down with "Changed" / "Unchanged" / "Increased" / "Decreased" / "Between" filters.
- 🧮 **Data types**: `byte`, `int16`, `int32`, `int64`, `float`, `double`, `string` (ASCII).
- 📌 **Watch list (Cheat Table)** — a separate table for pinned addresses with custom names, independent of the current scan results.
- ❄️ **Value freezing** — freeze all scan results at once, or individual entries in the watch list.
- 💾 **Save / load tables** — export and import the watch list as JSON.
- 📱💻 **Two connection modes** — Android device over USB and local processes on PC.
- ⚡ **Attach and Spawn** — attach to an already-running process, or have Frida spawn the app itself and inject before it starts.
- ✏️ **In-place editing** — double-click any scan result or watch-list entry to edit its value directly.
- 🎨 **Dark pink theme**, tabs, tooltips explaining every scan mode, scrollable layout (nothing gets cut off on small screens).
  
Developed with the help of Claude AI.
---

## 📋 Requirements

- **Python 3.7+**
- Packages:
  ```
  pip install frida frida-tools
  ```
- For **Android**:
  - Root access on the device
  - USB debugging enabled
  - [`frida-server`](https://github.com/frida/frida/releases) pushed to the device (version must match the `frida` package on your PC)
  - `adb` installed on your system

---

## 🚀 Installation & Launch

### 1. Install dependencies on your PC

```bash
pip install frida frida-tools
```

### 2. Start frida-server on the Android device

```bash
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"
```

Verify it's running:

```bash
frida-ps -U
```

If you see a list of processes from the device, you're good to go.

### 3. Run the script

```bash
python frida_gg_guiclaude.py
```

Local (PC) mode doesn't require `frida-server` — it uses Frida's own local process management.

---

## 📖 Quick Usage Guide

### Connecting

In the **"1. Connection"** panel, choose a mode:

- **📱 USB (Android)** — the list of running apps is fetched automatically and can be filtered by name.
- **💻 Local (PC)** — the list of processes on your current machine.

Two ways to connect:

1. **⚡ Connect (Attach)** — pick a process from the list and click the button. Works for already-running apps.
2. **🚀 Spawn launch** — enter a package identifier (e.g. `com.example.app`) or an executable path, then click "Launch and inject". Frida will spawn the process itself and inject before the first instruction — useful when Attach fails with errors like `ptrace pokedata`.

### Searching for a value

1. Pick a **data type** (the value range for each type is shown right below the selector).
2. Enter a known value (e.g. current ammo count) and click **🔍 First scan**.
3. Change the value in the app (e.g. fire a shot) and narrow the results with one of the filters: **Equal / Not equal / Increased / Decreased / Changed / Unchanged / Between**.
4. Repeat steps 2–3 until only 1–2 addresses remain.

If you don't know the starting value, use **❓ Unknown value**: it first snapshots every number in memory, then you narrow it down with the same filters (e.g. "Changed" after any in-app action).

### Editing and freezing

- **Double-click** a found address to edit its value in place.
- **✏️ Write to all** — write a new value to every found address at once.
- **❄️ FREEZE ALL** — periodically rewrite all found addresses with a fixed value (e.g. infinite health).
- Right-click an address → **📌 Add to watch list** — pin a specific address separately from the current scan results.

### Watch list (Cheat Table)

On the **📌 Watch list** tab:

- Add addresses manually or from scan results.
- Freeze each entry individually (not the whole table at once).
- Rename entries for clarity.
- **💾 Save table / 📂 Load table** — manage ready-made cheat sets as JSON via the "File" menu.

---

## 📄 License

This project is licensed under the **MIT License** — the code can be freely used, copied, modified, and distributed, including for commercial purposes, as long as the copyright notice is preserved. Full text: [`LICENSE`](LICENSE).

---

## ⚠️ Disclaimer

This tool is built **strictly for educational purposes** — to study process memory manipulation, reverse engineering, and analysis of **your own** applications.

By using this script, you take full responsibility for your own actions. The author **is not liable** for any damage, account bans, third-party terms-of-service violations, or other consequences resulting from the use of this tool. Do not use it to cheat in online games or to modify applications you don't own without the rights holder's permission.
