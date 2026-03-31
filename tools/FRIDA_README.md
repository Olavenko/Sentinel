# Frida Blowfish Key Capture — Usage Guide

## Prerequisites

- Frida installed: `pip install frida-tools`
- Conquer Online client (Env_DX9)
- Script: `F:\Sentinel\tools\hook_blowfish.js`

---

## Step-by-Step Instructions

### 1. Close everything first

- Close Conquer Online (if open)
- Close any running Frida sessions (Ctrl+C)
- Close x32dbg (if open — cannot run alongside Frida)

### 2. Launch the game

- Open Conquer Online normally (from launcher or Conquer.exe)
- Wait until the **login screen** appears
- **DO NOT login yet**

### 3. Open PowerShell

```powershell
cd F:\Sentinel\tools
frida -n Conquer.exe -l hook_blowfish_v13.js

frida -n Conquer.exe -l F:\Sentinel\tools\hook_blowfish_v14.js
frida -p (Get-Process Conquer).Id -l F:\Sentinel\tools\hook_blowfish.js
```

### 4. Attach Frida to the game

```powershell
frida -n Conquer.exe -l hook_blowfish.js
```

Wait for this message:

```
[*] All hooks installed! Login to capture the key.
```

### 5. Login to the game

- Go to the game window
- Enter your credentials and login
- Play for 30-60 seconds (move around, open menus, etc.)
- This generates encrypted/decrypted packets for capture

### 6. Stop capture

- Go back to the PowerShell window
- Press **Ctrl+C** to detach Frida
- Close the game

### 7. Check results

- Log file saved at: `F:\Sentinel\tools\frida_capture.log`
- Open with any text editor to review captured data

---

## Output File

| File | Location | Contents |
|------|----------|----------|
| `frida_capture.log` | `F:\Sentinel\tools\` | Full Blowfish key schedule, IV, encrypted/decrypted packets |

## Extract 100 Line

```powershell
Get-Content "F:\Sentinel\tools\frida_capture.log" -TotalCount 100

Get-Content "F:\Sentinel\tools\frida_capture_*.log" -TotalCount 150 | Select-Object -Last 150

Get-Content "F:\Sentinel\tools\frida_capture.log" -Tail 20

(Select-String -Path "F:\Sentinel\tools\frida_capture.log" -Pattern "call #").Count

Get-Content (Get-ChildItem "F:\Sentinel\tools\frida_capture_*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName -TotalCount 150
```

---

## Troubleshooting

### "Failed to attach: unable to find process"

The game is not running. Start the game first, then run Frida.

### "Failed to attach: access denied"

Run PowerShell as **Administrator**.

### Game crashes after Frida attaches

ScyllaHide or other anti-debug tools may conflict. Make sure x32dbg is fully closed.

### Log file is empty

Login was not performed after Frida attached. The hooks only trigger on encrypted packets (after handshake).

---

## Notes

- The log file is **overwritten** each run (mode "w"). Rename it if you want to keep multiple captures.
- Frida does NOT trigger Themida anti-debug detection (unlike x32dbg).
- The script hooks `BF_cfb64_encrypt` at address `0x012410f0` (DX9 binary).
- If TQ updates the client, addresses will change — re-run Ghidra RE.
