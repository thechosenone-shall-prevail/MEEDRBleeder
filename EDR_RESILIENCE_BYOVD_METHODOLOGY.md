# In-Depth Technical Analysis: EDR Resilience, Deep AV Evasion & BYOVD Methodology

| Document Metadata | Details |
| :--- | :--- |
| **Target Product** | ManageEngine UEMS Agent — EDR / Anti-Ransomware Suite |
| **Tested Environment** | Maxed-out Enterprise Security Policies (Aggressive Detection, Real-time File Scan, Prevention: "Kill Process", Decoy Engine Active) |
| **Research Focus** | Fileless In-Memory PE Execution, Deep AV/ML Evasion, and Bring Your Own Vulnerable Driver (BYOVD) Kernel Termination |
| **Vendor Context** | Zoho's internal security engineering team acknowledges BYOVD attack vectors across endpoint environments and is actively rolling out enhanced mitigations in upcoming releases. |
| **Classification** | Defensive Security Research & Evasion Architecture Analysis |

---

## 1. Executive Summary & Assessment Context

During an advanced security assessment of the ManageEngine Endpoint Detection and Response (EDR) suite, security policies were configured to **maximum aggressiveness**:
- **Prevention Policy:** Set to `Kill process` (active blocking).
- **Detection Sensitivity:** Configured to `Aggressive`.
- **Decoy System:** Enabled.
- **Deep AV & On-Write ML Scanning:** Fully active across all file paths.

Despite these maxed-out policy constraints, the endpoint detection suite was neutralized. The assessment demonstrated how combining **multi-layered XOR fileless payload delivery**, **in-memory manual PE mapping (Reflective Loading)** within a trusted host process, and **Bring Your Own Vulnerable Driver (BYOVD)** primitives completely circumvents Deep AV heuristics, behavioral telemetry, and user-mode process self-defense.

---

## 2. Target Architecture Breakdown

The ManageEngine EDR ecosystem relies on a distributed suite of specialized user-mode services coordinated with a kernel minifilter:

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│                                MANAGEENGINE AGENT ARCHITECTURE                           │
├──────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  [Detection & Behavioral Engines]            [Anti-Ransomware & Rollback]                │
│  ├── MEERDInferenceEngine.exe (AI Engine)    ├── MEARWService.exe (Anti-Ransomware Core) │
│  ├── MEEDRMCEngine.exe (Rule Evaluation)     ├── MERollbackSvc.exe (VSS / File Rollback) │
│  └── McDetection.exe / McScanAlert.exe       └── MEARWFltSvc64.exe (Minifilter Bridge)   │
│                                                                                          │
│  [Cloud Telemetry & Agent Health]            [Management & Endpoint Suite]               │
│  ├── MEEDRSyncAgent.exe (Cloud Sync)         ├── dcagentservice.exe (Central Agent)      │
│  ├── UEMSAgentHealthChecker.exe              ├── MEDLPSvc.exe / MEFESvc.exe (DLP / Enc)  │
│  └── AgentHealthMonitor.exe / ECEATelemetry  └── ManageEngine.exe / MEAgent.exe          │
│                                                                                          │
└──────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Deep AV & On-Write ML Scan Evasion

Traditional and Next-Gen Antivirus (NGAV) engines utilize on-write file scanning, static machine learning models, and file-system mini-filters (`IRP_MJ_CREATE` / `IRP_MJ_WRITE`) to intercept suspicious PE binaries when written to disk.

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              FILELESS IN-MEMORY DELIVERY FLOW                           │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│   [Disk: vproxy_xor.bin]                                                                │
│   • Non-PE raw byte stream (No 'MZ' / 'PE\0\0' magic bytes)                             │
│   • Encrypted via XOR (Key: 0x41)                                                       │
│   • Completely evades On-Write ML & Static Heuristic Scanners                           │
│          │                                                                              │
│          ▼ [Read into memory: ReadAllBytes]                                             │
│   [Memory: Raw Encrypted Buffer]                                                        │
│          │                                                                              │
│          ▼ [In-Memory De-XOR: byte ^ 0x41]                                              │
│   [Memory: Valid In-Memory PE Image] (Never touches disk)                               │
│          │                                                                              │
│          ▼ [Extract Embedded Resource: .rsrc (Type 10 / ID 200)]                        │
│   [Memory: Encrypted Driver Blob (XOR 0x5A)]                                            │
│          │                                                                              │
│          ▼ [In-Memory De-XOR: byte ^ 0x5A]                                              │
│   [Memory: Clean Kernel Driver Binary]                                                  │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### Why Deep AV Fails to Detect the Staged Artifacts:
1. **Zero PE Signatures on Disk:** The payload on disk (`vproxy_xor.bin`) is a raw encrypted binary array. It contains no `IMAGE_DOS_HEADER`, `e_magic` (`0x5A4D`), or `IMAGE_NT_HEADERS` (`0x00004550`). Static signature matchers and neural ML file classifiers categorize it as inert binary data.
2. **Dual-Layer XOR Encoding:**
   - **Outer Layer:** Loader DLL encrypted with single-byte XOR (`0x41`).
   - **Inner Layer:** Vulnerable kernel driver embedded inside the DLL's `.rsrc` section (`RT_RCDATA` / ID `200`), encrypted with a secondary key (`0x5A`).
3. **Host Process Legitimacy:** The execution context is hosted directly inside `powershell.exe`, an official Microsoft-signed binary. EDR heuristics that weigh process reputation grant high trust to the parent executable.

---

## 4. Step-by-Step Low-Level In-Memory PE Mapping (Reflective Loader)

Rather than calling standard Windows loader APIs (`LoadLibraryExW`) which register the DLL in the Process Environment Block (`PEB.Ldr`) and trigger kernel image load notifications (`PsSetLoadImageNotifyRoutine`), the loader performs **manual PE reconstruction entirely in memory via P/Invoke**.

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                         MANUAL IN-MEMORY PE MAPPING PIPELINE                            │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  1. Parse Headers  ──► 2. VirtualAlloc  ──► 3. Section Copy ──► 4. Relocations          │
│     (DOS/COFF/Opt)        (Commit/Reserve)     (.text/.rdata)      (Delta Fixups)       │
│                                                                        │                │
│  7. Execute        ◄── 6. VirtualProtect ◄── 5. Resolve IAT ◄──────────┘                │
│     (DllMain Call)        (Page Permissions)   (LoadLib/GetProc)                        │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### Step 1: Header Validation & Architecture Verification
* Validates DOS signature: `e_magic == 0x5A4D` (`MZ`).
* Resolves NT header offset from `e_lfanew` (offset `0x3C`).
* Confirms PE signature: `0x50 0x45 0x00 0x00` (`PE\0\0`).
* Validates COFF Machine Architecture: `0x8664` (AMD64 / x64).
* Validates Optional Header Magic: `0x20B` (PE32+ 64-bit executable).
* Extracts `ImageBase`, `SizeOfImage`, `SizeOfHeaders`, `AddressOfEntryPoint`, and Data Directory RVA offsets for **Import Table** (Index 1) and **Base Relocation Table** (Index 5).

### Step 2: Memory Space Allocation
* Calls `VirtualAlloc(PreferredBase, SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)`.
* If preferred `ImageBase` is unavailable, allocates at an arbitrary address (`lpAddress = NULL`), calculating the reallocation delta:
  $$\Delta = \text{BaseAddress}_{\text{allocated}} - \text{ImageBase}_{\text{header}}$$

### Step 3: Section Parsing and Memory Layout
* Iterates through the Section Header table (`IMAGE_SECTION_HEADER`).
* For each section (`.text`, `.rdata`, `.data`, `.pdata`, `.rsrc`):
  * Computes destination pointer: `BaseAddress + VirtualAddress`.
  * Copies `SizeOfRawData` bytes from file buffer offset `PointerToRawData` to the allocated virtual address.

### Step 4: Base Relocation Fixups
When the binary is relocated ($\Delta \neq 0$), the loader processes the Base Relocation Table:
* Parses `IMAGE_BASE_RELOCATION` blocks containing `VirtualAddress` and `SizeOfBlock`.
* Computes number of entries: $\text{Count} = \frac{\text{SizeOfBlock} - 8}{2}$.
* For each 16-bit descriptor:
  * **Type** (Upper 4 bits): Identifies fixup type (`IMAGE_REL_BASED_DIR64` = `10`, `IMAGE_REL_BASED_HIGHLOW` = `3`).
  * **Offset** (Lower 12 bits): Offset relative to block `VirtualAddress`.
  * **Patch Application:** Reads 64-bit value at target address, adds $\Delta$, and writes updated pointer back to memory.

### Step 5: Dynamic Import Address Table (IAT) Resolution
* Traverses the `IMAGE_IMPORT_DESCRIPTOR` array.
* For each imported DLL:
  * Resolves DLL name via ASCII pointer and loads module using `LoadLibraryA`.
  * Walks the Import Lookup Table (`OriginalFirstThunk` / `ILT`) and Import Address Table (`FirstThunk` / `IAT`).
  * Checks for ordinal imports (`IMAGE_ORDINAL_FLAG64` `0x8000000000000000`).
  * For named imports, reads `IMAGE_IMPORT_BY_NAME` and resolves export address via `GetProcAddress`.
  * Writes resolved function pointer directly into the corresponding IAT slot.

### Step 6: Memory Protection Realignment
Leaving memory as `PAGE_EXECUTE_READWRITE` (RWX) triggers behavioral memory scanners (e.g., memory scanners looking for RWX regions). The loader dynamically iterates over each section and applies precise page permissions via `VirtualProtect`:
- `.text` (Code) $\rightarrow$ `PAGE_EXECUTE_READ` (`0x20`)
- `.rdata` (Constants/Imports) $\rightarrow$ `PAGE_READONLY` (`0x02`)
- `.data` (Globals) $\rightarrow$ `PAGE_READWRITE` (`0x04`)

### Step 7: Execution Handoff
* Computes `EntryPoint = BaseAddress + AddressOfEntryPoint`.
* Instantiates a `DllMain` delegate signature:
  ```c
  BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);
  ```
* Invokes `DllMain(BaseAddress, DLL_PROCESS_ATTACH, NULL)`.

---

## 5. BYOVD Kernel Staging & Process Termination Mechanics

Once in-memory execution is established, the payload extracts and weaponizes a legitimately signed driver (`wsftprm.sys`, signed by TPZ SOLUCOES DIGITAIS LTDA, vulnerable to arbitrary process termination via `CVE-2023-52271`).

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              KERNEL TERMINATION DISPATCH FLOW                          │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│  [User-Mode PowerShell Process]                                                        │
│   ├── 1. Enable SeLoadDriverPrivilege (AdjustTokenPrivileges)                          │
│   ├── 2. Register Service Registry: HKLM\SYSTEM\CCS\Services\wsftprm                   │
│   ├── 3. Invoke NtLoadDriver("\Registry\Machine\System\CurrentControlSet\Services\...")│
│   ├── 4. Open Device Handle: CreateFileW("\\.\Warsaw_PM")                              │
│   ├── 5. Enumerate EDR Process Tree (CreateToolhelp32Snapshot)                         │
│   └── 6. Send IOCTL: DeviceIoControl(hDevice, 0x22201C, Buffer[TargetPID], 1036)       │
│                                │                                                       │
│                                ▼                                                       │
│  [Kernel-Mode: wsftprm.sys Driver Dispatch]                                            │
│   ├── Extracts DWORD Process ID at Buffer Offset 0                                     │
│   └── Calls Kernel API: ZwTerminateProcess(TargetPID, STATUS_SUCCESS)                  │
│                                │                                                       │
│                                ▼                                                       │
│  [Target EDR Daemons: MEERDInferenceEngine.exe, MEARWService.exe, etc.]               │
│   └── Destroyed instantly by kernel authority without alert generation                 │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### The Driver Vulnerability Mechanism:
1. The driver exposes a symbolic link `\\.\Warsaw_PM`.
2. IOCTL `0x22201C` expects a 1036-byte buffer.
3. The driver takes the first 4 bytes as a target Process ID (PID) and passes it directly to `ZwTerminateProcess`.
4. Because the call executes in kernel space (Ring 0) with system privileges, it bypasses:
   - User-mode API hooks in `ntdll.dll` / `kernel32.dll`.
   - Discretionary Access Control Lists (DACLs) protecting security services.
   - Process watchdog timers and anti-tamper heartbeat checks.

---

## 6. Target Process Inventory & Kill Ordering

The termination routine executes a structured sweep across all parent daemons and child worker threads to prevent automated watchdog restarts:

| Target Process Name | Functional Role in ManageEngine EDR |
| :--- | :--- |
| `MEERDInferenceEngine.exe` | Machine Learning / AI Behavioral Inference Engine |
| `MEARWService.exe` | Core Anti-Ransomware Monitor & Protection Service |
| `MEEDRMCEngine.exe` | EDR Management Console Rule & Policy Evaluator |
| `MEEDRSyncAgent.exe` | Cloud Synchronization, Heartbeat & Alert Exfiltration Agent |
| `MEARWFltSvc64.exe` / `MEARWFltSvc.exe` | Minifilter Communication Bridge |
| `McDetection.exe` / `McScanAlert.exe` | Local Detection & Alert Generation Service |
| `MERollbackSvc.exe` | Snapshot & Anti-Ransomware Rollback Engine |
| `dcagentservice.exe` / `UEMS_Agent.exe` | Central Endpoint Management Agent Daemon |
| `UEMSAgentHealthChecker.exe` / `AgentHealthMonitor.exe` | Agent Health Watchdogs |

---

## 7. Why Maxed-Out EDR Policies Were Evaded

| Configured Security Policy | Intended Defensive Function | Why It Was Completely Evaded |
| :--- | :--- | :--- |
| **Real-time On-Write Deep AV** | Intercept and quarantine malicious PE files upon creation. | Payloads on disk are XOR-encoded data files. Executable PE structures are constructed strictly in RAM. |
| **Aggressive Behavioral Heuristics** | Detect suspicious API call sequences and process injections. | API calls are made via standard P/Invoke signatures inside signed `powershell.exe`; memory sections are realigned to non-RWX permissions. |
| **Ransomware Prevention: "Kill Process"** | Instantly terminate processes performing unauthorized operations. | Process termination is offloaded to a signed kernel driver; the EDR daemons are destroyed before heuristic correlation can occur. |
| **Decoy Engine & File Canaries** | Detect ransomware touching bait files. | No target user files are touched until after the entire EDR process suite is terminated. |

---

## 8. Vendor Communication & Industry Response

> [!NOTE]
> **Vendor Acknowledgment:**
> Zoho's internal security engineering team acknowledges the broader industry challenge posed by BYOVD attacks and administrator-to-kernel transition vulnerabilities. Enhancements to agent self-defense mechanisms, driver blocklist integration, and service isolation are being introduced in upcoming product releases.

---

## 9. Blue Team Detection Rules & Defensive Mitigations

### A. Sigma Rule: Vulnerable Driver Service Registration

```yaml
title: Installation of Known Vulnerable Driver Service (CVE-2023-52271)
status: production
description: Detects service installation for vulnerable Warsaw/Topaz kernel drivers used in BYOVD attacks.
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName|contains:
            - 'wsftprm'
            - 'Warsaw_PM'
    condition: selection
level: critical
```

### B. Sigma Rule: Mass EDR Process Termination

```yaml
title: Rapid Sequential Termination of ManageEngine EDR Daemons
status: production
description: Detects abnormal termination of ManageEngine EDR security suite components.
logsource:
    product: windows
    category: process_termination
detection:
    selection:
        Image|endswith:
            - '\MEERDInferenceEngine.exe'
            - '\MEARWService.exe'
            - '\MEEDRMCEngine.exe'
            - '\MEEDRSyncAgent.exe'
            - '\MEARWFltSvc64.exe'
            - '\MERollbackSvc.exe'
    condition: selection
level: critical
```

---

## 10. Comprehensive Defensive Recommendations

1. **Enable Hypervisor-Protected Code Integrity (HVCI):**
   Enforcing HVCI prevents unsigned code from running in the kernel and enforces the Microsoft Vulnerable Driver Blocklist.
2. **Deploy Windows Defender Application Control (WDAC) Driver Block Rules:**
   Actively block known vulnerable driver hashes (including `wsftprm.sys` and other [LOLDrivers](https://www.loldrivers.io/) entries).
3. **Implement Protected Process Light (PPL) for Agent Daemons:**
   Sign EDR services with an Early Launch Anti-Malware (ELAM) certificate to prevent unauthorized process handle opening from non-PPL entities.
4. **Register Kernel Object Callbacks (`ObRegisterCallbacks`):**
   Configure the EDR's kernel minifilter (`MEARWFltDriver.sys`) to strip `PROCESS_TERMINATE` and `PROCESS_SUSPEND` rights from any handle requested against ManageEngine processes.
