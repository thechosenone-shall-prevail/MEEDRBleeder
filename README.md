<div align="center">

```
  __  __ _____ _____ ____  ____    ____  _     _____ _____ ____  _____ ____  
 |  \/  | ____| ____|  _ \|  _ \  | __ )| |   | ____| ____|  _ \| ____|  _ \ 
 | |\/| |  _| |  _| | | | | |_) | |  _ \| |   |  _| |  _| | | | |  _| | |_) |
 | |  | | |___| |___| |_| |  _ <  | |_) | |___| |___| |___| |_| | |___|  _ < 
 |_|  |_|_____|_____|____/|_| \_\ |____/|_____|_____|_____|____/|_____|_| \_\
```

### 🩸 In-Depth Security Assessment & Evasion Research on ManageEngine EDR 🩸

[![Target](https://img.shields.io/badge/TARGET-MANAGEENGINE%20EDR-8A0303?style=for-the-badge&logo=target&logoColor=white)](https://github.com/thechosenone-shall-prevail/MEEDRBleeder)
[![Research Class](https://img.shields.io/badge/CLASS-KERNEL%20%2F%20EVASION-660000?style=for-the-badge&logo=hackthebox&logoColor=white)](https://github.com/thechosenone-shall-prevail/MEEDRBleeder)
[![Status](https://img.shields.io/badge/EXPLOITATION-CONFIRMED%20LIVE-990000?style=for-the-badge&logo=target&logoColor=white)](https://github.com/thechosenone-shall-prevail/MEEDRBleeder)
[![Vendor](https://img.shields.io/badge/VENDOR-ACKNOWLEDGED-4A0000?style=for-the-badge&logo=shield&logoColor=white)](https://github.com/thechosenone-shall-prevail/MEEDRBleeder)

<br/>

> *“When security software claims enterprise resilience, you don’t just look for a single bypass.*  
> *You bleed it across its architectural seams until the entire telemetry chain fails.”*

---

</div>

## 🩸 Threat Landscape & Research Matrix

This repository documents two critical security research findings developed during an adversarial assessment of **ManageEngine Endpoint Detection & Response (EDR) / UEMS Agent**. 

Even with the EDR's policy set to **maximum enforcement** (*Ransomware Prevention: Kill Process*, *Detection Sensitivity: Aggressive*, *Decoy Engines: Enabled*, *Real-time Deep AV: Active*), the architecture was dismantled at two distinct layers:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              MEEDR BLEEDER ATTACK MATRIX                               │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│  [VECTOR 1] KERNEL DRIVER LOGIC DEFECT (FINDING #12)                                   │
│  ├── Component: MEARWFltDriver.sys (Kernel Minifilter Driver)                         │
│  ├── Mechanism: Semantic comparison mismatch in IOCTL_VOLSNAP_DELETE_SNAPSHOT          │
│  ├── Exploitation: Deletes Volume Shadow Copies undetected while EDR is active         │
│  └── Proof: Negative control mismatch vs positive control block verified in kernel log │
│                                                                                        │
│  [VECTOR 2] IN-MEMORY REFLECTIVE BYOVD KILLSWITCH                                      │
│  ├── Component: Entire User-Mode EDR Daemon & Sensor Suite                             │
│  ├── Mechanism: Dual-layer XOR fileless staging -> In-memory PE mapping (NativeLoader) │
│  ├── Exploitation: Staged vulnerable signed driver -> Ring 0 ZwTerminateProcess loop  │
│  └── Result: Complete, silent termination of all AI, heuristic & cloud sync daemons   │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📂 Research Papers & Technical Manifest

| Research Paper | Focus Area | Impact Level |
| :--- | :--- | :--- |
| 🩸 **[`VSS_SNAPSHOT_PROTECTION_BYPASS.md`](VSS_SNAPSHOT_PROTECTION_BYPASS.md)** | **Finding #12: VSS Delete Guard Semantic Mismatch**<br/>Exhaustive analysis of the kernel minifilter logic defect in `MEARWFltDriver.sys` that allows unauthorized deletion of shadow-copy recovery points. Includes disassembly flow and live debug proofs. | <kbd>**HIGH**</kbd><br/>Anti-Ransomware Invalidation |
| ⚔️ **[`EDR_RESILIENCE_BYOVD_METHODOLOGY.md`](EDR_RESILIENCE_BYOVD_METHODOLOGY.md)** | **Deep AV Evasion & In-Memory BYOVD Methodology**<br/>Low-level breakdown of the multi-tier XOR obfuscation, manual reflective PE mapping (`NativeLoader`), Ring 0 process termination mechanics, and architectural process-protection analysis. | <kbd>**CRITICAL**</kbd><br/>Complete EDR Disarmament |

---

## ⚔️ Chapter I: The Bleeding Driver (Finding #12)

When ransomware compromises a system, destroying **Volume Shadow Copies (VSS)** is its first objective to prevent backup restoration. ManageEngine deploys `MEARWFltDriver.sys` to intercept `IOCTL_VOLSNAP_DELETE_SNAPSHOT` (`0x53C038`) and block deletion requests.

### The Semantic Namespace Defect

```
[VSS Deletion Trigger]
         │
         ▼
[Driver Intercepts IOCTL 0x53C038]
         │
         ▼
[Target Buffer: "\Device\HarddiskVolumeShadowCopy20"]
         │
         ▼
[Driver Calls FltGetVolumeName() -> "\Device\HarddiskVolume3"]
         │
         ▼
[Case-Sensitive Substring Comparison: wcsstr()]
         │
         ├── Does Target contain Base Volume? ──► [MISMATCH]
         │
         ▼
[Block Logic Bypassed -> Volsnap Executes Deletion -> RECOVERY RESTORE DESTROYED]
```

* **The Reality:** Shadow-copy objects reside in the `\Device\HarddiskVolumeShadowCopyN` namespace. The driver checks for base volume strings (`\Device\HarddiskVolume3`). Because `'S'` $\neq$ `'3'`, the substring match returns `NULL`, driver debug logs emit `Mismatch`, and the snapshot is permanently deleted.
* **Confirmed with Telemetry:** Live kernel debug logs (`F12_PROOF_dbgview.log` vs `F12_PROOF_positive_control.log`) prove the block branch works if fed base strings, confirming the defect is purely a broken comparison key in production code.

👉 **[Read the Full Reverse Engineering & Kernel Proof Report](VSS_SNAPSHOT_PROTECTION_BYPASS.md)**

---

## 💀 Chapter II: The EDR Bleeder (In-Memory BYOVD Killswitch)

Enterprise EDRs pride themselves on **Deep AV**, **Behavioral Machine Learning**, and **Self-Defense Watchdogs**. The second research phase evaluated whether these controls could withstand a fileless, in-memory Bring Your Own Vulnerable Driver (BYOVD) attack under **maxed-out policy constraints**.

```
┌────────────────────────────────────────────────────────────────────────┐
│                      THE BLEEDER EXECUTION PIPELINE                    │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  [1. Disk Artifact: vproxy_xor.bin]                                    │
│      └── Raw binary stream (Encrypted with XOR key 0x41)               │
│      └── Zero PE magic bytes ('MZ' absent) -> Deep AV sees inert data  │
│                                                                        │
│  [2. In-Memory Reflection: NativeLoader P/Invoke]                      │
│      └── De-XOR buffer in RAM -> Native PE reconstructed in memory     │
│      └── Allocate commit/reserve memory via VirtualAlloc               │
│      └── Manual section copy (.text, .rdata, .data, .rsrc)             │
│      └── Base Relocation fixups (IMAGE_REL_BASED_DIR64 / HIGHLOW)      │
│      └── Dynamic IAT resolution via LoadLibraryA & GetProcAddress      │
│      └── Memory page permissions aligned (VirtualProtect RX/RO/RW)     │
│      └── Execute DllMain inside trusted host (powershell.exe)          │
│                                                                        │
│  [3. Resource Extraction & Staging]                                    │
│      └── Extract embedded driver blob from .rsrc (RT_RCDATA / ID 200)  │
│      └── De-XOR driver with secondary key (0x5A) in RAM                │
│      └── Enable SeLoadDriverPrivilege via token adjustment             │
│      └── Direct registry key creation + NtLoadDriver invocation        │
│                                                                        │
│  [4. Kernel Termination Loop: \\.\Warsaw_PM]                           │
│      └── Acquire device handle to CVE-2023-52271 driver                │
│      └── Snapshot target EDR process tree & active child workers       │
│      └── Dispatch IOCTL 0x22201C with target PID payload               │
│      └── Kernel calls ZwTerminateProcess() with Ring 0 authority       │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### 🎯 Neutralized EDR Processes

The kill routine systematically eliminates all ManageEngine parent engines and child workers:

```
  🩸 MEERDInferenceEngine.exe   (AI Behavioral Inference Engine)
  🩸 MEARWService.exe           (Core Anti-Ransomware Daemon)
  🩸 MEEDRMCEngine.exe          (Management Console & Heuristic Engine)
  🩸 MEEDRSyncAgent.exe         (Cloud Telemetry & Alert Dispatcher)
  🩸 MEARWFltSvc64.exe          (Minifilter Communication Bridge)
  🩸 McDetection.exe            (Local Threat Detection Worker)
  🩸 MERollbackSvc.exe          (File Recovery & Rollback Engine)
  🩸 UEMSAgentHealthChecker.exe (Agent Self-Defense Watchdog)
  🩸 dcagentservice.exe         (Central Management Daemon)
```

👉 **[Read the Full Methodology & Low-Level Evasion Paper](EDR_RESILIENCE_BYOVD_METHODOLOGY.md)**

---

## 🧪 Kernel Telemetry Evidence Snippets

### Real VSS Deletion Bypassing the Guard:
```text
[Kernel DebugView Excerpt - MEARWFltDriver.sys]
Buffer : 70 D\Device\HarddiskVolumeShadowCopy19
VolumeName \Device\HarddiskVolume3 D\Device\HarddiskVolumeShadowCopy19
Mismatch

Buffer : 70 D\Device\HarddiskVolumeShadowCopy20
VolumeName \Device\HarddiskVolume3 D\Device\HarddiskVolumeShadowCopy20
Mismatch
```

### Positive Control Proving the Defect:
```text
[Kernel DebugView Excerpt - Positive Control Validation]
Buffer : 48 \Device\HarddiskVolume3
VolumeName \Device\HarddiskVolume3 \Device\HarddiskVolume3
Matched perfectly
IOCTL_VOLSNAP_DELETE_SNAPSHOT BLOCKED
```

---

## 🛡️ Enterprise Mitigation & Blue Team Rules

To defend endpoints against this attack surface:

1. **Deploy Hypervisor-Protected Code Integrity (HVCI):** Enforces Microsoft’s Vulnerable Driver Blocklist to stop vulnerable drivers at load time.
2. **Implement Protected Process Light (PPL):** EDR vendors must sign service daemons with ELAM certificates to prevent arbitrary handle access.
3. **Register Kernel Object Callbacks:** Kernel drivers should register `ObRegisterCallbacks` to strip `PROCESS_TERMINATE` and `PROCESS_SUSPEND` rights from untrusted callers.
4. **Monitor System Event 7045 & Sysmon Event 6:** Alert on kernel driver service installations originating from user-writable directories.

---

## 🛑 Responsible Disclosure & Notice

> [!CAUTION]
> **Defensive & Research Intent:**  
> The artifacts, analyses, and detection signatures published in this repository are intended exclusively for authorized security practitioners, researchers, detection engineers, and vendor development teams.  
> **No weaponized binary exploits or PowerShell execution scripts are distributed.**
