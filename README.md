<div align="center">

<img src="assets/avatar.png" width="130" alt="MEEDR Bleeder" />

# MEEDR Bleeder
### ManageEngine EDR Telemetry Dismantling & Kernel Minifilter Vulnerability Assessment

[![Target](https://img.shields.io/badge/TARGET-MANAGEENGINE%20EDR-0d1117?style=for-the-badge&logo=target&logoColor=crimson)](https://github.com/thechosenone-shall-prevail/MEEDRBleeder)
[![Classification](https://img.shields.io/badge/CLASSIFICATION-KERNEL%20%26%20TELEMETRY%20EVASION-0d1117?style=for-the-badge&logo=hackthebox&logoColor=red)](https://github.com/thechosenone-shall-prevail/MEEDRBleeder)
[![Execution](https://img.shields.io/badge/STATUS-CONFIRMED%20LIVE-0d1117?style=for-the-badge&logo=target&logoColor=darkred)](https://github.com/thechosenone-shall-prevail/MEEDRBleeder)
[![Vendor](https://img.shields.io/badge/VENDOR-ACKNOWLEDGED%20BY%20ZOHO-0d1117?style=for-the-badge&logo=shield&logoColor=crimson)](https://github.com/thechosenone-shall-prevail/MEEDRBleeder)

<br/>

```
When a software is well-engineered, you don't evade it.
You bleed it with a hundred cuts.
```

---

</div>

## Executive Summary

This repository documents two critical vulnerability and evasion findings developed during an adversarial assessment of **ManageEngine Endpoint Detection & Response (EDR) / Unified Endpoint Management & Security (UEMS)** (`v1.0.80.10`).

Testing was conducted against an enterprise installation configured with **maximum protection policies**:
* **Prevention Policy:** Set to `Kill process`
* **Detection Sensitivity:** Set to `Aggressive`
* **Decoy System:** Enabled
* **Deep AV & Heuristic Engine:** Active real-time on-write scanning

Under these conditions, the endpoint protection suite was systematically bypassed and neutralized across two separate vectors: a logic defect in the driver's VSS protection routine, and an in-memory reflective BYOVD process termination loop.

---

## Research Index

| Document | Scope | Impact |
| :--- | :--- | :--- |
| **[VSS_SNAPSHOT_PROTECTION_BYPASS.md](VSS_SNAPSHOT_PROTECTION_BYPASS.md)** | **Finding #12: VSS Delete Guard Semantic Mismatch**<br/>Static reverse engineering and live kernel debug verification of `MEARWFltDriver.sys`, showing `IOCTL_VOLSNAP_DELETE_SNAPSHOT` checks against base volume paths instead of shadow-copy namespaces, allowing unhindered shadow copy deletion. | **High**<br/>Anti-Ransomware Safeguard Failure |
| **[EDR_RESILIENCE_BYOVD_METHODOLOGY.md](EDR_RESILIENCE_BYOVD_METHODOLOGY.md)** | **In-Memory Deep AV Evasion & BYOVD Killswitch**<br/>Technical analysis of multi-stage XOR payload de-obfuscation, manual PE loading in memory (`NativeLoader`), kernel driver staging via `NtLoadDriver`, and arbitrary process termination via `ZwTerminateProcess`. | **Critical**<br/>Complete EDR Telemetry Severance |

---

## Vector I: Minifilter Volume Shadow Copy Guard Bypass

ManageEngine EDR relies on a kernel minifilter driver (`MEARWFltDriver.sys`, internal name `EventCollectorDriver`) to prevent unauthorized deletion of Windows Volume Shadow Copies (VSS restore points) via `IOCTL_VOLSNAP_DELETE_SNAPSHOT` (`0x53C038`).

### Object Namespace Semantic Defect

```
[ Caller: VSS Deletion Request ]
                │
                ▼
[ MEARWFltDriver.sys Pre-Op Callback: FUN_14000a890 ]
                │
                ▼
[ Decision Helper: FUN_1400295f4 ]
                │
       ┌────────┴────────┐
       ▼                 ▼
Delete Target:      Enumerated Volume:
\Device\HarddiskVolumeShadowCopy20    \Device\HarddiskVolume3
       │                 │
       └────────┬────────┘
                ▼
Substring Match: wcsstr("\Device\HarddiskVolumeShadowCopy20", "\Device\HarddiskVolume3")
                │
                ▼
       [ Result: NULL / Mismatch ]
                │
                ▼
[ Block Decision Skipped -> Request Forwarded to Volsnap -> Snapshot Deleted ]
```

* **Root Cause:** When `FUN_1400295f4` evaluates a snapshot deletion target, it queries mounted Filter Manager volumes using `FltGetVolumeName`, returning base volume paths such as `\Device\HarddiskVolume3`. It performs a substring match (`wcsstr`) checking if the deletion target contains the base volume string. Because legitimate shadow-copy targets belong to the `\Device\HarddiskVolumeShadowCopy*` namespace, the comparison fails on the first differing character (`'S'` vs `'3'`). The driver logs `Mismatch` and allows the request through.
* **Positive Control:** Submitting a synthetic buffer containing `\Device\HarddiskVolume3` immediately triggers `IOCTL_VOLSNAP_DELETE_SNAPSHOT BLOCKED`. This proves the blocking logic is reachable in code, but fails for legitimate shadow copy deletions due to the incorrect string comparison key.

---

## Vector II: In-Memory Reflective BYOVD Killswitch

```
In the silence between kernel calls, death is written.
```

The second research vector analyzes the resilience of ManageEngine's user-mode EDR agents when subjected to in-memory reflective execution and Bring Your Own Vulnerable Driver (BYOVD) primitives:

```
[ Phase 1: Payload Obfuscation ]
  └── Non-PE encrypted raw binary on disk (vproxy_xor.bin)
  └── Single-byte XOR key (0x41) eliminates PE headers ('MZ' / 'PE\0\0')
  └── On-write ML heuristics and Deep AV scanners register inert file data

[ Phase 2: In-Memory PE Reconstruction ]
  └── In-memory de-XOR executed inside Microsoft-signed powershell.exe host
  └── Custom NativeLoader executes complete in-memory mapping:
      • VirtualAlloc commit/reserve memory allocation
      • Section mapping (.text, .rdata, .data, .rsrc)
      • Base Relocation parsing and delta patching (IMAGE_REL_BASED_DIR64 / HIGHLOW)
      • Import Address Table resolution via LoadLibraryA / GetProcAddress
      • Page protection alignment via VirtualProtect (RX / RO / RW)
  └── Invocation of DllMain(DLL_PROCESS_ATTACH) via stdcall delegate

[ Phase 3: Vulnerable Driver Staging & Termination ]
  └── Extraction of embedded driver blob from .rsrc (RT_RCDATA / ID 200)
  └── De-XOR driver buffer with secondary key (0x5A)
  └── Acquire SeLoadDriverPrivilege via AdjustTokenPrivileges
  └── Registry key provisioning + driver load via NtLoadDriver syscall
  └── Open handle to \\.\Warsaw_PM device symbolic link (CVE-2023-52271)
  └── Toolhelp32 process snapshot enumeration of target EDR daemons
  └── Dispatch IOCTL 0x22201C containing target PIDs
  └── Driver executes ZwTerminateProcess from Ring 0
```

---

## Target Process Architecture

The kill routine permanently terminates the entire suite of security processes:

| Process Name | Architectural Role |
| :--- | :--- |
| `MEERDInferenceEngine.exe` | Behavioral Machine Learning / AI Inference Engine |
| `MEARWService.exe` | Core Anti-Ransomware Monitoring Service |
| `MEEDRMCEngine.exe` | Management Console Rule & Heuristic Engine |
| `MEEDRSyncAgent.exe` | Cloud Synchronization & Alert Dispatcher |
| `MEARWFltSvc64.exe` / `MEARWFltSvc.exe` | Minifilter Communication Bridge |
| `McDetection.exe` / `McScanAlert.exe` | Local Threat Detection Daemons |
| `MERollbackSvc.exe` | Volume & File Rollback Engine |
| `UEMSAgentHealthChecker.exe` / `AgentHealthMonitor.exe` | Agent Health Watchdogs |
| `dcagentservice.exe` / `UEMS_Agent.exe` | Central Endpoint Management Daemons |

---

## Live Kernel Telemetry Evidence

### Real VSS Deletion Allowed Due to Mismatch
```text
[Kernel DebugView Excerpt - MEARWFltDriver.sys]
Buffer : 70 D\Device\HarddiskVolumeShadowCopy19
VolumeName \Device\HarddiskVolume3 D\Device\HarddiskVolumeShadowCopy19
Mismatch

Buffer : 70 D\Device\HarddiskVolumeShadowCopy20
VolumeName \Device\HarddiskVolume3 D\Device\HarddiskVolumeShadowCopy20
Mismatch
```

### Positive Control Triggering Block Branch
```text
[Kernel DebugView Excerpt - Positive Control Validation]
Buffer : 48 \Device\HarddiskVolume3
VolumeName \Device\HarddiskVolume3 \Device\HarddiskVolume3
Matched perfectly
IOCTL_VOLSNAP_DELETE_SNAPSHOT BLOCKED
```

---

## Enterprise Defenses & Hardening

1. **Hypervisor-Protected Code Integrity (HVCI):** Enforces hypervisor-level code integrity and activates the Microsoft Vulnerable Driver Blocklist.
2. **Windows Defender Application Control (WDAC):** Deploys explicit driver block rules against known vulnerable drivers (including `wsftprm.sys`).
3. **Protected Process Light (PPL):** EDR vendors should sign agent services with an ELAM certificate to enforce `ProtectedProcessLight`, blocking handle acquisition from non-protected callers.
4. **Kernel Object Callbacks:** Minifilters should implement `ObRegisterCallbacks` to strip `PROCESS_TERMINATE` and `PROCESS_SUSPEND` access masks from untrusted callers targeting agent processes.

---

## Research Disclosure Notice

This repository is published strictly for technical research, threat simulation, and defensive engineering. It provides blue teams, detection authors, and vendors with the architectural insights required to harden security telemetry against sophisticated adversaries.

No functional exploit binaries or offensive PowerShell scripts are hosted in this repository.
