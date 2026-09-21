<div align="center">

<img src="assets/avatar.png" width="140" alt="MEEDR Bleeder" />

# M E E D R &nbsp; B L E E D E R
### Advanced Adversarial Research & Telemetry Evasion on ManageEngine EDR

[![Target](https://img.shields.io/badge/TARGET-MANAGEENGINE%20EDR-0d1117?style=for-the-badge&logo=target&logoColor=crimson)](https://github.com/thechosenone-shall-prevail/MEEDRBleeder)
[![Classification](https://img.shields.io/badge/CLASSIFICATION-KERNEL%20%26%20TELEMETRY%20EVASION-0d1117?style=for-the-badge&logo=hackthebox&logoColor=red)](https://github.com/thechosenone-shall-prevail/MEEDRBleeder)
[![Execution](https://img.shields.io/badge/STATUS-WEAPONIZED%20RESEARCH%20CONFIRMED-0d1117?style=for-the-badge&logo=target&logoColor=darkred)](https://github.com/thechosenone-shall-prevail/MEEDRBleeder)
[![Vendor](https://img.shields.io/badge/VENDOR-ACKNOWLEDGED%20BY%20ZOHO-0d1117?style=for-the-badge&logo=shield&logoColor=crimson)](https://github.com/thechosenone-shall-prevail/MEEDRBleeder)

<br/>

```
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║  OPERATION   : MEEDR BLEEDER                                          ║
    ║  OBJECTIVE   : Full Blindness & Anti-Ransomware Invalidation          ║
    ║  TARGET      : ManageEngine UEMS / EDR Agent v1.0.80.10               ║
    ║  ENVIRONMENT : Maxed Heuristics, Aggressive Prevention ("Kill Proc")  ║
    ║  OUTCOME     : Total Telemetry Severance & Silent VSS Neutralization  ║
    ╚═══════════════════════════════════════════════════════════════════════╝
```

> *"When an endpoint protection suite is hardened with aggressive heuristics and active process-termination policies, you do not challenge its detection boundaries.*  
> *You bleed its underlying kernel primitives until every sensor goes dark."*

---

</div>

## ⚔️ Threat Landscape & Executive Briefing

This repository details advanced offensive research into the architectural failure modes of **ManageEngine Endpoint Detection & Response (EDR) / Unified Endpoint Management & Security (UEMS)**. 

During rigorous adversarial validation inside an enterprise testbed running **maximum protection policies** (Prevention Policy: *Kill Process*, Detection Sensitivity: *Aggressive*, Decoy System: *Active*, Deep AV & ML Scan: *Real-time On-Write*), the EDR agent was completely neutralized across two distinct operational phases:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              ATTACK VECTOR ARCHITECTURE                                │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                        │
│  [PHASE 01: MINIFILTER LOGIC DEFECT] ─────────────► [VSS PROTECTION COLLAPSE]          │
│   • Component: MEARWFltDriver.sys                   • IOCTL 0x53C038 Semantic Mismatch │
│   • Flaw: Namespace comparison failure              • Unrestricted shadow-copy purge   │
│   • Impact: Invalidation of ransomware rollback guarantees without triggering alerts  │
│                                                                                        │
│  [PHASE 02: IN-MEMORY REFLECTIVE BYOVD] ──────────► [RING 0 SENSOR EXTINCTION]         │
│   • Loader: NativeLoader in-memory PE rebuild       • Pure RAM staging via XOR 0x41    │
│   • Primitive: Dual-stage driver staging (0x5A)     • Arbitrary ZwTerminateProcess loop│
│   • Impact: Complete decapitation of all AI, heuristic & cloud telemetry daemons      │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📑 Research Papers

| Document | Operational Scope | Severity |
| :--- | :--- | :--- |
| 📄 **[`VSS_SNAPSHOT_PROTECTION_BYPASS.md`](VSS_SNAPSHOT_PROTECTION_BYPASS.md)** | **Finding #12: VSS Delete Guard Semantic Mismatch**<br/>Deep disassembly analysis of `MEARWFltDriver.sys`, detailing how `IOCTL_VOLSNAP_DELETE_SNAPSHOT` checks the wrong device namespace, permitting complete volume recovery destruction. | <kbd>**HIGH**</kbd><br/>Anti-Ransomware Failure |
| 📄 **[`EDR_RESILIENCE_BYOVD_METHODOLOGY.md`](EDR_RESILIENCE_BYOVD_METHODOLOGY.md)** | **In-Memory Deep AV Evasion & BYOVD Execution**<br/>Step-by-step engineering breakdown of fileless dual-layer XOR de-obfuscation, manual PE mapping in `powershell.exe`, driver deployment via `NtLoadDriver`, and Ring 0 process termination. | <kbd>**CRITICAL**</kbd><br/>Total EDR Decapitation |

---

## ⚡ Technical Deep Dive: Vector I — The Broken Minifilter

To mitigate ransomware attacks, ManageEngine deploys a kernel minifilter (`MEARWFltDriver.sys` / `EventCollectorDriver`) tasked with filtering volume operations and blocking `IOCTL_VOLSNAP_DELETE_SNAPSHOT` (`0x53C038`).

### The Root Cause: Object Namespace Semantic Defect

```
                    [ IOCTL_VOLSNAP_DELETE_SNAPSHOT (0x53C038) ]
                                         │
                                         ▼
                      [ Filter Pre-Op: FUN_14000a890 ]
                                         │
                                         ▼
                      [ Decision Routine: FUN_1400295f4 ]
                                         │
                ┌────────────────────────┴────────────────────────┐
                ▼                                                 ▼
      Target Buffer from Volsnap                      Enumerated Base Volumes
    \Device\HarddiskVolumeShadowCopy20               \Device\HarddiskVolume3
                │                                                 │
                └────────────────────────┬────────────────────────┘
                                         ▼
                   Case-Sensitive Substring Comparison:
             wcsstr("\Device\HarddiskVolumeShadowCopy20", "\Device\HarddiskVolume3")
                                         │
                                         ▼
                          [ RESULT: POINTER IS NULL ]
                                         │
                         [ Emits "Mismatch" Diagnostic ]
                                         │
                                         ▼
                  [ Driver Allows Volsnap to Destroy Snapshot ]
```

* **The Design Flaw:** The minifilter attempts to validate whether a target belongs to a protected volume by checking if the delete target string *contains* the base volume path. Because shadow-copy objects exist in an entirely distinct device namespace (`\Device\HarddiskVolumeShadowCopy*`), substring comparison against `\Device\HarddiskVolume*` consistently fails.
* **Positive Control Validation:** Supplying a synthetic buffer containing `\Device\HarddiskVolume3` immediately triggers `IOCTL_VOLSNAP_DELETE_SNAPSHOT BLOCKED`. This proves the blocking logic is functional but unreachable under legitimate Windows VSS delete operations.

👉 **[Read the Full Reverse Engineering Analysis](VSS_SNAPSHOT_PROTECTION_BYPASS.md)**

---

## 💀 Technical Deep Dive: Vector II — In-Memory BYOVD Killswitch

Where traditional attacks attempt basic service termination via `sc.exe` or `net stop` (which fail against ACLs and watchdogs), **MEEDR Bleeder** demonstrates an APT-level execution chain:

```
[ STAGE 01 : OBFUSCATION ]
  └── Encrypted payload staging on disk as raw byte stream (vproxy_xor.bin)
  └── Single-byte XOR key 0x41 strips all PE structure ('MZ', 'PE\0\0')
  └── On-Write ML heuristic scanners categorize the file as inert binary telemetry

[ STAGE 02 : IN-MEMORY REFLECTIVE MAPPING ]
  └── Execution spawned within Microsoft-signed powershell.exe host
  └── In-memory de-XOR reconstructs valid PE image entirely in RAM
  └── Custom NativeLoader executes complete PE loading lifecycle:
      • VirtualAlloc commit/reserve without touching disk
      • Manual section allocation (.text, .rdata, .data, .rsrc)
      • Base Relocation fixups (IMAGE_REL_BASED_DIR64 / HIGHLOW)
      • Dynamic IAT resolution (LoadLibraryA / GetProcAddress with ordinal support)
      • Realignment of page protections via VirtualProtect (RX / RO / RW)
  └── Invocation of DllMain(DLL_PROCESS_ATTACH) via stdcall delegate

[ STAGE 03 : KERNEL STAGING & ARBITRARY TERMINATION ]
  └── Traversal of .rsrc section tree (RT_RCDATA / ID 200) to extract driver blob
  └── De-XOR driver buffer with secondary key 0x5A
  └── Privilege elevation: Enable SeLoadDriverPrivilege via AdjustTokenPrivileges
  └── Registry key provisioning + driver load via NtLoadDriver syscall
  └── Open handle to \\.\Warsaw_PM device symbolic link (CVE-2023-52271)
  └── Process32First/Next enumeration of active EDR daemons & worker subtrees
  └── Transmission of IOCTL 0x22201C containing target PIDs
  └── Vulnerable driver calls ZwTerminateProcess from Ring 0
```

### Neutralized EDR Target Suite

The kill routine permanently terminates the entire suite of security processes:

| Process Image | Architecture Role |
| :--- | :--- |
| `MEERDInferenceEngine.exe` | Machine Learning Behavioral Analysis Engine |
| `MEARWService.exe` | Core Anti-Ransomware & Rollback Sensor |
| `MEEDRMCEngine.exe` | Management Console Rule & Policy Evaluator |
| `MEEDRSyncAgent.exe` | Cloud Sync, Alerting & Remote Command Handler |
| `MEARWFltSvc64.exe` | Minifilter Driver Communication Bridge |
| `McDetection.exe` / `McScanAlert.exe` | Local Threat Detection Daemons |
| `MERollbackSvc.exe` | Automated Volume & File Rollback Engine |
| `UEMSAgentHealthChecker.exe` | Agent Health Watchdog & Self-Healing Service |
| `dcagentservice.exe` | Core Enterprise Agent Controller |

👉 **[Read the Full Low-Level Methodology Paper](EDR_RESILIENCE_BYOVD_METHODOLOGY.md)**

---

## 🔬 Telemetry & Kernel Evidence

### Live Negative Control (Real Deletion Unchecked)
```text
[Kernel DebugView Excerpt - MEARWFltDriver.sys]
Buffer : 70 D\Device\HarddiskVolumeShadowCopy19
VolumeName \Device\HarddiskVolume3 D\Device\HarddiskVolumeShadowCopy19
Mismatch

Buffer : 70 D\Device\HarddiskVolumeShadowCopy20
VolumeName \Device\HarddiskVolume3 D\Device\HarddiskVolumeShadowCopy20
Mismatch
```

### Positive Control (Proving the Logic Gate Defect)
```text
[Kernel DebugView Excerpt - Positive Control Validation]
Buffer : 48 \Device\HarddiskVolume3
VolumeName \Device\HarddiskVolume3 \Device\HarddiskVolume3
Matched perfectly
IOCTL_VOLSNAP_DELETE_SNAPSHOT BLOCKED
```

---

## 🛡️ Enterprise Defenses & Hardening

Organizations relying on ManageEngine EDR should enforce the following compensating controls:

1. **Enforce Hypervisor-Protected Code Integrity (HVCI):** Ensures the Microsoft Vulnerable Driver Blocklist is actively enforced at the hypervisor boundary.
2. **Implement WDAC Driver Block Rules:** Deploy strict Windows Defender Application Control policies to prevent staging of known vulnerable drivers (e.g., `wsftprm.sys`).
3. **PPL (Protected Process Light) Enforcement:** EDR vendors must isolate agent daemons inside PPL-Antimalware boundaries to deny arbitrary process handles.
4. **Kernel Object Callbacks:** The EDR minifilter must register `ObRegisterCallbacks` to strip `PROCESS_TERMINATE` rights requested against security daemons.

---

## ⚠️ Research Disclaimer

> [!CAUTION]
> This documentation is published strictly for technical research, threat simulation, and defensive engineering. It provides blue teams, detection authors, and vendors with the architectural insights required to harden security telemetry against sophisticated adversaries.  
> **No functional malware, weaponized PowerShell scripts, or exploit binaries are hosted in this repository.**
