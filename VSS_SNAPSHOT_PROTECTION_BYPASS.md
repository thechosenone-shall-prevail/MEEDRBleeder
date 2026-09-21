# Vulnerability Report: VSS Shadow-Copy Deletion Guard Bypass in ManageEngine EDR

| Detail | Specification |
| :--- | :--- |
| **Product** | ManageEngine UEMS Agent — EDR / Anti-Ransomware Suite |
| **Component** | `MEARWFltDriver.sys` (Kernel Minifilter Driver / `EventCollectorDriver`) |
| **Observed Version** | `1.0.80.10` (x64) |
| **Vulnerability Class** | Security Feature Bypass / Object Namespace Semantic Comparison Defect |
| **Operation** | `IOCTL_VOLSNAP_DELETE_SNAPSHOT` (`0x53C038`) |
| **Relevant Routines** | `VssProtection_PreOp_Callback` (`FUN_14000a890`), `FUN_1400295f4` |
| **Severity** | High (CVSS: 7.1 — Anti-Ransomware Recovery Inhibition / Defense Evasion) |
| **Status** | Confirmed (Reverse Engineering + Live Kernel Telemetry + Positive Control Validation) |

---

## 1. Executive Summary

ManageEngine EDR incorporates an anti-ransomware kernel minifilter driver (`MEARWFltDriver.sys`) designed to protect Windows Volume Shadow Copies (VSS restore points) from unauthorized deletion. When malicious actors or ransomware attempt to delete restore points before file encryption, the driver intercepts the volume snapshot deletion IOCTL (`IOCTL_VOLSNAP_DELETE_SNAPSHOT`) and evaluates whether the request targets a protected volume.

**The deletion guard is structurally flawed and ineffective.** During evaluation, the driver compares the shadow-copy deletion target name against base-volume device names using a case-sensitive substring comparison. Because shadow-copy device names (`\Device\HarddiskVolumeShadowCopyN`) do not contain base-volume strings (`\Device\HarddiskVolume3`), the comparison always yields `Mismatch`. As a result, standard shadow-copy deletion requests bypass the block logic entirely and succeed, even when the EDR console policy is configured to **Kill process** on ransomware actions.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                            VSS DELETION FLOW COMPARISON                      │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  [Caller: vssadmin / PowerShell / Ransomware]                                │
│         │                                                                    │
│         ▼                                                                    │
│  IOCTL_VOLSNAP_DELETE_SNAPSHOT (Target: \Device\HarddiskVolumeShadowCopy20)  │
│         │                                                                    │
│         ▼                                                                    │
│  MEARWFltDriver.sys (VssProtection_PreOp_Callback)                           │
│         │                                                                    │
│         ▼                                                                    │
│  Enumerate Mounted Volumes (FltGetVolumeName) -> "\Device\HarddiskVolume3"  │
│         │                                                                    │
│         ▼                                                                    │
│  Substring Search: wcsstr("\Device\HarddiskVolumeShadowCopy20",              │
│                           "\Device\HarddiskVolume3")                         │
│         │                                                                    │
│         ├─── Match? ──► [NO: Character mismatch at index 20 ('S' != '3')]    │
│         │                                                                    │
│         ▼                                                                    │
│  Result: Driver logs "Mismatch" -> Request PASSED to Volsnap (SNAPSHOT LOST) │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Technical Root Cause Analysis

### A. Semantic Comparison Mismatch

When `IOCTL_VOLSNAP_DELETE_SNAPSHOT` (`0x53C038`) is dispatched, the pre-operation callback routes the request to decision helper `FUN_1400295f4`:

1. The function extracts the delete target buffer from the incoming I/O request packet (e.g., `\Device\HarddiskVolumeShadowCopy20`).
2. It iterates through all volume objects attached to the Filter Manager by invoking `FltGetVolumeName`.
3. For each volume, it retrieves the base-volume name (e.g., `\Device\HarddiskVolume3` for `C:\`).
4. It performs a substring match:
   ```c
   // Conceptual decompilation of FUN_1400295f4
   if (wcsstr(DeleteTargetBuffer, BaseVolumeName) != NULL) {
       DbgPrint("Matched perfectly\n");
       DbgPrint("IOCTL_VOLSNAP_DELETE_SNAPSHOT BLOCKED\n");
       return STATUS_ACCESS_DENIED;
   } else {
       DbgPrint("Mismatch\n");
   }
   return STATUS_SUCCESS;
   ```
5. A real shadow-copy device string belongs to a different object namespace/class than the base volume device:
   - **Delete Target:** `\Device\HarddiskVolumeShadowCopy20`
   - **Enumerated Base Volume:** `\Device\HarddiskVolume3`
   - **Comparison:** Character index 20 contains `'S'`, not `'3'`. `wcsstr` returns `NULL`.

Because a canonical object identity resolution is never performed, every real VSS snapshot deletion is treated as an unmatched request and permitted.

### B. Secondary Buffer Length Defect

In `FUN_1400295f4`, an additional flaw exists where memory is copied using `InputBufferLength * 2` bytes (`memcpy(dst, src, len * 2)` where `len` is already a byte count). This causes an out-of-bounds read past the end of the input buffer into adjacent pool memory during string parsing.

---

## 3. Verification & Live Kernel Telemetry

### Test A: Real VSS Deletion (Negative Control / Bug Reproduction)

A standard Windows administrative snapshot deletion was performed via WMI/CIM while monitoring kernel debug messages from `MEARWFltDriver.sys` via DebugView:

```powershell
$created = (Get-WmiObject -List Win32_ShadowCopy).Create('C:\', 'ClientAccessible')
$shadow = Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $created.ShadowID }
$shadow | Remove-CimInstance -ErrorAction Stop
```

**Captured Kernel Debug Output (`F12_PROOF_dbgview.log`):**
```text
Buffer : 70 D\Device\HarddiskVolumeShadowCopy19
VolumeName \Device\HarddiskVolume3 D\Device\HarddiskVolumeShadowCopy19
Mismatch

Buffer : 70 D\Device\HarddiskVolumeShadowCopy20
VolumeName \Device\HarddiskVolume3 D\Device\HarddiskVolumeShadowCopy20
Mismatch
```

*Observation:* The driver intercepts the deletion, receives the shadow copy target name, checks base volumes, logs `Mismatch`, and allows the snapshot to be permanently destroyed.

---

### Test B: Positive Control (Block Path Validation)

To verify that the block branch was not disabled by policy, missing configuration, or compiled out, a positive-control request was sent providing a buffer containing the exact base-volume string (`\Device\HarddiskVolume3`).

**Captured Kernel Debug Output (`F12_PROOF_positive_control.log`):**
```text
Buffer : 48 \Device\HarddiskVolume3
VolumeName \Device\HarddiskVolume3 \Device\HarddiskVolume3
Matched perfectly
IOCTL_VOLSNAP_DELETE_SNAPSHOT BLOCKED

Buffer : 76 prefix \Device\HarddiskVolume3 suffix
VolumeName \Device\HarddiskVolume3 prefix \Device\HarddiskVolume3 suffix
Greater length matched because not a number
IOCTL_VOLSNAP_DELETE_SNAPSHOT BLOCKED
```

*Conclusion:* The positive control proves that the blocking mechanism is active and reachable in the compiled binary; it only fails during real attacks because the driver searches for the wrong string class.

---

## 4. Why Configuration & Policy Cannot Fix This

1. **Driver-Level Toggle:** The VSS delete guard is controlled solely by the internal registry value `disable_vss_deletesnapshot` (default `0` = protection active).
2. **Independent from Prevention Level:** Static analysis of settings parser `FUN_140028a38` demonstrates that `RansomwarePreventionLevel` (Audit vs Kill Process) governs behavioral heuristics, not the VSS filter callback.
3. **Live Policy Confirmation:** Even with console policies enforced at maximum aggressiveness with "Kill Process" enabled, snapshots are deleted without triggering an alert or block.

---

## 5. Security Impact & Threat Modeling

| Metric | Details |
| :--- | :--- |
| **MITRE ATT&CK Mapping** | [T1490 - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/), [T1562.001 - Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| **Impact on Ransomware Defense** | Volume Shadow Copies are the primary fallback mechanism for local system restoration following a ransomware attack. Bypassing VSS protection leaves enterprise endpoints unable to recover via local snapshots. |
| **Sibling IOCTL Protections** | Unconditional blocking for sibling IOCTLs (`DELETE_OLDEST`, `VOLUME_OFFLINE`, `SET_APPLICATION_INFO`, `DISMOUNT`) remains functional. Only `IOCTL_VOLSNAP_DELETE_SNAPSHOT` suffers from this name-comparison defect. |

---

## 6. Remediation & Hardening Guidance

To resolve this defect, the vendor driver must implement proper kernel object resolution:

1. **Resolve to Canonical Object Identity:** Rather than performing raw string comparisons on display paths, resolve the target device object to its underlying Volume Device Object (VDO) or query Volsnap for the owning volume relation.
2. **Parse Shadow-Copy Indices Safely:** If string matching is used, parse the `HarddiskVolumeShadowCopy` prefix and resolve the corresponding volume map.
3. **Correct Buffer Length Arithmetic:** Eliminate `len * 2` multiplication on byte-length variables when calling memory copy routines.
4. **Fail-Closed Strategy:** In the event of string allocation or namespace resolution errors, the driver should fail securely (deny the deletion) rather than failing open.
