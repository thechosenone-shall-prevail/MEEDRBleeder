# ManageEngine EDR Security Assessment & Research

This repository contains technical research, security findings, and defensive methodology from an in-depth security assessment of **ManageEngine Endpoint Detection and Response (EDR) / Unified Endpoint Management & Security (UEMS) Agent**.

---

## 📑 Research Overview

The assessment uncovered two key areas of analysis:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                               MANAGEENGINE EDR ASSESSMENT                              │
├───────────────────────────────────────────┬────────────────────────────────────────────┤
│ 1. Kernel Driver Logic Flaw (Finding #12) │ 2. BYOVD & EDR Process Resilience Analysis │
├───────────────────────────────────────────┼────────────────────────────────────────────┤
│ • Component: MEARWFltDriver.sys           │ • Component: User-mode EDR Service Suite   │
│ • Flaw: VSS Delete Guard Semantic Mismatch│ • Threat Model: Admin-to-Kernel BYOVD      │
│ • Impact: Ransomware VSS Deletion Bypass  │ • Impact: Complete EDR Disarming           │
│ • Status: Confirmed with live kernel logs │ • Defense: WDAC/HVCI, Driver Blocklist, PPL│
└───────────────────────────────────────────┴────────────────────────────────────────────┘
```

---

## 📂 Repository Contents

| Document | Description | Focus Area |
| :--- | :--- | :--- |
| **[VSS Snapshot Protection Bypass](VSS_SNAPSHOT_PROTECTION_BYPASS.md)** | Full technical writeup and bug bounty report on the VSS snapshot deletion guard logic defect in `MEARWFltDriver.sys`. | Finding #12 (Logic Defect) |
| **[EDR Resilience & BYOVD Methodology](EDR_RESILIENCE_BYOVD_METHODOLOGY.md)** | Technical breakdown of Bring Your Own Vulnerable Driver (BYOVD) process termination dynamics, attack chain architecture, and blue-team mitigation strategies. | Architectural & Evasion Research |

---

## 🔬 Summary of Findings

### 1. VSS Snapshot Protection Logic Defect (Anti-Ransomware Bypass)
* **Affected Component:** `MEARWFltDriver.sys` (Kernel Minifilter Driver / `EventCollectorDriver`, v1.0.80.10)
* **Vulnerability Class:** Semantic String Comparison Mismatch / Filter Logic Defect
* **Core Issue:** When handling `IOCTL_VOLSNAP_DELETE_SNAPSHOT` (`0x53C038`), the driver intercepts deletion requests and enumerates base volumes (`\Device\HarddiskVolume3`) using `FltGetVolumeName`. It compares the delete target string against these base volume names using a substring search (`wcsstr`). However, legitimate shadow-copy deletion requests pass shadow-copy device paths (`\Device\HarddiskVolumeShadowCopyXX`). Because the target name never contains the base-volume name, `wcsstr` returns `NULL`, triggering the `Mismatch` path and allowing the snapshot deletion to succeed unimpeded.
* **Security Impact:** Untrusted processes and ransomware variants can delete Volume Shadow Copies (VSS restore points) prior to encryption even when anti-ransomware protection is set to active enforcement ("Kill process").
* **Read the Full Report:** [VSS_SNAPSHOT_PROTECTION_BYPASS.md](VSS_SNAPSHOT_PROTECTION_BYPASS.md)

### 2. EDR Resilience & BYOVD Process Termination Methodology
* **Target Services:** `MEERDInferenceEngine.exe`, `MEARWService.exe`, `MEEDRMCEngine.exe`, `MEEDRSyncAgent.exe`
* **Research Focus:** Evaluating the resistance of user-mode EDR agents against Bring Your Own Vulnerable Driver (BYOVD) primitives operating with local administrative privileges.
* **Core Takeaways:**
  - Analysis of kernel-level arbitrary process termination vectors (`ZwTerminateProcess` invocation via vulnerable signed drivers).
  - Identification of architectural gaps when EDR core services lack Protected Process Light (PPL) and kernel-level object callback self-defense.
  - Comprehensive blue-team detection telemetry, Sigma/YARA rules, and hardening recommendations (HVCI, WDAC driver blocklist enforcement).
* **Read the Methodology Paper:** [EDR_RESILIENCE_BYOVD_METHODOLOGY.md](EDR_RESILIENCE_BYOVD_METHODOLOGY.md)

---

## 🛡️ Responsible Disclosure & Research Disclaimer

> [!NOTE]
> This repository is published strictly for educational, research, and defensive purposes to assist security engineers, detection authors, and vendors in improving software resilience against modern threat tactics. No weaponized exploits or offensive script payloads are distributed within this repository.
