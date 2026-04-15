## Detection Summary

This detection identifies unauthorized LSASS access using Sysmon Event ID 10 by analyzing process handle requests and GrantedAccess values. It enables early detection of credential access attempts even when dumping is blocked by endpoint security controls.

# LSASS Credential Dumping

## Objective

This detection logic is engineered to identify unauthorized interactions with the Local Security Authority Subsystem Service (LSASS), a critical Windows process frequently targeted by adversaries for extracting plaintext passwords, NTLM hashes, and Kerberos tickets. 

This detection focuses on identifying adversarial intent at the earliest stage of credential access, rather than relying on post-exploitation artifacts.

By monitoring for suspicious source processes and anomalous access rights through analysis of access rights requested by the source process, we can detect the early stages of a credential access attempt. 

This proactive focus ensures visibility into potential exploitation even when existing security controls successfully block the final dumping execution.


## Detection Metadata

1. Detection Name: LSASS Process Access Detection  
2. Technique: Credential Access  
3. MITRE ATT&CK: T1003.001 – LSASS Memory  
4. Log Source: Sysmon  
5. Event ID: 10  
6. Index: main  


## Data Sources & Telemetry
This detection relies on high-fidelity endpoint telemetry captured via Sysmon Event ID 10 (ProcessAccess). This specific event type is invaluable for SOC analysts because it provides a granular look at inter-process behavior, specifically when a source process attempts to open a handle to the memory space of another. The telemetry required manual field extraction using rex due to the absence of normalized field mappings. This reflects a common scenario in lab environments where raw logs are ingested without a dedicated technology add-on (TA).

To differentiate between routine administrative tasks and high-risk credential harvesting, the detection evaluates the following critical fields:

- **SourceImage:** Identifies the specific executable initiating the access, allowing us to whitelist known-good system processes.

- **TargetImage:** Narrowed specifically to lsass.exe to monitor for unauthorized memory reads.

- **GrantedAccess:** Analyzes the specific permissions requested (e.g., 0x1010 or 0x1410); unusual access rights are often the "smoking gun" for credential dumping.

By correlating these data points, the detection minimizes "false positive" noise from legitimate Windows services and highlights anomalous patterns that indicate a clear intent to extract sensitive credentials.


## Initial Exploration & Baseline Analysis

The initial phase of this project focused on analyzing the baseline behavior of the environment to distinguish routine system operations from potential threats. By auditing Sysmon ProcessAccess logs, it established a clear picture of what "normal" looks like for LSASS interactions in a standard workstation environment. Initial detection attempts relied on Event ID 1 due to the absence of ProcessAccess visibility.

### Key Observations:

- **System Baselines:** Analysis revealed frequent, consistent access to LSASS from trusted system-level processes, such as svchost.exe and VBoxService.exe. These interactions are characteristic of standard Windows service management and virtualization overhead, typically requesting moderate, well-defined access rights.

- **Anomalous Findings:** During the exploration, the analysis identified powershell.exe interacting with the LSASS process. Unlike the system-level services, PowerShell is not typically expected to interact directly with LSASS, making such behavior a high-confidence deviation from the established baseline in standard workstation activity. Even if the requested access level appears limited, this deviation from the established baseline serves as a high-priority indicator of reconnaissance or the early stages of a credential access attempt.

- **Refinement Strategy:** This exploration confirmed that because LSASS is a focal point for both system stability and attacker interest, a "one-size-fits-all" alert is insufficient. Successful detection requires a nuanced approach that filters out benign, high-frequency system sources to highlight the rare, suspicious outliers.


## Challenges & Problem Encounters

Developing a robust detection for LSASS access involves navigating several technical hurdles, ranging from aggressive security defaults to the inherent "noise" of a modern operating system. During the development of this project, several key challenges were encountered:

- **Endpoint Security Interference:** Standard credential dumping techniques using common utilities like procdump.exe or rundll32.exe were consistently intercepted and blocked by the lab’s built-in antivirus and behavioral protection layers. These controls prevented generation of high-confidence attack telemetry required for validation.

- **High Signal-to-Noise Ratio:** Initial log analysis revealed that LSASS is a highly "chatty" process. Legitimate system components frequently interact with it, resulting in a high-volume, low-signal dataset. Simple keyword filtering or process-based whitelisting was insufficient, as it either missed suspicious activity or created an unmanageable volume of false positives.

- **Telemetry Gaps:** The controlled environment lacked a diverse range of attack signals. Relying solely on obvious execution patterns wasn't enough to build a resilient detection, necessitating a shift toward identifying the underlying behavioral access rights rather than just the names of the tools being used.

These obstacles required a more sophisticated approach to data engineering—moving away from signature-based detection and focusing on the specific Access Rights that remain consistent across different attack variants. The detection required manual field extraction using rex due to raw XML log ingestion without a Sysmon Technology Add-on (TA). As a result, fields such as SourceImage and TargetImage were not automatically parsed.

## Failed Attempts & Iterative Refinement

Before arriving at a successful detection model, several initial strategies were tested and discarded. These attempts provided critical insights into telemetry limitations and detection constraints.

### Testing & Simulation Hurdles
- Tool-Based Execution: Attempts to simulate dumping using industry-standard utilities like procdump.exe were unsuccessful. Despite running with administrative privileges, the environment's access restrictions prevented the process from attaching to LSASS.

- Living-off-the-Land (LotL) Blocks: Attempts to utilize rundll32.exe in conjunction with comsvcs.dll (a common native Windows method for dumping memory). However, the built-in antivirus protections immediately identified and blocked this behavior, preventing the generation of the necessary LSASS dump telemetry for my SIEM to ingest.

### Logging Limitations
- Inadequate Event Context: Initial detection strategies relied heavily on **Sysmon Event ID 1 (Process Creation)**. While Event ID 1 is excellent for seeing what started, it does not provide visibility into what a process does after it begins. This approach resulted in a "blind spot" where the tool was executed, but could not confirm if it actually accessed sensitive memory, leading to either no alerts or a flood of irrelevant false positives.

### Lessons Learned
These setbacks were pivotal; they highlighted that modern adversaries and security tools have moved beyond simple filenames. To build a truly effective detection, focus was shifted away from specific **tools** and toward **process access telemetry**, which significantly increases detection robustness against evasion techniques

## Detection Engineering Insight

The core takeaway from this project is that successful execution is not a prerequisite for detection. By shifting the focus from the outcome (the credential dump) to the attempt (the process interaction), we can identify adversarial intent much earlier in the attack lifecycle.

**Key Principle:** Not all LSASS access is malicious — the level of access determines intent.

### Key Engineering Principles:
- **Behavior Over Signatures:** Relying on specific filenames or hashes is a fragile strategy. This detection instead prioritizes behavioral indicators, such as process origin and anomalous access patterns. By identifying non-system processes—or those not typically associated with authentication—attempting to touch LSASS, we create a high-fidelity signal that persists even if an attacker renames their tools.

- **Resilience to Evasion:** Resilience to evasion is achieved by monitoring underlying process interaction behavior rather than relying on tool-specific indicators. Because this approach monitors the underlying mechanics of how Windows handles process memory, it is significantly more resilient to evasion. Even if an endpoint security tool blocks the final "dump" file from being written, the Sysmon Event ID 10 telemetry still captures the unauthorized handle request, providing the SOC with actionable intelligence.

- **Environmental Adaptability:** This insight allows for a more flexible detection posture. By understanding the "known good" system-level processes within a specific environment, we can build a baseline that highlights the rare and suspicious outliers, effectively reducing alert fatigue while maintaining a high catch rate for credential access attempts.


## Strategy Shift
Initial detection efforts focused on identifying known credential dumping tools and command-line patterns. However, these approaches proved unreliable due to endpoint security controls blocking execution and the absence of consistent tool-based telemetry.

The strategy was shifted toward behavior-based detection, focusing on process access interactions with LSASS. This approach prioritizes identifying anomalous source processes and access patterns rather than relying on successful dumping execution or specific tooling.

This shift enabled the development of a more resilient and environment-agnostic detection capable of identifying credential access attempts even in restricted environments.


## Detection Logic

The detection logic is designed to identify unauthorized process access to the Local Security Authority Subsystem Service (LSASS) by analyzing Sysmon Event ID 10 (ProcessAccess) telemetry. 

This approach represents a transition from indirect detection methods to direct behavioral monitoring, focusing on how processes interact with LSASS memory rather than relying on tool-specific indicators.


### SPL Query

**Query 1:**

```spl
index=main 
| search "<EventID>10</EventID>"
| head 20
```
Figure 1: Raw Sysmon Event ID 10 (ProcessAccess) events showing full XML structure, confirming that LSASS access telemetry is successfully ingested and available for detection engineering.

![Raw LSASS Process Access Events](../screenshots/detection11/01_raw_lsass_event10.png)

- **What this step does:**\
Retrieves raw Sysmon Event ID 10 logs directly from Splunk without any filtering or field extraction.
- **Why it is important:**\
Validates that ProcessAccess telemetry is successfully ingested and confirms the presence of LSASS-related events.
- **How it helps detection:**\
Establishes the foundation for detection engineering by ensuring that required telemetry exists before applying parsing and filtering logic.

**Query 3:**
```spl
index=main 
| search "<EventID>10</EventID>"
| rex field=_raw "<Data Name='SourceImage'>(?<SourceImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='TargetImage'>(?<TargetImage>[^<]+)</Data>"
| where like(TargetImage,"%lsass.exe")
| stats count by SourceImage TargetImage
| sort -count
```
Figure 3: Aggregated LSASS access events grouped by SourceImage, establishing baseline system behavior and identifying dominant processes interacting with LSASS prior to anomaly filtering.

![LSASS Baseline Analysis](../screenshots/detection11/03_lsass_baseline.png)


- **What this step does:**\
Aggregates Sysmon Event ID 10 events targeting LSASS and groups them by SourceImage to identify processes interacting with LSASS.

- **Why it is important:**\
Establishes a behavioral baseline by highlighting high-frequency system processes that regularly access LSASS.

- **How it helps detection:**\
Enables differentiation between normal system activity and anomalous process interactions, forming the foundation for effective noise reduction and anomaly detection.


**Query 2:**
```spl
index=main 
| search "<EventID>10</EventID>"
| rex field=_raw "<Data Name='SourceImage'>(?<SourceImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='TargetImage'>(?<TargetImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='GrantedAccess'>(?<GrantedAccess>[^<]+)</Data>"
| where like(TargetImage,"%lsass.exe")

| eval access_level=case(
    GrantedAccess=="0x1fffff","HIGH",
    GrantedAccess=="0x1f3fff","HIGH",
    GrantedAccess=="0x143a","MEDIUM",
    GrantedAccess=="0x1410","MEDIUM",
    GrantedAccess=="0x1010","LOW",
    GrantedAccess=="0x1000","LOW",
    true(),"UNKNOWN"
)

| where NOT (
    like(SourceImage,"%svchost.exe") OR
    like(SourceImage,"%VBoxService.exe") OR
    like(SourceImage,"%MsMpEng.exe") OR
    like(SourceImage,"%csrss.exe") OR
    like(SourceImage,"%wininit.exe")
)

| stats count by SourceImage TargetImage GrantedAccess access_level
| sort -count
```

Figure 2: Aggregated Sysmon Event ID 10 (ProcessAccess) telemetry displaying filtered LSASS access attempts, where baseline system processes have been excluded to surface low-frequency, high-signal anomalies based on GrantedAccess permissions.

![LSASS Process Access Detection](../screenshots/detection11/02_lsass_process_access_filtered.png)


- **What this step does:**\
Extracts key fields from raw Sysmon logs and filters for processes accessing LSASS, while excluding known baseline system processes.

- **Why it is important:**\
Reduces high-volume noise and isolates anomalous process interactions with LSASS based on behavior rather than tool signatures.

- **How it helps detection:**\
Enables identification of suspicious access patterns by combining process origin and access rights (GrantedAccess), improving detection fidelity and prioritization of high-risk events.

### Logic Explanation
The detection is based on identifying anomalous handle requests to LSASS, which is a prerequisite for credential extraction techniques.

Our logic performs a process-to-process correlation:

- **Target Isolation:**
The query filters events where the target process is lsass.exe, ensuring the detection is focused on credential access activity. Only events where LSASS is the target process are considered.

- **Baseline Exclusion:**
Known legitimate system processes such as svchost.exe, VBoxService.exe, MsMpEng.exe, csrss.exe, and wininit.exe are excluded to reduce noise and improve detection fidelity.

- **Behavioral Identification:**
Any remaining process accessing LSASS is treated as anomalous, as non-system processes are not typically expected to interact directly with LSASS memory. Events are grouped and analyzed based on access level and frequency.

- **Access-Based Risk Scoring:**
The GrantedAccess field is used to classify the level of access requested. Higher privilege access masks indicate increased likelihood of credential dumping or memory inspection activity.

### Key Insight

High-privilege access rights such as 0x1fffff indicate full control over the LSASS process, which is strongly associated with credential dumping techniques.

### Detection Value

This approach significantly reduces noise by focusing on access semantics rather than simple process presence, enabling more accurate identification of malicious behavior.


### Detection Conditions
The detection triggers when the following conditions are met:

- **Telemetry Source:** Sysmon Event ID 10 (ProcessAccess)
- **Target Process:** C:\Windows\System32\lsass.exe
- **Source Process:** Not part of the established system baseline
- **Access Pattern:** Presence of access rights indicative of process querying or memory interaction


### Expected True Positives
This detection is designed to identify:

- **Suspicious Process Interaction:**
Non-system processes such as powershell.exe, cmd.exe, or unknown binaries accessing LSASS.

- **Credential Access Attempts:**
Processes requesting access to LSASS memory, even if the dumping operation is blocked by endpoint security controls.

- **Suspicious Installation Activity:**
Suspicious installation or update binaries attempting to access LSASS outside normal system behavior


### Expected False Positives
The following legitimate activities may generate similar telemetry:

- **Security Solutions:**
Antivirus or EDR agents performing memory inspection on LSASS.

- **Administrative Diagnostics:**
System administrators using legitimate tools for troubleshooting or forensic analysis.

- **Virtualization Services:**
Components such as VBoxService.exe interacting with system processes for host integration.

These are mitigated through baseline filtering and can be further refined through environment-specific tuning.

## Detection Development

### Detection Analysis

The query was executed against Sysmon Event ID 10 telemetry to identify processes interacting with LSASS. Aggregation techniques were applied to group events by SourceImage and TargetImage, allowing for rapid identification of dominant system behavior and rare process interactions.

### SPL Query

```spl
index=main 
| search "<EventID>10</EventID>"
| rex field=_raw "<Data Name='SourceImage'>(?<SourceImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='TargetImage'>(?<TargetImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='GrantedAccess'>(?<GrantedAccess>[^<]+)</Data>"
| where like(TargetImage,"%lsass.exe")
| stats count by SourceImage TargetImage GrantedAccess
| where count < 10
| sort count
```

### Analysis

The results reveal a clear distinction between high-frequency system activity and low-frequency process interactions with LSASS.

- High-frequency processes such as VBoxService.exe and svchost.exe were identified as baseline system behavior.
- Security-related processes such as MsMpEng.exe were observed accessing LSASS as part of legitimate antivirus scanning.
- Low-frequency processes such as MicrosoftEdgeUpdate.exe, CompatTelRunner.exe, and services.exe were identified as rare interactions.

### Key Finding

Rare process access to LSASS represents a high-signal detection opportunity. While not all rare events are malicious, this approach significantly reduces noise and enables analysts to prioritize investigation of anomalous behavior.

### Detection Value

This method demonstrates how behavioral aggregation can be used to isolate suspicious activity in high-volume telemetry environments, improving detection efficiency and analyst visibility.

### Detection Enhancement

Additional baseline filtering was applied to exclude core Windows processes such as csrss.exe and wininit.exe, which were observed requesting high-privilege access to LSASS as part of normal operating system behavior. This refinement significantly improved detection fidelity by eliminating false positives associated with legitimate system activity.

## Conclusion

The implementation of this detection logic confirms that robust visibility into credential access attempts is achievable through the rigorous analysis of inter-process telemetry, specifically Sysmon Event ID 10. 

By pivoting from a signature-based approach to a behavioral methodology focused on GrantedAccess bitmasks and process-to-process correlation, the detection effectively identifies adversarial intent at the inception of the attack lifecycle. 

The successful filtration of high-frequency system baselines—such as svchost.exe and VBoxService.exe—ensures that limited SOC resources are directed toward high-signal anomalies. Ultimately, this project demonstrates that monitoring the mechanics of process handles provides a resilient defense-in-depth layer that remains effective even when traditional endpoint security controls prevent the final execution of credential dumping tools.

This approach aligns closely with real-world SOC detection strategies, where behavioral telemetry is prioritized over static indicators to ensure resilience against evolving adversarial techniques.

## Lessons Learned

Throughout the development and iterative testing of this detection, it became evident that relying on Event ID 1 (Process Creation) is insufficient for identifying sophisticated credential access activity, as it lacks visibility into post-execution behavior.

The transition to Sysmon Event ID 10 proved critical, as it provides granular insight into process handle requests and memory access patterns—offering a more stable and behavior-driven indicator of compromise compared to volatile attributes such as filenames or hashes.

Additionally, challenges related to raw XML ingestion and the need for manual field extraction highlighted the operational importance of data normalization and the role of Technology Add-ons (TAs) in enhancing SIEM efficiency and scalability.

Most importantly, the consistent failure of traditional credential dumping techniques due to endpoint security controls reinforced a key detection engineering principle: telemetry generated from a blocked attempt is equally valuable as telemetry from a successful attack. By focusing on the intent—captured through LSASS access attempts—rather than the outcome, this detection remains effective even in hardened environments.
