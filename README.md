# Brute Force Attempt Detection in Microsoft Sentinel

### Explanation  

When entities (local or remote users) attempt to log into a virtual machine, a log entry is generated on the local machine. This log is then forwarded to **Microsoft Defender for Endpoint (MDE)** under the **DeviceLogonEvents** table.  

These logs are subsequently sent to the **Log Analytics Workspace**, which is used by **Microsoft Sentinel**, our **Security Information and Event Management (SIEM)** solution.  

Within **Microsoft Sentinel**, we define an **alert rule** that triggers when a specific entity fails to log into the same virtual machine (VM) multiple times within a given time frame. In this lab, the rule is configured to detect **10 or more failed logins within a 5-hour period**.  


## Part 1: Creating an Alert Rule

To detect brute force attempts, I designed a Sentinel Scheduled Query Rule within Log Analytics. This rule identifies when the same remote IP address has failed to log in to the same local host (Azure VM) 10 or more times within the last 5 hours.

Using the `DeviceLogonEvents` table, I constructed the following KQL query to capture these events:

```kusto
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount
```

Once I validated the query, I proceeded to create the Scheduled Query Rule in **Sentinel → Analytics → Schedule Query Rule**, applying the following settings:

- **Enabled the Rule**
- **Mapped the MITRE ATT&CK Framework Categories using ChatGPT**
- **Configured the rule to run every 4 hours**
- **Set the query to look back at the last 5 hours of data**
- **Stopped the rule from running after an alert was generated**
- **Mapped Remote IP and DeviceName as entity attributes**
- **Ensured incidents were automatically created when the rule triggered**
- **Grouped all alerts into a single incident per 24-hour period**

---

## Part 2: Triggering an Alert and Creating an Incident

After configuring the rule, I manually triggered an alert to verify that it successfully created an incident in Sentinel. If the required logs were missing, I ensured the alert triggered by intentionally failing login attempts on the VM multiple times.

I carefully navigated **Sentinel’s Analytics and Incident Management sections**, ensuring the rule execution aligned with expected behavior.

---

## Part 3: Investigating and Resolving the Incident

Following the **NIST 800-161 Incident Response Lifecycle**, I worked the incident through completion:

### 1. Preparation
- Documented roles, responsibilities, and procedures.
- Ensured tools, systems, and training were in place for incident handling.

### 2. Detection & Analysis
- Identified and validated the incident.
- Assigned the incident to myself and set the status to **Active**.
- Initiated an **Investigation** to gather evidence and assess impact.
- Noted key entity mappings:

Several different Virtual Machines were potentially impacted by brute force attempts from multiple public IP addresses on the internet:

| Public IP Address      | Status       | Target VM Name                                                          | Logon Failures |
|------------------------|-------------|-------------------------------------------------------------------------|---------------:|
| **139.59.120.4**       | LogonFailed | kms-linux-vulnerability-scan.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net | 110            |
| **84.54.212.114**      | LogonFailed | resend7393-vm                                                           | 40             |
| **196.251.88.103**     | LogonFailed | kms-linux-vulnerability-scan.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net | 46             |

These repeated failed login attempts indicate potential brute force attacks targeting these virtual machines.



- Checked if any of the IP addresses actually **succeeded** in logging in. To validate, I ran the following **KQL query**:

```kusto
DeviceLogonEvents
| where RemoteIP in ("139.59.120.4", "218.92.0.187", "175.208.240.170", "84.54.212.114", "196.251.88.103", "172.86.114.236", "185.243.96.107")
| where ActionType != "LogonFailed"
```

### 3. Containment, Eradication & Recovery
- **Isolated the affected systems** to prevent further damage.
- Used **Microsoft Defender for Endpoint (MDE)** to **isolate devices** across all impacted systems.
- Ran an **antimalware scan** on all devices within **MDE** to detect any potential threats.
- Conducted an **AV scan** to ensure no malicious activity was present.
- To enhance security, I **updated the Network Security Group (NSG)** attached to my **Virtual Machine** to block all traffic **except from my home IP address** (alternatively, a **bastion host** could be used for access).
- Documented that:
  - The **NSG was locked down** to prevent **RDP attempts from the public internet**.
  - A **corporate policy was proposed** to enforce this as a requirement for all VMs going forward (**achievable via Azure Policy**).

- Verified that the brute force attempt **was unsuccessful** and confirmed **no threats related to this incident** were detected.

### 4. Post-Incident Activities
- Documented findings and lessons learned.
- Updated internal policies and security controls to prevent future occurrences.
- Recognized that a **company-wide policy** enforcing secure NSGs on all VMs should be implemented using **Azure Policy** (though no immediate action was taken for this lab).

### 5. Closure
- Reviewed and confirmed that the incident was **fully resolved**.
- Ensured all findings and actions were **properly recorded** within Sentinel.
- Finalized reporting and closed the case, categorizing it as a **True Positive** in Sentinel.


This structured approach ensured a **thorough investigation**, **effective containment**, and **proper documentation**, reinforcing security best practices within the Azure environment.

