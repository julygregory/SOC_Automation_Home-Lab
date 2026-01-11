# Automated SOC Incident Response Pipeline - Home Lab Documentation

**Stack:** Wazuh (SIEM) • Shuffle (SOAR) • TheHive (Case Management) • Sysmon • VirusTotal  
**Infrastructure:** Oracle VirtualBox • Ubuntu 22.04 LTS (x2) • Windows 10 Pro • Bridged Network (Home Router)

---

## 📋 Project Overview

I built this home lab to understand how security operations work in practice. I integrated Wazuh (SIEM), Shuffle (SOAR), and TheHive (case management) to learn how alerts are detected, enriched with threat intelligence, and responded to automatically. This project helped me understand the workflow from endpoint detection to automated response and case management.

**What I Learned:**

- How to integrate SIEM, SOAR, and case management platforms together
- How to create detection rules that catch real suspicious activity (like Mimikatz)
- How to build automated workflows that enrich alerts and create cases
- How Windows telemetry (Sysmon) works and why log aggregation matters
- How to automate security responses without needing manual intervention

---

## 🏗️ Architecture & Visual Layout

### System Design

![SOC Workflow Data Flow](screenshots/soc-workflow.png)

**Why I Designed It This Way**

- I put Wazuh and Shuffle together on one VM to reduce delays in my workflows
- I separated TheHive to keep case management from slowing down my detection pipeline
- I used Windows as the target endpoint because that's what I'll encounter in real jobs
- I used Bridged network so I could easily access all services from my computer while testing

---

## 🛠️ Technology Stack & Why I Use Them

| Tool            | Purpose                | Why I Chose It                                                         |
| :-------------- | :--------------------- | :--------------------------------------------------------------------- |
| **Wazuh**       | SIEM (Detection)       | Free and open-source; good for learning how SIEMs analyze logs         |
| **Shuffle**     | SOAR (Automation)      | Visual interface meant I could build workflows without coding          |
| **TheHive**     | Case Management        | Simple way to track incidents and understand analyst workflows         |
| **Sysmon**      | Windows Telemetry      | Gives detailed process logs that Windows Event Viewer doesn't show     |
| **VirusTotal**  | Threat Intelligence    | Free API to check file reputation; helps me understand threat scoring  |
| **Wazuh Agent** | Endpoint Communication | Agent on Windows sends logs to Wazuh and can execute response commands |

---

## 🖥️ Virtual Machine Setup

### Hardware Specifications

| VM       | OS                         | CPU     | RAM  | Storage | Purpose                                   |
| :------- | :------------------------- | :------ | :--- | :------ | :---------------------------------------- |
| **VM 1** | Windows 10 Enterprise LTSC | 2 cores | 8 GB | 50 GB   | Target endpoint with Sysmon + Wazuh Agent |
| **VM 2** | Ubuntu 24.04 LTS           | 4 cores | 8 GB | 50 GB   | Wazuh Manager + Shuffle (SOAR) in Docker  |
| **VM 3** | Ubuntu 24.04 LTS           | 4 cores | 8 GB | 50 GB   | TheHive + Elasticsearch + Cassandra       |

### Resource Reasoning

- **Windows: 2 CPUs** - Mainly sends logs; doesn't need heavy processing
- **Ubuntu VMs: 4 CPUs each** - Run multiple services (databases, indexing, containers)
- **8 GB RAM each** - Balanced for smooth operation without production overhead
- **50 GB storage each** - Enough for OS, logs, and test data

### Network Configuration

All VMs use **Bridged Adapter** connected to your home router:

- Each VM gets an IP from your router's DHCP
- VMs can communicate with each other and your main computer
- Find actual IPs: Use `ipconfig` (Windows) or `ip addr` (Linux) on each VM

---

## 🔧 Installation & Setup (Quick Reference)

### Installation Strategy

Instead of me documenting every installation step here, I'll point you to the **official guides** for each tool. I learned from the official docs and I recommend you do the same:

- **Wazuh:** https://documentation.wazuh.com/current/installation-guide/index.html
- **Shuffle:** https://github.com/frikky/shuffle/blob/master/README.md
- **TheHive:** https://docs.thehive-project.org/thehive/installation/
- **Sysmon:** https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

### Verification Steps (Check If Setup Works)

#### ✅ Windows VM - Verify Sysmon & Wazuh Agent

```powershell
# Check Sysmon is running
Get-Service Sysmon64
# Should show: Running

# Check Wazuh Agent is running
Get-Service WazuhSvc
# Should show: Running
```

#### ✅ Wazuh VM - Verify Manager is Active

```bash
# Check if Wazuh manager is running
sudo systemctl status wazuh-manager
# Should show: active (running)

# Verify it's listening on port 1514
sudo netstat -tulpn | grep 1514
```

#### ✅ Shuffle - Verify Docker Containers

```bash
# Check if Shuffle and Elasticsearch are running
docker ps
# Should show shuffle and elasticsearch containers

# Access Shuffle Manager
# Open browser: http://YOUR_WAZUH_VM_IP:3001
# Login: admin / admin
```

#### ✅ TheHive - Verify Web Interface

```bash
# Check if TheHive is running
sudo systemctl status thehive
# Should show: active (running)

# Access TheHive Manager
# Open browser: http://YOUR_THEHIVE_VM_IP:9000
# Login: admin@thehive.local / secret
```

---

## 🧪 Real-World Test: Detecting Mimikatz

### Scenario Overview

We'll run Mimikatz (a legitimate but suspicious Windows tool) and watch Wazuh detect it. This shows how the lab works in practice.

### Step 1: Initial Setup on Windows VM

1. **Disable Windows security features** (lab only - not for production):

   ```powershell
   # Disable Real-Time Protection
   Set-MpPreference -DisableRealtimeMonitoring $true

   # Disable Cloud-Delivered Protection
   Set-MpPreference -DisableCloudProtection $true
   ```

2. **Download Mimikatz** (a password dumping tool):
   - Download from: https://github.com/gentilkiwi/mimikatz/releases
   - Save to: `C:\Tools\mimikatz.exe`

### Step 2: Run Mimikatz (First Time)

Open PowerShell and run:

```powershell
C:\Tools\mimikatz.exe
```

### Step 3: Check Wazuh Manager for Alerts

1. Open Wazuh Manager: `http://YOUR_WAZUH_VM_IP`
2. Go to **Discover** section
3. **Problem:** Wazuh won't detect Mimikatz yet
   - Why? The default rules don't know about Mimikatz
   - We need to configure Wazuh to look for it

![SOC Workflow Data Flow](screenshots/wazuh_mimikatz-noresult.png)

### MITRE ATT&CK Mappings

This detection scenario covers:

| Tool           | Technique ID | Technique Name                    | Tactic            |
| :------------- | :----------- | :-------------------------------- | :---------------- |
| **Mimikatz**   | T1003        | OS Credential Dumping             | Credential Access |
| **PowerShell** | T1059.001    | Command and Scripting Interpreter | Execution         |

---

### Step 4: Configure Wazuh to Detect Mimikatz

#### 4a. Enable JSON Logging in Wazuh Config

```bash
# In Wazuh VM, then:
sudo nano /var/ossec/etc/ossec.conf
```

Find the `<global>` section and ensure these paths are enabled:

```xml
<jsonout_output>yes</jsonout_output>
<alerts_log>yes</alerts_log>
<logall>yes</logall>
<logall_json>yes</logall_json>
```

Restart Wazuh:

```bash
sudo systemctl restart wazuh-manager
```

#### 4b. Enable Filebeat Modules

```bash
# Edit filebeat configuration
sudo nano /etc/filebeat/modules.d/wazuh.yml
```

Make sure these lines are set to `true`:

```yaml
filebeat.modules:
 -module: wazuh
  alerts:
    enabled: true
  archives:
    enabled: true
```

Restart Filebeat:

```bash
sudo systemctl restart filebeat
```

#### 4c. Create Index Pattern in Wazuh

1. Open Wazuh Manager → **Stack Management** → **Index Patterns**
2. Click **Create Index Pattern**
3. Enter pattern name: `wazuh-archives-*`
4. Click **Create**
5. Use the new Index patern: `wazuh-archives-`

![SOC Workflow Data Flow](screenshots/wazuh_create-index-pattern.png)
![SOC Workflow Data Flow](screenshots/wazuh_use-new-index.png)

#### 4d. Create Detection Rule for Mimikatz

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Add this rule:

```xml
<rule id="100002" level="7">
  <description>Mimikatz execution detected</description>
  <match>mimikatz</match>
  <field name="Image">mimikatz</field>
</rule>
```

Restart Wazuh:

```bash
sudo systemctl restart wazuh-manager
```

### Step 5: Run Mimikatz Again & Verify Detection

1. On Windows VM, run Mimikatz again
2. Go to Wazuh Manager → **Discover**
3. Select the `wazuh-archives-*` index
4. You should now see Mimikatz alerts!

---

![SOC Workflow Data Flow](screenshots/wazuh_mimikatz-detected.png)

## 🔄 Shuffle Workflow: Building Automation

### Architecture Overview

- **Endpoint**: Windows VM (Wazuh agent)
- **SIEM**: Wazuh Manager (Ubuntu)
- **SOAR**: Shuffle (Hybrid Setup)
  - **UI/Manager**: Hosted on shuffle.io (cloud)
  - **Execution Engine**: Orborus (local Docker)
  - **Apps/Nodes**: Run locally via Docker containers
- **Threat Intel**: VirusTotal
- **Case Management**: TheHive
- **Response**: Wazuh Active Response (process kill)
- **Notification**: Email

### Setup Prerequisites

1. **Shuffle Hybrid Setup**:

   - Create account on **shuffle.io**
   - Sign in to the Shuffle Manager at shuffle.io
   - Install **Docker** on your local machine (where you want apps to run)
   - Install **Orborus** (Shuffle's execution engine/worker controller):
     ```bash
     docker pull frikky/orborus:latest
     docker run -d -p 8000:8000 \
       -e SHUFFLE_ORBORUS_EXECUTION_TIMEOUT=600 \
       -e SHUFFLE_WORKER_IMAGE=frikky/shuffle-worker:latest \
       frikky/orborus:latest
     ```
   - Connect Orborus to your shuffle.io account
   - Deploy required apps in your local Docker: Wazuh, TheHive, HTTP, VirusTotal, Email
   - Docker pulls app images automatically when workflow uses them

   ![SOC Workflow Data Flow](screenshots/shuffle_download-orgapp.png)

2. **TheHive User Setup**:

   ```
   - Create a new organization
   - Create Analyst (Normal) user for triage
   - Create Service Account user for Shuffle integration
   - Generate API key from service account
   ```

   ![SOC Workflow Data Flow](screenshots/shuffle_create-new-user.png)

3. **Wazuh API Credentials**:
   ```bash
   sudo tar -xvf wazuh-install-files.tar
   cd wazuh-install-files
   sudo cat wazuh-passwords.txt
   # Copy username and password for API integration
   ```
   ![SOC Workflow Data Flow](screenshots/wazuh_api-key.png)

---

### Workflow Nodes (Step-by-Step Configuration)

#### Node 1: Shuffle Webhook (Ingestion)

**Purpose**: Receive alerts from Wazuh and start automation

**Steps**:

1. Drag **Webhook** node into workflow
2. Copy the **Webhook URL** generated
3. Configure Wazuh to send alerts:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add webhook section:

```xml
<integration>
  <name>shuffle</name>
  <hook_url>http://YOUR_SHUFFLE_IP:3001/api/v1/hooks/YOUR_WEBHOOK_ID</hook_url>
  <alert_format>json</alert_format>
  <rule_id>100002</rule_id>
</integration>
```

Restart Wazuh:

```bash
sudo systemctl restart wazuh-manager
```

**Verify webhook connectivity:**

```bash
# Test from Wazuh VM to Shuffle Orborus
curl -X POST http://YOUR_SHUFFLE_ORBORUS_IP:3001/api/v1/hooks/YOUR_WEBHOOK_ID \
   -H "Content-Type: application/json" \
   -d '{"test": "connection"}'
```

Once configured, when you execute Mimikatz again, Wazuh will automatically send the alert to Shuffle within 1-2 seconds.

![SOC Workflow Data Flow](screenshots/shuffle_webhook-run.png)

---

#### Node 2: Regex Capture Group (Hash Extraction)

**Purpose**: Extract SHA256 hash from Wazuh logs

**Configuration**:

- **Input field**: `$exec.all_fields.full_log.win.eventdata.hashes`
- **Regex pattern**: `SHA256=([0-9A-Fa-f]{64})`
- **Output**: Captured SHA256 hash for enrichment

![SOC Workflow Data Flow](screenshots/shuffle_SHA256.png)

---

#### Node 3: VirusTotal – Get Hash Report

**Purpose**: Threat intelligence enrichment via VirusTotal

**Setup**:

1. Create VirusTotal account and generate API key
2. In Shuffle, create VirusTotal authentication:
   - Paste API key
   - Use VirusTotal base URL

**Node Configuration**:

- **Hash field (dynamic)**: `$sha256-hash` (from Regex node)
- **Output**: Detection statistics and vendor consensus

![SOC Workflow Data Flow](screenshots/shuffle_virustotal.png)

---

#### Node 4: Python Code – Severity Normalization

**Purpose**: Convert VirusTotal results into SOC severity levels

**Script**:

```python
malicious = int($vt-malicious-count)

if malicious >= 10:
    severity = "Critical"
elif malicious >= 5:
    severity = "High"
elif malicious >= 1:
    severity = "Medium"
else:
    severity = "Low"

print(severity)
```

**Output**: Normalized severity for branching logic

![SOC Workflow Data Flow](screenshots/shuffle_python.png)

---

#### Node 5: HTTP/Curl – Wazuh API Token

**Purpose**: Retrieve valid Wazuh API token for response actions

**Configuration**:

- **URL**: `https://YOUR_WAZUH_IP:55000/security/user/authenticate`
- **Method**: POST
- **Body**: Username and password from `wazuh-passwords.txt`
- **Output**: Bearer token for Wazuh API calls

![SOC Workflow Data Flow](screenshots/shuffle_Get-API.png)

---

#### Node 6: Wazuh Response Node (Process Termination)

**Purpose**: Kill malicious processes via Wazuh Active Response

**Configuration Steps**:

1. **Enable Active Response in Wazuh**:

```bash
sudo nano /var/ossec/etc/ossec.conf
```

Add the command definition:

```xml
<command>
   <name>win_kill_process</name>
   <executable>kill-process.cmd</executable>
   <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
   <command>win_kill_process</command>
   <location>defined-agent</location>
   <rules_group>100002</rules_group>
</active-response>
```

2. **Create the Response Script on Windows Agent**:

Open **Notepad as Administrator** and create `kill-process.cmd`:

```cmd
@echo off
:: Script: kill-process.cmd
:: Author: julybansale
:: Purpose: Kill malicious processes detected by Wazuh

echo %date% %time% - Active Response Triggered >> "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

:: Kill Mimikatz
taskkill /F /IM mimikatz.exe /T >> "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" 2>&1

exit /B 0
```

Save to: `C:\Program Files (x86)\ossec-agent\active-response\bin\kill-process.cmd`

3. **Restart Wazuh Manager**:

```bash
sudo systemctl restart wazuh-manager
```

Verify agents:

```bash
cd /var/ossec/bin
./agent_control -L
```

![SOC Workflow Data Flow](screenshots/check_active-response.png)

**Shuffle Configuration**:

In your Shuffle workflow, add a **Wazuh** node configured as:

- **Action**: `run_command`
- **Command name**: `win_kill_process0` _(matches the Wazuh response name)_
- **Agent ID**: `001` (or your Windows agent ID)

This ensures Shuffle triggers the exact active response command defined in Wazuh.

---

#### Node 7: TheHive – Create Alert/Case

**Purpose**: Generate analyst-readable alerts and cases

**Shuffle Configuration**:

1. Create TheHive authentication
2. URL: `http://YOUR_THEHIVE_IP:9000`
3. API key: From service account

**Alert Fields**:

- Title: `Suspicious Activity: {process_name}`
- Severity: `$normalized-severity`
- TLP: 2 (Amber)
- Tags: `MITRE-ATT&CK`, `Malware`, `Detection`
- Description: Includes hash, command line, host

**Case Creation** (for Critical severity):

- Title: `INCIDENT: {hostname} - {threat_name}`
- Description: Full event details
- Related observables: File hash, IP, hostname

![SOC Workflow Data Flow](screenshots/thehive-test.png)

---

#### Node 8: HTTP node create_thehive-case/POST

**Purpose**: Create or update case in TheHive for tracking and investigation

**Shuffle Configuration**:

1. Add **HTTP** node to workflow
2. Configure authentication and endpoint:

   - **URL**: `http://YOUR_THEHIVE_IP:9000/api/v1/case`
   - **Method**: POST
   - **Headers**:
     ```
     Authorization: Bearer YOUR_THEHIVE_API_KEY
     Content-Type: application/json
     ```

3. **Request Body**:

   ```json
   {
     "title": "Suspicious Process: $process_name on $hostname",
     "description": "Process: $process_name\nHash: $sha256_hash\nCommand: $command_line\nVirusTotal Score: $vt_detection_count/70",
     "severity": 2,
     "tlp": 2,
     "tags": ["mimikatz", "credential-dumping", "T1003"],
     "status": "Open"
   }
   ```

4. **Output**: Extract case ID from response for reference in email notifications

**Verification**: Check TheHive dashboard to confirm case created with correct title, severity, and tags from Shuffle workflow execution.

![SOC Workflow Data Flow](screenshots/thehive_alerts.png)

---

#### Node 9: Email Notification

**Purpose**: Notify analysts of critical activity

**Configuration**:

- **Recipient**: Analyst email address
- **Subject**: `[ALERT] {severity} - {threat_name} on {hostname}`
- **Body**:
  ```
  Threat Name: {threat_name}
  Hostname: {hostname}
  Severity: {severity}
  VirusTotal Score: {vt-detection-count}/70
  Action Taken: {response-action}
  TheHive Case: {case-link}
  ```

**Verification**:

Once the workflow completes, you should receive an email notification at your configured analyst email address within 1-2 seconds. The email will contain all relevant alert details and a link to the newly created TheHive case for further investigation.

![SOC Workflow Data Flow](screenshots/sent-email.png)

---

## ✅ Automated Response in Action: Mimikatz Process Termination

### Real-Time Process Kill Verification

Every time Mimikatz is executed on the Windows agent VM, Wazuh's active response automatically terminates the process within seconds. Below is evidence of the automated defense in action:

![Mimikatz Process Killed by Wazuh Active Response](screenshots/wazuh_task-kill-success.png)

![Mimikatz Process Killed by Wazuh Active Response](screenshots/mimikatz_run-kill.png)

### How This Works

1. **Mimikatz launches** on Windows VM
2. **Sysmon detects** process creation event
3. **Wazuh receives** the detection (1-2 seconds)
4. **Rule 100002 matches** the executable name
5. **Active response triggers** automatically
6. **kill-process.cmd executes** on the endpoint
7. **Process terminated** - Mimikatz never completes

This demonstrates a complete automated incident response cycle without manual analyst intervention.

---

### Final Workflow Logic

The automated response workflow follows this decision tree:

1. **Alert Reception**: Wazuh webhook sends detected Mimikatz alert to Shuffle
2. **Hash Extraction**: Regex node extracts SHA256 hash from process telemetry
3. **Branching Logic (Hash Validation)**:
   - **If Hash Found (True)**: Proceeds to threat intelligence enrichment
   - **If No Hash (False)**: Skips to TheHive alert creation for analyst review
4. **Threat Intelligence** (Hash Found Branch): VirusTotal API enriches hash with detection counts and vendor consensus
5. **Severity Assessment**: Python script normalizes VirusTotal results into SOC severity levels (Critical/High/Medium/Low)
6. **Response Decision**:
   - **If Critical**: Executes full response (process kill + case + email)
   - **If High/Medium/Low**: Creates TheHive alert for analyst review without auto-termination
7. **Active Response** (Critical Branch): Obtains Wazuh API token and triggers process termination command
8. **Case Management**: Creates detailed case in TheHive with observables, severity, and MITRE ATT&CK tags
9. **Notification**: Sends email alert to analyst with case link and threat details

This multi-stage approach ensures that only high-confidence threats with file hashes trigger automatic response, while hash-less detections and lower-severity findings are logged for analyst triage.

![SOC Workflow Data Flow](screenshots/final_workflow.png)

---

## 📊 Understanding the Alert Flow

### What Happens When Mimikatz Runs:

```
1. DETECTION (Sysmon on Windows)
   └─► Sysmon logs process creation: mimikatz.exe

2. COLLECTION (Wazuh Agent on Windows)
   └─► Agent sends Sysmon logs to Wazuh Manager

3. ANALYSIS (Wazuh Manager)
   └─► Wazuh rule matches: "Mimikatz execution detected"
   └─► Alert generated with severity level

4. AUTOMATION (Shuffle)
   └─► Receives webhook from Wazuh
   └─► Parses alert data
   └─► Triggers workflow actions

5. CASE MANAGEMENT (TheHive)
   └─► Case created with alert details
   └─► Analyst can review and analyze
```

---

## 💡 Tips & Troubleshooting

### Common Issues

| Problem                         | Cause                  | Solution                                                                                      |
| :------------------------------ | :--------------------- | :-------------------------------------------------------------------------------------------- |
| Wazuh agent offline             | Firewall/network issue | Check `sudo systemctl status wazuh-manager` on Wazuh VM; verify Windows VM can reach Wazuh VM |
| No alerts in Wazuh              | Rules not configured   | Check `/var/ossec/etc/rules/local_rules.xml` exists and restart Wazuh                         |
| Shuffle can't reach Wazuh       | Wrong IP or port       | Verify webhook URL uses correct Wazuh VM IP; test ping between VMs                            |
| TheHive won't start             | Resource issue         | Check Java is running: `ps aux \| grep java`                                                  |
| "Connection refused" on TheHive | Still starting up      | Wait 2-3 minutes after restart; check logs                                                    |

### Useful Commands

**Check Wazuh alert logs:**

```bash
tail -f /var/ossec/logs/alerts/alerts.json
```

**Find your VM's actual IP:**

```bash
# Ubuntu
ip addr show

# Windows PowerShell
ipconfig
```

**Test network connectivity between VMs:**

```bash
ping YOUR_OTHER_VM_IP
```

**Check Shuffle webhook deliveries:**

- Shuffle Manager → Workflows → Click workflow → See execution logs

---

## 📚 Next Steps for My Learning

1. **Create more detection rules:** I want to add rules for other suspicious activities beyond Mimikatz
2. **Test different tools:** I plan to test PsExec, PowerUp, and other security tools
3. **Expand my workflows:** I want to add more Shuffle actions like email alerts and ticketing
4. **Simulate a network:** I'd like to add more VMs to see how detection works at scale
5. **Get better with TheHive:** I want to use MITRE ATT&CK mappings more effectively in my cases

---

## 🔗 Official Documentation Links

- **Wazuh Rules:** https://documentation.wazuh.com/current/user-manual/ruleset/index.html
- **Shuffle Documentation:** https://github.com/frikky/shuffle
- **TheHive API:** https://docs.thehive-project.org/thehive/api/
- **Sysmon Events:** https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
- **MITRE ATT&CK:** https://attack.mitre.org/

---
