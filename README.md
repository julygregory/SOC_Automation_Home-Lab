# Automated SOC Incident Response Pipeline - Home Lab Documentation

**Stack:** Wazuh (SIEM) • Shuffle (SOAR) • TheHive (Case Management) • Sysmon • VirusTotal  
**Infrastructure:** Oracle VirtualBox • Ubuntu 22.04 LTS (x2) • Windows 10 Pro • Bridged Network (Home Router)

---

## Project Overview

I built this home lab because I wanted to understand how real SOC teams detect and respond to threats. Instead of just reading about SIEM and SOAR tools, I decided to set up a working environment where I could see the entire process: detection, analysis, automation, and incident management.

My goal was simple: take a real threat (Mimikatz), see how each tool detects it, and build an automated response without any manual steps. This project taught me what it takes to build a complete security operations workflow.

**What I Understand Now:**

- How SIEM, SOAR, and case management systems work together in practice
- Why detection rules matter and how to write them for real threats
- How automation can speed up response time without sacrificing accuracy
- How Windows logging (through Sysmon) feeds into detection pipelines
- Why analyst oversight is crucial even in automated environments

---

## Architecture Overview

### System Layout

![SOC Workflow Data Flow](screenshots/soc-workflow.png)

**Why I Built It This Way**

I had to make some practical decisions about how to organize three VMs. Here's my thinking:

- **Wazuh + Shuffle on same VM**: I wanted fast automation—no network delays when an alert comes in
- **TheHive separate**: Case management shouldn't slow down my detection and response pipeline
- **Windows as target**: This is what I'll encounter at work, so it makes sense to practice with it
- **Bridged network**: I needed all services accessible from my main computer for easy testing and troubleshooting

---

## Technology Stack

I didn't pick these tools randomly. Each one solves a specific problem I had:

| Tool            | What It Does           | Why I'm Using It                                                         |
| :-------------- | :--------------------- | :----------------------------------------------------------------------- |
| **Wazuh**       | Detects threats        | It's free, open-source, and I can see exactly how it analyzes logs       |
| **Shuffle**     | Automates responses    | No coding required—I can drag-and-drop a complete workflow visually      |
| **TheHive**     | Tracks incidents       | I need somewhere to organize cases and maintain context during incidents |
| **Sysmon**      | Logs process activity  | Windows doesn't give me detailed process logs by default; Sysmon does    |
| **VirusTotal**  | Checks file reputation | Free API to understand if a file is actually malicious before I respond  |
| **Wazuh Agent** | Collects & responds    | Sends logs to Wazuh and executes response commands on the endpoint       |

---

## Virtual Machine Setup

### Hardware Allocation

I sized these VMs based on what each needs to do:

| VM       | OS                         | CPU     | RAM  | Storage | Role                                      |
| :------- | :------------------------- | :------ | :--- | :------ | :---------------------------------------- |
| **VM 1** | Windows 10 Enterprise LTSC | 2 cores | 8 GB | 50 GB   | Target endpoint (Sysmon + Wazuh Agent)    |
| **VM 2** | Ubuntu 24.04 LTS           | 4 cores | 8 GB | 50 GB   | Detection center (Wazuh + Shuffle Docker) |
| **VM 3** | Ubuntu 24.04 LTS           | 4 cores | 8 GB | 50 GB   | Case tracking (TheHive + Databases)       |

### Resource Decisions

- **Windows gets 2 CPUs**: It mostly just sends logs—doesn't need heavy processing
- **Ubuntu VMs get 4 CPUs each**: They run multiple services and databases that need computing power
- **8 GB RAM across the board**: Enough to run everything smoothly without wasting resources
- **50 GB storage each**: Plenty for operating systems, log storage, and test data

### Network Setup

I connected all VMs with **Bridged Adapter** to my home router:

- Each VM gets a real IP from my router's DHCP server
- VMs can talk to each other and to my main computer
- To find each VM's IP: use `ipconfig` on Windows or `ip addr` on Linux

---

## Getting Started

### Installing the Tools

I'm not going to repeat installation guides here—the official documentation is more up-to-date and thorough. Instead, I'll point you to where I learned:

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

## Testing Detection in Action

### My Test: Mimikatz Detection

I wanted to test my entire setup with a real tool that SOC teams actually deal with. Mimikatz is popular with attackers because it extracts credentials from memory. By testing with it, I can see the whole workflow:

Detection → Analysis → Enrichment → Response → Investigation

Here's how I tested it:

### Step 1: Initial Setup on Windows VM

1. **Disable Windows Defender** (this is just for my lab environment):

   ```powershell
   # Disable Real-Time Protection so it doesn't interfere with testing
   Set-MpPreference -DisableRealtimeMonitoring $true

   # Disable Cloud-Delivered Protection
   Set-MpPreference -DisableCloudProtection $true
   ```

2. **Get Mimikatz** (the tool I'm testing with):
   - Download from: https://github.com/gentilkiwi/mimikatz/releases
   - Save to: `C:\Tools\mimikatz.exe`

### Step 2: Run Mimikatz (Initial Test)

From the Windows VM, I run Mimikatz to trigger it:

```powershell
C:\Tools\mimikatz.exe
```

### Step 3: Check Wazuh for Alerts (Before Configuration)

1. Go to Wazuh → **Discover** section
2. **Nothing shows up** - That's expected. Without a detection rule, Wazuh has no way to know Mimikatz is suspicious.
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

#### 4d. Add Detection Rule for Mimikatz

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Add this rule:

```xml
<rule id="100002" level="15">
   <if_group>sysmon_event1</if_group>
   <field name="win.eventdata.originalFileName" type="pcre2">(?i)mimikatz\.exe</field>
   <description>Mimikatz Usage Detected</description>
   <mitre>
      <id>T1003</id>
   </mitre>
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

## Building Automation Workflows

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

# Workflow Nodes (Step-by-Step Configuration)

#### Node 1: Shuffle Webhook (Alert Reception)

**Purpose**: Receive suspicious activity alerts from Wazuh and initiate workflow

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

#### Node 2: Regex Capture Group (Artifact Extraction)

**Purpose**: Extract SHA256 hash from process telemetry - **Artifact Validation (Guardrail #1) Entry Point**

**Configuration**:

- **Input field**: `$exec.all_fields.full_log.win.eventdata.hashes`
- **Regex pattern**: `SHA256=([0-9A-Fa-f]{64})`
- **Output**: Captured SHA256 hash for enrichment (or null if not found)

**Why This Matters**: This node is the first guardrail. If no hash is found (fileless malware, encoded PowerShell), the workflow bypasses threat intelligence and goes directly to analyst review.

![SOC Workflow Data Flow](screenshots/shuffle_SHA256.png)

---

#### Conditional Branch - Artifact Validation (Guardrail #1)

**Purpose**: Decision point - does a valid hash exist?

**Configuration**:

- **Condition**: `if $sha256-hash exists and length > 0`
- **True Branch**: Continue to VirusTotal enrichment (high-confidence path)
- **False Branch**: Skip enrichment → TheHive alert only (analyst review path)

**Security Rationale**: Hash-less detections (fileless attacks, PowerShell encoding) cannot be auto-remediated with confidence. These are escalated to analyst triage.

---

#### Node 3: VirusTotal – Get Hash Report (Threat Intelligence Enrichment)

**Purpose**: Threat intelligence enrichment via VirusTotal (True branch only)

**Setup**:

1. Create VirusTotal account and generate API key
2. In Shuffle, create VirusTotal authentication:
   - Paste API key
   - Use VirusTotal base URL

**Node Configuration**:

- **Hash field (dynamic)**: `$sha256-hash` (from Regex node)
- **Output**: Detection statistics and vendor consensus (malicious count, legitimate count, undetected count)

![SOC Workflow Data Flow](screenshots/shuffle_virustotal.png)

---

#### Node 4: Python Code – Policy-Based Severity Assessment (Control Layer)

**Purpose**: Normalize VirusTotal results into SOC severity levels - **Response Authorization Gate**

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

**Why This Matters**: This is a **control layer**. The severity score directly determines whether automated response is authorized. Only Critical severity permits auto-remediation.

**Output**: Normalized severity for response authorization decision

![SOC Workflow Data Flow](screenshots/shuffle_python.png)

---

#### Response Authorization Decision (Guardrail #2)

**Purpose**: Policy gate - is automated response authorized?

**Configuration**:

- **If Severity == "Critical"**: Proceed to active response path (authorized)
- **If Severity == "High" / "Medium" / "Low"**: Proceed to alert-only path (analyst review)

**Security Rationale**: Only threats with high VirusTotal consensus trigger automatic remediation. Lower-severity findings receive analyst oversight before any action.

---

#### Node 5: HTTP/Curl – Wazuh API Token (Critical Branch Only)

**Purpose**: Retrieve short-lived Wazuh API token for active response execution (Critical branch only)

**Configuration**:

- **URL**: `https://YOUR_WAZUH_IP:55000/security/user/authenticate`
- **Method**: POST
- **Body**: Username and password from `wazuh-passwords.txt`
- **Output**: Bearer token for Wazuh API calls

**Execution Gate**: This node only executes if Response Authorization Decision == Critical.

![SOC Workflow Data Flow](screenshots/shuffle_Get-API.png)

---

#### Node 6: Wazuh Active Response (Process Termination - Critical Branch Only)

**Purpose**: Execute authorized response - terminate malicious process (Critical branch only)

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

**Audit Note**: This node only executes if both Guardrail #1 (hash exists) AND Guardrail #2 (Critical severity) are satisfied.

---

#### Node 7: [HTTP] Create Case in TheHive

**Purpose**: Create or update case in TheHive for tracking and investigation via API

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

#### Node 8: TheHive – Create Alert/Case (Incident Case Creation)

**Purpose**: Generate analyst-readable incident case with full context (all branches)

**Shuffle Configuration**:

1. Create TheHive authentication
2. URL: `http://YOUR_THEHIVE_IP:9000`
3. API key: From service account

**Alert Fields** (Low/Medium/High severity):

- Title: `Suspicious Activity: {process_name}`
- Severity: `$normalized-severity`
- TLP: 2 (Amber)
- Tags: `MITRE-ATT&CK`, `Malware`, `Detection`
- Description: Includes hash (if available), command line, host

**Case Creation** (Critical severity - automated response):

- Title: `INCIDENT: {hostname} - {threat_name}`
- Description: Full event details + **"Automated response authorized and executed"**
- Related observables: File hash, IP, hostname
- Status: Open (for post-response investigation)
- Tags: `AutoResponse`, `Critical`, MITRE technique

![SOC Workflow Data Flow](screenshots/thehive-test.png)

---

#### Node 9: Email Notification (Analyst Notification)

**Purpose**: Alert analyst of detected activity and action taken

**Configuration**:

- **Recipient**: Analyst email address
- **Subject**: `[ALERT] {severity} - {threat_name} on {hostname}`
  - For Critical with auto-response: `[CRITICAL + AUTOMATED RESPONSE] {threat_name} on {hostname}`
- **Body**:

  ```
  Threat Name: {threat_name}
  Hostname: {hostname}
  Severity: {severity}
  VirusTotal Score: {vt-detection-count}/70

  Automation Status: {response-action}
  (e.g., "Automatic response AUTHORIZED - Process terminated")

  TheHive Case: {case-link}
  Analyst Review Required: [Yes/No based on severity]
  ```

**Verification**:

Once the workflow completes, you should receive an email notification within 1-2 seconds. The email clearly indicates:

- Whether automatic response was executed
- The authorization policy that was applied
- Links to the detailed case for post-incident investigation

![SOC Workflow Data Flow](screenshots/sent-email.png)

---

## Automated Response in Action

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

The automated response workflow follows a **policy-driven decision tree** designed to balance detection accuracy, analyst oversight, and automated containment.

1. **Alert Reception**
   Wazuh detects suspicious activity (e.g., Mimikatz or encoded PowerShell) and forwards the alert to Shuffle via webhook.

2. **Artifact Extraction**
   A regex node attempts to extract a SHA256 hash from the process telemetry.

3. **Artifact Validation (Guardrail #1)**

   - **If a valid hash exists**: The workflow proceeds to threat intelligence enrichment.
   - **If no hash exists** (e.g., fileless or encoded PowerShell): The workflow bypasses enrichment and creates a TheHive alert for analyst review, preventing blind automation.

4. **Threat Intelligence Enrichment**
   VirusTotal enriches the extracted hash with detection ratios and vendor consensus.

5. **Policy-Based Severity Assessment (Control Layer)**
   A Python node normalizes VirusTotal results into SOC severity levels (Low / Medium / High / Critical).
   This node also functions as a **response authorization gate**, determining whether automated remediation is permitted.

6. **Response Authorization Decision (Guardrail #2)**

   - **Low / Medium / High**:
     - No automated containment
     - TheHive alert is created for analyst triage
   - **Critical**:
     - Automation is authorized due to high confidence and impact

7. **Active Response Execution (Critical Only)**
   Shuffle retrieves a short-lived Wazuh API token and instructs the Wazuh manager to execute an active response, terminating the malicious process on the endpoint.

8. **Analyst Notification**
   A high-priority email notification is sent to the analyst, indicating automated containment has occurred.

9. **Incident Case Creation**
   A detailed TheHive case is created via HTTP POST, including:

   - Observables (hash, host, process)
   - Severity
   - Automated actions taken
   - MITRE ATT&CK techniques

---

### Why This Approach Matters

**Policy-Driven Automation**: This workflow is not just reactive (detect → kill). Instead, it implements **authorization gates** (guardrails) that ensure:

- Only high-confidence threats trigger automatic response
- Fileless/hash-less attacks are flagged for analyst review (not blindly automated)
- Severity assessment acts as a control layer, not just a classification
- Every automated action is logged and auditable

This distinction demonstrates mature SOC engineering and is what security teams and interviewers look for in automation projects.

![SOC Workflow Data Flow](screenshots/final_workflow.png)

---

## How the Workflow Processes Alerts

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

## Troubleshooting Common Issues

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

## Resources I Used

- **Wazuh Rules:** https://documentation.wazuh.com/current/user-manual/ruleset/index.html
- **Shuffle Documentation:** https://github.com/frikky/shuffle
- **TheHive API:** https://docs.thehive-project.org/thehive/api/
- **Sysmon Events:** https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
- **MITRE ATT&CK:** https://attack.mitre.org/

---
