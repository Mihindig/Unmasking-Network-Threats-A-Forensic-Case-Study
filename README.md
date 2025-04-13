# Investigation into Network Infection and Command-and-Control (C2) Analysis

## **Introduction**
This investigation stems from a suspicious file downloaded by a coworker while searching for Google Authenticator. The subsequent infection prompted the need for a detailed analysis of the provided packet capture (PCAP). The main objectives of this investigation were to identify the infected Windows client, analyze its communication, pinpoint command-and-control (C2) servers, and uncover the likely domain for the fake Google Authenticator page. 

Through methodical analysis using tools such as Wireshark and VirusTotal, the following findings and insights were derived.

---

## **1. Initial Analysis and Suspicious Indicators**
The investigation began with a comprehensive review of the PCAP and associated indicators:
- **MITRE ATT&CK Tactics and Techniques:**  
  Upon checking the file hash in VirusTotal, the behavior analysis flagged several tactics and techniques under MITRE ATT&CK. Key observations included the use of:
  - Suspicious PowerShell commands and web request activities.
  - Indicators of non-interactive PowerShell processes.
- **Crowdsourced Sigma Rules Matches:**  
  Rules detected included the use of suspicious PowerShell downloads and web request commands, further corroborating malicious activity.
- **Crowdsourced IDS Rules Alerts:**  
  Notable high-priority alerts flagged policy violations and potential scripting activities. HTTP requests by IPv4 and scripting host calls were among the significant findings.
- **HTTP Requests to 5.252.153.241:**  
  Repeated GET requests were observed, fetching suspicious files (`pas.ps1`, `TeamViewer`, etc.), confirming communication with a likely C2 server.

---

## **2. Identifying the Infected Client**
To determine the infected client:
- **Wireshark Endpoint Statistics:**  
  Examining IPv4 endpoint statistics revealed that the IP `10.1.17.215` stood out due to its high packet count (39,045 packets, 26MB bytes exchanged). This significant activity indicated that the host was the most active in the LAN segment, confirming it as the infected client.
- **MAC Address Discovery:**  
  Filtering for `ip.addr == 10.1.17.215` and inspecting Ethernet II in Wireshark identified the MAC address of the infected client as `00:d0:b7:26:4a:74`.
- **Hostname Identification:**  
  Running filters for NBNS, LLMNR, and DHCP traffic revealed the hostname of the infected client as `DESKTOP-L8C5GSJ`. The host’s behavior, including name registration and LLMNR queries, reinforced this conclusion.

---

## **3. Pinpointing C2 Servers**
The next step involved identifying the command-and-control (C2) infrastructure:
- **Primary C2 Server:**  
  Traffic with IP `5.252.153.241` revealed repeated GET requests for malicious scripts and executables, confirming it as the primary C2 server.
- **Secondary C2 Servers:**  
  - **`45.125.66.32`:**  
    TLSv1.2 traffic with rare JA3 hashes, minimal cipher suites, and live data exchange indicated active C2 communication.
  - **`45.125.66.252`:**  
    Encrypted traffic over port 443 with low round-trip times and immediate data exchange also confirmed its role as a C2 server.
- **Differentiation from Tool Downloader:**  
  The IP `185.188.32.26` was initially suspected but found to be linked to `master16.teamviewer.com` and associated with "DynGate" traffic. This suggested it was more likely a tool downloader or backdoor rather than a C2 server.

---

## **4. Username of the Infected Client**
To uncover the username of the infected client:
- **Kerberos Traffic Analysis:**  
  Filtering for Kerberos, NTLMSSP, and SMB traffic (`ip.addr == 10.1.17.215 && (ntlmssp || kerberos || smb)`), and inspecting an AS-REQ packet, revealed the username as `shutchenson`, operating under the domain `BLUEMOONTUESDAY`.

---

## **5. Likely Domain of Fake Google Authenticator**
The investigation also identified the domain associated with the fake Google Authenticator page:
- **Traffic Analysis:**  
  Filtering for "authenticator" in Wireshark highlighted DNS queries and SNI indications for `google-authenticator.burleson-appliance.net`.
- **DNS Resolution:**  
  The domain resolved to multiple IPs in the `104.21.x.x` range, part of Cloudflare infrastructure, which is often misused for phishing.
- **Validation with urlscan.io:**  
  A search on `urlscan.io` confirmed the malicious nature of the domain and its links to `burleson-appliance.net`.

---

## **Conclusion**
This investigation successfully identified the infected Windows client, analyzed its communication with malicious C2 servers, and uncovered the fake domain used in this phishing campaign. Through diligent analysis using Wireshark, VirusTotal, and corroborative tools, the following critical details were determined:

- **Infected Client Details:**  
  - **IP Address:** `10.1.17.215`  
  - **MAC Address:** `00:d0:b7:26:4a:74`  
  - **Hostname:** `DESKTOP-L8C5GSJ`  
  - **Username:** `shutchenson`  

- **C2 Servers:**  
  - **Primary C2:** `5.252.153.241`  
  - **Secondary C2s:** `45.125.66.32`, `45.125.66.252`  

- **Fake Domain:**  
  - Likely Domain: `google-authenticator.burleson-appliance.net`  
---

## **Screenshots**

### MITRE ATT&CK Summary - Execution and Techniques

![MITRE ATT&CK Summary - Execution and Techniques](https://github.com/caitwork/networktraffic/blob/main/MITRE%20ATT%26CK%20Summary%20-%20Execution%20and%20Techniques.png)

- A screenshot highlighting the malicious behavior detected using MITRE ATT&CK Tactics and Techniques. This includes key stages such as Execution, Persistence, and Command and Control (C2), offering a structured view of the threat landscape.

### Crowdsourced Sigma Rules - Detection Highlights

![Crowdsourced Sigma Rules - Detection Highlights](https://github.com/caitwork/networktraffic/blob/main/Crowdsourced%20Sigma%20Rules%20-%20Detection%20Highlights.png)

- A snapshot showing matched Sigma rules detecting suspicious PowerShell activity and web request commands during malware execution. This supports the investigation's focus on command-line and script-based anomalies.

### Crowdsourced IDS Alerts - Severity Levels

![Crowdsourced IDS Alerts - Severity Levels](https://github.com/caitwork/networktraffic/blob/main/Crowdsourced%20IDS%20Alerts%20-%20Severity%20Levels.png)

- A snapshot detailing severity-based alerts from Crowdsourced IDS rules. Highlights include HTTP policy violations, scripting host access, and PowerShell activities, supporting evidence of malicious network activity and potential command-and-control communication.

### Network Communication Logs - HTTP Traffic to C2 Server

![Network Communication Logs - HTTP Traffic to C2 Server](https://github.com/caitwork/networktraffic/blob/main/Network%20Communication%20Logs%20-%20HTTP%20Traffic%20to%20C2%20Server.png)

- A screenshot depicting HTTP GET requests and headers related to suspicious traffic with the primary C2 server `(5.252.153.241)`. These logs reveal script downloads and command-related traffic, confirming malicious communication.

### File System Analysis - Dropped Malicious Files

![File System Analysis - Dropped Malicious Files](https://github.com/caitwork/networktraffic/blob/main/File%20System%20Analysis%20-%20Dropped%20Malicious%20Files.png)

- This screenshot shows a list of files dropped by the malware during execution. Files include temporary files, PowerShell scripts, and other artifacts written to paths such as the AppData and Temp folders, indicating infection activities and persistence techniques.

### Endpoint Statistics - Identifying the Infected Client

![Endpoint Statistics - Identifying the Infected Client](https://github.com/caitwork/networktraffic/blob/main/Endpoint%20Statistics%20-%20Identifying%20the%20Infected%20Client.png)

- This screenshot showcases IPv4 endpoint statistics from Wireshark, highlighting the network activity for `10.1.17.215`. The significant number of packets (39,045) and bytes exchanged (26MB) led to its identification as the infected Windows client.

### Endpoint Statistics - C2 Traffic from 5.252.153.241

![Endpoint Statistics - C2 Traffic from 5.252.153.241](https://github.com/caitwork/networktraffic/blob/main/Endpoint%20Statistics%20-%20C2%20Traffic%20from%205.252.153.241.png)

-This screenshot highlights the network activity of the C2 server `5.252.153.241`. Key statistics include 9,076 packets and 7MB of data exchanged, with breakdowns of Tx and Rx packets. These metrics confirm its role as a primary command-and-control server.

### Captured HTTP Traffic - Infected Client and Primary C2 Server

![Captured HTTP Traffic - Infected Client and Primary C2 Server](https://github.com/caitwork/networktraffic/blob/main/Captured%20HTTP%20Traffic%20-%20Infected%20Client%20and%20Primary%20C2%20Server.png)

- This screenshot displays HTTP GET requests from the infected client `10.1.17.215` to the primary C2 server `5.252.153.241`. The requests retrieve malicious scripts (`pas.ps1`, `TeamViewer`, etc.), further solidifying the server's role in malware communication.


### Wireshark Analysis - HTTP Traffic Details

![Wireshark Analysis - HTTP Traffic Details](https://github.com/caitwork/networktraffic/blob/main/Wireshark%20Analysis%20-%20HTTP%20Traffic%20Details.png)

- This screenshot illustrates the detailed breakdown of HTTP traffic originating from `10.1.17.215`, showing GET requests to suspicious hosts such as `185.188.32.26`. Key elements like headers, host information, and request paths reinforce the investigation findings regarding backdoor activity and suspicious downloads.

### MAC Address Discovery - Infected Client Identification

![MAC Address Discovery - Infected Client Identification](https://github.com/caitwork/networktraffic/blob/main/MAC%20Address%20Discovery%20-%20Infected%20Client%20Identification.png)

- The screenshot displays a filtered Wireshark view (`ip.addr == 10.1.17.215`) pinpointing the infected client's MAC address (`00:d0:b7:26:4a:74`). This analysis links physical hardware to malicious network activity.

### Hostname Identification - NBNS and LLMNR Queries

![Hostname Identification - NBNS and LLMNR Queries](https://github.com/caitwork/networktraffic/blob/main/Hostname%20Identification%20-%20NBNS%20and%20LLMNR%20Queries.png)

- This screenshot shows filtered Wireshark traffic (`ip.addr == 10.1.17.215 && (nbns.name || llmnr || dhcp)`) used to identify the hostname of the infected client (`DESKTOP-L8C5G5J`). The traffic includes NBNS registration and LLMNR standard queries, confirming typical Windows domain behavior.

### TLS Handshake Analysis - Suspicious Encrypted Traffic

![TLS Handshake Analysis - Suspicious Encrypted Traffic](https://github.com/caitwork/networktraffic/blob/main/TLS%20Handshake%20Analysis%20-%20Suspicious%20Encrypted%20Traffic.png)

- This screenshot captures the TLSv1.2 handshake between the infected client and `45.125.66.32`, a suspected C2 server. Highlighted elements include cipher suites used for encryption and the Server Name Indication (SNI) extension, confirming a direct attempt to establish communication.

### TCP Packet Analysis - Stream Details

![TCP Packet Analysis - Stream Details](https://github.com/caitwork/networktraffic/blob/main/TCP%20Packet%20Analysis%20-%20Stream%20Details.png)

- This screenshot captures key attributes of a TCP packet exchanged within the infected client’s network traffic. Details include sequence numbers, acknowledgments, checksum verification, and transmission behavior, offering insights into potential C2 communication or unusual activity.

### TLSv1.2 Handshake - Client Hello Analysis

![TLSv1.2 Handshake - Client Hello Analysis](https://github.com/caitwork/networktraffic/blob/main/TLSv1.2%20Handshake%20-%20Client%20Hello%20Analysis.png)

- This screenshot captures the details of a TLSv1.2 Client Hello message, highlighting key fields such as cipher suites, extensions, session ticket requests, and encryption preferences. These details help confirm encrypted communications between the infected client and a possible C2 infrastructure.

### TCP Packet Analysis - Deep Dive into Connection Behavior

![TCP Packet Analysis - Deep Dive into Connection Behavior](https://github.com/caitwork/networktraffic/blob/main/TCP%20Packet%20Analysis%20-%20Deep%20Dive%20into%20Connection%20Behavior.png)

- This screenshot captures the detailed attributes of a TCP packet exchange, showcasing fields such as sequence numbers, acknowledgment values, checksum verification, flags, and timestamps. These details contribute to understanding packet transmission and anomalies in communication between the infected client and external hosts.

### Kerberos Authentication Request - Username Extraction

![Kerberos Authentication Request - Username Extraction](https://github.com/caitwork/networktraffic/blob/main/Kerberos%20Authentication%20Request%20-%20Username%20Extraction.png)

- This screenshot captures a Kerberos AS-REQ packet filtered using `ip.addr == 10.1.17.215 && (ntlmssp || kerberos || smb)`, displaying key authentication details. The cname field reveals the username (`shutchenson`), while the sname confirms authentication requests targeting `krbtgt` within the realm `BLUEMOONTUESDAY`. This step is crucial in identifying the user account associated with the infected client.

### Network Traffic Analysis - Suspicious TLS & DNS Queries

![Network Traffic Analysis - Suspicious TLS & DNS Queries](https://github.com/caitwork/networktraffic/blob/main/Network%20Traffic%20Analysis%20-%20Suspicious%20TLS%20%26%20DNS%20Queries.png)

- This screenshot captures network traffic filtered for packets containing ‘authenticator,’ revealing TLS handshake and DNS queries to `google-authenticator.burleson-appliance.net`. Highlighted packets include a Client Hello with SNI information and DNS lookups confirming resolution attempts to multiple IP addresses associated with the domain. These details reinforce the investigation into potential encrypted C2 communication.


### TLSv1.3 Handshake - Client Hello with SNI Extension

![TLSv1.3 Handshake - Client Hello with SNI Extension](https://github.com/caitwork/networktraffic/blob/main/TLSv1.3%20Handshake%20-%20Client%20Hello%20with%20SNI%20Extension.png)

- This screenshot displays a TLSv1.3 Client Hello message, showcasing important extensions such as the Server Name Indication (SNI) field. The highlighted portion reveals the requested server name, `google-authenticator.burleson-appliance.net`, which aids in understanding encrypted communication targets and potential suspicious connections.

### DNS Query Analysis - Google Authenticator Domain

![DNS Query Analysis - Google Authenticator Domain](https://github.com/caitwork/networktraffic/blob/main/DNS%20Query%20Analysis%20-%20Google%20Authenticator%20Domain.png)

- This screenshot captures filtered DNS query traffic, specifically highlighting a request from `10.1.17.215` for `google-authenticator.burleson-appliance.net`. The detailed breakdown includes flags, transaction IDs, and query type (A record), showcasing potential host resolution for this domain. This information supports investigations into domain activity linked to authentication mechanisms or potential security risks.

### urlscan.io Report - Malicious Domain Analysis

![urlscan.io Report - Malicious Domain Analysis](https://github.com/caitwork/networktraffic/blob/main/urlscan.io%20Report%20-%20Malicious%20Domain%20Analysis.png)

- This screenshot showcases an urlscan.io report for the domain `google-authenticator.burleson-appliance.net`. Key findings include:\n   - Google Safe Browsing flags the domain as malicious.\n   - The TLS certificate is issued by WE1 (valid for 3 months, starting January 20th, 2025).\n   - The main IP address is `104.21.48.1` (CLOUDFLARENET, US).\nThe report strengthens evidence of malicious hosting infrastructure linked to this domain.

---

## **Resources**

- [Malware Traffic Analysis: Packet Capture and Case Studies](https://www.malware-traffic-analysis.net/)  
- [Palo Alto Networks Unit42: Timely Threat Intel IOCs](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2025-01-22-IOCs-for-malware-from-fake-Microsoft-Teams-site.txt)  
- [urlscan.io: Suspicious Domain Analysis Platform](https://urlscan.io/)  
- [VirusTotal: File and URL Reputation Analysis](https://www.virustotal.com/gui/home/upload)  
- [Wireshark: Network Traffic Analysis and Packet Inspection Tool](https://www.wireshark.org/)


