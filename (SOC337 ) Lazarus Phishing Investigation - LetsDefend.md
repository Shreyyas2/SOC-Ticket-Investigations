# SOC Ticket Investigation (SOC337) : Lazarus Phishing Campaign Detected (APT38)

**Event ID:** 315
**Event Time:** 2025-03-06T07:15:00+03:00
**Alert Type:** APT Group / Phishing
**Severity:** High
**Difficulty:** Medium
**Role:** Incident Responder
**MITRE ATT&CK Techniques:** T1598.002 (Phishing for Information), T1566 (Phishing), T1059 / T1059.001 (Command and Scripting Interpreter / PowerShell), T1204.001 (User Execution: Malicious Link), T1105 (Ingress Tool Transfer)

---

## What I Observed

An email was flagged by the SIEM matching a known Lazarus Group (APT38) phishing pattern. The message was **allowed** through to the recipient's inbox rather than auto blocked.

- **Source Address:** trevorgreer9312@gmail.com
- **Destination Address:** Ellen@letsdefend.io
- **SMTP Address:** 152.89.61.96
- **Subject:** "Invitation: Coinbase Crypto Trader Hiring Assessment"

## Investigation Steps

1. **Sender legitimacy check** : the sender used a free Gmail address rather than a corporate domain, despite claiming to represent Coinbase for a hiring process. Legitimate corporate hiring outreach does not originate from personal Gmail accounts. This is a strong indicator of impersonation.

2. **Pattern cross-reference** : the subject line and pretext (a fake crypto industry "hiring assessment") match a publicly documented Lazarus Group technique: using fake job offers to target employees in the crypto and tech sectors, typically to deliver a malicious "assessment" file.

3. **Threat Intelligence lookup** : checked the SMTP IP (152.89.61.96) against the platform's threat intelligence database. No prior record was found. This does not clear the IP as safe : it likely reflects new or previously unreported attacker infrastructure rather than legitimate use, given the strength of the other indicators.

4. **Endpoint log review** : reviewed process logs for the affected host (EC2AMAZ-ILGVOIN) around the alert time. Chrome (chrome.exe) was launched normally by the user (parent process: explorer.exe), consistent with routine browsing. All other logged activity (svchost.exe, services.exe, Google Updater, DeviceCensus.exe, etc.) was standard Windows/system background activity, unrelated to the alert.

5. **Targeted search for compromise indicators** : filtered the endpoint logs specifically for any process spawned as a child of chrome.exe, No such child process was found.

## Conclusion

**True Positive : Attempted Phishing, No Successful Compromise.**

The email itself is assessed as a genuine, targeted phishing attempt matching a known threat actor's tactics (sender impersonation, social engineering pretext, and a MITRE mapped attack chain designed to lead to script execution and further payload delivery). However, endpoint evidence shows no indication that the recipient interacted with any malicious link or attachment — no anomalous child processes, script execution, or file downloads were observed following the email's arrival.

## Recommended Response

- Block the sender address and the associated SMTP IP (152.89.61.96) at the email gateway
- Directly confirm with Ellen whether she recalls receiving or interacting with the email, as a secondary verification beyond log evidence
- Add the sender domain pattern and IP to a watchlist, in case the same actor attempts contact through a different address
- Close the alert as a true positive with no compromise, and retain the case for reference given the APT linked nature of the campaign

---
*Investigated as part of hands on SOC analyst training (LetsDefend / HTB).*
