# Cherif Zouaoui

**Master 2 — Information & Systems Security, Université de Lorraine**  
**Blue Team · Security Infrastructure · SOC · Pentest**

I am currently looking for a **6-month final-year cybersecurity internship starting in March 2027**.

My main interests are defensive security, infrastructure security, security monitoring, Active Directory, network security and technical security analysis. This portfolio presents the projects and technical work I use to develop those skills.

---

## Featured Projects

### Security Monitoring Lab — Wazuh, Suricata & pfSense

**Technologies:** Wazuh · Suricata · pfSense · Sysmon · Windows Server · Ubuntu · Kali Linux · Docker

A segmented security-monitoring lab combining network and endpoint telemetry. The environment uses pfSense for network segmentation, Suricata for network intrusion detection, Wazuh for centralized monitoring and Sysmon for Windows endpoint visibility.

The project also includes controlled attack simulations from Kali Linux against an internal OWASP Juice Shop instance in order to validate detection and alerting capabilities.

[View the project →](Projects/01-deploiement-siem-wazuh.md)

---

### Active Directory Attack & Defense Lab

**Technologies:** Active Directory · Windows Server · DNS · Kerberos · Ubuntu · DVWA · Impacket · Hashcat · GPO · Network Segmentation

An end-to-end Active Directory security lab combining offensive analysis and defensive hardening.

The attack scenario starts from an external Kali Linux machine, compromises an exposed DVWA web server through command injection, escalates privileges on Ubuntu, pivots into the internal network and abuses Kerberos and excessive Active Directory permissions through **Kerberoasting, DCSync and Pass-the-Hash** until obtaining `NT AUTHORITY\SYSTEM` access on the Domain Controller.

The second phase focuses on reducing the attack surface through **network segmentation, firewall rules, security zones, least privilege, service-account hardening and GPO-based security controls**, while identifying relevant Blue Team detection opportunities.

[View the project →](Projects/02-active-directory-security-lab.md)

---

### Bitcoin Mining Optimization on PiM Architecture

**Technologies:** C · Assembly · UPMEM · Performance Optimization · SHA-256

R&D internship project conducted at the MIS Laboratory of the Université de Picardie Jules Verne. I implemented and optimized Bitcoin mining workloads on a Processor-in-Memory architecture, achieving up to a **3× increase in hashes calculated per second**.

[View the project →](Projects/03-bitcoin-pim.md)

---

## CTF & Practical Training

I also document selected CTF and practical security exercises to develop and maintain hands-on skills in enumeration, exploitation, Active Directory and web security.

[Browse CTF write-ups →](CTF/attacktive-directory.md)

---

## Contact

- **Email:** zouaouiicherif@gmail.com
- **GitHub:** [github.com/ZouCherif](https://github.com/ZouCherif)
- **Portfolio:** [ZouCherif.github.io/portfolio](https://ZouCherif.github.io/portfolio/)
