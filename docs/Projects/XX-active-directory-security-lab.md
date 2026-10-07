# Active Directory Attack & Defense Lab

> **Educational lab only.** This project was built in an isolated virtual environment to understand how a compromise can propagate from an exposed web server to an Active Directory domain, and how segmentation, least privilege and domain hardening can break that attack chain.

## 1. Project Overview

The objective of this lab was to build a small enterprise-like Active Directory environment, deliberately introduce several weaknesses, compromise it from an external attacker position, and then redesign the infrastructure with defensive controls.

The offensive scenario starts from a Kali Linux host placed on an external network. A vulnerable Ubuntu web server running DVWA is exposed to that network and also connected to the internal Active Directory network. By exploiting the web application, escalating privileges on Ubuntu and abusing excessive Active Directory permissions, the attack ultimately reaches the Domain Controller with `NT AUTHORITY\SYSTEM` privileges.

The defensive phase focuses on breaking this path using firewall rules, network segmentation, security zones, Group Policy Objects (GPOs) and least-privilege principles.

**Main technologies and concepts:** Windows Server 2022, Active Directory Domain Services, DNS, Kerberos, Ubuntu, DVWA, Kali Linux, Impacket, Hashcat, command injection, privilege escalation, Kerberoasting, DCSync, Pass-the-Hash, network segmentation, firewalling and GPO hardening.

---

## 2. Initial Architecture

The initial lab contained three main systems:

| System | Role | Network position |
|---|---|---|
| **Kali Linux** | External attacker | `192.168.91.129/24` |
| **Ubuntu Server** | DVWA web server, domain member and pivot host | `192.168.91.128/24` + `192.168.176.128/24` |
| **Windows Server 2022** | Domain Controller, AD DS and DNS | `192.168.176.129/24` |

The Active Directory forest/domain used **`LAB.LOCAL`**. Test users visible in the domain included **Alice**, **Bob**, **Charles** and a service account named **`svc_web`**.

The Ubuntu server was deliberately dual-homed. One interface was reachable from the external Kali network while the second interface provided direct access to the internal Active Directory network. This configuration made the web server a high-value pivot point once compromised.

```text
External network: 192.168.91.0/24

[Kali Linux]
192.168.91.129
      |
      | HTTP / attack traffic
      v
[Ubuntu + DVWA]
192.168.91.128
192.168.176.128
      |
      | Internal network access
      v
[Windows Server 2022 / DC]
192.168.176.129
LAB.LOCAL

Internal network: 192.168.176.0/24
```

---

## 3. Active Directory Configuration

The Windows Server was configured with the **Active Directory Domain Services (AD DS)** and **DNS** roles and promoted as the Domain Controller for `LAB.LOCAL`.

Several user accounts were created to simulate a small organization. A dedicated service account, `svc_web`, was intentionally configured with excessive privileges in order to model a realistic privilege-management failure.

In particular, the account was granted directory replication permissions such as **Replicating Directory Changes**, creating the conditions required for a later **DCSync** attack if the service account credentials were compromised.

This misconfiguration is important because it demonstrates a common security principle: a service account should never receive domain-wide privileges that are unrelated to the service it runs.

---

## 4. Offensive Scenario

### 4.1. Initial Access through DVWA

The Ubuntu server hosted **Damn Vulnerable Web Application (DVWA)**. The attack began from Kali Linux by targeting the **Command Injection** functionality exposed by the application.

After validating that commands could be executed on the server, a reverse shell was triggered back to the Kali machine.

Kali listener:

```bash
nc -nvlp 4444
```

The injected payload established a connection back to the attacker and returned a shell running as the web-service account:

```text
www-data@ubuntuserver
```

At this stage, the attacker had remote command execution on the exposed Ubuntu host but did not yet have administrative privileges.

### 4.2. Linux Privilege Escalation

The compromised `www-data` account was checked for sudo permissions:

```bash
sudo -l
```

The configuration allowed `www-data` to execute `/usr/bin/find` with `NOPASSWD`. Because `find` can execute arbitrary commands, this sudo rule could be abused to spawn a privileged shell.

```bash
sudo find . -exec /bin/bash \; -quit
```

The attacker therefore escalated from the low-privileged web-service account to **root** on the Ubuntu pivot host.

This phase highlights why sudo rules must not grant unrestricted access to binaries that support command execution or shell escapes.

### 4.3. Pivot to the Internal Domain

Once root access was obtained, the second Ubuntu network interface provided direct connectivity to the internal `192.168.176.0/24` network.

The compromised server was also already integrated into the `LAB.LOCAL` Kerberos realm. Domain discovery confirmed that the machine was a Kerberos/Active Directory member:

```bash
realm discover
```

The Ubuntu machine's Kerberos keytab was then used to obtain credentials for the machine account:

```bash
kinit -k -t /etc/krb5.keytab 'UBUNTUSERVER$@LAB.LOCAL'
klist
```

This step demonstrates another important risk: compromising a domain-joined server can expose domain credentials or Kerberos material that can be reused for further domain reconnaissance.

### 4.4. Kerberoasting the Service Account

Using the Kerberos context available on the compromised Ubuntu server, Impacket was used to request service tickets for accounts with Service Principal Names (SPNs):

```bash
GetUserSPNs.py -request -k -no-pass LAB.LOCAL/UBUNTUSERVER$
```

A Kerberos TGS hash associated with the web service account was recovered and exported for offline cracking.

The ticket was then tested against a wordlist with Hashcat using mode **13100** (Kerberos 5 TGS-REP, etype 23):

```bash
hashcat -m 13100 svc_web.hash /usr/share/wordlists/rockyou.txt
```

The service-account password was successfully recovered, demonstrating that the password was not sufficiently resistant to offline guessing.

> The recovered lab password is intentionally omitted from this public write-up.

### 4.5. DCSync through Excessive Replication Rights

The compromise became critical because the service account had previously been granted directory replication privileges.

With the recovered account credentials, Impacket's `secretsdump` was used against the Domain Controller:

```bash
impacket-secretsdump lab.local/svcweb:'<recovered-password>'@192.168.176.129
```

Because the account possessed replication rights, it could request sensitive directory data in a way similar to a Domain Controller replication operation. This exposed domain credential material, including the Administrator NTLM hash.

The attack demonstrates why the following permissions are exceptionally sensitive:

- Replicating Directory Changes
- Replicating Directory Changes All
- Replicating Directory Changes in Filtered Set

Accounts holding these rights should be treated as highly privileged and continuously audited.

### 4.6. Pass-the-Hash and Domain Controller Compromise

The recovered Administrator NTLM hash was then reused directly without knowing the Administrator clear-text password.

```bash
psexec.py Administrator@192.168.176.129 -hashes :<ADMIN_NTLM_HASH>
```

The remote execution succeeded through the administrative share and created a privileged service on the Domain Controller.

Final verification:

```cmd
whoami
```

Result:

```text
nt authority\system
```

The lab therefore demonstrated a complete attack path from an external web application to **SYSTEM-level execution on the Domain Controller**.

---

## 5. Attack Path Summary

```text
External Kali attacker
        |
        v
DVWA command injection
        |
        v
Reverse shell as www-data
        |
        v
Unsafe sudo rule on /usr/bin/find
        |
        v
Root on dual-homed Ubuntu server
        |
        v
Kerberos access to LAB.LOCAL
        |
        v
Kerberoasting of svc_web
        |
        v
Weak service-account password recovered
        |
        v
svc_web replication / DCSync privileges
        |
        v
Domain credential hashes recovered
        |
        v
Pass-the-Hash with Administrator NTLM hash
        |
        v
NT AUTHORITY\SYSTEM on Domain Controller
```

---

## 6. Security Weaknesses Identified

The exercise exposed several independent weaknesses that became much more dangerous when chained together:

1. **Externally reachable vulnerable web application** allowing operating-system command injection.
2. **Dual-homed web server** providing a direct bridge between the exposed network and the internal domain network.
3. **Unsafe sudo configuration** allowing the web-service account to execute a shell-capable binary as root without a password.
4. **Domain-joined exposed server** containing reusable Kerberos material in a local keytab.
5. **Weak service-account password** that could be recovered through offline Kerberoasting.
6. **Excessive privileges on `svc_web`**, especially Active Directory replication rights.
7. **Insufficient network filtering** between the compromised web server and the Domain Controller.
8. **Administrative protocols reachable from the pivot host**, allowing credential material to be reused for lateral movement.

The main lesson is that domain compromise did not depend on one critical vulnerability. It resulted from a **chain of smaller configuration and privilege weaknesses**.

---

## 7. Defensive Redesign & Hardening

The second phase of the project focused on breaking the attack path using defense-in-depth rather than relying on a single control.

### 7.1. Network Segmentation and Security Zones

The flat connectivity model was redesigned around separate security zones protected by firewall rules.

A typical hardened design for this lab separates:

- **External / Untrusted zone** — attacker or Internet-facing network.
- **DMZ / Web zone** — exposed application servers.
- **Internal server zone** — trusted internal services.
- **Domain Controller / Identity zone** — the most sensitive Active Directory systems.
- **Administration zone** — privileged management traffic where applicable.

The firewall policy follows a **default-deny** approach: communication between zones is blocked unless an explicit business requirement exists.

For the web server, only the application ports required by users should be exposed from the external network. Direct unrestricted communication from the DMZ to the Domain Controller should not be permitted.

This single architectural change limits the value of the web server as a pivot even if the application itself is compromised.

### 7.2. Firewall Rules and Flow Restriction

The firewall rules were designed around the principle of minimum required connectivity:

- External users can reach only the published web service.
- The DMZ cannot initiate arbitrary connections toward internal systems.
- Administrative protocols such as SMB, WinRM and RDP are not exposed to the web zone without a justified requirement.
- Domain Controller access is limited to trusted systems and necessary identity services.
- East-west traffic between security zones is explicitly controlled and logged.

The objective is not simply to hide the Domain Controller, but to ensure that compromising one server does not automatically provide a routable path to the identity infrastructure.

### 7.3. Linux Privilege Hardening

The dangerous sudo rule allowing `www-data` to execute `/usr/bin/find` with `NOPASSWD` must be removed.

Service accounts should not receive generic sudo rights. If a web application genuinely requires a privileged operation, it should be implemented through a narrowly scoped mechanism that cannot execute arbitrary commands.

Key principles applied to sudo configuration:

- no shell-capable binaries for untrusted service accounts;
- no unnecessary `NOPASSWD` rules;
- explicit command paths and arguments when possible;
- regular review of `/etc/sudoers` and `/etc/sudoers.d/`;
- separation between application identities and administrator identities.

### 7.4. Active Directory Least Privilege

The most important identity fix is the removal of replication privileges from the service account.

`svc_web` should not have any of the permissions required for DCSync. Replication rights should remain restricted to Domain Controllers and explicitly authorized administrative identities.

The service account should also follow a dedicated hardening policy:

- long and randomly generated password;
- no interactive logon;
- no membership in administrative groups;
- only the exact permissions required by the associated service;
- regular credential rotation;
- use of modern Kerberos encryption where possible;
- periodic review of SPNs and delegated permissions.

This change breaks the attack chain even if the account password were somehow recovered.

### 7.5. Group Policy Hardening

Group Policy was used as part of the defensive phase to centralize security configuration and reduce privilege exposure across the domain.

The hardening strategy focuses on areas such as:

- stronger password and account-lockout policy;
- restriction of privileged and local administrator rights;
- Windows Defender Firewall enforcement;
- enhanced security auditing;
- reduction of legacy or unnecessary authentication protocols;
- restriction of remote administrative access;
- tighter user-rights assignments;
- consistent security configuration across domain-joined machines.

The exact GPO settings can be extended in the portfolio as screenshots or exports from the original lab become available.

### 7.6. Protecting the Domain Controller

The Domain Controller is placed in the most restricted network zone and should not be treated as a general-purpose server.

Defensive principles include:

- no direct exposure to untrusted zones;
- no unnecessary applications or services;
- privileged administration only from controlled systems;
- restricted SMB/RPC/RDP access;
- regular review of accounts with replication permissions;
- dedicated administrative accounts;
- strong auditing of changes to privileged groups and directory permissions.

---

## 8. Detection Opportunities

The attack also provides several useful Blue Team detection points.

| Attack phase | Detection opportunity |
|---|---|
| Web command injection | Web-server logs, abnormal shell execution, suspicious child processes |
| Reverse shell | Unexpected outbound connection from web service process |
| Sudo privilege escalation | `sudo` logs showing `www-data` executing privileged commands |
| Kerberoasting | Unusual volume or pattern of Kerberos service-ticket requests (Windows Event ID 4769) |
| DCSync | Directory replication activity by an account that is not a Domain Controller (Event ID 4662 with replication rights) |
| Pass-the-Hash / PsExec | Remote SMB authentication, administrative share access, new service creation and unusual privileged logons |

This makes the lab useful from both offensive and defensive perspectives: each attack technique can be mapped to a potential prevention or detection control.

---

## 9. Before vs. After Hardening

### Before

```text
Internet/Attacker -> Web Server -> Internal Network -> Domain Controller
                         |
                         +-> privileged sudo
                         +-> Kerberos material
                         +-> unrestricted internal reachability

svc_web -> weak password + replication privileges -> DCSync
```

### After

```text
External Zone
      |
   Firewall
      |
     DMZ
 [Web Server]
      |
   restricted flows
      |
 Internal Services
      |
   restricted flows
      |
 Identity / DC Zone
```

The redesigned model creates multiple independent barriers. Compromising the web application should no longer automatically provide root privileges, unrestricted internal connectivity, domain-replication privileges and administrative access to the Domain Controller.

---

## 10. Skills Demonstrated

This project combines offensive and defensive security skills:

- Windows Server and Active Directory deployment
- AD DS and DNS administration
- Kerberos authentication and service accounts
- Linux and Windows networking
- Web application exploitation in a controlled lab
- Reverse shells and Linux privilege escalation
- Internal network pivoting
- Kerberoasting
- DCSync
- Pass-the-Hash
- Impacket tooling
- Hashcat
- Active Directory privilege analysis
- Firewall policy design
- Network segmentation and security zones
- GPO-based hardening
- Least-privilege design
- Attack-path analysis
- Blue Team detection thinking

---

## 11. Evidence to Add from the Original Demonstration

The original project demonstration video provides strong visual evidence for the offensive portion of the lab. Useful screenshots for the final portfolio version include:

1. Active Directory users (`Alice`, `Bob`, `Charles`, `svc_web`).
2. `svc_web` directory replication permissions.
3. Ubuntu dual-interface network configuration.
4. DVWA Command Injection page.
5. Reverse shell as `www-data` and the unsafe sudo rule.
6. `realm discover` / Kerberos domain membership.
7. Kerberoasting ticket extraction.
8. Hashcat result with the recovered password **redacted**.
9. `secretsdump` output with credential hashes **redacted**.
10. Final `whoami` output showing `nt authority\system` on the Domain Controller.

These screenshots should be cropped and sanitized before publication so that the write-up demonstrates the technique without publishing reusable credentials or hashes.
