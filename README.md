# Rubber Ducky 


---

## Hello — quick friendly note
Hi — I’m Charles. I wrote this repo to help students, instructors and defenders understand the concepts behind autonomous USB delivery (Rubber‑Ducky) across Linux and Windows. 

Read the safety and legal warnings below *before* you do anything.

---

## 🚨 Very strict legal & safety disclaimers (read carefully)
- **Do not run offensive code** on systems you do not own or do not have explicit, written permission to test.  
- **Unauthorized access or modification of computer systems is illegal.** Running or distributing operational attack code without authorization can lead to criminal prosecution, civil liability, academic discipline, fines, and **imprisonment**. This is a real legal boundary — not a suggestion. 
- If you are an instructor or lab owner and require runnable lab assets, create a **private, permissioned** lab environment and coordinate with your institution. Never publish operational code in public repositories.  
- **Hardware safety warning:** Use the Dupont cable to bridge the Rubber Ducky device when writing the payload onto it. Failure to do so will run the payload on your host machine rather than the virtual machine.

- Make sure you edit the IPs to match that of your host machine. I used three VMs to stage this attack. The attack VM (Kali) and the two victims, Ubuntu and Windows. The payloads (of both Windows and Linux) are hosted on the attack VM whilst Ubuntu and Windows have the Payload.dd file.

---

## Table of contents
- [High-level summary](#high-level-summary)  
- [What’s included (conceptual)](#whats-included-conceptual)  
- [Short conceptual descriptions](#short-conceptual-descriptions)  
- [Cyber Kill Chain mapping](#cyber-kill-chain-mapping)  

---

## High-level summary
This project provides a walkthrough of an autonomous USB delivery assessment (Rubber‑Ducky concept) targeting Linux and Windows hosts. The focus is on the chain of attacks — payload delivery, beaconing/check‑in logic, persistence concepts, reconnaissance, lateral movement and exfiltration concepts.

---

## What’s included
- `server/` — server stub for staging/beaconing. 
- `samples/linux/` — Payload for Linux machine
- `samples/windows/` — Payload for Windows machine 
- `docs/` — lab setup, defensive notes, and recommended telemetry.

---

## Short descriptions

### Server
**Role:** A lab-only staging/check-in component used to illustrate how beaconing and payload staging behave.

**Key teaching points:** how to read server logs, how staged payload fetches look in logs, and how to build simple, auditable test servers in private labs.

---

### Linux payload
**Role:** Demonstrates how a Linux-based autonomous payload operates during a red‑team exercise:
- **Reconnaissance:** collect sensitive system metadata (hostname, user context, kernel version).  
- **Beaconing/C2 (concept):** periodic check‑ins to a lab-only controller to request instructions  
- **Persistence (concept):** possible persistence locations and indicators  
- **Collection (concept):** what data enumeration looks like;



---

### Windows payload 
**Role:** The Windows counterpart covering the same phases: reconnaissance, beaconing idea, persistence vectors (Run keys, scheduled tasks), and collection patterns 

---

### Rubber Ducky 
**Role:** Explains how a keystroke injector automates command entry. 

**Detection focus:** HID device insertions, correlated process launches, and unexpected interactive sessions.

---

## Cyber Kill Chain mapping

We map the traditional kill chain stages to the conceptual steps represented here so you can think both like an attacker and a defender.

```mermaid
flowchart LR
  Recon[Reconnaissance]
  Weapon[Weaponization (concept)]
  Delivery[Delivery (USB / keystroke)]
  Exploit[Exploitation (initial execution - concept)]
  Install[Installation / Persistence (concept)]
  C2[Command & Control (beaconing concept)]
  Actions[Actions on Objectives (collection / exfil - concept)]

  Recon --> Weapon --> Delivery --> Exploit --> Install --> C2 --> Actions


