# Proposal: OT/ICS emitter (Modbus / DNP3 / BACnet) for the EventDispatcher

> This is the text to post as a GitHub **issue** on `Cisco-Talos/EvidenceForge`
> (not a PR). It proposes scope and design and asks for maintainer direction
> before any implementation. No commercial content. Review it, then post it
> yourself.

---

**Title:** Proposal: OT/ICS synthetic telemetry emitter (Modbus/DNP3/BACnet)

**Body:**

### Motivation

EvidenceForge generates correlated, ground-truth-labeled logs across a strong set
of IT sources (Windows, Sysmon, Zeek, eCAR, syslog, web/proxy), but there is
currently no OT/ICS/IoT coverage. Threat-hunting and detection-engineering for
industrial environments has the same problem EvidenceForge solves for IT — real
OT captures are scarce, sensitive, and hard to label — so an OT emitter would
extend the tool into a domain that badly lacks realistic, labeled data.

### What I'd like to add

An OT emitter set that produces, from the canonical event model, correlated
records in:

- a **Zeek `modbus.log`-style** format (Zeek ships a native Modbus analyzer),
- **syslog** (OT gateway / SIEM style),
- **JSON** lines,

all sharing the cross-format correlation id, with **MITRE ATT&CK for ICS**
technique mappings in the ground truth (e.g. `T0855` Unauthorized Command
Message, `T0836` Modify Parameter, `T0846` Remote System Discovery, `T0814`
Denial of Service). Initial protocol scope: **Modbus**, then **DNP3** and
**BACnet**.

### The design question I need direction on

OT telemetry does not map cleanly onto the existing host/user/process canonical
model — a Modbus register write is an *asset/point/operation*, not a logon or a
process spawn. So the real design decision is **how you'd prefer to extend the
canonical event model for OT concepts** (asset, register/point, operation,
protocol), and the **emitter interface** a new source should implement. I'd
rather agree that shape with you before writing anything sizeable.

### Working prototype (proof this is deliverable)

I've built a standalone, tested prototype of exactly this mapping — canonical OT
event → Zeek/syslog/JSON with shared `uid` and ATT&CK-for-ICS ground truth,
across Modbus/DNP3/BACnet: **https://github.com/AAH20/otforge** (see
`otforge_scenario` and `examples/evidenceforge_ot_demo.py`). It's not wired to
EvidenceForge's internals yet — that's the part I'd adapt to your canonical model
and emitter interface once you point me at the intended shape.

### Ask

Is an OT emitter in scope for EvidenceForge? If so, how would you like the
canonical model extended for OT, and is there a preferred emitter interface to
target? Happy to implement it behind your guidance.
