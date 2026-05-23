# Strategic Business Plan: NetSentry

**Author:** Brent Schoenmakers
**Structure:** Open-Core Micro-SaaS (Cybersecurity Logistics)
**Target Market:** Belgian Web Agencies, Managed Service Providers (MSPs), & SMEs
**Legal Framework:** Student-Zelfstandige (Flanders, Belgium)

---

## 1. Executive Summary

### The Problem

Small and Medium Enterprises (SMEs) in Belgium face escalating threats from automated ransomware and internal network breaches. However, enterprise security infrastructure (like Cisco or Fortinet clusters) is cost-prohibitive and requires dedicated security teams. Conversely, local web and IT agencies managing dozens of client environments want to provide proactive monitoring but lack the engineering resources to build internal detection pipelines.

### The Solution

NetSentry provides high-throughput, low-overhead network visibility by combining an open-source, auditable hardware edge sensor with a premium, multi-tenant cloud management dashboard. By utilizing an "out-of-band passive network tap" architecture, NetSentry eliminates the liability of network downtime while delivering enterprise-grade threat forensics.

---

## 2. Product Architecture & Engineering Strategy

NetSentry splits its unified development workspace into two distinct layers to balance community trust with commercial protection.

```
                  ┌─────────────────────────────────────────┐
                  │          THE NETSENTRY PLATFORM         │
                  └─────────────────────────────────────────┘
                                       │
         ┌─────────────────────────────┴─────────────────────────────┐
         ▼                                                           ▼
  OPEN-CORE LAYER                                             PREMIUM CLOUD LAYER
  (Public Repo: `netsentry-sensor`)                           (Private Repo: `netsentry-cloud`)
  ─────────────────────────────────                           ─────────────────────────────────
  • Rust `raspi-collector` engine                             • Multi-Tenant Angular 21 Console
  • Kernel-level bridge setup (`br0`)                         • Axum `api-gateway` Aggregator
  • Local Suricata log ingestion                              • Real-Time Alerting (SMS/Mail)
  • Outbound WireGuard routing                                • Executive PDF Reporting Crates
```

### Core Workflow

1. **The Edge Appliance:** A dual-interface Raspberry Pi sits as a transparent kernel-bridge (`br0`) inside the client network. It captures packets passively without routing production traffic, ensuring a **fail-open state**.
2. **The Encrypted Tunnel:** The sensor initiates an outbound WireGuard connection back to a central Hetzner VPS (`10.10.0.1`), seamlessly traversing complex corporate firewalls and carrier-grade NAT without port-forwarding.
3. **The Analytics Engine:** Token-bucket rate-limited WebSockets stream telemetry back to a centralized Axum gateway, which separates traffic by strict `tenant_id` scopes before committing data to a MongoDB data layer.

---

## 3. Market Analysis & Target Audience

Instead of pursuing high-burn B2C marketing, NetSentry utilizes a highly targeted **B2B Channel Strategy**.

### Target Segments

- **Primary Target (The Force Multiplier): Local Web & IT Agencies (Flanders).** These firms manage IT operations for 10 to 50 small local companies each. They are actively looking for margin-rich, white-labeled security add-ons to increase their monthly client retainer fees.
- **Secondary Target: High-Risk Boutique SMEs.** Distributed accountancies, legal firms, and localized private medical clinics that handle highly sensitive personal data subject to strict GDPR enforcement.

### Competitive Advantage

- **Auditability:** Keeping the network agent completely open-source under the **MIT License** means client IT directors can review every line of code running inside their physical facilities, clearing the "black-box" trust hurdle immediately.
- **Solo Efficiency:** Built completely in memory-safe, ultra-performant Rust, the entire cloud ingestion engine operates cleanly on a single low-cost Hetzner instance (CPX42), driving operational margins above 95%.

---

## 4. Monetization & Financial Model

Operating under the Belgian **BTW-vrijstellingsregeling** (VAT exemption for revenue under €25,000/year) ensures minimal administrative overhead.

### Pricing Tiers

| Tier | Pricing | Target | Value Deliverable |
| --- | --- | --- | --- |
| **Community Edition** | Free / Open-Source | DevOps / HomeLabs | Self-compiled sensor code, manual MongoDB/Redis setup, no hosted dashboard support. |
| **Managed Node SaaS** | **€39 / month** (per site) | Managed IT Providers & Small Businesses | Pre-compiled 1-line installation, hosted cloud management console, automated SMS alerts, weekly executive PDF compliance reports. |

### 3-Year Financial Forecast (Bootstrapped Scaling)

```
Year 1 (Validation Phase)
├── Target: 3 IT Agencies onboarded (managing 10 nodes each = 30 paid nodes)
└── Annual Recurring Revenue (ARR): 30 nodes × €39 × 12 months = €14,040
    └── *Completely tax-free under Student-Zelfstandige caps (~€8.6k net taxable after deductions).*

Year 2 (Expansion Phase)
├── Target: 10 IT Agencies onboarded (totaling 100 paid nodes)
└── ARR: 100 nodes × €39 × 12 months = €46,800
    └── *Transitions out of the €25k VAT exemption scheme; hire an accountant.*

Year 3 (Maturity Phase)
├── Target: 25 IT Agencies onboarded (totaling 250 paid nodes)
└── ARR: 250 nodes × €39 × 12 months = €117,000
```

---

## 5. Marketing & Sales Go-To-Market Blueprint

With a €0 marketing budget, growth is achieved through direct developer authority and hyper-focused B2B outreach.

### Phase 1: Establish Developer Credibility (Months 1–2)

- Launch the polished, public GitHub repository for `netsentry-sensor` featuring flawless documentation and an architectural blueprint.
- Publish an in-depth technical case study on `brentweb.eu` titled: *"How I built a high-throughput distributed network threat detector in Rust for my university thesis."* Drop this write-up into specialized developer channels like HackerNews, r/rust, and r/homelab to collect early stars and domain authority.

### Phase 2: Direct B2B Agency Acquisition (Months 3–6)

- Compile a clean list of 100 mid-sized web design and IT management agencies across Flanders (Antwerp, Ghent, Bruges).
- Send highly targeted, low-volume cold emails or LinkedIn messages directly to the owners.

> **The Pitch Template:**
> *"Hey [Name], I'm a cybersecurity student at Howest. I noticed you build/manage IT infrastructure for local SMEs. I've open-sourced an auditable, lightweight Rust network threat sensor. You can deploy it to your client switch networks in 5 minutes, brand my automated weekly PDF threat reports with your own agency logo, and upsell your clients a €100/mo 'Advanced Security Monitoring' retainer. You keep the €60+ margin, and I handle the hosted cloud infrastructure for €39/site. Let me know if I can drop a test sensor off at your office next Tuesday."*

---

## 6. Execution Roadmap & Milestones

```
MILESTONE 1: Code Separation & Multi-Tenancy (Current - 1 Month)
├── Cut cloud backend and Angular interface into private `netsentry-cloud` repository
├── Update Mongo schemas with strict client `tenant_id` keys to ensure data isolation
└── Clean and verify the unified single-command installation script on the public sensor

MILESTONE 2: Legal Setup & Infrastructure Polish (Month 2)
├── Reach 18th birthday; register online as a Student-Zelfstandige (via Liantis/Xerius)
├── Resolve the `threat-intel` service stub by integrating public abuse IP reputation blocklists
└── Deploy Stripe Billing links connected directly to manual user account provisioning

MILESTONE 3: The Beta Launch (Month 3)
├── Deliver 3 physical test sensors to friendly local web shops or acquaintances for feedback
└── Polish UI layouts based on live data ingest from active nodes

MILESTONE 4: Outbound Engine (Months 4+)
└── Kick off the 100-contact B2B agency outbound campaign to secure the first 10 paid tenants
```

---

## 7. Risk Analysis & Risk Mitigation

**Risk 1: Client Internet Outage.**
Even with a fail-open kernel bridge configuration, an unforeseen hardware lockup on the Raspberry Pi interface could temporarily disrupt a client's local router link.

*Mitigation:* Pitch and sell the tool exclusively as an **out-of-band passive tap / network canary**. Instruct clients to plug the device into a mirrored monitor port (SPAN port) on their switch. If the device loses power or locks up entirely, production data traffic is completely untouched.

---

**Risk 2: Time Management.**
Juggling engineering, data pipelines, client acquisition, and university coursework until graduation in June 2029.

*Mitigation:* Rely heavily on asynchronous, automated software systems. By containerizing the entire backend using Docker and Traefik on your Hetzner CPX42, your platform requires zero manual server maintenance once launched. Focus strictly on sales during weekend blocks.

---

**Risk 3: Data Compliance Regulation (GDPR).**
Processing network threat telemetry logs that occasionally capture internal corporate IP addresses.

*Mitigation:* Your open-source code ensures raw data packet payloads are dropped completely at the edge sensor level; only structured alert metadata reaches your cloud servers. Provide a standardized Data Processing Agreement (DPA) to your B2B agencies upon checkout.
