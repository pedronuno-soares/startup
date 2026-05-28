# Incorrupt - Distributed Chain of Custody System

Incorrupt is an enterprise-grade digital evidence management platform designed to ensure the absolute immutability and cryptographic integrity of forensic data. Utilizing a Byzantine Fault Tolerant (BFT) consensus architecture, the system guarantees that digital evidence remains tamper-proof across multiple distributed audit nodes.

## Core Features

- **BFT Consensus Matrix:** Three independent MongoDB audit nodes run a synchronized BFT-Lite algorithm, requiring a 2/3 quorum for any block validation.
- **Cryptographic Hashing:** Every piece of evidence is hashed locally via SHA-256 before interacting with the network, preventing middleman tampering.
- **Deep Forensic Engine:** In-built structural analysis module capable of detecting PDF incremental updates, metadata wiping, and visual falsifications (e.g., unauthorized stamps, underlines).
- **Strict Custody Control:** First-mover cryptographic ownership prevents unauthorized transfers or overwriting of digital evidence.
- **Global Dossier Generation:** One-click generation of military-grade PDF dossiers detailing the complete chain of custody for legal and court compliance.
- **Chaos Simulator:** Integrated testing environment to simulate node failure and validate the BFT quorum resilience under cyberattack conditions.

## Architecture

- **Backend:** Node.js (TypeScript), Express, Mongoose
- **Frontend:** Vanilla JS/HTML/CSS (Zero heavy framework overhead for maximum security and auditability)
- **Database:** MongoDB (Clustered Audit Nodes)
- **Authentication:** JWT-based stateless sessions

## Getting Started

1. Ensure MongoDB memory servers or Docker containers are configured.
2. Navigate to the orchestrator directory and run:
   ```bash
   npm install
   npm run dev:local
   ```
3. Access the web interface to upload and manage forensic evidence.