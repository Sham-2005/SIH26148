# JOCKY Forensic Architecture Documentation

## Core Architectural Lifecycle

The JOCKY platform implements a strict, cryptographically verified digital forensic lifecycle:

```text
JOCKY Script (.jocky)
         ↓
    Script Hash (SHA-256)
         ↓
  Execution Lease (VM)
         ↓
Forensic Collectors (Registry, Processes, Network, Files, System)
         ↓
Raw Evidence Capture
         ↓
Normalized Evidence (RFC-8785 Canonical JSON)
         ↓
Composite Evidence Hash & Sequential Chain
         ↓
Correlation Layer (Multi-Source Activity Clusters)
         ↓
Detection Rules & Explainable ML (Random Forest)
         ↓
Actionable Findings (FND-*)
         ↓
Unified Chronological Timeline
         ↓
Binary Merkle Tree Root
         ↓
Local Evidence Blockchain Anchor (Append-Only Ledger)
         ↓
Court-Admissible Forensic Report (JSON / HTML / CSV)
```

## Cryptographic Guarantees

1. **RFC-8785 Canonical Serialization**: Guarantees deterministic serialization across all platforms by sorting dictionary keys and eliminating insignificant whitespace.
2. **Sequential Hash Chain**: Every evidence record embeds the composite `evidence_hash` of its immediate predecessor:
   $$\text{Evidence Hash} = \text{SHA256}(\text{Canonical}(\text{raw\_data\_hash} \,\|\, \text{normalized\_data\_hash} \,\|\, \text{collector} \,\|\, \text{timestamp} \,\|\, \text{previous\_hash}))$$
3. **Deterministic Binary Merkle Tree**: Leaf hashes are computed from evidence records. Any odd level duplicates the final node to ensure binary tree balance.
4. **Local Evidence Blockchain Anchor**: The Merkle root, script hash, and evidence count are committed to an append-only cryptographic block linked to its predecessor block hash.

> **Clarification**: JOCKY implements a Local Evidence Blockchain — an internal append-only cryptographic ledger used to anchor evidence integrity. It is not a public decentralized blockchain.
