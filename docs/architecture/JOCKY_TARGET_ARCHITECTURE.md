# JOCKY Target Architecture

## 1. Goal

Extend the existing JOCKY forensic DSL from a JSON execution-plan compiler into a controlled bytecode + VM execution architecture while preserving the existing agent, allowlist, evidence-integrity, Merkle, blockchain, ML, correlation, backend, and dashboard layers.

## 2. Execution pipeline

```
JOCKY source
  -> Lexer
  -> Parser
  -> AST
  -> Semantic Analyzer
  -> Forensic IR
  -> Bytecode
  -> JOCKY VM
  -> Capability / Allowlist Gate
  -> Platform-specific forensic collectors
  -> Evidence Envelope
  -> Evidence Hash Chain
  -> Merkle Root
  -> Local Evidence Blockchain
  -> Correlation / CTI / MITRE / ML
  -> Backend / SOC Dashboard
```

## 3. Bytecode layer

The new compiler/bytecode package introduces:

- explicit opcodes
- deterministic constants
- forensic CALL instructions
- capability metadata
- deterministic SHA-256 image hashing
- a versioned bytecode image representation

The bytecode layer is deliberately restricted to the forensic DSL. It does not provide arbitrary shell, Python, or native-code execution.

## 4. VM layer

The new vm package provides a controlled interpreter for the bytecode image.

The VM currently supports:

- constants
- variables
- forensic function dispatch
- controlled branching instructions
- evidence sealing
- execution step limits
- deterministic execution results

CALL_FORENSIC is delegated through an injected dispatcher. The dispatcher is expected to enforce the existing JOCKY allowlist/capability policy before a collector is executed.

## 5. Multi-platform execution

```
                 Bytecode Package
                       |
              Capability Resolver
                 /           \
                /             \
        Windows Agent      Linux Agent
             |                  |
        JOCKY VM            JOCKY VM
             |                  |
     Windows collectors    Linux collectors
```

The bytecode describes forensic intent; platform-specific collectors provide the implementation.

## 6. Evidence provenance

Every future VM execution should be traceable through:

```
Source Hash
    |
Bytecode Hash
    |
Execution ID
    |
Collector Execution
    |
Evidence Envelope
    |
Evidence Hash / Chain
    |
Merkle Root
    |
Blockchain Anchor
```

This connects the new execution layer to the evidence-integrity architecture already present in the repository.

## 7. Implementation phases

1. Complete bytecode lowering for all supported JOCKY grammar constructs.
2. Add a production capability-aware VM dispatcher.
3. Add bytecode verification before execution.
4. Integrate VM execution with platform-specific collectors.
5. Add semantic-equivalence tests for representation transformations.
6. Bind VM executions directly to evidence provenance.
7. Expand forensic functions where required by the final scope.

## 8. Scope boundary

This branch is an architectural foundation. It does not claim that every target capability described in the PPT is already implemented.

The existing forensic collectors, evidence integrity, Merkle/blockchain, ML, correlation, backend, and dashboard remain the foundation for the next phases.
