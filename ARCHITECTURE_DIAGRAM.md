# ANAN Server Management Architecture Diagram

```mermaid
flowchart LR
    U[User / Operator] --> A[agent/ assistant]
    A -->|MCP tool calls| M[MCP Server]
    M -->|client registry + command sync| C1[Ubuntu Client 1]
    M -->|client registry + command sync| C2[Ubuntu Client N]
    C1 -->|validated command execution| R1[Linux host / firewall / system info]
    C2 -->|validated command execution| R2[Linux host / firewall / system info]
    M -->|OAuth / no-auth| Auth[Authentication layer]
    C1 -->|API key + TLS| Policy[Execution policy + audit log]
```

## Diagram meaning

- The assistant is the interaction layer.
- The MCP server is the coordination and routing layer.
- The Ubuntu client is the enforcement layer.
- The runtime host is the actual system being managed.

This diagram reflects the repo’s central design principle: the final command decision is always made at the execution node, not at the AI or orchestration layer.
