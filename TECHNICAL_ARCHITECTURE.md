# ANAN Server Management Technical Architecture

This document describes the technical architecture of the repository in a more detailed engineering form. It explains the responsibilities of each project component, the security model, and the runtime flow across the managed system.

## 1. Architectural layering

The project is built as a three-layer system.

### Layer 1: Assistant interface

Location: `agent/`

This layer is responsible for human-facing assistance and model interaction.

Main responsibilities:

- model provider integration
- MCP client connection setup
- conversation orchestration
- tool invocation and response handling
- local identity propagation and authentication support

Key logic is implemented in `agent/src/anan_agent.py`.

### Layer 2: MCP coordination layer

Location: `mcp_server/`

This layer provides the control plane.

Main responsibilities:

- server-side FastMCP endpoints
- client registry management
- command catalog synchronization
- per-client routing
- authentication and token verification
- read-only non-admin mode

Main implementation: `mcp_server/src/anan_mcp_server/server.py`.

### Layer 3: Enforcement and execution

Location: `client/ubuntu/`

This layer is the runtime enforcement layer.

Main responsibilities:

- HTTP API endpoints for command execution and policy management
- execution-policy validation
- default-deny allowlist handling
- dangerous-binary guardrails
- timeout and output limiting
- request logging and audit tracking

Main implementation: `client/ubuntu/src/app.py` and `client/ubuntu/src/execution_policy.py`.

## 2. Data and control flow

The flow is intentionally asymmetric:

- user intent is handled by the assistant
- system coordination is handled by the MCP server
- actual runtime execution is handled by the client

This creates a clean separation between decision-making and enforcement.

## 3. Client management model

The MCP server maintains a registry of managed endpoints, each with metadata such as:

- name
- agent URL
- API key
- TLS verification flag
- command profile

This allows the MCP server to route tool calls to the appropriate target client while keeping the managed fleet logically centralized.

## 4. Command policy model

The command model is global at the MCP layer but enforced locally at the client.

The MCP server defines a canonical set of command definitions, including:

- name
- description
- binary path
- arguments
- aliases
- whether extra arguments are allowed
- examples

The client then validates each execution request against its local policy file. If the logical command name is not present, or if the command is blocked by guardrails, execution is denied.

## 5. Security model

### Default deny
The client does not allow arbitrary commands. Unknown commands are rejected.

### Restricted execution
The client prevents:

- shell execution
- `sudo` execution
- unapproved extra arguments
- dangerous command classes
- command execution if runtime policy is invalid

### Guardrail examples
The implementation explicitly blocks dangerous commands such as:

- `rm`
- `chmod`
- `chown`
- `systemctl`
- `reboot`
- `shutdown`
- `iptables`
- `nft`
- `ufw` except for exact read-only permitted cases

### Permission checks
The policy file must be owned properly and must not be too permissive. This is validated before startup and before execution.

## 6. Authentication and transport

The project supports either:

- no-auth MCP access
- OAuth authenticated MCP access with trusted provider configuration

The client-side API relies on API keys and protected routes. In other words, MCP auth and runtime command auth are separate concerns but both are policy-driven.

## 7. Observability and audit trail

The Ubuntu client emits logs for both request-level and operational activity. These logs are useful for:

- command tracing
- failed policy decisions
- operations review
- system debugging
- evidence collection for audits

This is especially important for a security-sensitive system that mediates access to remote Linux hosts.

## 8. Operational modes

The project supports multiple runtime modes:

### Standard mode
Full command and management surfaces are available.

### MVP non-admin mode
Only read-only or non-sensitive tools are exposed to the operator.

This reduces risk for constrained deployment environments and supports safer automation patterns.

## 9. Deployment model

The project is designed for multi-host deployment:

- one or more managed Ubuntu execution hosts
- one central MCP orchestration service
- one or more agent clients or operator clients

This allows the control plane to stay centralized while the actual command execution remains close to the target systems.

## 10. Summary

The technical architecture of ANAN-SERVER-MGMT is built around separation of concerns, policy enforcement, and centralized orchestration. The assistant reasons, the MCP server coordinates, and the Ubuntu client enforces the final security boundary.

This makes the platform suitable for controlled automation in environments that require stronger operational discipline and clearer auditability.
