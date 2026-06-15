# Advanced Enterprise Architecture

While W.H.Agent acts natively as a CLI for checking and safely running untrusted AI agents, the platform is backed by a full Enterprise execution-layer control plane designed for SOC teams and platform engineers.

This architecture scales from local development environments to distributed Kubernetes clusters.

## The Defense-in-Depth Stack

1. **Kernel Enforcement (eBPF Agent)**
   - Located in `packages/ebpf-agent`.
   - Uses BPF Linux Security Modules (LSM) hooks (`lsm/socket_connect`) to intercept outbound network traffic synchronously at the kernel level.
   - Blocks egress traffic that violates the agent's behavioral envelope with microsecond latency, providing true zero-trust containment that cannot be bypassed by user-space library hacking.

2. **Session Correlation Engine (Posture Service)**
   - Located in `packages/posture-service`.
   - A Go-based backend that ingests W3C Trace Context headers (via Kafka).
   - This explicitly links isolated events (a tool call, a database query, an outbound connection) to the exact conversational turn of the AI agent, providing full incident lineage for security forensics.

3. **Inline Middleware SDK**
   - Located in `packages/sdk-python`.
   - Injects W3C telemetry into agent frameworks like LangChain.
   - Provides a developer surface for policy authoring and warning logging, acting as a lightweight guardrail inside the container envelope.

4. **Security Operations Dashboard**
   - Located in `packages/dashboard`.
   - A React/Next.js dashboard for SOC analysts to monitor intent drift, visualize W3C event timelines, and review blocked eBPF kernel events.

## Deployment

Enterprise platforms can deploy this stack using Docker Compose for infrastructure (Kafka, Postgres, Redis) and native Linux deployments for the eBPF kernel agent.
