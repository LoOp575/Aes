# Vercel deployment boundary

Vercel can host the future dashboard and control-plane API. Do not assume a Vercel function is a suitable network sensor: outbound access, runtime limits, and network visibility depend on the deployed environment.

Recommended split:
- Vercel: dashboard, user sessions, scan orchestration, findings and reports.
- Authorized local/server agent: private-network reachability, packet capture, TLS endpoint telemetry, and cryptographic operation metadata.
- Managed PostgreSQL: production persistence.
- Authenticated ingestion: agent-to-control-plane communication.

The current scanner is local-first. Do not expose it publicly without authentication, rate limiting, strict target/port allowlists, and request auditing. SQLite is development-only.
