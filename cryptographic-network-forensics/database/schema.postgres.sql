-- Proposed normalized production schema. Stage 1 runtime currently uses SQLite.
CREATE TABLE IF NOT EXISTS targets (
    id UUID PRIMARY KEY,
    target_value TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('hostname', 'ipv4', 'ipv6', 'cidr')),
    authorization_reference TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id UUID PRIMARY KEY,
    target_id UUID REFERENCES targets(id),
    requested_port INTEGER NOT NULL CHECK (requested_port BETWEEN 1 AND 65535),
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL,
    scanner_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
    id BIGSERIAL PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    observation_type TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    data JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    finding_code TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical', 'unknown')),
    confidence TEXT NOT NULL CHECK (confidence IN ('confirmed', 'suspected', 'unverified')),
    description TEXT NOT NULL,
    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE TABLE IF NOT EXISTS evidence (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    evidence_type TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    storage_ref TEXT,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS agent_heartbeats (
    agent_id TEXT PRIMARY KEY,
    last_seen TIMESTAMPTZ NOT NULL,
    agent_version TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- Never store raw AES keys, private keys, cookies, bearer tokens, or session secrets.
