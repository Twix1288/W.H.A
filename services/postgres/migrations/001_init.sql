-- Core agent registry
CREATE TABLE agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    framework       VARCHAR(50) NOT NULL,  -- 'langchain', 'semantic-kernel', 'autogpt'
    version         VARCHAR(50),
    owner_id        UUID NOT NULL,
    config          JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Package registry
CREATE TABLE packages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    version         VARCHAR(50) NOT NULL,
    registry_source VARCHAR(20) DEFAULT 'public',  -- 'private', 'public'
    published_at    TIMESTAMPTZ NOT NULL,
    maintainer_id   UUID,
    tarball_url     TEXT NOT NULL,
    signature       TEXT NOT NULL,
    conformance_score INTEGER,
    weekly_downloads INTEGER DEFAULT 0,
    metadata        JSONB,
    UNIQUE(name, version)
);

-- Behavioral envelope profiles
CREATE TABLE envelope_profiles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID REFERENCES agents(id),
    tool_sequences  JSONB NOT NULL DEFAULT '[]',
    parameter_shapes JSONB NOT NULL DEFAULT '{}',
    delegation_graph JSONB NOT NULL DEFAULT '[]',
    sample_count    INTEGER DEFAULT 0,
    convergence_date TIMESTAMPTZ,
    is_converged    BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Risk objects (correlated incidents)
CREATE TABLE risk_objects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID REFERENCES agents(id),
    session_chain   TEXT[] NOT NULL DEFAULT '{}',
    event_count     INTEGER DEFAULT 0,
    risk_score      NUMERIC(4,3),
    risk_factors    TEXT[],
    status          VARCHAR(20) DEFAULT 'open',
    first_seen      TIMESTAMPTZ,
    last_seen       TIMESTAMPTZ,
    resolved_at     TIMESTAMPTZ,
    metadata        JSONB
);

-- Red team results
CREATE TABLE red_team_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_agent_id UUID REFERENCES agents(id),
    strategy        VARCHAR(100),
    succeeded       BOOLEAN,
    turns_required  INTEGER,
    attack_vector   TEXT,
    attack_history  JSONB,
    remediation_id  UUID,
    run_at          TIMESTAMPTZ DEFAULT NOW()
);

-- Generated policies
CREATE TABLE generated_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    red_team_run_id UUID REFERENCES red_team_runs(id),
    policy_type     VARCHAR(20),  -- 'middleware', 'opa', 'ebpf'
    policy_content  TEXT NOT NULL,
    deployed_at     TIMESTAMPTZ,
    is_active       BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_packages_name ON packages(name);
CREATE INDEX idx_packages_published_at ON packages(published_at DESC);
CREATE INDEX idx_risk_objects_agent_id ON risk_objects(agent_id);
CREATE INDEX idx_risk_objects_status ON risk_objects(status);
CREATE INDEX idx_red_team_runs_agent ON red_team_runs(target_agent_id);
