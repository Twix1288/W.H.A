CREATE TABLE IF NOT EXISTS snapshot_refs (
    id VARCHAR(64) PRIMARY KEY,
    vm_id VARCHAR(64) NOT NULL,
    mem_key VARCHAR(255) NOT NULL,
    disk_key VARCHAR(255) NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_snapshot_refs_active 
ON snapshot_refs(created_at DESC) 
WHERE deleted_at IS NULL AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP);
