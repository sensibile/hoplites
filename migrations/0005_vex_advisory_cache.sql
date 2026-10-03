-- Rebuildable runtime cache. Public upstream facts are pinned by commit/hash.
CREATE TABLE vex_advisory_cache (
  snapshot_commit TEXT NOT NULL,
  cve TEXT NOT NULL,
  source_url TEXT NOT NULL,
  source_sha256 TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  retrieved_at TEXT NOT NULL,
  PRIMARY KEY(snapshot_commit,cve)
);
