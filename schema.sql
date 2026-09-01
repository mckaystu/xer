-- Xer DXL graph storage (Neon PostgreSQL)
-- Run once: psql $DATABASE_URL -f schema.sql

CREATE TABLE IF NOT EXISTS dxl_graphs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nsf_path        TEXT NOT NULL,
    database_title  TEXT,
    parser_version  TEXT,
    parsed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    totals          JSONB NOT NULL DEFAULT '{}'::jsonb,
    graph           JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dxl_graphs_nsf_path ON dxl_graphs (nsf_path);
CREATE INDEX IF NOT EXISTS idx_dxl_graphs_parsed_at ON dxl_graphs (parsed_at DESC);

CREATE TABLE IF NOT EXISTS graph_edges (
    id              BIGSERIAL PRIMARY KEY,
    graph_id        UUID NOT NULL REFERENCES dxl_graphs(id) ON DELETE CASCADE,
    edge_type       TEXT NOT NULL,
    source_type     TEXT NOT NULL,
    source_name     TEXT NOT NULL,
    target_type     TEXT NOT NULL,
    target_name     TEXT NOT NULL,
    evidence        TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_graph_edges_graph_id ON graph_edges (graph_id);
CREATE INDEX IF NOT EXISTS idx_graph_edges_type ON graph_edges (graph_id, edge_type);
CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges (graph_id, source_type, source_name);
CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges (graph_id, target_type, target_name);
