-- Migration: add analysis columns to dxl_graphs
-- Safe to re-run (IF NOT EXISTS).

ALTER TABLE dxl_graphs ADD COLUMN IF NOT EXISTS business_rules JSONB;
ALTER TABLE dxl_graphs ADD COLUMN IF NOT EXISTS modernization_score JSONB;
