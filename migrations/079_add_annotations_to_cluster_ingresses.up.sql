-- migrations/079_add_annotations_to_cluster_ingresses.up.sql
ALTER TABLE cluster_ingresses ADD COLUMN IF NOT EXISTS annotations JSONB;
