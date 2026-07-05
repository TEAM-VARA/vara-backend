-- migrations/079_add_annotations_to_cluster_ingresses.down.sql
ALTER TABLE cluster_ingresses DROP COLUMN IF EXISTS annotations;
