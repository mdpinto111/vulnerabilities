-- ============================================================
-- Vulnerability triage query — to paste into Looker Studio
-- (Add data > BigQuery > CUSTOM QUERY)
--
-- Billing project : my-gcp-project
-- Location        : me-west1
--
-- No write permission needed: Looker Studio runs this query read-only,
-- there is no view to create.
-- ============================================================

SELECT
  -- Image identity
  repository_name,
  image_name,
  image_uri,
  image_tags,
  image_digest,
  artifact_registry_url,

  -- Where it runs (or not) — the main prioritization axis
  deployed_status,                       -- DEPLOYED / NOT_DEPLOYED
  IFNULL(deployed_in, 'NONE')        AS runtime,
  IFNULL(deployed_projects, '')      AS deployed_projects,
  IFNULL(deployed_workloads, '')     AS workloads,
  IFNULL(gke_clusters, '')           AS gke_clusters,
  IFNULL(gke_namespaces, '')         AS gke_namespaces,

  -- The vulnerability
  cve_id,
  severity,
  severity_score,
  package_name,
  installed_version,
  fixed_version,
  external_uri,

  -- Computed fields to drive the Looker charts
  CASE
    WHEN fixed_version IS NOT NULL AND fixed_version != '' THEN 'Fixable'
    ELSE 'No fix'
  END AS fixable,

  -- Priority score: deployed + critical + fix available = to do first
  (CASE WHEN deployed_status = 'DEPLOYED' THEN 100 ELSE 0 END)
  + (severity_score * 10)
  + (CASE WHEN fixed_version IS NOT NULL AND fixed_version != '' THEN 5 ELSE 0 END)
  AS priority_score,

  event_date,
  event_time,
  DATE_DIFF(CURRENT_DATE(), event_date, DAY) AS age_days

FROM `my-gcp-project.scc_findings.v_today_vulnerabilities_whole_picture`


-- ============================================================
-- VARIANT: aggregated per image, one row = one rebuild to plan.
-- Lighter, ideal for a "work plan" table.
-- ============================================================
--
-- SELECT
--   repository_name,
--   image_name,
--   ANY_VALUE(image_tags)             AS tags,
--   ANY_VALUE(deployed_in)            AS runtime,
--   ANY_VALUE(deployed_workloads)     AS workloads,
--   ANY_VALUE(artifact_registry_url)  AS console_link,
--   COUNTIF(severity = 'CRITICAL')    AS critical,
--   COUNTIF(severity = 'HIGH')        AS high,
--   COUNT(DISTINCT cve_id)            AS unique_cves,
--   COUNTIF(fixed_version IS NOT NULL AND fixed_version != '') AS fixable,
--   STRING_AGG(DISTINCT package_name, ', '
--              ORDER BY package_name LIMIT 8)  AS packages_to_update
-- FROM `my-gcp-project.scc_findings.v_today_vulnerabilities_whole_picture`
-- WHERE deployed_status = 'DEPLOYED'
-- GROUP BY repository_name, image_name
-- ORDER BY critical DESC, high DESC
