-- ============================================================
-- Requête de triage des vulnérabilités — à coller dans Looker Studio
-- (Ajouter des données > BigQuery > REQUÊTE PERSONNALISÉE)
--
-- Projet de facturation : my-gcp-project
-- Emplacement          : me-west1
--
-- Aucun droit d'écriture requis : Looker Studio exécute cette requête
-- en lecture, il n'y a pas de vue à créer.
-- ============================================================

SELECT
  -- Identité de l'image
  repository_name,
  image_name,
  image_uri,
  image_tags,
  image_digest,
  artifact_registry_url,

  -- Où elle tourne (ou pas) — l'axe de priorisation principal
  deployed_status,                       -- DEPLOYED / NOT_DEPLOYED
  IFNULL(deployed_in, 'AUCUN')       AS runtime,
  IFNULL(deployed_projects, '')      AS projets_deploiement,
  IFNULL(deployed_workloads, '')     AS workloads,
  IFNULL(gke_clusters, '')           AS clusters_gke,
  IFNULL(gke_namespaces, '')         AS namespaces_gke,

  -- La vulnérabilité
  cve_id,
  severity,
  severity_score,
  package_name,
  installed_version,
  fixed_version,
  external_uri,

  -- Champs calculés pour piloter les graphiques Looker
  CASE
    WHEN fixed_version IS NOT NULL AND fixed_version != '' THEN 'Corrigeable'
    ELSE 'Pas de correctif'
  END AS corrigeable,

  -- Score de priorité : déployé + critique + correctif dispo = à faire en premier
  (CASE WHEN deployed_status = 'DEPLOYED' THEN 100 ELSE 0 END)
  + (severity_score * 10)
  + (CASE WHEN fixed_version IS NOT NULL AND fixed_version != '' THEN 5 ELSE 0 END)
  AS score_priorite,

  event_date,
  event_time,
  DATE_DIFF(CURRENT_DATE(), event_date, DAY) AS age_jours

FROM `my-gcp-project.scc_findings.v_today_vulnerabilities_whole_picture`


-- ============================================================
-- VARIANTE : agrégée par image, une ligne = un rebuild à planifier.
-- Plus légère, idéale pour un tableau "plan de travail".
-- ============================================================
--
-- SELECT
--   repository_name,
--   image_name,
--   ANY_VALUE(image_tags)             AS tags,
--   ANY_VALUE(deployed_in)            AS runtime,
--   ANY_VALUE(deployed_workloads)     AS workloads,
--   ANY_VALUE(artifact_registry_url)  AS lien_console,
--   COUNTIF(severity = 'CRITICAL')    AS critiques,
--   COUNTIF(severity = 'HIGH')        AS elevees,
--   COUNT(DISTINCT cve_id)            AS cve_uniques,
--   COUNTIF(fixed_version IS NOT NULL AND fixed_version != '') AS corrigeables,
--   STRING_AGG(DISTINCT package_name, ', '
--              ORDER BY package_name LIMIT 8)  AS paquets_a_mettre_a_jour
-- FROM `my-gcp-project.scc_findings.v_today_vulnerabilities_whole_picture`
-- WHERE deployed_status = 'DEPLOYED'
-- GROUP BY repository_name, image_name
-- ORDER BY critiques DESC, elevees DESC
