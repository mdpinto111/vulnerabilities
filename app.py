#!/usr/bin/env python3
"""
Console de triage des vulnerabilites SCC - application locale.

Interroge BigQuery en direct via la CLI `bq` (deja authentifiee), croise le
resultat avec l'etat reel de Cloud Run lu via `gcloud`, et sert le tableau de
bord sur http://localhost:8787

Aucune dependance a installer : stdlib Python uniquement.

Usage :
    python app.py              # port 8787, accessible depuis ce PC seulement
    python app.py 9000         # autre port
    python app.py --lan        # accessible depuis le telephone (meme Wi-Fi)
"""

import http.server
import json
import os
import re
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

PROJET = "my-gcp-project"
DATASET = "my-gcp-project.scc_findings"
LOCATION = "me-west1"
REGION_RUN = "me-west1"     # region ou vivent les services Cloud Run sondes
TTL = 600                   # secondes avant qu'un rechargement relance tout
ICI = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(ICI, "app_tpl.html")

FINDINGS = f"`{DATASET}.findings`"

# Meme deduplication que v_today_vulnerabilities_whole_picture (dernier etat
# connu de chaque finding), mais SANS son filtre state = "ACTIVE".
#
# SCC passe en INACTIVE des findings qu'Artifact Registry affiche toujours.
# Verifie le 2026-10-06 sur example-service@sha256:6fa15066 en service :
# SCC ne garde aucun Critical/High actif, la console Artifact Registry
# (scan actif) affiche 2 Critical et 7 High openssl, exactement les 9
# findings que SCC a retires. La vue faisait donc disparaitre du tableau
# 37 des 50 images Cloud Run du depot docker-images.
#
# Ce n'est pas exact a 100 % : SCC fige un finding INACTIVE et l'export ne
# dit pas si Artifact Analysis l'a supprime depuis. Sur
# srloginpermissionscloudapi@sha256:eded8302, la console affiche les 15
# Critical mais masque 5 des 118 High (CVE-2026-55199, -55200, -66033,
# -66035, -82560). Aucun champ de l'export ne les distingue des retires
# encore affiches ; seule l'API Artifact Analysis donnerait le chiffre exact.
#
# Regle retenue : pour une image en service, tout finding connu compte (elle
# existe, la console le montre). Pour le stock non deploye, on s'en tient a
# l'etat SCC : une image supprimee du registre laisse aussi des findings
# INACTIVE, et rien dans l'export ne permet de la distinguer.
VUE = f"""(
  WITH dernier AS (
    SELECT
      event_time,
      finding.severity AS severity,
      finding.state AS state,
      REGEXP_EXTRACT(resource.name, r"repositories/([^/]+)") AS repository_name,
      REGEXP_EXTRACT(resource.name, r"dockerImages/([^@]+)") AS image_name,
      REGEXP_EXTRACT(resource.name, r"(sha256:[a-f0-9]+)") AS image_digest,
      CONCAT(
        "https://console.cloud.google.com/artifacts/docker/",
        REGEXP_EXTRACT(resource.name, r"projects/([^/]+)"), "/",
        REGEXP_EXTRACT(resource.name, r"locations/([^/]+)"), "/",
        REGEXP_EXTRACT(resource.name, r"repositories/([^/]+)"), "/",
        REGEXP_EXTRACT(resource.name, r"dockerImages/([^@]+)"),
        "?project=", REGEXP_EXTRACT(resource.name, r"projects/([^/]+)")
      ) AS artifact_registry_url,
      finding.vulnerability.cve.id AS cve_id,
      finding.vulnerability.offending_package.package_name AS package_name,
      finding.vulnerability.fixed_package.package_version AS fixed_version,
      ROW_NUMBER() OVER (
        PARTITION BY resource.name,
          finding.vulnerability.cve.id,
          finding.vulnerability.offending_package.package_name,
          finding.vulnerability.offending_package.package_version
        ORDER BY event_time DESC) AS rn
    FROM {FINDINGS}
    WHERE finding.finding_class = "VULNERABILITY"
      AND LOWER(resource.type) = "google.artifactregistry.dockerimage"
  ),
  tags_agg AS (
    SELECT repository_name, digest AS image_digest,
      STRING_AGG(DISTINCT tag, ", " ORDER BY tag) AS image_tags
    FROM `{DATASET}.artifact_registry_tags_inventory`
    WHERE digest IS NOT NULL
    GROUP BY repository_name, digest
  )
  SELECT d.* EXCEPT (rn),
    d.state != "ACTIVE" AS retire,
    IFNULL(t.image_tags, "NO_TAG_FOUND") AS image_tags
  FROM dernier d
  LEFT JOIN tags_agg t
    ON d.image_digest = t.image_digest
   AND d.repository_name = t.repository_name
  WHERE d.rn = 1
    AND d.severity IN ("HIGH", "CRITICAL")
)"""

# Fenetres proposees dans l'interface. La vue est dedoublonnee : event_time y
# est la date du DERNIER signalement d'une vulnerabilite, pas sa decouverte.
# Filtrer dessus repond donc a "quoi de neuf", pas a "qu'est-ce qui reste".
PERIODES = {
    "all": ("Tout", ""),
    "1m":  ("1 min",  "INTERVAL 1 MINUTE"),
    "1h":  ("1 h",    "INTERVAL 1 HOUR"),
    "24h": ("24 h",   "INTERVAL 24 HOUR"),
    "7d":  ("7 jours", "INTERVAL 7 DAY"),
    "30d": ("30 jours", "INTERVAL 30 DAY"),
}
PERIODE_DEFAUT = "all"
MARQUEUR = "__PERIODE__"
MARQUEUR_DEP = "__DEPLOYE__"

RE_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")


def clause_periode(periode):
    """Clause AND a injecter dans les requetes portant sur la vue."""
    intervalle = PERIODES.get(periode, PERIODES[PERIODE_DEFAUT])[1]
    if not intervalle:
        return ""
    return (f"AND event_time >= "
            f"TIMESTAMP_SUB(CURRENT_TIMESTAMP(), {intervalle})")


FILTRE_IMG = (
    'finding.finding_class = "VULNERABILITY" '
    'AND LOWER(resource.type) = "google.artifactregistry.dockerimage"'
)

# --------------------------------------------------------------------------
# Ce qui tourne vraiment
# --------------------------------------------------------------------------
#
# Deux pieges se cumulent dans les donnees d'inventaire, et tous deux
# gonflent artificiellement le perimetre "deploye" :
#
# 1. v_runtime_org_images_all liste TOUTES les revisions Cloud Run jamais
#    inventoriees. 1973 des 2114 revisions du parc portent la condition
#    Active = "Retired" : sans filtre, les CVE d'un build retire depuis des
#    mois sont imputees au service qui tourne aujourd'hui.
#
# 2. L'export Cloud Asset Inventory est un instantane : il a plusieurs
#    semaines de retard. Meme la revision qu'il croit active peut avoir ete
#    remplacee depuis.
#
# Le CTE ci-dessous regle le point 1. Le point 2 se regle en sondant
# Cloud Run en direct (sonder_cloud_run), seule source qui dise quelle
# revision sert le trafic maintenant, et sous quelle image exacte.

CTE_RUNTIME = f"""
  revisions_cai AS (
    SELECT
      REGEXP_EXTRACT(name, r"projects/([^/]+)") AS proj,
      REGEXP_EXTRACT(name, r"locations/([^/]+)") AS loc,
      REGEXP_EXTRACT(name, r"revisions/(.+)$") AS rev,
      COALESCE(
        REGEXP_EXTRACT(name, r"services/([^/]+)"),
        JSON_VALUE(resource.data,
                   "$.metadata.labels.\\"serving.knative.dev/service\\"")
      ) AS svc,
      JSON_VALUE(resource.data, "$.metadata.creationTimestamp") AS cree,
      (SELECT JSON_VALUE(c, "$.reason")
       FROM UNNEST(JSON_QUERY_ARRAY(
              JSON_QUERY(resource.data, "$.status.conditions"))) c
       WHERE JSON_VALUE(c, "$.type") = "Active") AS raison
    FROM `{DATASET}.assets_org_runtime`
    WHERE asset_type = "run.googleapis.com/Revision"
  ),
  revisions_servantes AS (
    SELECT proj, loc, svc, rev FROM (
      SELECT r.*,
        ROW_NUMBER() OVER (
          PARTITION BY proj, loc, svc ORDER BY cree DESC) AS rn,
        COUNTIF(IFNULL(raison, "") != "Retired")
          OVER (PARTITION BY proj, loc, svc) AS vivantes
      FROM revisions_cai r
    )
    -- Repli : si toutes les revisions d'un service sont retirees (service
    -- supprime, ou inventaire partiel), on garde la plus recente plutot que
    -- de faire disparaitre le workload sans le dire.
    WHERE IFNULL(raison, "") != "Retired" OR (vivantes = 0 AND rn = 1)
  ),
  pods_vivants AS (
    SELECT
      REGEXP_EXTRACT(name, r"projects/([^/]+)") AS proj,
      REGEXP_EXTRACT(name, r"pods/([^/]+)") AS pod,
      IFNULL(REGEXP_EXTRACT(name, r"clusters/([^/]+)"), "") AS cluster,
      IFNULL(REGEXP_EXTRACT(name, r"namespaces/([^/]+)"), "") AS ns
    FROM `{DATASET}.assets_org_runtime`
    WHERE asset_type = "k8s.io/Pod"
      -- un pod Succeeded ou Failed ne fait plus tourner son image
      AND IFNULL(JSON_VALUE(resource.data, "$.status.phase"), "Running")
          NOT IN ("Succeeded", "Failed")
  ),
  runtime_actif AS (
    SELECT r.*
    FROM `{DATASET}.v_runtime_org_images_all` r
    WHERE CASE r.runtime_type
      WHEN "CLOUD_RUN_REVISION" THEN EXISTS (
        SELECT 1 FROM revisions_servantes s
        WHERE s.proj = r.project_id AND s.loc = r.location
          AND s.rev = r.runtime_resource_name)
      WHEN "GKE_POD" THEN EXISTS (
        SELECT 1 FROM pods_vivants p
        WHERE p.proj = r.project_id AND p.pod = r.workload_name
          AND p.cluster = IFNULL(r.cluster_name, "")
          AND p.ns = IFNULL(r.namespace_name, ""))
      ELSE TRUE END
  )
"""

# Les labels GCP ne sont exposes par aucune vue : on les lit dans le JSON brut
# de l'export Cloud Asset Inventory. Un service Cloud Run a plusieurs
# revisions : on garde la derniere.
CTE_LABELS = f"""
  labels_src AS (
    SELECT
      REGEXP_EXTRACT(name, r"projects/([^/]+)") AS proj,
      "CLOUD_RUN_REVISION" AS rt,
      COALESCE(
        REGEXP_EXTRACT(name, r"services/([^/]+)"),
        JSON_VALUE(resource.data,
                   "$.metadata.labels.\\"serving.knative.dev/service\\"")
      ) AS wl,
      "" AS cluster, "" AS ns,
      TO_JSON_STRING(JSON_QUERY(resource.data, "$.metadata.labels")) AS labels,
      update_time
    FROM `{DATASET}.assets_org_runtime`
    WHERE asset_type = "run.googleapis.com/Revision"
    UNION ALL
    SELECT
      REGEXP_EXTRACT(name, r"projects/([^/]+)"), "GKE_POD",
      REGEXP_EXTRACT(name, r"pods/([^/]+)"),
      IFNULL(REGEXP_EXTRACT(name, r"clusters/([^/]+)"), ""),
      IFNULL(REGEXP_EXTRACT(name, r"namespaces/([^/]+)"), ""),
      TO_JSON_STRING(JSON_QUERY(resource.data, "$.metadata.labels")),
      update_time
    FROM `{DATASET}.assets_org_runtime`
    WHERE asset_type = "k8s.io/Pod"
  ),
  labels_dedup AS (
    SELECT proj, rt, wl, cluster, ns, labels FROM (
      SELECT *, ROW_NUMBER() OVER (
        PARTITION BY proj, rt, wl, cluster, ns
        ORDER BY update_time DESC) AS rn
      FROM labels_src WHERE wl IS NOT NULL
    ) WHERE rn = 1
  )
"""


# --------------------------------------------------------------------------
# Requetes : phase 1 (independantes du perimetre deploye)
# --------------------------------------------------------------------------

# Projets hebergeant du Cloud Run. Sert a savoir qui sonder en direct : on la
# lance en premier pour lancer la sonde pendant que le reste interroge BQ.
REQ_PROJETS_CR = f"""
    SELECT DISTINCT REGEXP_EXTRACT(name, r"projects/([^/]+)") AS proj
    FROM `{DATASET}.assets_org_runtime`
    WHERE asset_type = "run.googleapis.com/Revision"
      AND REGEXP_EXTRACT(name, r"locations/([^/]+)") = "{REGION_RUN}"
"""

REQUETES_BASE = {
    # Projets dont le registre alimente la table des findings. Une image
    # hebergee ailleurs n'y a aucune ligne, quel que soit son etat reel.
    "exportes": f"""
        SELECT DISTINCT REGEXP_EXTRACT(resource.name, r"projects/([^/]+)") AS p
        FROM {FINDINGS}
        WHERE {FILTRE_IMG}
    """,
    "meta": f"""
        SELECT
          FORMAT_TIMESTAMP("%Y-%m-%d %H:%M", MAX(event_time), "Asia/Jerusalem") AS dernier_scan,
          COUNT(DISTINCT REGEXP_EXTRACT(resource.name, r"(sha256:[a-f0-9]+)")) AS images_totales,
          COUNT(*) AS lignes_brutes,
          FORMAT_DATE("%Y-%m-%d", MIN(DATE(event_time))) AS date_min
        FROM {FINDINGS}
        WHERE {FILTRE_IMG}
    """,
    "tendance": f"""
        WITH premiere_vue AS (
          SELECT REGEXP_EXTRACT(resource.name, r"(sha256:[a-f0-9]+)") AS dig,
            finding.vulnerability.cve.id AS cve,
            finding.vulnerability.offending_package.package_name AS pkg,
            finding.severity AS sev,
            MIN(DATE(event_time)) AS jour
          FROM {FINDINGS}
          WHERE {FILTRE_IMG}
          GROUP BY dig, cve, pkg, sev
        )
        SELECT FORMAT_DATE("%Y-%m-%d", jour) AS j,
          COUNTIF(sev = "CRITICAL") AS c,
          COUNTIF(sev = "HIGH") AS h
        FROM premiere_vue
        WHERE jour > DATE_SUB(CURRENT_DATE(), INTERVAL 30 DAY)
        GROUP BY j ORDER BY j
    """,
    # Date des instantanes sur lesquels repose la partie GKE : l'afficher
    # evite de faire passer un inventaire vieux de plusieurs semaines pour
    # l'etat du parc a l'instant present.
    "fraicheur": f"""
        SELECT
          (SELECT FORMAT_TIMESTAMP("%Y-%m-%d %H:%M", MAX(update_time))
           FROM `{DATASET}.assets_org_runtime`) AS cai,
          (SELECT FORMAT_TIMESTAMP("%Y-%m-%d %H:%M", MAX(collected_at))
           FROM `{DATASET}.artifact_registry_tags_inventory`) AS tags
    """,
    # Gravites par digest sur TOUT le registre, et non sur le seul perimetre
    # deploye : c'est ce qui permet de dire "une version publiee depuis porte
    # moins de failles". Volontairement hors periode, sinon la comparaison
    # dependrait de la fenetre choisie.
    "severites": f"""
        SELECT repository_name AS repo, image_name AS img,
          REGEXP_EXTRACT(image_digest, r"(sha256:[a-f0-9]{{64}})") AS dig,
          COUNTIF(severity = "CRITICAL") AS c,
          COUNTIF(severity = "HIGH") AS h
        FROM {VUE}
        GROUP BY repo, img, dig
    """,
    # Digest -> tag publie. Sert de repli quand la reference deployee est
    # epinglee par digest et ne porte donc aucune version lisible.
    "tags": f"""
        SELECT dig, tag FROM (
          SELECT REGEXP_EXTRACT(digest, r"(sha256:[a-f0-9]{{64}})") AS dig,
            tag,
            ROW_NUMBER() OVER (PARTITION BY digest
                               ORDER BY collected_at DESC) AS rn
          FROM `{DATASET}.artifact_registry_tags_inventory`
          WHERE tag IS NOT NULL AND tag NOT IN ("UNTAGGED", "NO_TAG_FOUND")
        ) WHERE rn = 1
    """,
    # Emplacements d'execution selon l'inventaire, revisions retirees et pods
    # termines exclus. Source de verite pour GKE ; repli pour Cloud Run quand
    # la sonde en direct n'a pas pu repondre.
    "placements": f"""
        WITH {CTE_RUNTIME},
        {CTE_LABELS}
        SELECT
          r.runtime_type AS rt,
          r.project_id AS proj,
          r.location AS loc,
          r.workload_name AS wl,
          r.runtime_resource_name AS res,
          IFNULL(r.cluster_name, "") AS cluster,
          IFNULL(r.namespace_name, "") AS ns,
          r.runtime_image AS ref,
          REGEXP_EXTRACT(r.image_digest, r"(sha256:[a-f0-9]{{64}})") AS dig,
          IFNULL(l.labels, "") AS labels
        FROM runtime_actif r
        LEFT JOIN labels_dedup l
          ON l.proj = r.project_id
         AND l.rt = r.runtime_type
         AND l.wl = r.workload_name
         AND l.cluster = IFNULL(r.cluster_name, "")
         AND l.ns = IFNULL(r.namespace_name, "")
        GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
    """,
}


# --------------------------------------------------------------------------
# Requetes : phase 2 (restreintes aux digests reellement en execution)
# --------------------------------------------------------------------------

REQUETES_VULN = {
    "matrice": f"""
        SELECT severity AS sev,
          IF({MARQUEUR_DEP}, "DEPLOYED", "NOT_DEPLOYED") AS dep,
          COUNT(*) AS nb,
          COUNTIF(fixed_version IS NOT NULL AND fixed_version != "") AS fix,
          COUNT(DISTINCT image_digest) AS img,
          COUNT(DISTINCT cve_id) AS cve
        FROM {VUE}
        WHERE (NOT retire OR {MARQUEUR_DEP}) __PERIODE__
        GROUP BY sev, dep
    """,
    "paquets": f"""
        SELECT package_name AS n,
          COUNTIF(severity = "CRITICAL") AS c,
          COUNTIF(severity = "HIGH") AS h,
          COUNT(DISTINCT image_digest) AS img,
          COUNT(DISTINCT cve_id) AS cve,
          ANY_VALUE(fixed_version) AS fix
        FROM {VUE}
        WHERE {MARQUEUR_DEP}
          AND fixed_version IS NOT NULL AND fixed_version != "" __PERIODE__
        GROUP BY n ORDER BY c DESC, h DESC LIMIT 12
    """,
    "cves": f"""
        SELECT cve_id AS id, COUNT(DISTINCT image_digest) AS img,
          ANY_VALUE(package_name) AS pkg, ANY_VALUE(fixed_version) AS fix
        FROM {VUE}
        WHERE {MARQUEUR_DEP} AND severity = "CRITICAL" __PERIODE__
        GROUP BY id ORDER BY img DESC LIMIT 12
    """,
    # Une ligne par digest, et non par tag : c'est le digest qui tourne, et
    # deux digests de la meme image peuvent tourner cote a cote.
    "worklist": f"""
        SELECT repository_name AS repo, image_name AS img,
          image_tags AS tags,
          REGEXP_EXTRACT(image_digest, r"(sha256:[a-f0-9]{{64}})") AS dig,
          COUNTIF(severity = "CRITICAL") AS c,
          COUNTIF(severity = "HIGH") AS h,
          COUNTIF(fixed_version IS NOT NULL AND fixed_version != "") AS fix,
          COUNT(DISTINCT cve_id) AS cve,
          ANY_VALUE(artifact_registry_url) AS url,
          -- alimentent la recherche : on cherche aussi par paquet et par CVE
          STRING_AGG(DISTINCT package_name, " "
                     ORDER BY package_name LIMIT 60) AS pkgs,
          STRING_AGG(DISTINCT cve_id, " " ORDER BY cve_id LIMIT 80) AS cves_l
        FROM {VUE}
        WHERE {MARQUEUR_DEP} __PERIODE__
        GROUP BY repo, img, tags, dig
        ORDER BY c DESC, h DESC
    """,
    # Part des Critical/High d'une image en service que SCC a retires alors
    # que la console Artifact Registry les montre encore. Comptes dans les
    # totaux ; isoles ici pour expliquer l'ecart avec SCC.
    "retires": f"""
        SELECT REGEXP_EXTRACT(image_digest, r"(sha256:[a-f0-9]{{64}})") AS dig,
          COUNT(*) AS nb,
          STRING_AGG(DISTINCT cve_id, " " ORDER BY cve_id LIMIT 40) AS cves_l
        FROM {VUE}
        WHERE {MARQUEUR_DEP} AND retire
        GROUP BY dig
    """,
}

# Digests en service que SCC a analyses au moins une fois, toutes gravites et
# tous etats confondus. Pour les autres, deux cas a ne pas confondre :
#  - registre absent de l'export des findings (seul my-gcp-project
#    y figure au 2026-10-06) : on ne sait rien de l'image ;
#  - registre exporte : aucune faille remontee, image saine ou non analysee.
REQ_COUVERTS = f"""
    SELECT DISTINCT REGEXP_EXTRACT(resource.name, r"(sha256:[a-f0-9]{{64}})") AS dig
    FROM {FINDINGS}
    WHERE {FILTRE_IMG}
      AND REGEXP_EXTRACT(resource.name, r"(sha256:[a-f0-9]{{64}})") IN (__LISTE__)
"""

ENTIERS = {"nb", "fix", "img", "cve", "c", "h", "crit", "wl",
           "images_totales", "lignes_brutes"}


# --------------------------------------------------------------------------
# Acces aux CLI
# --------------------------------------------------------------------------

class ErreurBQ(Exception):
    pass


class ErreurGcloud(Exception):
    pass


def _cli(binaire):
    return ["cmd", "/c", binaire] if os.name == "nt" else [binaire]


def lancer_bq(sql, max_rows=50000):
    """Execute une requete et renvoie une liste de dicts."""
    cmd = _cli("bq") + [
        f"--project_id={PROJET}", "query", f"--location={LOCATION}",
        "--use_legacy_sql=false", "--format=json", "--quiet",
        f"--max_rows={max_rows}"]
    try:
        r = subprocess.run(cmd, input=sql, capture_output=True,
                           text=True, encoding="utf-8", errors="replace",
                           timeout=180)
    except subprocess.TimeoutExpired:
        raise ErreurBQ("La requete a depasse 180 s.")
    if r.returncode != 0:
        detail = (r.stderr or r.stdout or "").strip()
        raise ErreurBQ(detail[:600] or f"bq a renvoye le code {r.returncode}")
    sortie = (r.stdout or "").strip()
    # bq peut prefixer la sortie par des lignes d'attente : on isole le JSON
    debut = sortie.find("[")
    if debut == -1:
        return []
    lignes = json.loads(sortie[debut:])
    for ligne in lignes:
        for cle, val in list(ligne.items()):
            if cle in ENTIERS and val is not None:
                try:
                    ligne[cle] = int(val)
                except (TypeError, ValueError):
                    pass
    return lignes


def _gcloud(args, timeout=150):
    """Sortie brute de gcloud, ou ErreurGcloud."""
    try:
        r = subprocess.run(_cli("gcloud") + args, capture_output=True,
                           text=True, encoding="utf-8", errors="replace",
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ErreurGcloud(f"gcloud a depasse {timeout} s")
    except FileNotFoundError:
        raise ErreurGcloud("gcloud est introuvable dans le PATH")
    if r.returncode != 0:
        raise ErreurGcloud((r.stderr or r.stdout or "").strip()[:300]
                           or f"gcloud a renvoye le code {r.returncode}")
    return (r.stdout or "").strip()


# L'API Cloud Run est interrogee en HTTP plutot que par `gcloud run` : une
# centaine d'appels CLI coutent une demi-minute en lancements de processus,
# les memes requetes en HTTP tiennent en quelques secondes. Le jeton vient de
# gcloud, n'est jamais ecrit sur disque et expire de lui-meme.
API_RUN = f"https://{REGION_RUN}-run.googleapis.com/apis/serving.knative.dev/v1"


def jeton_acces():
    jeton = _gcloud(["auth", "print-access-token"], timeout=60)
    if not jeton:
        raise ErreurGcloud("gcloud n'a pas renvoye de jeton d'acces")
    return jeton.splitlines()[-1].strip()


def _api_run(chemin, jeton, timeout=60):
    req = urllib.request.Request(
        f"{API_RUN}/{chemin}",
        headers={"Authorization": f"Bearer {jeton}",
                 "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as rep:
            return json.load(rep)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.load(exc).get("error", {}).get("message", "")
        except Exception:
            pass
        raise ErreurGcloud(f"HTTP {exc.code} : {detail or exc.reason}"[:300])
    except urllib.error.URLError as exc:
        raise ErreurGcloud(f"Cloud Run injoignable : {exc.reason}")


# --------------------------------------------------------------------------
# References d'image
# --------------------------------------------------------------------------

def digest_de(ref):
    """Digest porte par une reference d'image, ou chaine vide."""
    if not ref or "@" not in ref:
        return ""
    d = ref.rsplit("@", 1)[1].strip()
    return d if RE_DIGEST.match(d) else ""


def version_de(ref):
    """Tag porte par une reference d'image, ou chaine vide.

    Le tag est la partie apres ':' du dernier segment, en ignorant le port
    eventuel du registre et le digest.
    """
    if not ref:
        return ""
    dernier = ref.split("@", 1)[0].rsplit("/", 1)[-1]
    return dernier.rsplit(":", 1)[1] if ":" in dernier else ""


def chemin_image(ref):
    """Reference sans tag ni digest : le nom d'image nu."""
    chemin = (ref or "").split("@", 1)[0]
    tete, _, dernier = chemin.rpartition("/")
    if ":" in dernier:
        dernier = dernier.rsplit(":", 1)[0]
    return f"{tete}/{dernier}" if tete else dernier


# --------------------------------------------------------------------------
# Versions publiees dans Artifact Registry
# --------------------------------------------------------------------------

API_AR = "https://artifactregistry.googleapis.com/v1"


def _decomposer_ar(ref):
    """(projet, region, depot, image) d'une reference Artifact Registry."""
    parts = chemin_image(ref).split("/")
    if len(parts) < 4 or "-docker.pkg.dev" not in parts[0]:
        return None
    return (parts[1], parts[0].split("-docker.pkg.dev")[0],
            parts[2], "/".join(parts[3:]))


# Une image multi-architecture n'est pas taguee sur le conteneur mais sur
# l'index qui le reference. Le digest qu'execute une revision Cloud Run est
# celui de l'enfant amd64 : Artifact Registry ne lui attache aucun tag, et
# demander "quelle version tourne ?" impose de remonter a l'index parent.
ACCEPT_MANIFESTE = ",".join((
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))

# L'appartenance d'un digest a un index ne change jamais : un index est
# immuable. On memorise donc les resolutions pour la duree du processus, et
# les rechargements suivants ne repaient pas le parcours des manifestes.
_versions_vues = {}
_verrou_versions = threading.Lock()


def _registre_v2(chemin, suffixe, jeton, timeout=30):
    """Appel a l'API registre Docker v2, qui seule expose les manifestes."""
    parts = chemin.split("/")
    if len(parts) < 4:
        raise ErreurGcloud(f"chemin d'image inattendu : {chemin}")
    url = (f"https://{parts[0]}/v2/{parts[1]}/{parts[2]}/"
           f"{'/'.join(parts[3:])}/{suffixe}")
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {jeton}",
                      "Accept": ACCEPT_MANIFESTE})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as rep:
            return json.load(rep), rep.headers.get("Docker-Content-Digest", "")
    except (urllib.error.URLError, ValueError, OSError) as exc:
        raise ErreurGcloud(str(exc)[:200])


def resoudre_versions(cibles, jeton):
    """Version sous laquelle Artifact Registry publie aujourd'hui un digest.

    `cibles` associe un digest au chemin de son image et, quand il existe, au
    tag que le deploiement reclame — essaye en premier parce que c'est
    presque toujours le bon.

    Deux lectures se completent :

    1. le tag pose directement sur le digest (image mono-architecture) ;
    2. sinon, le tag de l'index qui reference ce digest (image multi-arch).

    Ce qui sort est verifiable : "ce conteneur s'appelle X aujourd'hui". Le
    tag reclame par un service Cloud Run, lui, n'est qu'une chaine figee dans
    le gabarit ; il peut avoir ete republie ailleurs depuis le dernier
    deploiement. L'ecart entre les deux est justement ce qu'il faut montrer.
    """
    if not jeton or not cibles:
        return {}

    with _verrou_versions:
        resultats = {d: list(v) for d, v in _versions_vues.items() if d in cibles}
    restants = {d: c for d, c in cibles.items() if d not in resultats}
    if not restants:
        return resultats

    # 1. tag direct sur le digest
    def direct(item):
        dig, cible = item
        pieces = _decomposer_ar(cible["chemin"])
        if not pieces:
            return
        proj, loc, depot, image = pieces
        ident = urllib.parse.quote(f"{image}@{dig}", safe="")
        url = (f"{API_AR}/projects/{proj}/locations/{loc}"
               f"/repositories/{depot}/dockerImages/{ident}")
        req = urllib.request.Request(
            url, headers={"Authorization": f"Bearer {jeton}",
                          "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as rep:
                tags = json.load(rep).get("tags") or []
        except (urllib.error.URLError, ValueError, OSError):
            return      # image purgee, droits manquants : on s'en passe
        if tags:
            # le registre ne garantit aucun ordre : on trie pour que deux
            # chargements successifs ne nomment pas la meme image autrement
            resultats[dig] = sorted(tags)

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(direct, restants.items()))

    # 2. remontee aux index, pour les digests restes sans tag
    par_chemin = {}
    for dig, cible in restants.items():
        if dig not in resultats:
            par_chemin.setdefault(cible["chemin"], {"digests": set(),
                                                    "tags": []})
            par_chemin[cible["chemin"]]["digests"].add(dig)
            if cible.get("tag"):
                par_chemin[cible["chemin"]]["tags"].append(cible["tag"])
    if par_chemin:
        _resoudre_index(par_chemin, resultats, jeton)

    with _verrou_versions:
        for dig, tags in resultats.items():
            _versions_vues.setdefault(dig, list(tags))
    return resultats


def _resoudre_index(par_chemin, resultats, jeton):
    """Parcourt les tags d'une image jusqu'a retrouver ses digests cibles."""
    def lister(chemin):
        try:
            rep, _ = _registre_v2(chemin, "tags/list", jeton)
        except ErreurGcloud:
            return chemin, []
        tags = rep.get("tags") or []
        # le tag reclame par le deploiement d'abord : c'est le candidat
        # le plus probable, et le trouver evite de derouler tout le reste
        prioritaires = [t for t in par_chemin[chemin]["tags"] if t in tags]
        return chemin, prioritaires + [t for t in tags if t not in prioritaires]

    with ThreadPoolExecutor(max_workers=16) as pool:
        listes = dict(pool.map(lister, par_chemin))

    taches = [(c, t) for c, tags in listes.items() for t in tags]

    def inspecter(item):
        chemin, tag = item
        manquants = par_chemin[chemin]["digests"] - set(resultats)
        if not manquants:
            return      # tous les digests de cette image sont deja nommes
        try:
            manifeste, propre = _registre_v2(chemin, f"manifests/{tag}", jeton)
        except ErreurGcloud:
            return
        candidats = [propre] + [e.get("digest") for e
                                in (manifeste.get("manifests") or [])]
        for dig in candidats:
            if dig in manquants:
                resultats.setdefault(dig, []).append(tag)

    with ThreadPoolExecutor(max_workers=24) as pool:
        list(pool.map(inspecter, taches))


def inventaire_versions(chemins, jeton):
    """Versions publiees d'une image : digest, date de creation, tags.

    Un appel par image suffit, la ou interroger chaque digest en coutait un
    par digest. La date de creation est ce qui manque partout ailleurs : sans
    elle, impossible de dire qu'une version est "plus recente".
    """
    if not jeton or not chemins:
        return {}
    inventaire = {}

    def lister(chemin):
        pieces = _decomposer_ar(chemin)
        if not pieces:
            return
        proj, loc, depot, image = pieces
        url = (f"{API_AR}/projects/{proj}/locations/{loc}"
               f"/repositories/{depot}/packages/"
               f"{urllib.parse.quote(image, safe='')}"
               f"/versions?view=FULL&pageSize=500")
        req = urllib.request.Request(
            url, headers={"Authorization": f"Bearer {jeton}",
                          "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as rep:
                versions = json.load(rep).get("versions") or []
        except (urllib.error.URLError, ValueError, OSError):
            return
        par_dig = {}
        for v in versions:
            dig = (v.get("name") or "").rsplit("/", 1)[-1]
            if not RE_DIGEST.match(dig):
                continue
            meta = v.get("metadata") or {}
            try:
                taille = int(meta.get("imageSizeBytes") or 0)
            except (TypeError, ValueError):
                taille = 0
            par_dig[dig] = {
                "cree": v.get("createTime") or "",
                "tags": sorted((t.get("name") or "").rsplit("/", 1)[-1]
                               for t in (v.get("relatedTags") or [])),
                "type": meta.get("mediaType") or "",
                "taille": taille,
            }
        inventaire[chemin] = par_dig

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(lister, sorted(chemins)))
    return inventaire


# Une publication multi-architecture depose plusieurs objets sous le meme
# numero : un index sans taille, l'image par plateforme, et des attestations
# de quelques kilo-octets. Seule l'image est executable — et SCC analyse les
# trois separement, en ne voyant qu'un sous-ensemble des failles sur l'index.
# Comparer sans trier ferait passer l'index d'une version pour un progres.
TAILLE_MINI_IMAGE = 1 << 20      # en dessous, c'est une attestation


def est_image_executable(infos):
    return (infos.get("type", "").endswith("manifest.v1+json")
            or infos.get("type", "").endswith("manifest.v2+json"))         and infos.get("taille", 0) >= TAILLE_MINI_IMAGE


def meilleure_version(dig, chemin, inventaire, severites):
    """Version publiee depuis, et moins vulnerable que celle en service.

    Ne compare que des digests que SCC a reellement analyses : une version
    absente de ses findings peut etre saine comme jamais scannee, et la
    presenter comme un progres serait un mensonge par omission.
    """
    versions = inventaire.get(chemin) or {}
    courante = versions.get(dig)
    if not courante or dig not in severites:
        return None
    ref_c, ref_h = severites[dig]
    candidates = []
    for autre, infos in versions.items():
        if autre == dig or autre not in severites:
            continue
        if not est_image_executable(infos):
            continue
        if not infos.get("cree") or infos["cree"] <= (courante.get("cree") or ""):
            continue
        c, h = severites[autre]
        if (c, h) < (ref_c, ref_h):
            candidates.append((c, h, infos["cree"], autre))
    if not candidates:
        return None
    # la moins vulnerable d'abord, la plus recente pour departager
    c, h, cree, autre = min(candidates, key=lambda x: (x[0], x[1], x[2]))
    return {"dig": autre, "c": c, "h": h, "cree": cree[:10],
            "ver": (versions[autre].get("tags") or [""])[0]}


def lien_registre(chemin, dig):
    """Page Artifact Registry du digest exact, dans la Cloud Console."""
    pieces = _decomposer_ar(chemin)
    if not pieces or not dig:
        return ""
    proj, loc, depot, image = pieces
    return (f"{CONSOLE}/artifacts/docker/{proj}/{loc}/{depot}/{image}/{dig}"
            f"?project={proj}")


# --------------------------------------------------------------------------
# Provenance : depot de code et responsable
# --------------------------------------------------------------------------
#
# Aucun lien n'est fabrique : un depot n'est affiche que s'il existe.
#  - "sur"     : l'image nomme son depot (label pose au build), ou un depot
#                Secure Source Manager porte exactement le nom de l'image ;
#  - "suppose" : un seul depot SSM porte le meme nom au prefixe "ita-" et au
#                suffixe "-api" pres, ou un nom qui prolonge l'autre de trois
#                caracteres au plus (event-handle / event-handler-api) ;
#  - sinon rien.
# Le responsable est l'auteur du plus grand nombre de commits du depot, avec
# la certitude du depot dont il est tire.

SSM_INSTANCE = "my-ssm-instance"
SSM_PROJET = "my-git-project"
SSM_REGION = "me-west1"
DOSSIER_DEPOTS = os.path.join(
    os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"),
    "console-vuln", "depots")              # hors de tout depot versionne
CACHE_PROVENANCE = os.path.join(ICI, "provenance.local.json")
_verrou_prov = threading.Lock()

# Cles de label qui nomment le depot source, par ordre de preference.
LABELS_DEPOT = ("org.opencontainers.image.source", "org.label-schema.vcs-url",
                "vcs-url")
LABELS_COMMIT = ("org.opencontainers.image.revision",
                 "org.label-schema.vcs-ref")
# Valeurs de gabarit jamais remplies
VALEURS_VIDES = {"name", "author", "maintainer", "unknown", "todo", "none"}


def _lire_cache_provenance():
    try:
        with open(CACHE_PROVENANCE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def labels_image(chemin, dig, jeton):
    """Labels poses au build, lus dans la configuration de l'image."""
    man, _ = _registre_v2(chemin, f"manifests/{dig}", jeton)
    if man.get("manifests"):                # index : l'enfant amd64
        enfant = next((m for m in man["manifests"]
                       if (m.get("platform") or {}).get("architecture") == "amd64"),
                      man["manifests"][0])
        man, _ = _registre_v2(chemin, f"manifests/{enfant['digest']}", jeton)
    cfg = (man.get("config") or {}).get("digest")
    if not cfg:
        return {}
    blob, _ = _registre_v2(chemin, f"blobs/{cfg}", jeton)
    return (blob.get("config") or {}).get("Labels") or {}


def provenance_labels(cibles, jeton):
    """{digest: labels} ; un digest etant immuable, le cache est definitif."""
    cache = _lire_cache_provenance()
    a_lire = [(dig, chemin) for dig, chemin in cibles.items()
              if dig not in cache and _decomposer_ar(chemin)]

    def lire(item):
        dig, chemin = item
        try:
            return dig, labels_image(chemin_image(chemin), dig, jeton)
        except ErreurGcloud:
            return dig, None                 # on retentera au prochain tour

    if a_lire and jeton:
        with ThreadPoolExecutor(max_workers=8) as pool:
            for dig, labels in pool.map(lire, a_lire):
                if labels is not None:
                    cache[dig] = labels
        with _verrou_prov:
            try:
                with open(CACHE_PROVENANCE, "w", encoding="utf-8") as fh:
                    json.dump(cache, fh)
            except OSError:
                pass
    return {dig: cache.get(dig) for dig in cibles}


def _valeur_utile(v):
    v = str(v or "").strip().strip("\"'“”")
    if not v or v.lower() in VALEURS_VIDES:
        return ""
    if v.startswith(("<", "${", "$(")):
        return ""
    return v


def _label(labels, cles, suffixe=None):
    for k in cles:
        v = _valeur_utile(labels.get(k))
        if v:
            return k, v
    if suffixe:
        for k, v in sorted(labels.items()):
            if k.endswith(suffixe) and _valeur_utile(v):
                return k, _valeur_utile(v)
    return "", ""


def depots_ssm():
    """{nom: (url web, url git)} des depots Secure Source Manager.

    Un seul appel par rafraichissement : la liste de l'instance, rien de plus.
    """
    sortie = _gcloud(["source-manager", "repos", "list",
                      f"--instance={SSM_INSTANCE}", f"--region={SSM_REGION}",
                      f"--project={SSM_PROJET}",
                      "--format=value(name.basename(),uris.html,uris.gitHttps)"])
    depots = {}
    for ligne in sortie.splitlines():
        champs = ligne.split("\t")
        if len(champs) == 3 and champs[0]:
            depots[champs[0]] = (champs[1], champs[2])
    return depots


def _coeur(nom):
    n = re.sub(r"[^a-z0-9]", "", (nom or "").lower())
    n = n[3:] if n.startswith("ita") else n
    return n[:-3] if n.endswith("api") else n


def trouver_depot(image, depots):
    """(nom du depot, "sur" | "suppose") ou (None, None)."""
    norm = lambda x: re.sub(r"[^a-z0-9]", "", x.lower())
    exacts = [d for d in depots if norm(d) == norm(image)]
    if len(exacts) == 1:
        return exacts[0], "sur"
    c = _coeur(image)
    proches = [d for d in depots
               if _coeur(d) == c
               or (min(len(_coeur(d)), len(c)) >= 12
                   and (_coeur(d).startswith(c) or c.startswith(_coeur(d)))
                   and abs(len(_coeur(d)) - len(c)) <= 3)]
    if len(proches) == 1:
        return proches[0], "suppose"
    return None, None


def _env_git(jeton):
    """Authentification passee par l'environnement : rien n'est ecrit."""
    import base64
    cle = base64.b64encode(f"oauth2:{jeton}".encode()).decode()
    return {**os.environ, "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {cle}"}


def principal_contributeur(nom, url_git, jeton):
    """(auteur, ses commits, total) d'apres l'historique du depot.

    Clone nu, sans le contenu des fichiers ; les rafraichissements suivants
    ne font qu'un fetch.
    """
    cible = os.path.join(DOSSIER_DEPOTS, nom + ".git")
    env = _env_git(jeton)
    try:
        marque = os.path.join(cible, "FETCH_HEAD")
        if os.path.isdir(cible) and os.path.exists(marque) \
                and time.time() - os.path.getmtime(marque) < 3600:
            pass                            # historique lu il y a moins d'1 h
        elif os.path.isdir(cible):
            subprocess.run(["git", "-C", cible, "fetch", "-q", "origin",
                            "+refs/heads/*:refs/heads/*"],
                           env=env, capture_output=True, timeout=120)
        else:
            os.makedirs(DOSSIER_DEPOTS, exist_ok=True)
            subprocess.run(["git", "clone", "-q", "--bare", "--filter=blob:none",
                            url_git, cible],
                           env=env, capture_output=True, timeout=180)
        r = subprocess.run(["git", "-C", cible, "log", "--format=%aE%x09%aN",
                            "HEAD"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    # Compte par adresse : une meme personne signe parfois sous plusieurs
    # noms (yonathanb, Yonathan...) avec le meme e-mail.
    par_mail, noms = {}, {}
    for ligne in r.stdout.splitlines():
        mail, _, nom = ligne.partition("\t")
        mail, nom = mail.strip().lower(), nom.strip()
        if not mail:
            continue
        par_mail[mail] = par_mail.get(mail, 0) + 1
        noms.setdefault(mail, {})[nom] = noms.get(mail, {}).get(nom, 0) + 1
    if not par_mail:
        return None
    mail, n = max(par_mail.items(), key=lambda x: x[1])
    nom = max(noms[mail].items(), key=lambda x: x[1])[0]
    return f"{nom} <{mail}>", n, sum(par_mail.values())


def depots_et_contributeurs(images, jeton):
    """{image: {nom, url, etat, auteur, commits, total}} pour les images
    dont un depot SSM a ete trouve."""
    try:
        depots = depots_ssm()
    except ErreurGcloud:
        return {}
    trouves = {}
    for img in images:
        nom, etat = trouver_depot(img, depots)
        if nom:
            trouves[img] = {"nom": nom, "url": depots[nom][0], "etat": etat}
    noms = {t["nom"] for t in trouves.values()}

    def lire(nom):
        return nom, principal_contributeur(nom, depots[nom][1], jeton)

    contrib = {}
    if jeton and noms:
        with ThreadPoolExecutor(max_workers=4) as pool:
            contrib = dict(pool.map(lire, sorted(noms)))
    for t in trouves.values():
        c = contrib.get(t["nom"])
        if c:
            t["auteur"], t["commits"], t["total"] = c
    return trouves


def decrire_provenance(dig, chemin, labels, ssm):
    """Depot et responsable d'une image, chacun avec son niveau de certitude.

    `ssm` est l'entree de depots_et_contributeurs pour cette image, ou None.
    """
    labels = labels or {}
    depot = {"etat": "inconnu", "url": "", "source": ""}
    dev = {"etat": "inconnu", "nom": "", "source": ""}
    k, url = _label(labels, LABELS_DEPOT, ".repository.uri")
    if url and not re.match(r"^[a-z]+://", url):
        url = "https://" + url
    if url:
        depot = {"etat": "sur", "url": url,
                 "source": f"declare par l'image (label {k})"}
    elif ssm:
        depot = {"etat": ssm["etat"], "url": ssm["url"],
                 "source": f"depot Secure Source Manager {ssm['nom']}"
                           + (" : nom proche de celui de l'image"
                              if ssm["etat"] == "suppose" else "")}
        if ssm.get("auteur"):
            dev = {"etat": ssm["etat"], "nom": ssm["auteur"],
                   "source": f"{ssm['commits']} commits sur {ssm['total']} "
                             f"dans {ssm['nom']}"}
    depot["commit"] = _label(labels, LABELS_COMMIT, ".sourceversion")[1]
    return depot, dev


# Owners declared by hand, keyed by image name. They win over the git-history
# guess, which credits whoever committed most, not who owns the service.
# Kept out of version control (*.local.json): it names people.
DECLARED_OWNERS = os.path.join(ICI, "responsables.local.json")


def declared_owners():
    """{image: {"dev": name, "since": date}} — read on every collection."""
    try:
        with open(DECLARED_OWNERS, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def apply_declared_owner(dev, image, owners):
    entry = owners.get(image)
    if not entry or not entry.get("dev"):
        return dev
    source = "declared by hand"
    if entry.get("since"):
        source += f" on {entry['since']}"
    if dev.get("nom") and dev["nom"] != entry["dev"]:
        source += f" (git history suggests {dev['nom']})"
    return {"etat": "sur", "nom": entry["dev"], "source": source}


# --------------------------------------------------------------------------
# Sonde Cloud Run en direct
# --------------------------------------------------------------------------

def sonder_cloud_run(projets, jeton):
    """Ce que Cloud Run execute reellement, a l'instant present.

    L'inventaire BigQuery ne peut pas repondre : c'est un instantane, et il
    conserve les revisions retirees. Seule l'API Cloud Run dit quelle revision
    sert le trafic maintenant, et sous quelle reference d'image exacte.

    Renvoie ({(projet, service): [entrees]}, {projet: erreur}, {projets lus}).
    """
    services, erreurs, lus = {}, {}, set()
    a_resoudre, a_comparer = [], []
    if not jeton:
        return {}, {"*": "jeton d'acces gcloud indisponible"}, set()

    def lister(proj):
        try:
            rep = _api_run(f"namespaces/{proj}/services", jeton)
            return proj, rep.get("items") or [], None
        except ErreurGcloud as exc:
            return proj, None, str(exc)

    def resoudre(entree):
        """Digest reellement execute par une revision donnee."""
        try:
            rev = _api_run(
                f"namespaces/{entree['proj']}/revisions/{entree['rev']}",
                jeton)
        except ErreurGcloud as exc:
            erreurs.setdefault(entree["proj"], str(exc))
            return
        ref = (rev.get("status") or {}).get("imageDigest") or ""
        entree["dig"] = digest_de(ref)
        entree["ref"] = entree["ref"] or ref

    def comparer(entree):
        """Image portee par la derniere revision, celle qui ne sert pas."""
        try:
            rev = _api_run(
                f"namespaces/{entree['proj']}/revisions/{entree['recente']}",
                jeton)
        except ErreurGcloud:
            return
        entree["recente_dig"] = digest_de(
            (rev.get("status") or {}).get("imageDigest") or "")

    with ThreadPoolExecutor(max_workers=12) as pool:
        for proj, lignes, err in pool.map(lister, projets):
            if lignes is None:
                erreurs[proj] = err
                continue
            lus.add(proj)
            for s in lignes:
                nom = (s.get("metadata") or {}).get("name") or ""
                if not nom:
                    continue
                meta_svc = s.get("metadata") or {}
                ann = meta_svc.get("annotations") or {}
                conteneurs = (((s.get("spec") or {}).get("template") or {})
                              .get("spec") or {}).get("containers") or [{}]
                ref_spec = conteneurs[0].get("image") or ""
                statut = s.get("status") or {}
                dernier = statut.get("latestReadyRevisionName") or ""
                # La derniere revision CREEE, et non la derniere "prete" :
                # une revision deployee puis rendue au repos redevient
                # "Retired" et cesse de compter comme prete, alors qu'elle
                # porte bien la derniere image publiee.
                recente = statut.get("latestCreatedRevisionName") or dernier
                # Un trafic epingle nomme explicitement sa revision ; un
                # service qui suit ses deploiements dit "latestRevision".
                epingle = any(
                    t.get("revisionName") and not t.get("latestRevision")
                    for t in ((s.get("spec") or {}).get("traffic") or []))
                servantes = [(t["revisionName"], t.get("percent") or 0,
                              t.get("tag") or "")
                             for t in (statut.get("traffic") or [])
                             if t.get("revisionName")]
                if not servantes and dernier:
                    servantes = [(dernier, 100, "")]
                # Le digest vient TOUJOURS de la revision, jamais du
                # gabarit. Un gabarit epingle sur `@sha256:` peut nommer
                # l'index d'une image multi-architecture ; ce que le
                # conteneur execute est l'enfant amd64 que la revision a
                # resolu, et lui seul porte les couches analysees.
                for rev, part, tag_url in servantes:
                    entree = {
                        "proj": proj, "svc": nom, "rev": rev,
                        "part": part, "tag_url": tag_url,
                        "ref": "",
                        "dig": "",
                        # Le tag du gabarit ne vaut que pour la derniere
                        # revision : une revision figee par un partage de
                        # trafic execute autre chose.
                        "ver": version_de(ref_spec) if rev == dernier else "",
                        # Ce service sert-il bien sa derniere revision ?
                        "recente": recente,
                        "epingle": epingle,
                        "retard": bool(recente and rev != recente),
                        "recente_dig": "",
                        # lus en direct : l'inventaire peut avoir des
                        # semaines de retard sur les labels
                        "labels_live": meta_svc.get("labels") or {},
                        "createur": ann.get("serving.knative.dev/creator") or "",
                        "modificateur": ann.get("serving.knative.dev/lastModifier") or "",
                    }
                    services.setdefault((proj, nom), []).append(entree)
                    if not entree["dig"]:
                        a_resoudre.append(entree)
                    if entree["retard"]:
                        a_comparer.append(entree)
        list(pool.map(resoudre, a_resoudre))
        list(pool.map(comparer, a_comparer))

    return services, erreurs, lus


# --------------------------------------------------------------------------
# Mise en forme
# --------------------------------------------------------------------------

CONSOLE = "https://console.cloud.google.com"

# Labels poses par la plateforme : ils n'apprennent rien sur le workload.
LABELS_SYSTEME = (
    "serving.knative.dev/", "client.knative.dev/", "autoscaling.knative.dev/",
    "run.googleapis.com/", "cloud.googleapis.com/", "topology.kubernetes.io/",
    "addonmanager.kubernetes.io/", "networking.gke.io/", "goog-",
    "kubernetes.io/cluster-service",
)
LABELS_IGNORES = {
    "controller-revision-hash", "pod-template-hash", "pod-template-generation",
    "container-watcher-unique-id",
}


def nettoyer_labels(brut):
    """Ne garde que les labels poses par vos equipes."""
    if not brut or brut == "null":
        return {}
    try:
        obj = json.loads(brut)
        if isinstance(obj, str):      # JSON_QUERY rend parfois une chaine
            obj = json.loads(obj)
    except (ValueError, TypeError):
        return {}
    if not isinstance(obj, dict):
        return {}
    return {
        k: v for k, v in obj.items()
        if k not in LABELS_IGNORES
        and not any(k.startswith(p) for p in LABELS_SYSTEME)
    }


def est_prod(projet):
    """Un projet est de production sauf s'il est explicitement nonprod/stg.

    Les noms suivent la convention ita-<site>-<env>-<role>, ou 'nonprod'
    contient deja 'prod' : l'ordre des tests compte.
    """
    p = (projet or "").lower()
    if any(marq in p for marq in ("nonprod", "non-prod", "stg", "staging",
                                  "-dev", "dev-", "test", "sandbox", "qa")):
        return False
    return "prod" in p


def est_prod_workload(projet, labels):
    """Le label `environment` prime sur le nom du projet quand il existe.

    Sur le parc actuel les deux concordent partout ; le label reste plus sur,
    un projet pouvant heberger plusieurs environnements.
    """
    env = (labels.get("environment") or "").strip().lower()
    if env:
        return env == "prod" or env.endswith("-prod") or env.startswith("prod-")
    return est_prod(projet)


def lien_workload(d):
    """URL Cloud Console du workload lui-meme."""
    proj, nom, loc = d.get("proj"), d.get("wl"), d.get("loc") or ""
    if not proj or not nom:
        return ""
    if d.get("rt") == "GKE_POD":
        cluster, ns = d.get("cluster") or "", d.get("ns") or ""
        if not (cluster and ns and loc):
            return f"{CONSOLE}/kubernetes/workload/overview?project={proj}"
        return (f"{CONSOLE}/kubernetes/pod/{loc}/{cluster}/{ns}/{nom}"
                f"/details?project={proj}")
    if not loc:
        return f"{CONSOLE}/run?project={proj}"
    return f"{CONSOLE}/run/detail/{loc}/{nom}/metrics?project={proj}"


def lien_config(d):
    """URL de la page qui montre la reference d'image reellement deployee.

    Cloud Run : l'onglet Revisions, qui affiche le conteneur de chaque
    revision. GKE : l'onglet YAML du pod, ou figure l'image du conteneur.
    """
    proj, nom, loc = d.get("proj"), d.get("wl"), d.get("loc") or ""
    if not proj or not nom:
        return ""
    if d.get("rt") == "GKE_POD":
        cluster, ns = d.get("cluster") or "", d.get("ns") or ""
        if not (cluster and ns and loc):
            return f"{CONSOLE}/kubernetes/workload/overview?project={proj}"
        return (f"{CONSOLE}/kubernetes/pod/{loc}/{cluster}/{ns}/{nom}"
                f"/yaml?project={proj}")
    if not loc:
        return f"{CONSOLE}/run?project={proj}"
    return f"{CONSOLE}/run/detail/{loc}/{nom}/revisions?project={proj}"


def reference_courte(ref, dig):
    """Nom d'image lisible : chemin complet sans le digest en entier."""
    base = (ref or "").split("@", 1)[0]
    if base:
        return base
    return dig[:19] + "..." if dig else ""


def registre_de(ref):
    """Projet Artifact Registry (ou hote) d'une reference d'image."""
    ref = (ref or "").split("@", 1)[0]
    if not ref or ref.startswith("sha256:"):
        return "GKE, image sans nom dans l'inventaire"
    hote, _, reste = ref.partition("/")
    if hote.endswith("-docker.pkg.dev") and reste:
        return reste.split("/", 1)[0]
    return hote


def non_couverts(deploiements, couverts, exportes):
    """Images en service sur lesquelles SCC n'a jamais rien remonte."""
    par_reg = {}
    for d in deploiements:
        dig = d.get("dig") or ""
        if not dig or dig in couverts:
            continue
        e = par_reg.setdefault(registre_de(d.get("ref")), {
            "img": set(), "wl": set(), "rt": set(), "ex": set()})
        e["img"].add(dig)
        e["wl"].add((d["proj"], d["wl"]))
        e["rt"].add(d["rt"])
        if len(e["ex"]) < 6:
            e["ex"].add(reference_courte(d.get("ref"), dig).rsplit("/", 1)[-1])
    lignes = [{"reg": reg, "exporte": reg in exportes,
               "img": len(e["img"]), "wl": len(e["wl"]),
               "rt": sorted(e["rt"]), "ex": sorted(e["ex"])}
              for reg, e in par_reg.items()]
    lignes.sort(key=lambda l: -l["img"])
    return lignes


def clause_deploye(digests):
    """Predicat SQL isolant les findings des images en cours d'execution."""
    surs = sorted(d for d in digests if RE_DIGEST.match(d or ""))
    if not surs:
        return "FALSE"
    liste = ", ".join(f'"{d}"' for d in surs)
    return (f'REGEXP_EXTRACT(image_digest, r"(sha256:[a-f0-9]{{64}})") '
            f'IN ({liste})')


# --------------------------------------------------------------------------
# Assemblage
# --------------------------------------------------------------------------

def construire_deploiements(placements, live, lus, tags, cai_date):
    """Un enregistrement par emplacement d'execution reel.

    Cloud Run est decrit par la sonde en direct quand elle a repondu pour le
    projet ; sinon on retombe sur l'inventaire, et on le dit.
    """
    par_service = {}          # labels et localisation connus de l'inventaire
    deploiements = []

    for p in placements:
        labels = nettoyer_labels(p.get("labels"))
        base = {
            "rt": p["rt"], "proj": p["proj"], "loc": p.get("loc") or "",
            "wl": p["wl"], "cluster": p.get("cluster") or "",
            "ns": p.get("ns") or "", "labels": labels,
            "env": labels.get("environment", ""),
            "prod": est_prod_workload(p["proj"], labels),
        }
        if p["rt"] == "CLOUD_RUN_REVISION":
            par_service.setdefault((p["proj"], p["wl"]), []).append(
                {**base, "res": p.get("res") or "",
                 "ref": p.get("ref") or "", "dig": p.get("dig") or ""})
            continue
        ref = p.get("ref") or ""
        dig = p.get("dig") or ""
        deploiements.append({
            **base, "rev": p.get("res") or "", "ref": ref, "dig": dig,
            "ver": version_de(ref) or tags.get(dig, ""),
            "src": "inventaire", "date": cai_date,
        })

    vus = set()
    for (proj, svc), entrees in live.items():
        vus.add((proj, svc))
        connu = (par_service.get((proj, svc)) or [{}])[0]
        for e in entrees:
            labels = (nettoyer_labels(json.dumps(e.get("labels_live")))
                      or connu.get("labels") or {})
            dig = e.get("dig") or ""
            deploiements.append({
                "rt": "CLOUD_RUN_REVISION", "proj": proj,
                "loc": connu.get("loc") or REGION_RUN, "wl": svc,
                "cluster": "", "ns": "", "labels": labels,
                "env": labels.get("environment", ""),
                "prod": est_prod_workload(proj, labels),
                "rev": e.get("rev") or "", "ref": e.get("ref") or "",
                "dig": dig,
                "ver": e.get("ver") or version_de(e.get("ref") or "")
                       or tags.get(dig, ""),
                "part": e.get("part") or 0,
                # Une revision plus recente existe mais ne recoit pas le
                # trafic : le correctif est publie, pas mis en service.
                "retard": bool(e.get("retard")),
                "epingle": bool(e.get("epingle")),
                "recente": e.get("recente") or "",
                "recente_dig": e.get("recente_dig") or "",
                "createur": e.get("createur") or "",
                "modificateur": e.get("modificateur") or "",
                "src": "live", "date": "",
            })

    # Services Cloud Run absents de la sonde. Si le projet a bien ete lu,
    # c'est que le service n'existe plus : le garder recreerait le faux
    # positif qu'on cherche a eliminer. On ne retombe sur l'inventaire que
    # pour les projets illisibles, et on compte les disparus pour le dire.
    disparus = 0
    for (proj, svc), entrees in par_service.items():
        if (proj, svc) in vus:
            continue
        if proj in lus:
            disparus += 1
            continue
        for e in entrees:
            ref, dig = e.get("ref") or "", e.get("dig") or ""
            deploiements.append({
                **{k: e[k] for k in ("rt", "proj", "loc", "wl", "cluster",
                                     "ns", "labels", "env", "prod")},
                "rev": e.get("res") or "", "ref": ref, "dig": dig,
                "ver": version_de(ref) or tags.get(dig, ""),
                "src": "inventaire", "date": cai_date,
            })

    for d in deploiements:
        d["url"] = lien_workload(d)
        d["cfg"] = lien_config(d)
        d["nom"] = reference_courte(d.get("ref"), d.get("dig"))
    return deploiements, disparus


def construire_donnees(periode=PERIODE_DEFAUT):
    """Lance les deux phases et assemble le payload."""
    debut = time.time()
    clause = clause_periode(periode)

    # Phase 1 : inventaire, metadonnees, et sonde Cloud Run en direct.
    with ThreadPoolExecutor(max_workers=8) as pool:
        f_projets = pool.submit(lancer_bq, REQ_PROJETS_CR)
        f_jeton = pool.submit(jeton_acces)
        futurs = {nom: pool.submit(lancer_bq, sql.replace(MARQUEUR, clause))
                  for nom, sql in REQUETES_BASE.items()}
        projets = sorted({l["proj"] for l in f_projets.result()
                          if l.get("proj")})
        try:
            jeton = f_jeton.result()
        except ErreurGcloud:
            jeton = ""
        f_live = pool.submit(sonder_cloud_run, projets, jeton)
        base = {nom: f.result() for nom, f in futurs.items()}
        live, err_live, lus = f_live.result()
    t_phase1 = time.time() - debut

    fraicheur = (base["fraicheur"] or [{}])[0]
    cai_date = fraicheur.get("cai") or "-"
    tags = {l["dig"]: l["tag"] for l in base["tags"] if l.get("dig")}

    deploiements, disparus = construire_deploiements(
        base["placements"], live, lus, tags, cai_date)
    digests = {d["dig"] for d in deploiements if d.get("dig")}

    # Phase 2 : les findings, restreints a ce qui tourne pour de vrai.
    dep_sql = clause_deploye(digests)
    resultats, erreurs = {}, {}

    def executer(item):
        nom, sql = item
        try:
            resultats[nom] = lancer_bq(
                sql.replace(MARQUEUR_DEP, dep_sql).replace(MARQUEUR, clause))
        except ErreurBQ as exc:
            erreurs[nom] = str(exc)

    surs = sorted(d for d in digests if RE_DIGEST.match(d))
    requetes = dict(REQUETES_VULN)
    if surs:
        requetes["couverts"] = REQ_COUVERTS.replace(
            "__LISTE__", ", ".join(f'"{d}"' for d in surs))
    else:
        resultats["couverts"] = []

    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(executer, requetes.items()))
    if erreurs:
        raise ErreurBQ("; ".join(f"[{k}] {v}" for k, v in erreurs.items()))

    # On ne renvoie au navigateur que les emplacements d'une image vulnerable.
    vulnerables = {l["dig"] for l in resultats["worklist"] if l.get("dig")}
    retires = {l["dig"]: l["nb"] for l in resultats["retires"] if l.get("dig")}
    workloads = [d for d in deploiements if d.get("dig") in vulnerables]

    par_dig = {}
    for d in workloads:
        par_dig.setdefault(d["dig"], []).append(d)

    # Sous quel nom Artifact Registry publie aujourd'hui chacun de ces
    # digests. Le tag reclame par le deploiement sert de premier candidat.
    chemins = {}
    for dig, ws in par_dig.items():
        chemin = next((w["nom"] for w in ws if w.get("nom")), "")
        if chemin:
            chemins.setdefault(chemin, set()).add(dig)

    # Ce que le registre publie pour ces images, et ce que SCC a trouve sur
    # chaque digest : de quoi dire si une version posterieure fait mieux.
    inventaire = inventaire_versions(chemins, jeton)
    severites = {l["dig"]: (l["c"], l["h"]) for l in base["severites"]
                 if l.get("dig")}
    meilleures = {}
    for chemin, digs in chemins.items():
        for dig in digs:
            trouvee = meilleure_version(dig, chemin, inventaire, severites)
            if trouvee:
                meilleures[dig] = trouvee

    cibles = {}
    for dig, ws in par_dig.items():
        chemin = next((w["nom"] for w in ws if w.get("nom")), "")
        if not chemin:
            continue
        cibles[dig] = {
            "chemin": chemin,
            "tag": next((w["ver"] for w in ws if w.get("ver")), ""),
        }
        # la revision plus recente porte une autre image : la nommer aussi,
        # c'est elle qu'il faudra mettre en service
        for w in ws:
            if w.get("recente_dig") and w["recente_dig"] not in cibles:
                cibles[w["recente_dig"]] = {"chemin": chemin,
                                            "tag": w.get("reclamee") or ""}
        # et la version moins vulnerable, pour pouvoir la nommer aussi
        if dig in meilleures and meilleures[dig]["dig"] not in cibles:
            cibles[meilleures[dig]["dig"]] = {
                "chemin": chemin, "tag": meilleures[dig].get("ver") or ""}
    vivants = resoudre_versions(cibles, jeton)

    # un digest enfant n'est pas tague : c'est son index parent qui l'est
    for dig, m in meilleures.items():
        if not m.get("ver"):
            noms = vivants.get(m["dig"]) or []
            m["ver"] = noms[0] if noms else ""

    for d in workloads:
        dig = d.get("dig") or ""
        publiees = vivants.get(dig, [])
        reclamee = d.get("ver") or ""          # tag fige dans le gabarit
        d["ar"] = publiees
        d["ver"] = publiees[0] if publiees else (reclamee or tags.get(dig, ""))
        d["reclamee"] = reclamee
        # Le service reclame un tag qui ne designe plus ce conteneur : une
        # image a ete republiee sans que la revision soit redeployee.
        d["derive"] = bool(reclamee and publiees and reclamee not in publiees)
        attente = vivants.get(d.get("recente_dig") or "", [])
        d["recente_ver"] = attente[0] if attente else reclamee
        d["registre"] = lien_registre(d.get("nom") or "", dig)

    prov = provenance_labels(
        {dig: next((w["nom"] for w in ws if w.get("nom")), "")
         for dig, ws in par_dig.items()}, jeton)
    ssm = depots_et_contributeurs(
        {l.get("img", "").rsplit("/", 1)[-1] for l in resultats["worklist"]},
        jeton)

    owners = declared_owners()
    worklist = []
    for l in resultats["worklist"]:
        dig = l.get("dig") or ""
        ws = par_dig.get(dig) or []
        runtimes = {w["rt"] for w in ws}
        publiees = vivants.get(dig, [])
        chemin = next((w["nom"] for w in ws if w.get("nom")), l.get("img"))
        worklist.append({
            **l,
            "rt": ("GKE_POD" if runtimes == {"GKE_POD"}
                   else "CLOUD_RUN_REVISION" if runtimes == {"CLOUD_RUN_REVISION"}
                   else "MIXTE" if runtimes else ""),
            "tags": l.get("tags") or "NO_TAG_FOUND",
            # Le lien du registre pointe sur le digest exact, et non sur le
            # paquet : la page du paquet ouvre la derniere version publiee,
            # qui n'est pas celle qui tourne.
            "url": lien_registre(chemin, dig) or l.get("url") or "",
            "ver": (publiees[0] if publiees
                    else next((w["reclamee"] for w in ws if w.get("reclamee")), "")
                    or tags.get(dig, "")),
            "ar": publiees,
            "reclamee": next((w["reclamee"] for w in ws if w.get("reclamee")), ""),
            "derive": any(w.get("derive") for w in ws),
            "retard": any(w.get("retard") for w in ws),
            "mieux": meilleures.get(dig),
            "recente": next((w["recente"] for w in ws if w.get("retard")), ""),
            "recente_ver": next((w["recente_ver"] for w in ws
                                 if w.get("retard") and w.get("recente_ver")), ""),
            "nom": chemin,
            "live": any(w["src"] == "live" for w in ws),
            "ret": retires.get(dig, 0),
            **dict(zip(("depot", "dev"),
                       decrire_provenance(
                           dig, chemin, prov.get(dig),
                           ssm.get(l.get("img", "").rsplit("/", 1)[-1])))),
        })
        worklist[-1]["dev"] = apply_declared_owner(
            worklist[-1]["dev"], l.get("img", "").rsplit("/", 1)[-1], owners)

    # Repartition par runtime, recomptee sur les emplacements reels : les
    # champs agreges de la vue concatenent des chaines et perdent le detail.
    par_runtime = {}
    for w in workloads:
        e = par_runtime.setdefault(w["rt"], {"wl": set(), "img": set()})
        e["wl"].add((w["proj"], w["wl"]))
        e["img"].add(w["dig"])
    lignes_par_dig = {l["dig"]: l for l in worklist}
    runtime = []
    for rt, e in par_runtime.items():
        lignes = [lignes_par_dig[d] for d in e["img"] if d in lignes_par_dig]
        runtime.append({
            "nom": {"CLOUD_RUN_REVISION": "Cloud Run",
                    "GKE_POD": "GKE"}.get(rt, rt),
            "nb": sum(l["c"] + l["h"] for l in lignes),
            "crit": sum(l["c"] for l in lignes),
            "img": len(e["img"]), "wl": len(e["wl"]),
        })
    runtime.sort(key=lambda r: -r["nb"])

    meta = (base["meta"] or [{}])[0]
    matrice = resultats["matrice"]
    return {
        "meta": {
            "dernier_scan": meta.get("dernier_scan") or "-",
            "images_totales": meta.get("images_totales") or 0,
            "lignes_brutes": meta.get("lignes_brutes") or 0,
            "date_min": meta.get("date_min") or "-",
            "actives": sum(l["nb"] for l in matrice),
            "recupere_a": datetime.now().strftime("%H:%M:%S"),
            "duree": round(time.time() - debut, 1),
            "duree_live": round(t_phase1, 1),
            "periode": periode,
            "periode_nom": PERIODES.get(periode, PERIODES[PERIODE_DEFAUT])[0],
            "periodes": [{"id": k, "nom": v[0]} for k, v in PERIODES.items()],
            "cai_date": cai_date,
            "tags_date": fraicheur.get("tags") or "-",
            "cr_projets": len(projets),
            "cr_services": len(live),
            "cr_disparus": disparus,
            "cr_erreurs": [{"proj": k, "msg": v}
                           for k, v in sorted(err_live.items())],
            "retires": sum(retires.values()),
            "img_retires": len(retires),
            # images en service dont SCC a TOUT retire : la vue SCC les ignore
            "img_retires_seuls": sum(1 for l in worklist
                                     if l["ret"] and l["ret"] >= l["c"] + l["h"]),
            "non_couverts": non_couverts(
                deploiements, {l["dig"] for l in resultats["couverts"]
                               if l.get("dig")},
                {l["p"] for l in base["exportes"] if l.get("p")}),
        },
        "matrice": matrice,
        "runtime": runtime,
        "workloads": workloads,
        "tendance": base["tendance"],
        "paquets": resultats["paquets"],
        "cves": resultats["cves"],
        "worklist": worklist,
    }


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------

_cache = {}          # periode -> {"donnees":..., "ts":...}
_verrou = threading.Lock()


def obtenir_donnees(forcer=False, periode=PERIODE_DEFAUT):
    if periode not in PERIODES:
        periode = PERIODE_DEFAUT
    with _verrou:
        entree = _cache.get(periode)
        if entree and not forcer and (time.time() - entree["ts"]) < TTL:
            return entree["donnees"], True
        donnees = construire_donnees(periode)
        _cache[periode] = {"donnees": donnees, "ts": time.time()}
        return donnees, False


def cached_data(periode=PERIODE_DEFAUT):
    """Last computed payload whatever its age, or (None, None).

    Never triggers a collection: callers that must not sweep the fleet
    (BigQuery, Cloud Run API on every project, SSM listing) rely on this.
    """
    with _verrou:
        entree = _cache.get(periode)
    if not entree:
        return None, None
    return entree["donnees"], entree["ts"]


# --------------------------------------------------------------------------
# Flat table API: the rows the UI renders, one per (image, workload)
# --------------------------------------------------------------------------

TABLE_COLUMNS = [
    "image", "image_path", "registry_repo", "version", "tags",
    "version_claimed", "tag_drift", "digest", "runtime",
    "critical", "high", "cves", "fixable", "out_of_scc",
    "better_version", "better_critical", "better_high", "registry_url",
    "source_repo_url", "source_repo_status", "source_commit",
    "dev", "dev_status", "dev_source",
    "project", "prod", "environment", "location", "cluster", "namespace",
    "workload", "revision", "traffic_percent", "workload_source",
    "pending_revision", "pending_version", "workload_url", "config_url",
    "labels", "packages", "cve_ids",
]


def flat_rows(donnees, image=""):
    """Join worklist and workloads the way the UI does (by digest)."""
    by_digest = {}
    for w in donnees.get("workloads") or []:
        by_digest.setdefault(w.get("dig") or "", []).append(w)

    needle = image.strip().lower()
    rows = []
    for r in donnees.get("worklist") or []:
        name = (r.get("img") or "").rsplit("/", 1)[-1]
        if needle and needle != name.lower() and needle not in (r.get("img") or "").lower():
            continue
        repo = r.get("depot") or {}
        dev = r.get("dev") or {}
        better = r.get("mieux") or {}
        base = {
            "image": name,
            "image_path": r.get("nom") or "",
            "registry_repo": r.get("repo") or "",
            "version": r.get("ver") or "",
            "tags": r.get("tags") or "",
            "version_claimed": r.get("reclamee") or "",
            "tag_drift": bool(r.get("derive")),
            "digest": r.get("dig") or "",
            "runtime": r.get("rt") or "",
            "critical": r.get("c") or 0,
            "high": r.get("h") or 0,
            "cves": r.get("cve") or 0,
            "fixable": r.get("fix") or 0,
            "out_of_scc": r.get("ret") or 0,
            "better_version": better.get("ver") or "",
            "better_critical": better.get("c", ""),
            "better_high": better.get("h", ""),
            "registry_url": r.get("url") or "",
            # "sur" = certain, "suppose" = inferred, "inconnu" = unknown
            "source_repo_url": repo.get("url") or "",
            "source_repo_status": repo.get("etat") or "inconnu",
            "source_commit": repo.get("commit") or "",
            "dev": dev.get("nom") or "",
            "dev_status": dev.get("etat") or "inconnu",
            "dev_source": dev.get("source") or "",
            "packages": r.get("pkgs") or "",
            "cve_ids": r.get("cves_l") or "",
        }
        workloads = by_digest.get(r.get("dig") or "") or [{}]
        for w in workloads:
            labels = w.get("labels") or {}
            rows.append({**base,
                "project": w.get("proj") or "",
                "prod": bool(w.get("prod")),
                "environment": w.get("env") or "",
                "location": w.get("loc") or "",
                "cluster": w.get("cluster") or "",
                "namespace": w.get("ns") or "",
                "workload": w.get("wl") or "",
                "revision": w.get("rev") or "",
                "traffic_percent": w.get("part") if w.get("part") else "",
                "workload_source": w.get("src") or "",
                "pending_revision": w.get("recente") or "" if w.get("retard") else "",
                "pending_version": w.get("recente_ver") or "" if w.get("retard") else "",
                "workload_url": w.get("url") or "",
                "config_url": w.get("cfg") or "",
                "labels": ";".join(f"{k}={labels[k]}" for k in sorted(labels)),
            })
    return rows


def rows_to_csv(rows):
    import csv
    import io
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=TABLE_COLUMNS, lineterminator="\r\n")
    writer.writeheader()
    writer.writerows(rows)
    # BOM so that Excel opens accented characters correctly
    return "﻿" + buf.getvalue()


# --------------------------------------------------------------------------
# Rendu
# --------------------------------------------------------------------------

def page_erreur(message):
    msg = (message.replace("&", "&amp;").replace("<", "&lt;")
                  .replace(">", "&gt;"))
    return f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Erreur BigQuery</title><style>
body{{margin:0;background:#F2F4F0;color:#171A1B;font:14px/1.6 "Segoe UI",system-ui,sans-serif;
display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px}}
.b{{max-width:660px;background:#fff;border:1px solid #DEE2DB;border-left:3px solid #C4362C;
border-radius:4px;padding:26px 30px}}
h1{{margin:0 0 10px;font-size:20px;color:#C4362C}}
pre{{background:#FAFBF8;border:1px solid #EBEEE8;border-radius:3px;padding:12px;
font-size:12px;white-space:pre-wrap;word-break:break-word;color:#414A4C}}
ul{{padding-left:20px;color:#414A4C}} li{{margin:5px 0}}
code{{background:#FAFBF8;border:1px solid #EBEEE8;padding:1px 5px;border-radius:2px;font-size:12px}}
a{{color:#0E7BAE}}
</style></head><body><div class="b">
<h1>BigQuery n'a pas repondu</h1>
<pre>{msg}</pre>
<p>Pistes a verifier :</p>
<ul>
<li>Authentification expiree : <code>gcloud auth login</code></li>
<li>La CLI <code>bq</code> n'est pas dans le PATH de ce terminal</li>
<li>Droits de lecture retires sur <code>{DATASET}</code></li>
</ul>
<p><a href="/?refresh=1">Reessayer</a></p>
</div></body></html>"""


def rendre(donnees, depuis_cache):
    with open(TEMPLATE, encoding="utf-8") as fh:
        html = fh.read()
    charge = json.dumps(donnees, ensure_ascii=False)
    etat = "cache" if depuis_cache else "direct"
    return html.replace("__DATA__", charge).replace("__ETAT__", etat)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if "/api/" in self.path or self.path.startswith("/?"):
            print(f"  {self.path}  {fmt % args}")

    def _envoyer(self, corps, code=200, ctype="text/html; charset=utf-8"):
        donnees = corps.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(donnees)))
        self.send_header("Cache-Control", "no-store")
        try:
            self.end_headers()
            self.wfile.write(donnees)
        except (ConnectionAbortedError, ConnectionResetError,
                BrokenPipeError):
            # Le navigateur a ferme ou recharge l'onglet pendant les ~40 s
            # de calcul : il n'y a plus personne a qui repondre.
            self.close_connection = True

    def _send_table(self, params, forcer, periode):
        """GET /api/table?image=<name>&format=json|csv&cache=only

        cache=only never starts a collection: it serves the last payload,
        whatever its age, or 503 when nothing has been computed yet.
        """
        jtype = "application/json; charset=utf-8"
        image = params.get("image", [""])[0]
        fmt = params.get("format", ["json"])[0].lower()
        if params.get("cache", [""])[0] == "only":
            donnees, ts = cached_data(periode)
            if donnees is None:
                self._envoyer(json.dumps({
                    "error": "no cached data; open the UI or call without "
                             "cache=only to run a collection"}), 503, jtype)
                return
        else:
            try:
                donnees, _ = obtenir_donnees(forcer, periode)
            except ErreurBQ as exc:
                self._envoyer(json.dumps({"error": str(exc)}), 500, jtype)
                return
            _, ts = cached_data(periode)
        rows = flat_rows(donnees, image)
        if fmt == "csv":
            self._envoyer(rows_to_csv(rows), 200, "text/csv; charset=utf-8")
            return
        meta = donnees.get("meta") or {}
        self._envoyer(json.dumps({
            "fetched_at": meta.get("recupere_a"),
            "age_seconds": round(time.time() - ts) if ts else None,
            "period": meta.get("periode"),
            "last_scc_scan": meta.get("dernier_scan"),
            "cloud_run_errors": meta.get("cr_erreurs") or [],
            "columns": TABLE_COLUMNS,
            "count": len(rows),
            "rows": rows,
        }, ensure_ascii=False), 200, jtype)

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(url.query)
        forcer = params.get("refresh", ["0"])[0] == "1"
        periode = params.get("p", [PERIODE_DEFAUT])[0]
        if periode not in PERIODES:
            periode = PERIODE_DEFAUT
        chemin = url.path

        if chemin == "/favicon.ico":
            self._envoyer("", 404, "text/plain")
            return

        if chemin == "/api/data":
            try:
                donnees, cache = obtenir_donnees(forcer, periode)
                self._envoyer(json.dumps(donnees, ensure_ascii=False), 200,
                              "application/json; charset=utf-8")
            except ErreurBQ as exc:
                self._envoyer(json.dumps({"erreur": str(exc)}), 500,
                              "application/json; charset=utf-8")
            return

        if chemin == "/api/table":
            self._send_table(params, forcer, periode)
            return

        if chemin != "/":
            self._envoyer("Not found", 404, "text/plain")
            return

        try:
            if forcer:
                print("  Interrogation de BigQuery et de Cloud Run...")
            donnees, cache = obtenir_donnees(forcer, periode)
            if not cache:
                m = donnees["meta"]
                print(f"  [{m['periode_nom']}] {len(donnees['worklist'])} "
                      f"images en execution · {m['cr_services']} services "
                      f"Cloud Run verifies ({m['duree']} s)")
                for e in m["cr_erreurs"]:
                    print(f"    ! Cloud Run {e['proj']} : {e['msg']}")
            self._envoyer(rendre(donnees, cache))
        except ErreurBQ as exc:
            self._envoyer(page_erreur(str(exc)), 500)
        except FileNotFoundError:
            self._envoyer(page_erreur(
                f"Template introuvable : {TEMPLATE}"), 500)


class Serveur(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ServeurV6(Serveur):
    address_family = socket.AF_INET6


def ip_locale():
    """Adresse de cette machine sur le reseau local, ou chaine vide."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))   # aucun paquet n'est emis
        return s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()


def ouvrir_serveurs(port, lan=False):
    """Ecoute locale par defaut ; sur tout le reseau si lan=True.

    Sous Windows `localhost` resout ::1 avant 127.0.0.1 : un serveur IPv4
    seul fait patienter ~2 s le temps que le navigateur bascule. On sert
    donc aussi ::1 en mode local.
    """
    if lan:
        return Serveur(("0.0.0.0", port), Handler), []
    principal = Serveur(("127.0.0.1", port), Handler)  # doit reussir
    secondaires = []
    try:
        secondaires.append(ServeurV6(("::1", port), Handler))
    except OSError:
        pass  # pas d'IPv6 sur cette machine : 127.0.0.1 suffit
    for srv in secondaires:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    return principal, secondaires


def lire_arguments(argv):
    port, lan = 8787, False
    for arg in argv[1:]:
        if arg in ("--lan", "--reseau"):
            lan = True
        elif arg.isdigit():
            port = int(arg)
        else:
            print(f"  Argument ignore : {arg}")
    return port, lan


def main():
    if not os.path.exists(TEMPLATE):
        print(f"ERREUR : {TEMPLATE} est introuvable.")
        sys.exit(1)

    port, lan = lire_arguments(sys.argv)
    url = f"http://127.0.0.1:{port}/"
    print()
    print("  Console de triage des vulnerabilites")
    print(f"  Projet : {PROJET}  ({LOCATION})")
    print(f"  -> {url}")
    if lan:
        ip = ip_locale()
        if ip:
            print(f"  -> http://{ip}:{port}/   (depuis un autre appareil "
                  f"du meme Wi-Fi)")
        print("  ATTENTION : en mode --lan l'app n'a aucune authentification.")
        print("  Toute machine du reseau peut la lire. A n'utiliser que sur")
        print("  un reseau de confiance, et a couper apres usage.")
        print("  Si le telephone n'y accede pas, ouvrir le port une fois :")
        print(f'    netsh advfirewall firewall add rule '
              f'name="Console vulnerabilites {port}" dir=in action=allow '
              f'protocol=TCP localport={port}')
    print("  Ctrl+C pour arreter.")
    print()

    try:
        serveur, secondaires = ouvrir_serveurs(port, lan)
    except OSError as exc:
        print(f"  Impossible d'ouvrir le port {port} : {exc}")
        print(f"  Essayez : python app.py {port + 1}")
        sys.exit(1)

    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        serveur.serve_forever()
    except KeyboardInterrupt:
        print("\n  Arret.")
        serveur.shutdown()
        for srv in secondaires:
            srv.shutdown()


if __name__ == "__main__":
    main()
