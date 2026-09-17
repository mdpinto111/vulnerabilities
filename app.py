#!/usr/bin/env python3
"""
Console de triage des vulnerabilites SCC - application locale.

Interroge BigQuery en direct via la CLI `bq` (deja authentifiee) et sert le
tableau de bord sur http://localhost:8787

Aucune dependance a installer : stdlib Python uniquement.

Usage :
    python app.py              # port 8787
    python app.py 9000         # autre port
"""

import http.server
import json
import os
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

PROJET = "my-gcp-project"
DATASET = "my-gcp-project.scc_findings"
LOCATION = "me-west1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8787
TTL = 600  # secondes avant qu'un rechargement relance les requetes
ICI = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(ICI, "app_tpl.html")

VUE = f"`{DATASET}.v_today_vulnerabilities_whole_picture`"
FINDINGS = f"`{DATASET}.findings`"

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
# Requetes
# --------------------------------------------------------------------------

REQUETES = {
    "meta": f"""
        SELECT
          FORMAT_TIMESTAMP("%Y-%m-%d %H:%M", MAX(event_time), "Asia/Jerusalem") AS dernier_scan,
          COUNT(DISTINCT REGEXP_EXTRACT(resource.name, r"(sha256:[a-f0-9]+)")) AS images_totales,
          COUNT(*) AS lignes_brutes,
          FORMAT_DATE("%Y-%m-%d", MIN(DATE(event_time))) AS date_min
        FROM {FINDINGS}
        WHERE {FILTRE_IMG}
    """,
    "matrice": f"""
        SELECT severity AS sev, deployed_status AS dep,
          COUNT(*) AS nb,
          COUNTIF(fixed_version IS NOT NULL AND fixed_version != "") AS fix,
          COUNT(DISTINCT image_digest) AS img,
          COUNT(DISTINCT cve_id) AS cve
        FROM {VUE}
        WHERE TRUE __PERIODE__
        GROUP BY sev, dep
    """,
    "runtime": f"""
        SELECT deployed_in AS nom, COUNT(*) AS nb,
          COUNTIF(severity = "CRITICAL") AS crit,
          COUNT(DISTINCT image_digest) AS img,
          COUNT(DISTINCT deployed_workloads) AS wl
        FROM {VUE}
        WHERE deployed_status = "DEPLOYED" __PERIODE__
        GROUP BY nom ORDER BY nb DESC
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
    "paquets": f"""
        SELECT package_name AS n,
          COUNTIF(severity = "CRITICAL") AS c,
          COUNTIF(severity = "HIGH") AS h,
          COUNT(DISTINCT image_digest) AS img,
          COUNT(DISTINCT cve_id) AS cve,
          ANY_VALUE(fixed_version) AS fix
        FROM {VUE}
        WHERE deployed_status = "DEPLOYED"
          AND fixed_version IS NOT NULL AND fixed_version != "" __PERIODE__
        GROUP BY n ORDER BY c DESC, h DESC LIMIT 12
    """,
    "cves": f"""
        SELECT cve_id AS id, COUNT(DISTINCT image_digest) AS img,
          ANY_VALUE(package_name) AS pkg, ANY_VALUE(fixed_version) AS fix
        FROM {VUE}
        WHERE deployed_status = "DEPLOYED" AND severity = "CRITICAL" __PERIODE__
        GROUP BY id ORDER BY img DESC LIMIT 12
    """,
    "worklist": f"""
        SELECT repository_name AS repo, image_name AS img, image_tags AS tags,
          ANY_VALUE(deployed_in) AS rt,
          ANY_VALUE(deployed_workloads) AS wl,
          ANY_VALUE(deployed_projects) AS proj,
          COUNTIF(severity = "CRITICAL") AS c,
          COUNTIF(severity = "HIGH") AS h,
          COUNTIF(fixed_version IS NOT NULL AND fixed_version != "") AS fix,
          COUNT(DISTINCT cve_id) AS cve,
          ANY_VALUE(artifact_registry_url) AS url,
          SUBSTR(ANY_VALUE(image_digest), 1, 19) AS dig,
          -- alimentent la recherche : on cherche aussi par paquet et par CVE
          STRING_AGG(DISTINCT package_name, " "
                     ORDER BY package_name LIMIT 60) AS pkgs,
          STRING_AGG(DISTINCT cve_id, " " ORDER BY cve_id LIMIT 80) AS cves_l
        FROM {VUE}
        WHERE deployed_status = "DEPLOYED" __PERIODE__
        GROUP BY repo, img, tags
        ORDER BY c DESC, h DESC
    """,
    # Detail des workloads : ou tourne chaque image, dans quel projet,
    # sous quels labels. La vue whole_picture concatene ces champs, ce qui
    # perd la correspondance workload -> projet ; on repart de la source.
    # Les labels ne sont exposes par aucune vue : on les lit dans le JSON
    # brut de l'export Cloud Asset Inventory.
    "workloads": f"""
        WITH labels_src AS (
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
        -- Un service Cloud Run a plusieurs revisions : on garde la derniere.
        labels_dedup AS (
          SELECT proj, rt, wl, cluster, ns, labels FROM (
            SELECT *, ROW_NUMBER() OVER (
              PARTITION BY proj, rt, wl, cluster, ns
              ORDER BY update_time DESC) AS rn
            FROM labels_src WHERE wl IS NOT NULL
          ) WHERE rn = 1
        ),
        deployees AS (
          SELECT DISTINCT repository_name AS repo, image_name AS img,
            image_tags AS tags,
            REGEXP_EXTRACT(image_digest, r"(sha256:[a-f0-9]{{64}})") AS dig
          FROM {VUE}
          WHERE deployed_status = "DEPLOYED" __PERIODE__
        )
        SELECT d.repo, d.img, d.tags,
          r.project_id AS proj,
          r.runtime_type AS rt,
          r.workload_name AS wl,
          r.location AS loc,
          IFNULL(r.cluster_name, "") AS cluster,
          IFNULL(r.namespace_name, "") AS ns,
          IFNULL(REGEXP_EXTRACT(SPLIT(r.runtime_image, "@")[OFFSET(0)],
                                r":([^:/]+)$"), "") AS tag,
          IFNULL(l.labels, "") AS labels
        FROM deployees d
        JOIN `{DATASET}.v_runtime_org_images_all` r
          ON REGEXP_EXTRACT(r.image_digest, r"(sha256:[a-f0-9]{{64}})") = d.dig
        LEFT JOIN labels_dedup l
          ON l.proj = r.project_id
         AND l.rt = r.runtime_type
         AND l.wl = r.workload_name
         AND l.cluster = IFNULL(r.cluster_name, "")
         AND l.ns = IFNULL(r.namespace_name, "")
        GROUP BY 1,2,3,4,5,6,7,8,9,10,11
        ORDER BY d.repo, d.img, proj, wl
    """,
}

ENTIERS = {"nb", "fix", "img", "cve", "c", "h", "crit", "wl",
           "images_totales", "lignes_brutes"}


# --------------------------------------------------------------------------
# Acces BigQuery
# --------------------------------------------------------------------------

class ErreurBQ(Exception):
    pass


def lancer_bq(sql):
    """Execute une requete et renvoie une liste de dicts."""
    cmd = ["cmd", "/c", "bq"] if os.name == "nt" else ["bq"]
    cmd += [f"--project_id={PROJET}", "query", f"--location={LOCATION}",
            "--use_legacy_sql=false", "--format=json", "--quiet",
            "--max_rows=5000"]
    try:
        r = subprocess.run(cmd, input=sql, capture_output=True,
                           text=True, encoding="utf-8", timeout=180)
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


def lien_console(ligne):
    """URL Cloud Console du workload, ou chaine vide si non constructible."""
    proj = ligne.get("proj") or ""
    nom = ligne.get("wl") or ""
    loc = ligne.get("loc") or ""
    if not proj or not nom:
        return ""
    if ligne.get("rt") == "GKE_POD":
        cluster, ns = ligne.get("cluster") or "", ligne.get("ns") or ""
        if not (cluster and ns and loc):
            return f"{CONSOLE}/kubernetes/workload/overview?project={proj}"
        return (f"{CONSOLE}/kubernetes/pod/{loc}/{cluster}/{ns}/{nom}"
                f"/details?project={proj}")
    if not loc:
        return f"{CONSOLE}/run?project={proj}"
    return f"{CONSOLE}/run/detail/{loc}/{nom}/metrics?project={proj}"


def construire_donnees(periode=PERIODE_DEFAUT):
    """Lance toutes les requetes en parallele et assemble le payload."""
    debut = time.time()
    resultats, erreurs = {}, {}
    clause = clause_periode(periode)

    def executer(item):
        nom, sql = item
        try:
            resultats[nom] = lancer_bq(sql.replace(MARQUEUR, clause))
        except ErreurBQ as exc:
            erreurs[nom] = str(exc)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(executer, REQUETES.items()))

    if erreurs:
        raise ErreurBQ("; ".join(f"[{k}] {v}" for k, v in erreurs.items()))

    meta = (resultats["meta"] or [{}])[0]
    matrice = resultats["matrice"]
    actives = sum(l["nb"] for l in matrice)

    workloads = []
    for l in resultats["workloads"]:
        labels = nettoyer_labels(l.get("labels"))
        workloads.append({
            "repo": l["repo"], "img": l["img"],
            "tags": l.get("tags") or "NO_TAG_FOUND",
            "proj": l["proj"], "rt": l["rt"], "wl": l["wl"],
            "loc": l.get("loc") or "", "cluster": l.get("cluster") or "",
            "ns": l.get("ns") or "", "tag": l.get("tag") or "",
            "labels": labels,
            "env": labels.get("environment", ""),
            "prod": est_prod_workload(l["proj"], labels),
            "url": lien_console(l),
        })

    # Le comptage de workloads de la vue whole_picture porte sur des chaines
    # deja concatenees : on recompte sur les workloads reels.
    par_runtime = {}
    for w in workloads:
        par_runtime.setdefault(w["rt"], set()).add((w["proj"], w["wl"]))

    donnees = {
        "meta": {
            "dernier_scan": meta.get("dernier_scan") or "-",
            "images_totales": meta.get("images_totales") or 0,
            "lignes_brutes": meta.get("lignes_brutes") or 0,
            "date_min": meta.get("date_min") or "-",
            "actives": actives,
            "recupere_a": datetime.now().strftime("%H:%M:%S"),
            "duree": round(time.time() - debut, 1),
            "periode": periode,
            "periode_nom": PERIODES.get(periode, PERIODES[PERIODE_DEFAUT])[0],
            "periodes": [{"id": k, "nom": v[0]} for k, v in PERIODES.items()],
        },
        "matrice": matrice,
        "runtime": [
            {"nom": "Cloud Run" if l["nom"] == "CLOUD_RUN_REVISION"
                    else "GKE" if l["nom"] == "GKE_POD" else l["nom"],
             "nb": l["nb"], "crit": l["crit"], "img": l["img"],
             "wl": len(par_runtime.get(l["nom"], ()))}
            for l in resultats["runtime"]
        ],
        "workloads": workloads,
        "tendance": resultats["tendance"],
        "paquets": resultats["paquets"],
        "cves": resultats["cves"],
        "worklist": [
            {**l, "wl": l.get("wl") or "", "proj": l.get("proj") or "",
             "url": l.get("url") or "", "dig": l.get("dig") or "",
             "tags": l.get("tags") or "NO_TAG_FOUND"}
            for l in resultats["worklist"]
        ],
    }
    return donnees


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
        self.end_headers()
        self.wfile.write(donnees)

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

        if chemin != "/":
            self._envoyer("Not found", 404, "text/plain")
            return

        try:
            if forcer:
                print("  Interrogation de BigQuery...")
            donnees, cache = obtenir_donnees(forcer, periode)
            if not cache:
                print(f"  [{donnees['meta']['periode_nom']}] "
                      f"{len(donnees['worklist'])} images deployees "
                      f"({donnees['meta']['duree']} s)")
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


def ouvrir_serveurs(port):
    """Ecoute sur les deux boucles locales, et seulement celles-ci.

    Sous Windows `localhost` resout ::1 avant 127.0.0.1 : un serveur IPv4
    seul fait patienter ~2 s le temps que le navigateur bascule. On sert
    donc aussi ::1, sans jamais s'exposer sur le reseau.
    """
    principal = Serveur(("127.0.0.1", port), Handler)  # doit reussir
    secondaires = []
    try:
        secondaires.append(ServeurV6(("::1", port), Handler))
    except OSError:
        pass  # pas d'IPv6 sur cette machine : 127.0.0.1 suffit
    for srv in secondaires:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    return principal, secondaires


def main():
    if not os.path.exists(TEMPLATE):
        print(f"ERREUR : {TEMPLATE} est introuvable.")
        sys.exit(1)

    url = f"http://127.0.0.1:{PORT}/"
    print()
    print("  Console de triage des vulnerabilites")
    print(f"  Projet : {PROJET}  ({LOCATION})")
    print(f"  -> {url}")
    print("  Ctrl+C pour arreter.")
    print()

    try:
        serveur, secondaires = ouvrir_serveurs(PORT)
    except OSError as exc:
        print(f"  Impossible d'ouvrir le port {PORT} : {exc}")
        print(f"  Essayez : python app.py {PORT + 1}")
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
