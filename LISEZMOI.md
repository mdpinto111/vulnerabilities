# Console de triage des vulnérabilités

Application locale qui interroge BigQuery en direct et affiche l'état des
vulnérabilités SCC du projet `my-gcp-project`.

## Démarrer

Double-cliquer sur **`lancer.bat`**, ou en ligne de commande :

```
python app.py
```

Le navigateur s'ouvre sur <http://127.0.0.1:8787/>. Pour un autre port :
`python app.py 9000`.

Arrêter avec `Ctrl+C`.

## Prérequis

Rien à installer : uniquement Python (déjà présent) et la CLI `bq` du Cloud SDK
(déjà installée et authentifiée). L'app n'utilise que la bibliothèque standard.

Si l'authentification a expiré, l'app affiche une page d'erreur explicite :

```
gcloud auth login
```

L'accès en **lecture seule** suffit — aucune vue n'est créée dans BigQuery.

## Comment ça marche

Au chargement, sept requêtes partent en parallèle vers BigQuery (environ 10 s au
total). Le résultat est gardé en cache **10 minutes** : les rechargements de page
sont instantanés pendant ce laps de temps.

Le bouton **Rafraîchir** en haut force une nouvelle interrogation. La barre d'état
indique si les chiffres affichés viennent du cache ou d'une requête fraîche.

Pour changer la durée du cache, modifier `TTL` en haut de `app.py`.

## Ce que montre l'écran

Le tri repose sur une seule question : **l'image tourne-t-elle réellement ?**
La vue `v_today_vulnerabilities_whole_picture` croise les findings SCC avec
l'inventaire des workloads Cloud Run et GKE, ce qui sépare les vulnérabilités
réellement exposées des anciens builds dormants.

| Section | Ce qu'elle répond |
|---|---|
| Verdict | Combien de failles sont réellement exposées, et combien dorment |
| Le levier principal | Quels paquets corriger pour éliminer le plus de failles d'un coup |
| Rythme des découvertes | Le flux entrant que la remédiation doit absorber |
| Plan de travail | Une ligne par image déployée = un rebuild à planifier |

### Recherche

Le champ au-dessus du plan de travail filtre les images **instantanément**, sans
requête. Il cherche dans tout ce qui identifie une image et ses déploiements :

nom d'image, dépôt, tags, projet, workload, cluster, namespace, **clés et valeurs
de labels**, paquets vulnérables et identifiants CVE.

Plusieurs mots s'additionnent — `openssl prod` ne garde que les images touchées
par openssl **et** déployées en production. Les correspondances sont surlignées,
y compris dans le détail déplié. `Échap` efface la recherche.

Exemples : `fileupload-prod` (label `environment`), `owner_email`, `elastic`,
`CVE-2026-8376`, `my-gke-project`.

### Période

Le sélecteur **Dernier signalement**, en haut à droite, restreint les chiffres aux
vulnérabilités signalées par SCC pendant la fenêtre choisie : 1 min, 1 h, 24 h,
7 jours, 30 jours, ou Tout (par défaut).

> ⚠️ **Ce filtre répond à « quoi de neuf », pas à « qu'est-ce qui reste ».**
> La vue est dédoublonnée : `event_time` y est la date du *dernier signalement*
> d'une vulnérabilité, pas sa découverte. SCC réémettant ses findings par vagues,
> une fenêtre courte peut renvoyer **zéro** alors que le parc reste vulnérable.
> Un bandeau le rappelle dès qu'une période est active, et le cas « zéro » est
> explicitement signalé. Pour l'état réel du parc, restez sur **Tout**.

Changer de période relance les requêtes côté serveur ; chaque période a son propre
cache. Le graphique des découvertes reste sur 30 jours, indépendamment du choix.

### Détail des déploiements

**Cliquer une ligne du plan de travail** déplie le détail de l'image : un bloc par
projet, avec le runtime (Cloud Run, ou GKE avec cluster et namespace), et pour
chaque workload :

- son **nom en lien direct** vers la Cloud Console (service Cloud Run, ou pod GKE) ;
- ses **labels GCP** sous forme de puces — `environment` en premier et mis en
  évidence, puis les autres (`owner_email`, `department`, `app.kubernetes.io/name`,
  `product_name`…) ;
- la référence d'image : tag, ou mention « par digest ».

Les workloads de production sont signalés par un badge rouge **PROD**, repris sur
la ligne de l'image et dans les indicateurs du haut. Un filtre
**Production seulement** isole les images concernées.

### D'où viennent ces données

| Donnée | Source |
|---|---|
| Correspondance image → workload | `v_runtime_org_images_all` |
| Labels GCP | `assets_org_runtime`, champ `resource.data` (JSON brut de Cloud Asset Inventory) |

La vue `whole_picture` ne convient pas ici : elle concatène workloads et projets
en une seule chaîne, ce qui perd la correspondance workload → projet. Et aucune
vue n'expose les labels — il faut les lire dans le JSON de l'export CAI.

Les labels posés par la plateforme (`serving.knative.dev/*`, `run.googleapis.com/*`,
`pod-template-hash`, `goog-*`…) sont filtrés : seuls restent ceux posés par vos
équipes. La liste est dans `LABELS_SYSTEME` et `LABELS_IGNORES`, en haut de
`app.py`.

## Fichiers

| Fichier | Rôle |
|---|---|
| `app.py` | Serveur local, requêtes BigQuery, cache |
| `app_tpl.html` | Gabarit de la page (styles, graphiques, tableau) |
| `lancer.bat` | Lanceur Windows |
| `looker_studio_query.sql` | Variante Looker Studio, si vous voulez un tableau partageable |
| `dashboard.html` | Export statique figé (instantané du 17/09/2026) |

## Limites connues

- Seules les sévérités **CRITICAL** et **HIGH** remontent : SCC n'exporte pas les
  sévérités inférieures vers BigQuery.
- Le badge **PROD** s'appuie d'abord sur le label `environment` du workload, et
  retombe sur le nom du projet quand ce label est absent (`est_prod_workload()`
  dans `app.py`). Seuls **24 workloads sur 81** portent ce label : pour les
  autres, la classification reste une heuristique de nommage.
- Les labels métier sont inégalement posés : 46 workloads sur 81 en ont au moins
  un, et seulement 2 portent `owner_email` / `department`. Généraliser ces deux
  labels rendrait l'attribution des correctifs beaucoup plus directe.
- Les pods GKE portent un nom à suffixe aléatoire : un même déploiement apparaît
  en plusieurs lignes (dix pods `elastic-agent-*`, par exemple).
- L'app écoute uniquement sur les boucles locales (`127.0.0.1` et `::1`), elle
  n'est donc pas accessible depuis le réseau. Pour la partager, passer par
  Looker Studio.
