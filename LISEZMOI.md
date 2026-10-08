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

### Consulter depuis un téléphone

Double-cliquer sur **`lancer-reseau.bat`** (ou `python app.py --lan`). L'app
écoute alors sur tout le réseau local au lieu de la seule boucle locale, et
affiche au démarrage l'adresse à saisir dans le navigateur du téléphone, du
type `http://192.168.1.50:8787/`. Le téléphone doit être sur le même Wi-Fi.

Si la page ne s'ouvre pas, le pare-feu Windows bloque le port. À lancer une
fois dans un terminal administrateur :

```
netsh advfirewall firewall add rule name="Console vulnerabilites 8787" dir=in action=allow protocol=TCP localport=8787
```

> ⚠️ **En mode `--lan`, l'app n'a aucune authentification.** Toute machine du
> réseau qui connaît l'adresse voit la cartographie complète des
> vulnérabilités non corrigées. À réserver à un réseau de confiance, et à
> couper (`Ctrl+C`) dès que vous avez fini. Le mode par défaut, lui, reste
> inaccessible depuis l'extérieur de ce poste.

La mise en page s'adapte à l'écran : sous 680 px, les colonnes CVE,
Corrigeables et Registry disparaissent du tableau — le détail déplié les
redonne intégralement.

## Prérequis

Rien à installer : uniquement Python (déjà présent) et le Cloud SDK, dont les
CLI `bq` et `gcloud` (déjà installées et authentifiées). L'app n'utilise que la
bibliothèque standard.

`gcloud` sert à deux choses : obtenir un jeton d'accès, puis interroger en HTTP
les API Cloud Run et Artifact Registry. Le jeton n'est jamais écrit sur disque.

Si l'authentification a expiré, l'app affiche une page d'erreur explicite :

```
gcloud auth login
```

L'accès en **lecture seule** suffit — aucune vue n'est créée dans BigQuery.

## Comment ça marche

Le chargement se fait en deux temps, pour environ **20 à 25 s** au total :

1. BigQuery livre l'inventaire et les métadonnées pendant que l'API Cloud Run
   est interrogée en direct, projet par projet, pour savoir quelle révision
   sert le trafic maintenant et quelle image exacte elle exécute.
2. Les findings SCC sont ensuite comptés **en restreignant la requête aux seuls
   digests réellement en exécution**.

Artifact Registry est enfin interrogé pour retrouver le numéro de version de
chaque image concernée. Le résultat est gardé en cache **10 minutes** : les
rechargements de page sont instantanés pendant ce laps de temps.

Le bouton **Rafraîchir** en haut force une nouvelle interrogation. La barre d'état
indique si les chiffres affichés viennent du cache ou d'une requête fraîche.

Pour changer la durée du cache, modifier `TTL` en haut de `app.py`.

## Ce que montre l'écran

Le tri repose sur une seule question : **l'image tourne-t-elle réellement ?**
Les findings SCC sont croisés avec ce qui s'exécute aujourd'hui, ce qui sépare
les vulnérabilités réellement exposées des anciens builds dormants.

Un bandeau sous les filtres rappelle en permanence d'où vient ce périmètre :
combien de services Cloud Run ont été relus en direct, à quelle date s'arrête
l'inventaire qui couvre GKE, et combien de services que cet inventaire liste
encore n'existent plus.

| Section | Ce qu'elle répond |
|---|---|
| Verdict | Combien de failles sont réellement exposées, et combien dorment |
| Le levier principal | Quels paquets corriger pour éliminer le plus de failles d'un coup |
| Rythme des découvertes | Le flux entrant que la remédiation doit absorber |
| Plan de travail | Une ligne par image déployée = un rebuild à planifier |

### Une version plus saine existe-t-elle ?

Quand Artifact Registry publie, **après** celle en service, une version que SCC
trouve **moins vulnérable**, une puce verte le signale sur la ligne :

```
mon-api :1.0.8   [:1.0.9 dispo : 2C / 7H]
```

L'infobulle donne le détail et la date de publication. Un bouton
**Version plus saine disponible** filtre le plan de travail sur ces images ; il
n'apparaît que s'il y a au moins un cas, un filtre toujours vide n'apprenant rien.

La comparaison n'a de sens que si elle est prudente, donc elle ne retient que des
images **réellement exécutables et réellement analysées** :

- les **index** sont écartés. Une publication multi-architecture dépose plusieurs
  objets sous un même numéro, et SCC les analyse séparément : sur une image
  observée, l'index remontait 0 critique et 7 élevées là où le conteneur qu'il
  référence en portait 2 et 9. Comparer à l'index annoncerait un progrès
  imaginaire.
- les **attestations** (quelques kilo-octets, SBOM et provenance) sont écartées de
  même ;
- une version **absente des findings** n'est jamais présentée comme meilleure :
  elle peut être saine comme n'avoir jamais été scannée, et rien ne permet de
  trancher depuis ces données.

La comparaison porte sur les seules sévérités exportées par SCC, **CRITICAL et
HIGH**, et ignore la période sélectionnée — sans quoi elle dépendrait de la
fenêtre d'affichage.

### Recherche

Le champ au-dessus du plan de travail filtre les images **instantanément**, sans
requête. Il cherche dans tout ce qui identifie une image et ses déploiements :

nom d'image et chemin complet du dépôt, **numéro de version**, digest, projet,
workload, **révision Cloud Run**, cluster, namespace, **clés et valeurs de
labels**, paquets vulnérables et identifiants CVE.

Plusieurs mots s'additionnent — `openssl prod` ne garde que les images touchées
par openssl **et** déployées en production. Les correspondances sont surlignées,
y compris dans le détail déplié. `Échap` efface la recherche.

Exemples : `fileupload-prod` (label `environment`), `owner_email`, `elastic`,
`CVE-2026-8376`, `my-gke-project`, `2.30.0` (numéro de version).

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
- un lien **image dans le registre** vers la page Artifact Registry du **digest
  exact** — de là, l'onglet *Vulnerabilities & Malicious Packages* donne le
  détail côté Google ;
- la **référence exacte de l'image qu'il exécute** : chemin complet du dépôt,
  numéro de version, et digest tronqué — c'est ce qui tourne, pas ce que le
  registre contient ;
- la **révision Cloud Run** (ou le pod GKE) qui porte cette image, et un lien
  **config Cloud Run** vers l'onglet Révisions de la console, où figure la même
  référence d'image côté Google ;
- un marqueur de provenance : **en direct** quand l'information vient de l'API
  Cloud Run, **inventaire** quand elle vient de l'export Cloud Asset et porte
  donc la date de cet export ;
- ses **labels GCP** sous forme de puces — `environment` en premier et mis en
  évidence, puis les autres (`owner_email`, `department`, `app.kubernetes.io/name`,
  `product_name`…).

La version affichée est celle sous laquelle **Artifact Registry publie ce digest
aujourd'hui**, pas la chaîne figée dans le gabarit du service Cloud Run. Les deux
ne disent pas la même chose, et c'est la source de confusion la plus coûteuse :
la console Cloud Run montre l'image du **gabarit**, alors que le trafic peut être
servi par une **révision antérieure** qui exécute autre chose.

Quand c'est le cas, une puce rouge **`révision :X prête, sans trafic`** apparaît à
côté de la version réelle, et le détail déplié affiche les deux faits côte à
côte : l'image du gabarit — celle que montre le champ *Container image URL* de la
console — et la révision qui la porte, avec sa part de trafic. Le correctif est alors publié et même déployé, mais il
ne reçoit rien — c'est exactement le genre de situation qu'un tableau de bord doit
faire remonter. La détection compare la révision qui sert le trafic à
`latestCreatedRevisionName`, et non à `latestReadyRevisionName` : une révision mise
au repos repasse en `Retired` et cesse de compter comme « prête » tout en portant
la dernière image publiée.

Une seconde puce, **`gabarit :X, non confirmé`**, signale le cas plus rare où le
gabarit réclame un tag que le registre n'associe plus à ce conteneur, sans qu'une
révision plus récente soit en cause.

La résolution suit les images **multi-architecture**. Le tag n'est pas posé sur le
conteneur mais sur l'index qui le référence ; le digest qu'exécute une révision
est celui de l'enfant `linux/amd64`, auquel Artifact Registry n'attache aucun tag.
L'app remonte donc à l'index parent, via l'API registre Docker v2, pour nommer ce
qui tourne. Sans cette remontée, la quasi-totalité des images apparaîtrait « sans
version ».

Les workloads de production sont signalés par un badge rouge **PROD**, repris sur
la ligne de l'image et dans les indicateurs du haut. Un filtre
**Production seulement** isole les images concernées.

### D'où viennent ces données

| Donnée | Source |
|---|---|
| Services Cloud Run en exécution | API Cloud Run, interrogée en direct à chaque chargement |
| Pods GKE en exécution | `assets_org_runtime`, pods `Running` ou `Pending` |
| Numéro de version d'une image | API Artifact Registry, puis manifestes du registre Docker v2 pour les images multi-architecture |
| Versions publiées d'une image | API Artifact Registry, `packages/*/versions` (digest, date de création, tags, type et taille) |
| Labels GCP | `assets_org_runtime`, champ `resource.data` (JSON brut de Cloud Asset Inventory) |
| Vulnérabilités | `v_today_vulnerabilities_whole_picture` |

Le champ `deployed_status` de la vue n'est **pas** utilisé, et `v_runtime_org_images_all`
ne sert plus que de repli. Les deux répondent « déployé » dès qu'un digest
apparaît quelque part dans l'inventaire — or cet inventaire garde toutes les
révisions Cloud Run jamais créées, retirées comprises : **1973 des 2114 révisions
du parc portent la condition `Active = Retired`**. S'y fier impute à un service
qui tourne aujourd'hui les CVE d'un build abandonné depuis des mois.

Trois filtres corrigent cela :

1. les révisions Cloud Run retirées et les pods `Succeeded`/`Failed` sont exclus
   côté SQL ;
2. pour Cloud Run, l'API fait ensuite autorité : seule la révision qui sert le
   trafic compte, avec le digest qu'elle exécute vraiment ;
3. un service que l'inventaire liste encore mais que l'API ne renvoie plus a été
   supprimé ou déplacé : il est écarté, et compté dans le bandeau.

L'inventaire n'est conservé comme repli que pour un projet dont l'API n'a pas pu
être lue — le bandeau le signale alors nommément.

La vue `whole_picture` ne convient pas non plus pour le détail : elle concatène
workloads et projets en une seule chaîne, ce qui perd la correspondance
workload → projet. Et aucune vue n'expose les labels — il faut les lire dans le
JSON de l'export CAI.

Les labels posés par la plateforme (`serving.knative.dev/*`, `run.googleapis.com/*`,
`pod-template-hash`, `goog-*`…) sont filtrés : seuls restent ceux posés par vos
équipes. La liste est dans `LABELS_SYSTEME` et `LABELS_IGNORES`, en haut de
`app.py`.

## Fichiers

| Fichier | Rôle |
|---|---|
| `app.py` | Serveur local, requêtes BigQuery, sondes Cloud Run et Artifact Registry, cache |
| `app_tpl.html` | Gabarit de la page (styles, graphiques, tableau) |
| `lancer.bat` | Lanceur Windows |
| `lancer-reseau.bat` | Lanceur Windows, accessible depuis le réseau local |
| `looker_studio_query.sql` | Variante Looker Studio, si vous voulez un tableau partageable |
| `dashboard.html` | Export statique figé (instantané du 17/09/2026) |

## Limites connues

- Seules les sévérités **CRITICAL** et **HIGH** remontent : SCC n'exporte pas les
  sévérités inférieures vers BigQuery.
- **Le volet GKE reste daté.** Cloud Run est relu en direct, mais aucune API
  équivalente n'est interrogée pour les pods : ils viennent de l'export Cloud
  Asset Inventory, dont la date est affichée dans le bandeau. Un pod redéployé
  depuis n'y figure pas. Rafraîchir cet export est la seule façon de corriger ce
  décalage.
- **Un numéro de version peut manquer.** Si un digest n'est référencé par aucun
  index tagué — image purgée, tag supprimé — la ligne affiche « version non
  étiquetée » et le digest, qui reste exact.
- **Les compteurs d'Artifact Registry ne correspondront jamais exactement.** La
  console compte toutes les sévérités, SCC n'exporte que CRITICAL et HIGH. Le
  lien mène en revanche bien au **même digest**, ce qui rend les deux listes
  comparables ligne à ligne.
- Le badge **PROD** s'appuie d'abord sur le label `environment` du workload, et
  retombe sur le nom du projet quand ce label est absent (`est_prod_workload()`
  dans `app.py`). Seuls **37 workloads sur 86** portent ce label : pour les
  autres, la classification reste une heuristique de nommage.
- Les labels métier sont inégalement posés : 59 workloads sur 86 en ont au moins
  un, et seulement 3 portent `owner_email` / `department`. Généraliser ces deux
  labels rendrait l'attribution des correctifs beaucoup plus directe.
- Les pods GKE portent un nom à suffixe aléatoire : un même déploiement apparaît
  en plusieurs lignes (dix pods `elastic-agent-*`, par exemple).
- Par défaut l'app écoute uniquement sur les boucles locales (`127.0.0.1` et
  `::1`). `--lan` l'ouvre au réseau local, sans authentification : pour un
  partage durable, passer plutôt par Looker Studio.
