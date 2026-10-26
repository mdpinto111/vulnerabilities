# Vulnerability triage console

Local application that queries BigQuery live and shows the state of the SCC
vulnerabilities of the `my-gcp-project` project.

## Getting started

Double-click **`lancer.bat`**, or from the command line:

```
python app.py
```

The browser opens on <http://127.0.0.1:8787/>. For another port:
`python app.py 9000`.

Stop with `Ctrl+C`.

### Viewing from a phone

Double-click **`lancer-reseau.bat`** (or `python app.py --lan`). The app then
listens on the whole local network instead of the loopback only, and prints at
startup the address to type in the phone's browser, such as
`http://192.168.1.50:8787/`. The phone must be on the same Wi-Fi.

If the page does not open, the Windows firewall is blocking the port. Run once
in an administrator terminal:

```
netsh advfirewall firewall add rule name="Vulnerability console 8787" dir=in action=allow protocol=TCP localport=8787
```

> ⚠️ **In `--lan` mode, the app has no authentication.** Any machine on the
> network that knows the address sees the full map of unpatched
> vulnerabilities. Keep it to a trusted network, and stop it (`Ctrl+C`) as
> soon as you are done. The default mode stays unreachable from outside this
> machine.

The layout adapts to the screen: below 680 px, the CVE, Fixable and Registry
columns disappear from the table — the expanded detail shows them in full.

## Prerequisites

Nothing to install: only Python (already there) and the Cloud SDK, with its
`bq` and `gcloud` CLIs (already installed and authenticated). The app only uses
the standard library.

`gcloud` is used for two things: getting an access token, then querying the
Cloud Run and Artifact Registry APIs over HTTP. The token is never written to
disk.

If authentication has expired, the app shows an explicit error page:

```
gcloud auth login
```

**Read-only** access is enough — no view is created in BigQuery.

## How it works

Loading happens in two steps, for about **20 to 25 s** in total:

1. BigQuery delivers the inventory and the metadata while the Cloud Run API
   is queried live, project by project, to find out which revision serves
   traffic right now and which exact image it runs.
2. SCC findings are then counted **by restricting the query to the digests
   actually running**.

Artifact Registry is finally queried to find the version number of each image
concerned. The result is cached for **10 minutes**: page reloads are instant
during that time.

The **Refresh** button at the top forces a new query. The status bar tells
whether the figures shown come from the cache or from a fresh query.

To change the cache duration, edit `TTL` at the top of `app.py`.

## What the screen shows

Sorting relies on a single question: **is the image really running?**
SCC findings are cross-checked with what runs today, which separates the
vulnerabilities really exposed from old dormant builds.

A banner below the filters always recalls where this scope comes from: how
many Cloud Run services were re-read live, on which date the inventory covering
GKE stops, and how many services this inventory still lists no longer exist.

| Section | What it answers |
|---|---|
| Verdict | How many flaws are really exposed, and how many are dormant |
| The main lever | Which packages to fix to remove the most flaws at once |
| Discovery rate | The incoming flow remediation has to absorb |
| Work plan | One row per deployed image = one rebuild to plan |

### Is there a cleaner version?

When Artifact Registry publishes, **after** the one in service, a version that
SCC finds **less vulnerable**, a green badge flags it on the row:

```
my-api :1.0.8   [:1.0.9 available: 2C / 7H]
```

The tooltip gives the details and the publication date. A **Cleaner version
available** button filters the work plan on these images; it only appears if
there is at least one case, since an always-empty filter tells nothing.

The comparison only makes sense if it is careful, so it only keeps images that
are **actually runnable and actually analyzed**:

- **indexes** are excluded. A multi-architecture push stores several objects
  under the same version, and SCC analyzes them separately: on one observed
  image, the index reported 0 critical and 7 high where the container it
  references carried 2 and 9. Comparing with the index would announce
  imaginary progress.
- **attestations** (a few kilobytes, SBOM and provenance) are excluded too;
- a version **missing from the findings** is never presented as better: it may
  be clean or never scanned, and nothing in this data can tell.

The comparison only covers the severities SCC exports, **CRITICAL and HIGH**,
and ignores the selected period — otherwise it would depend on the display
window.

### Search

The field above the work plan filters the images **instantly**, without a
query. It searches everything that identifies an image and its deployments:

image name and full repository path, **version number**, digest, project,
workload, **Cloud Run revision**, cluster, namespace, **label keys and
values**, vulnerable packages and CVE IDs.

Several words add up — `openssl prod` only keeps the images affected by
openssl **and** deployed in production. Matches are highlighted, including in
the expanded detail. `Esc` clears the search.

Examples: `fileupload-prod` (`environment` label), `owner_email`, `elastic`,
`CVE-2026-8376`, `my-gke-project`, `2.30.0` (version number).

### Period

The **Last reported** selector, at the top right, restricts the figures to the
vulnerabilities reported by SCC during the chosen window: 1 min, 1 h, 24 h,
7 days, 30 days, or All (default).

> ⚠️ **This filter answers "what's new", not "what's left".**
> The view is deduplicated: `event_time` there is the date of the *last report*
> of a vulnerability, not its discovery. Since SCC re-emits its findings in
> waves, a short window can return **zero** while the fleet is still
> vulnerable. A banner recalls it as soon as a period is active, and the
> "zero" case is flagged explicitly. For the real state of the fleet, stay on
> **All**.

Changing the period reruns the queries on the server side; each period has its
own cache. The discovery chart stays on 30 days, whatever the choice.

### Deployment details

**Clicking a row of the work plan** expands the image's detail: one block per
project, with the runtime (Cloud Run, or GKE with cluster and namespace), and
for each workload:

- its **name as a direct link** to the Cloud Console (Cloud Run service, or
  GKE pod);
- an **image in the registry** link to the Artifact Registry page of the
  **exact digest** — from there, the *Vulnerabilities & Malicious Packages*
  tab gives Google's details;
- the **exact reference of the image it runs**: full repository path, version
  number, and truncated digest — this is what runs, not what the registry
  contains;
- the **Cloud Run revision** (or GKE pod) carrying this image, and a **Cloud
  Run config** link to the console's Revisions tab, where the same image
  reference appears on Google's side;
- a provenance marker: **live** when the information comes from the Cloud Run
  API, **inventory** when it comes from the Cloud Asset export and therefore
  carries that export's date;
- its **GCP labels** as chips — `environment` first and highlighted, then the
  others (`owner_email`, `department`, `app.kubernetes.io/name`,
  `product_name`…).

The version shown is the one under which **Artifact Registry publishes this
digest today**, not the string frozen in the Cloud Run service template. The
two don't say the same thing, and this is the most costly source of confusion:
the Cloud Run console shows the **template's** image, while traffic may be
served by an **earlier revision** running something else.

When that happens, a red **`revision :X ready, no traffic`** badge appears next
to the real version, and the expanded detail shows both facts side by side:
the template's image — the one shown in the console's *Container image URL*
field — and the revision carrying it, with its share of traffic. The fix is
then published and even deployed, but receives nothing — exactly the kind of
situation a dashboard must surface. Detection compares the revision serving
traffic with `latestCreatedRevisionName`, not with `latestReadyRevisionName`:
an idled revision goes back to `Retired` and stops counting as "ready" while
still carrying the latest published image.

A second badge, **`template :X, not confirmed`**, flags the rarer case where
the template asks for a tag the registry no longer associates with this
container, with no more recent revision involved.

Resolution follows **multi-architecture** images. The tag is not set on the
container but on the index that references it; the digest a revision runs is
that of the `linux/amd64` child, to which Artifact Registry attaches no tag.
The app therefore goes up to the parent index, through the Docker v2 registry
API, to name what runs. Without this, almost every image would show up
"without a version".

Production workloads are flagged with a red **PROD** badge, repeated on the
image row and in the headline indicators. A **Production only** filter
isolates the images concerned.

### Where this data comes from

| Data | Source |
|---|---|
| Running Cloud Run services | Cloud Run API, queried live on every load |
| Running GKE pods | `assets_org_runtime`, `Running` or `Pending` pods |
| Version number of an image | Artifact Registry API, then Docker v2 registry manifests for multi-architecture images |
| Published versions of an image | Artifact Registry API, `packages/*/versions` (digest, creation date, tags, type and size) |
| GCP labels | `assets_org_runtime`, `resource.data` field (raw Cloud Asset Inventory JSON) |
| Vulnerabilities | `v_today_vulnerabilities_whole_picture` |

The view's `deployed_status` field is **not** used, and
`v_runtime_org_images_all` is only a fallback now. Both answer "deployed" as
soon as a digest appears anywhere in the inventory — yet this inventory keeps
every Cloud Run revision ever created, retired ones included: **1973 of the
fleet's 2114 revisions carry the `Active = Retired` condition**. Relying on it
attributes to a service running today the CVEs of a build abandoned months
ago.

Three filters fix this:

1. retired Cloud Run revisions and `Succeeded`/`Failed` pods are excluded on
   the SQL side;
2. for Cloud Run, the API then has the final say: only the revision serving
   traffic counts, with the digest it really runs;
3. a service the inventory still lists but the API no longer returns was
   deleted or moved: it is set aside, and counted in the banner.

The inventory is only kept as a fallback for a project whose API could not be
read — the banner then names it.

The `whole_picture` view does not fit the detail either: it concatenates
workloads and projects into a single string, which loses the workload →
project mapping. And no view exposes labels — they must be read from the JSON
of the CAI export.

Labels set by the platform (`serving.knative.dev/*`, `run.googleapis.com/*`,
`pod-template-hash`, `goog-*`…) are filtered out: only those set by your teams
remain. The list is in `LABELS_SYSTEME` and `LABELS_IGNORES`, at the top of
`app.py`.

## Files

| File | Role |
|---|---|
| `app.py` | Local server, BigQuery queries, Cloud Run and Artifact Registry probes, cache |
| `app_tpl.html` | Page template (styles, charts, table) |
| `lancer.bat` | Windows launcher |
| `lancer-reseau.bat` | Windows launcher, reachable from the local network |
| `looker_studio_query.sql` | Looker Studio variant, if you want a shareable dashboard |
| `dashboard.html` | Frozen static export (snapshot of 2026-09-17) |

## Known limitations

- Only **CRITICAL** and **HIGH** severities come through: SCC does not export
  lower severities to BigQuery.
- **The GKE part stays dated.** Cloud Run is re-read live, but no equivalent
  API is queried for pods: they come from the Cloud Asset Inventory export,
  whose date is shown in the banner. A pod redeployed since is not in it.
  Refreshing that export is the only way to fix this lag.
- **A version number may be missing.** If a digest is referenced by no tagged
  index — purged image, deleted tag — the row shows "untagged version" and the
  digest, which stays exact.
- **Artifact Registry's counters will never match exactly.** The console
  counts every severity, SCC only exports CRITICAL and HIGH. The link does lead
  to the **same digest**, though, which makes the two lists comparable row by
  row.
- The **PROD** badge relies first on the workload's `environment` label, and
  falls back on the project name when that label is missing
  (`est_prod_workload()` in `app.py`). Only **37 of 86 workloads** carry this
  label: for the others, the classification remains a naming heuristic.
- Business labels are unevenly set: 59 of 86 workloads have at least one, and
  only 3 carry `owner_email` / `department`. Generalizing these two labels
  would make assigning fixes much more direct.
- GKE pods have a name with a random suffix: the same deployment shows up on
  several rows (ten `elastic-agent-*` pods, for example).
- By default the app only listens on the loopbacks (`127.0.0.1` and `::1`).
  `--lan` opens it to the local network, without authentication: for lasting
  sharing, use Looker Studio instead.
