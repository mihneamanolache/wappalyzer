# Catalog maintenance

`technologies/*.json` is data consumed by `wappalyzer.js`. The engine reads a
fixed set of fields in a fixed set of shapes and **silently ignores everything
else**. That is the whole reason this document and `scripts/validate.js` exist: a
typo'd field or a wrong-shaped channel produces no error, just a pattern that can
never match.

Before this was enforced, the catalog contained 52 entries with a `script` field
where `scriptSrc` was meant, 28 channels written in a shape the engine skips, 85
duplicate names across letter files, and 6 dangling cross-references that threw
mid-scan. `npm test` now fails on any of these.

## The one rule

**If `npm run validate` reports zero errors, every pattern in the catalog can
fire.** Nothing is silently dropped. Adding a technology means adding an entry
that validates.

## Detection channels

`scripts/lib/channels.js` is the single source of truth. Shapes differ by how the
engine matches them, and using the wrong one is the most common defect.

| Channel | Shape | Matched against |
| --- | --- | --- |
| `scriptSrc` | string or array | each script URL on the page |
| `scripts` | string or array | inline script contents |
| `html` | string or array | the page HTML |
| `css` | string or array | stylesheet rule text |
| `text` | string or array | visible page text |
| `url` | string or array | the page URL |
| `xhr` | string or array | **bare hostnames** the page made requests to |
| `xhrUrl` | string or array | the **full URL** of those same requests |
| `robots` | string or array | `robots.txt` contents |
| `certIssuer` | string or array | the TLS certificate issuer |
| `headers` | `{ "header-name": pattern }` | that response header's value |
| `cookies` | `{ "cookie-name": pattern }` | that cookie's value |
| `meta` | `{ "meta-name": pattern }` | that meta tag's content |
| `dns` | `{ "TXT": pattern }` | that DNS record type |
| `js` | `{ "window.chain": pattern }` | that JS property's value |
| `dom` | selector list, or `{ selector: rule }` | the rendered DOM |
| `probe` | `{ "/path": pattern }` | the body of a request to that path |

### `xhr` versus `xhrUrl`

This distinction is the single easiest way to write a pattern that can never fire.
`xhr` receives a **bare hostname** — `driver.js` does `analyze({ xhr: hostname })`
— so a pattern mentioning a path or a scheme cannot match there:

```jsonc
// WRONG: a hostname never contains a slash, so this is dead
{ "xhr": "/api/2.0/jobs" }
{ "xhr": "https://efs.us-east-1.api.aws/v1" }
// RIGHT
{ "xhrUrl": "/api/2.0/jobs" }
{ "xhr": "efs\.[a-z0-9-]+\.api\.aws" }
```

168 catalog patterns across 85 technologies were written the wrong way and could
never fire. `scripts/lib/normalize.js` now **relocates** them to `xhrUrl` rather
than deleting them, because the intent — "a request to this URL" — is clear and
recoverable. It runs on every merge, since upstream keeps adding them.

`validate.js` reports the remainder: `E_XHR_NOT_A_HOSTNAME` for an unambiguous
path or scheme, `W_XHR_PATH_DEPENDENT` where no hostname-shaped match could be
demonstrated. A slash-free match is treated as proof of life, so a pattern is only
flagged when none can be found.

Two safeguards apply because relocation *wakes a dead pattern up*:

- **The hostname-suffix anchoring is `xhr`-only.** A URL does not end at the
  hostname, so applying it to `xhrUrl` would break every path pattern.
- **An over-broad pattern is dropped, not promoted.** `Microsoft Azure Table
  storage` carried `/(?:Tables|\$metadata|[A-Za-z0-9._%-]+)(?:\?.*)?$`, which
  matches any path. Harmless while dead; a false-positive generator once live. Any
  relocation candidate matching a benign control URL is discarded instead, and
  `test/catalog.test.js` asserts none survives.

Keyed channels (`headers`, `cookies`, `meta`, `dns`, `js`) look the key up
**literally** — `analyzeManyToMany` does `items[key]`. A regex in the key never
matches. The validator warns about this as `W_REGEX_KEY`; it is upstream's
behaviour too, so it is reported rather than rewritten.

An empty pattern in a keyed channel means "this key just has to be present". In a
non-keyed channel an empty pattern matches everything, which is an error.

### Shapes that look right and do nothing

```jsonc
// WRONG: dns is keyed by record type, so an array yields keys "0", "1", ...
{ "dns": ["example.com"] }
// RIGHT
{ "dns": { "CNAME": "example\\.com" } }

// WRONG: scripts is matched against a single value, so an object is skipped
{ "scripts": { "regex": "example" } }
// RIGHT
{ "scripts": "example" }

// WRONG: `content` is not a dom rule
{ "dom": { "meta[name=\"keywords\"]": { "content": "Example" } } }
// RIGHT (and cheaper — no browser needed)
{ "meta": { "keywords": "Example" } }

// WRONG: exists must be an empty pattern; `true` compiles to /true/ and never matches
{ "dom": { ".marker": { "exists": true } } }
// RIGHT, optionally pinning a version to the selector's presence
{ "dom": { ".marker": { "exists": "" } } }
{ "dom": { ".marker": { "exists": "\\;version:2" } } }
```

### DNS record types

Only `cname`, `mx`, `ns`, `soa` and `txt` are resolved by `driver.js`. Any other
`dns` key is an error. DNS requires `--probe`.

## Versions

A version comes from a capture group plus a `\;version:\1` suffix:

```jsonc
{ "scriptSrc": "jquery-([\\d.]+)\\.js\\;version:\\1" }
```

Version detection only works where a version is actually exposed — a filename, a
JS property, a header, a generator tag. It is **not** available for hosted SaaS:
Samsara, for example, ships content-hashed bundles (`app.CllSA3nk.js`) with no
semantic version anywhere in the response. Asking for "product versions" of a
pure SaaS product has no answer from the outside; product *lines* do, and those
are modelled as separate entries with `requires`/`implies`.

## Fork-specific fields

`saas` and `oss` are booleans curated here and surfaced through `resolve()` and
the CLI output. They were previously present in the data but dropped by the
engine.

## Categories

`categories.json` merges upstream's ids with fork-local ones from
`scripts/lib/categories-extra.js`, which start at **200** so upstream can keep
numbering upward without colliding. They split upstream's single "Artificial
Intelligence" bucket into the distinctions the taxonomy request asked for:
generative AI platforms, AI development frameworks, vector databases, AI
infrastructure, data platforms, fleet & telematics, IoT, cloud security, AI
coding assistants, AI agents, workflow automation, observability.

## Evidence standard for new entries

A fingerprint must rest on something checked, not assumed. Four classes are used
for the entries in `scripts/lib/emerging-technologies.js`:

- **`hostname`** — a vendor-owned hostname confirmed to resolve, matched on
  `scriptSrc` or `xhr`. If a page loads or calls that host, the technology is
  genuinely there. Preferred over guessed asset filenames, which go stale.
- **`dns-txt`** — a domain-verification TXT record. This is a **tenant** signal:
  the company completed a domain-ownership check with the vendor. It is not
  evidence that the website embeds anything or that a specific feature is
  enabled. Needs `--probe`.
- **`shipped-markup`** — a pattern taken from the project's own index template
  in its repository, for self-hosted operator UIs (Airflow, Superset, MLflow,
  Argo CD, Metabase, Prometheus, Prefect, Kiali, Ray, Kubeflow, Kubernetes
  Dashboard, OpenShift). These are read from source, not guessed.
- **`badge`** — a status or vulnerability badge image served from the vendor's
  own host (CircleCI, Buildkite, Travis CI, Snyk).
- **`customer-page`** — something the vendor puts on *its customers'* pages: an
  embedded widget, a form iframe, a run-button, a generated-image host, a
  response header, or a tenant link. Added 2026-08-03 and collected in
  `CUSTOMER_VISIBLE` in `scripts/lib/emerging-technologies.js`.

### Whose page is the marker on?

This is the distinction the 2026-08-02 DQ turned into a measurement. 128 of the
154 AI entries never fired across 1.87M crawled domains, and the reason was not
crawl quality:

| Where the marker lives | Fires on a crawl of company root domains? |
| --- | --- |
| The customer's own page (widget, iframe, header, tenant link) | Yes |
| A request the customer's own front end makes (`*.cloudhub.io`) | Yes |
| The vendor's console (`app.pinecone.io`) | Only if the vendor's domain is in the crawl list — once, for the vendor |
| An operator UI on an internal subdomain | Only if subdomains are crawled |
| A back-end API hostname (`\.pinecone\.io`, `\.snowflakecomputing\.com`) | **Never** — the browser does not make that call |

An `xhr` rule is not automatically dead: `hook.eu1.make.com` and
`*.cloudhub.io` are called *by the customer's page*. What is dead is an `xhr`
rule for an API only a server calls. Before adding one, ask which of these rows
it lands in and record the answer in the evidence record's `signal` field.

Where the answer is the last row and nothing else exists — Pinecone, Snowflake,
the EDR agents, local editors — the honest route is the text-signal layer
below, not a pattern that cannot fire.

Every custom entry has an `EVIDENCE` record with a verification level:
`live-observed`, `official-documented`, `unreproduced-prior-sweep`,
`catalog-pattern-only`, or `rejected-marker`. Concrete targets retained during
the audit are in `docs/live-evidence.md`.

### Anchor to markup, never to prose

The single most important rule for the self-hosted UIs. A page that *writes
about* Airflow must not be detected as *running* Airflow, so every pattern is
anchored to a `<title>` element or a unique id/class from the shipped template:

```jsonc
// WRONG: matches any blog post about the tool
{ "html": "Apache Airflow" }
// RIGHT: only matches the tool serving its own UI
{ "html": ["<title>\\s*Airflow\\s*</title>", "href=\"/static/pin_32\\.png\""] }
```

`test/emerging-technologies.test.js` asserts this directly: a paragraph naming nine
of these tools detects none of them.

Also avoid a link to a vendor's site as evidence of using it. Linking to a GitHub
repository is not evidence of running on GitHub. The exception is a link that
only exists because of a tenant, such as a `*.myworkdayjobs.com` careers link.

## Two tiers, and why they are separate

The report distinguishes **mapped** from **catalog-matchable**, and they are different
numbers on purpose:

| | Count | Meaning |
| --- | --- | --- |
| Mapped onto the catalog | 402/402 (100%) | Every requested product has a catalog entry with a category, description, vendor and website. The taxonomy is complete. |
| Catalog-matchable | 387/402 (96%) | The entry has a detection path that passes synthetic tests. This is not empirical live-scan coverage. |

The 15-product gap is carried as **taxonomy-only** entries (`CATALOG_ONLY` in
`scripts/lib/emerging-technologies.js`). They have full metadata and no detection
channel, so the mapping is complete without the coverage figure being inflated by
patterns that can never match. `npm test` asserts both properties.

## The text-mined signal layer

`scripts/lib/text-signals.js` is a **second, lower-confidence source** that
reaches technologies which emit nothing observable. Companies write about the
tools they run, most reliably on their careers pages: "5+ years administering
CrowdStrike Falcon" is good evidence, even though nothing on the website will
ever say so.

It is deliberately kept apart from the pattern catalog:

| | Catalog (`technologies`) | Text signals (`signals`) |
| --- | --- | --- |
| Answers | "this page is running X" | "this company appears to use X" |
| Standard | zero false positives | an explicit inference |
| Confidence | 100 by default | 30 |
| Carries | pattern match | the sentence it came from |

They must not be merged — a hiring signal is not a detection, and reporting it as
one would destroy the catalog's precision. `driver.js` returns them in a separate
`signals` array, off by default:

```javascript
const wappalyzer = new Wappalyzer({ textSignals: true, recursive: true })
// results.technologies -> detections
// results.signals      -> [{ technology, confidence, source, evidence, url }]
```

Two gates must both pass before anything is emitted:

1. **The page must be a job posting or a stated tech stack.** A vendor name in a
   press release or a competitor comparison means nothing.
2. **The vendor must sit inside tooling language** — "experience with",
   "administering", "our stack includes" — not merely appear on the page.

Either gate alone produces false positives. `test/text-signals.test.js` is mostly
negative cases for this reason, including press releases, comparison pages, and
ambiguity guards (Orca the screen reader, MCP the Microsoft certification, "Zed"
without editor context).

The layer was pinned to exactly the taxonomy-only entries until 2026-08-03. The
DQ made that too narrow — an entry whose only pattern matches a back-end API
hostname is, in practice, as unreachable as one with no pattern. It now covers
102 vendors, and every one of them has to fall into a declared bucket:

1. taxonomy-only (`CATALOG_ONLY`), or
2. no page-visible channel in the catalog at all, or
3. listed in `COMPLEMENTARY` with a one-line reason why the catalog pattern
   only fires on a surface a root-domain crawl usually will not see — dbt docs
   that only some teams publish, a `X-ClickHouse-*` header that needs an
   exposed endpoint, an operator UI on an internal subdomain.

`test/text-signals.test.js` enforces this, so the layer cannot quietly grow into
a duplicate of the catalog for products that are already detected on ordinary
pages. Each vendor also carries a probe sentence (`PROBE_OVERRIDES`, defaulting
to "experience with <name>") that must produce a signal, which is what catches a
pattern that compiles but can never match.

### Products that genuinely cannot be detected

15 of the 402 tracked products have no externally observable signal of any kind,
and no pattern was written for them. They are reachable only through the text
signal layer above. `test/coverage.test.js` pins this list so the coverage figure
cannot be inflated later by a pattern that cannot fire:

- **Endpoint and network security** (CrowdStrike Falcon and Charlotte AI,
  SentinelOne and Purple AI, Zscaler, Netskope, Orca, Lacework, Abnormal). These
  run as agents or out-of-band scanners. Their admin consoles resolve
  (`falcon.crowdstrike.com`, `admin.zscaler.net`) but are reachable only from
  inside the customer's tenant. The earlier claimed TXT sweep did not retain
  its input corpus or raw output, so its negative result is not reproducible.
  Adding `xhr` patterns for the consoles would have been correct-but-inert, so
  nothing was added.
- **A Postgres extension and an edge module** (pgvector, NVIDIA Jetson Orin).
  Nothing is emitted to a visitor.
- **A protocol** (Anthropic MCP) with no stable public endpoint to match.
- **Local editors** (Neovim, Zed).
- **Phind**, a standalone AI search site with no embed surface.

Everything else on the list resolves to something observable. Where a product is
a model or an in-platform AI feature, it is reported at `platform-level` against
the API or suite that actually serves it — the report never implies the model
itself was fingerprinted.

### What made the difference

Two reframings moved catalog reachability from 47% to 96%:

1. **"Back-end" tools ship web UIs.** Airflow, Superset, MLflow, Argo CD,
   Metabase, Prometheus, Prefect, Spark, Flink, Kiali, Ray, Kubeflow, Rancher,
   Kedro-Viz, AutoGPT and the Kubernetes/OpenShift consoles are all routinely
   exposed on a subdomain. The engine is invisible; the operator UI is not.
2. **A model's output is evidence of the model.** An image served from
   `cdn.midjourney.com` was made with Midjourney. Generated-media CDNs make the
   image, video and music generators reportable, and hosted provider APIs
   (`api.x.ai`, `api.llama.com`, `dashscope.aliyuncs.com`) cover the rest.

## Workflow

```shell
npm test                  # engine, merge policy, normalizer, catalog, coverage
npm run validate          # catalog coherence only
npm run validate -- --json
npm run update            # pull upstream, merge additively, normalize, validate
npm run update:report     # what upstream would contribute, change nothing
npm run update:dry-run    # full run, write nothing
npm run normalize         # re-normalize locally without cloning
npm run coverage          # per-product report (needs the untracked inputs)
npm run coverage -- --summary > docs/coverage-summary.md
```

### Upstream merges are additive

`npm run update` merges **field by field**. Detection channels, categories,
pricing and cross-references are unioned; scalar metadata prefers the local value
and falls back to upstream. The previous script replaced any shared technology
with upstream's copy, which discarded local work — `Salesforce Service Cloud` and
`Microsoft Application Insights` each carry locally-authored channels that
upstream does not have, and those are now preserved. `test/merge.test.js` guards
this.

Upstream keeps reintroducing shapes the engine ignores, so `normalizeCatalog`
runs as part of every update rather than as a one-off migration. Every rewrite is
printed; use `--verbose` for the full list.

## Adding technologies

Put the definitions in `scripts/lib/emerging-technologies.js` and run:

```shell
node scripts/add-technologies.js --dry-run
node scripts/add-technologies.js
```

Existing entries are merged, not replaced, so a verified TXT record is added
alongside whatever already detected the technology. Then add a detection test to
`test/emerging-technologies.test.js` — including a negative case proving the pattern
does not over-match.
