# Rewriting the dead AI rules against customer-visible evidence (2026-08-03)

Follow-up to `wappalyzer-ai-tech-dq-2026-08-02.md`, which measured the AI
additions over 1.87M crawled domains and found **128 of 154 entries never fired
once**. The cause was structural: most of them matched a **back-end** API
hostname.

## The distinction that mattered

A crawl visits a company's public website. So the only markers that can ever
fire are the ones that appear on *that* page — or in a request *that page*
makes. Sorting the request-driven additions by that test:

| Where the marker lives | Can fire on a root-domain crawl |
| --- | --- |
| Customer's own page: widget, iframe, response header, tenant link | yes |
| A call the customer's own front end makes (`*.cloudhub.io`) | yes |
| Vendor console (`app.pinecone.io`) | only when the vendor's own domain is crawled |
| Operator UI on an internal subdomain | only if subdomains are crawled |
| Back-end API host (`\.pinecone\.io`, `aiplatform.googleapis.com`) | **never** |

`xhr` is not the problem in itself — `hook.eu1.make.com` is an `xhr` rule that
fires from the customer's page. The problem is an `xhr` rule for an API only a
server calls.

## What was done

**120 entries** added for this request had no page-visible channel at all
(xhr-only, dns-only, or no pattern). Each was researched against the question
"does this vendor put anything on its customers' pages?", and every marker that
survived was fetched on 2026-08-03 before being written. Nothing here comes from
vendor marketing copy.

### 22 now detect from a customer's own page

| Technology | New channel | Marker |
| --- | --- | --- |
| Google Vertex AI | scriptSrc, dom | `<df-messenger>` + its gstatic bootstrap (Agent Builder / Dialogflow CX chat widget) |
| IBM watsonx | scriptSrc | watsonx Assistant web chat entry script |
| IBM Cloud | xhr, url | `*.appdomain.cloud` — where the app is served from or called |
| MuleSoft | xhr | `*.cloudhub.io` — the customer's own API, called from its front end |
| Postman | scriptSrc, html | "Run in Postman" button (`run.pstmn.io`) |
| Monday.com | html | `forms.monday.com/forms/embed/`, `view.monday.com/embed/` |
| Wrike | html | Wrike request-form iframe |
| Zapier | scriptSrc, dom | app-directory widget + `<zapier-interfaces-chatbot-embed>` |
| Make | xhr, html | `hook.<region>.make.com` webhook target |
| Superblocks | html | embedded application iframe |
| Amazon Q | html | anonymous web-experience iframe (`chat.qbusiness.*.on.aws`) |
| Autodesk | scriptSrc | APS/Forge `viewer3D.min.js` |
| Adobe Acrobat Sign | html | `esignWidget` web-form iframe |
| SAP SuccessFactors | html | tenant careers link (`career*.successfactors.*/career`) |
| HackerOne | html | embedded submission form |
| Replicate | html | `replicate.delivery` model output |
| Ideogram | html | generated-image path |
| ClickHouse | headers, html | `X-ClickHouse-*` response headers, `/play` markup |
| dbt | html | `ng-app='dbt'` + `<title>dbt Docs</title>` in published docs |
| Unleash | meta, xhr | `unleashToken`/`uiFlags` meta, hosted frontend API |
| Metaflow / Kedro / ZenML | html | shipped operator-UI markup |

Evidence for each is in `REVIEWED_EVIDENCE` in
`scripts/lib/emerging-technologies.js`, with the fetch that established it.
Coverage is in `test/customer-visible-selectors.test.js`: a positive case per
marker, plus a page that *discusses* all 18 vendors and must detect none of
them, plus suffix-spoof controls.

Three of these (Metaflow, Kedro, ZenML) are operator UIs, recorded as
`signal: operator-ui`. They will not fire on a root-domain-only crawl and are
not counted as a fill-rate fix.

### 97 have no customer-visible marker, and now carry a text signal

Pinecone, Snowflake, Weaviate, Qdrant, the EDR agents, the local editors, the
model APIs and the rest are genuinely invisible from outside: nothing is emitted
to a visitor. For these the alternative is the existing text-mined layer —
`scripts/lib/text-signals.js`, confidence 30, returned in a separate `signals`
array and never merged into `technologies`. It went from 13 vendors to 102.

The layer's invariant was restated rather than dropped. Every vendor must be
taxonomy-only, have no page-visible channel, or be declared in `COMPLEMENTARY`
with a reason why its catalog pattern only fires on a surface a root-domain
crawl usually will not see. `test/text-signals.test.js` enforces that, plus a
probe sentence per vendor so a pattern that can never match is caught.

This is a *company-level* inference, not a detection. It is worth having and it
must not be reported as a detection.

### 1 left alone deliberately

`Samsara Assistant` — the marker is a global bundle present for every tenant, so
it cannot prove the feature is enabled. Already recorded as `rejected-marker`.

## Still open, and outside this repo

1. **DNS is switched off in production.** 14 entries (Anthropic/Claude
   Enterprise, Cursor, Perplexity Enterprise, Windsurf, Wiz, Jamf, 1Password,
   HashiCorp Cloud Platform, Sourcegraph Amp, Island, HackerOne, Postman,
   JetBrains IDEs, Adobe) are reachable through a TXT verification record and
   nothing else. `driver.js probe()` is gated on `options.probe`, default
   `false`, and the consumer never sets it. Either enable `probe: 'basic'` —
   one DNS round-trip per domain, size it before a 5M dispatch — or accept that
   these stay tenant-invisible. Nothing in the catalog can fix this.
2. **The block-rate regression** (1.03% → 3.91%) from the DQ. It costs 60k
   previously-rich domains and is unrelated to selector quality, but it caps
   whatever these rules can return.
3. **Product-level detection** for the 102 unimplemented spreadsheet products is
   still unmet, and for pure SaaS there is no version to read from outside.

## What to expect from this

The 22 rewritten entries can now fire on an ordinary company website; the
previous 70 could not, at any crawl volume. That is the whole of the fix. The
absolute numbers will still be small — an embedded monday.com form or a Vertex
AI chat widget is a real but uncommon thing to find — and they should be
measured on the next campaign rather than predicted here. What has changed is
that a zero now means "not present" instead of "not observable".
