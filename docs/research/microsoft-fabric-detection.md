# Microsoft Fabric detection research

Research date: 22 October 2026. Repository baseline: `15373eb125b61f2b43d4a9b29c90b4108add0685`; `git pull --ff-only` reported already up to date. The research sections below describe that baseline; the subsequent implementation is recorded separately here.

## Implemented improvements

At the user's request, the working tree now detects observed requests to regional/general/workspace OneLake, workspace GraphQL, Fabric Kusto, Cosmos, and documented deployed Rayfin endpoints. Full hostname boundaries reject lookalikes and unverified subdomains. Shared Fabric API hosts require a Fabric-specific Lakehouse, Warehouse, or GraphQL item path; a hostname alone, generic workspace request, or Power BI report request is insufficient. The iframe rule validates `/itemEmbed` on both SDK-supported hosts, `app.fabric.microsoft.com` and `app.powerbi.com`, including protocol-relative URLs and explicit port 443. CSP-only Fabric detection has been removed. Power BI rules remain unchanged and do not imply Fabric.

The stricter iframe rule exposed an attribute-collection bug: `getDom` compared an already observed value with itself and discarded later values for the same selector and attribute. The collector now compares each new attribute value against prior values, so an unrelated first iframe cannot hide a later Fabric frame. This fix also applies to other attribute-based technology rules.

Regression tests are in `test/microsoft-fabric.test.js`; browser-level checks use the actual collector via `scripts/fabric-detection-audit.js`. The original [baseline audit](fabric-marker-audit.json) is retained separately from the [post-change audit](fabric-marker-audit-after.json). These are fixture validations, not measured coverage increases across customer websites. SDK text, static configuration, Microsoft identity records, and adoption inference remain outside the Fabric rules. These rules identify attempted browser integrations, not successful authentication, production deployment, or organizational ownership. The driver observes XHR/fetch before aborting the requests.

Validation on 22 October 2026: all 294 tests and 5 CLI smoke checks passed; the Fabric audit recorded 39 cases, including 12 asserted Chromium DOM cases. `npm run validate` reported 0 errors and 102 existing catalog warnings, with none for Fabric. Catalog delta and whitespace checks passed. The ignored local XHR measurement was refreshed against the changed driver so its provenance check remains valid; that general 29-page audit is not a Fabric coverage measurement.

## Review of the supplied Grok proposal

Grok's endpoint research is useful, but its JSON should not be applied wholesale. Running six additional counterexamples through this repository's engine produced Fabric detections in every case with the supplied proposal, and none with the implemented rules. Inputs and confidences are retained in [proposal counterexamples](fabric-proposal-counterexamples.json):

- A Power BI report request on `api.fabric.microsoft.com` still emitted Fabric at confidence 40. Microsoft explicitly documents report operations on that host; DNS aliasing is not needed to establish the ambiguity. [Report API](https://learn.microsoft.com/en-us/rest/api/fabric/report/items/get-report).
- A request for `/rayfin.config.json` on an unrelated host emitted Fabric at 100. Microsoft's client requests this default file even when local configuration is absent; the filename alone does not establish deployment. An unused copy of that string in a bundle also emitted Fabric at 100. [Pinned runtime configuration source](https://github.com/microsoft/rayfin/blob/0979439a7a0806abd0ee48c2619b37f297ae1324/packages/typescript-sdk/client/src/config.ts).
- The proposed GraphQL URL rule accepted the Fabric-shaped path on `example.com` at 100 because it did not validate the origin.
- A CSP `report-uri` pointing to a OneLake host emitted Fabric at 100. A report-only allowlist emitted it at 75. Allowed destinations are not observed service use, and reduced confidence does not suppress a detection in this engine.

The additional workspace GraphQL family is independently supported by a [published hands-on example](https://community.fabric.microsoft.com/blog/fbc_comm_blog/graphql-explained-transforming-data-access-in-microsoft-fabric/4864051). Its linked `e8dbcd73d60b45958b34f50f9a9bf274.ze8.graphql.fabric.microsoft.com` endpoint returned HTTP 401 during verification: evidence of the live endpoint shape, not a successful customer integration. The implementation uses the documented workspace/shard shape rather than any subdomain containing `graphql`.

The blanket claim that every Fabric web feature requires an interactively signed-in user is incorrect: GraphQL supports service principals, and Fabric Apps can expose static assets publicly. Fabric Embed rendering requires authentication, but the published SDK's `preload()` can create its `/itemEmbed` iframe before login, so the iframe marker is not dead. [GraphQL service principals](https://learn.microsoft.com/en-us/fabric/data-engineering/api-graphql-service-principal), [Fabric Apps hosting](https://learn.microsoft.com/en-us/fabric/apps/hosting).

The `*.webapp.fabricapps.net` / `*.api.fabricapps.net` additions are deferred pending verified production examples and attribution. The inspected Microsoft source contains an internal `msit.fabricapps.net` hostname and internal-host test fixtures; that does not justify the proposed arbitrary environment/subdomain regex. The documented `*-app.rayfin.windows.net` backend is included as an observed-request marker. No SDK string, outbound link, or config filename rule is included.

PublicWWW source-string counts, npm downloads, and a paid-customer count cannot establish homepage recall or a specific ceiling. They use different populations and do not measure the same observable surface as the browser crawler. The claim of less than 1% recall and the forecast of only tens of domains are unvalidated. The one domain from the 25-million sample still needs its raw match inspected.

## Findings and recommended direction

Microsoft Fabric is detectable on some customer web applications, but public website detection cannot measure its overall enterprise adoption. The current rules have genuine gaps, particularly Fabric Apps, regional OneLake endpoints, and Eventhouse/Kusto traffic. They also contain precision problems in CSP and iframe matching. Broader, carefully scoped technical markers should recover some missed integrations; a separate company adoption evidence pipeline is the more promising route to useful sales intelligence coverage.

The reported one domain out of 25 million is a supplied result, not a reproduced measurement. It is a detected-domain rate of 0.000004%, not a recall rate: the sample does not tell us how many companies actually use Fabric. The matched domain and its raw evidence are needed to establish whether even that one result is valid.

The October 16 correction was directionally right. Do not restore the earlier generic `app.fabric.microsoft.com` iframe rule or imply Fabric from Power BI. Power BI supports several capacity types, and a report embed does not reveal its capacity or underlying data platform. Microsoft explicitly routes Power BI items through Power BI embedding separately from Fabric Embed. [Power BI embedding capacities](https://learn.microsoft.com/en-us/power-bi/developer/embedded/embedded-capacity), [Fabric Embed overview](https://learn.microsoft.com/en-us/fabric/embed/what-is-fabric-embed).

## Audit of the baseline markers

The definition is in `technologies/m.json`, under `Microsoft Fabric`. The retained [baseline marker audit](fabric-marker-audit.json) ran synthetic observations through the real engine and evaluated iframe selectors in Chromium. Run the updated audit against the working tree without overwriting that baseline:

```sh
node scripts/fabric-detection-audit.js > docs/research/fabric-marker-audit-after.json
```

| Current marker | Accuracy | Coverage and recommended change |
| --- | --- | --- |
| `iframe[src*='.fabric.microsoft.com/itemEmbed']` | The product path is verified in the published SDK. The substring selector also matches an unrelated site's redirect query containing that URL and paths such as `/itemEmbedLookalike`. | Keep the signal; use a DOM attribute regex that validates the actual HTTPS host and exact path boundary. |
| XHR `api.fabric.microsoft.com` | Shared endpoint: also serves Power BI report operations. The engine already enforces hostname suffix boundaries for `xhr`, rejecting `notapi.fabric.microsoft.com` and `api.fabric.microsoft.com.attacker.example`. | Replace with `xhrUrl` checks for Fabric-specific item paths. Do not detect Fabric from this hostname alone. Server-side calls remain invisible. |
| XHR `onelake.(dfs\|blob).fabric.microsoft.com` | Genuine OneLake hosts. | Keep and extend: regional prefixes, general OneLake API hosts, and documented workspace forms are missing. |
| CSP containing either endpoint | Demonstrates an allowed destination, not an actual request. Currently matches attacker suffixes, partial host labels, and an endpoint name inside a report URI path. The audit resolves these at confidence 100. | Parse CSP source expressions and treat as supporting evidence. If strict technical usage is the product contract, omit CSP-only detections. A narrower regex alone cannot establish active use. |

The current XHR regex misses `westus-onelake.dfs.fabric.microsoft.com` because the engine rejects the mid-label `onelake` substring after a hyphen. The same string *does* match CSP, where hostname boundary enforcement is absent. Therefore a simple regex match outside the engine would give misleading audit results.

Lowering CSP to `confidence:25` would still emit a technology entry: `Wappalyzer.resolve()` sums confidence and does not require 100. Repeated observations may accumulate confidence. Any confidence-only fix must also specify downstream reporting behavior.

## Verified Fabric Embed behavior

The public npm registry supplied `@microsoft/fabric-embed` version `0.1.0`, published 25 June 2026. Its `src/lib/embed-url.js` sets the default host to `https://app.fabric.microsoft.com` and the path to `/itemEmbed`; `embed-iframe.js` creates an iframe with that URL. This independently validates the existing path, rather than relying on a guessed name. [Published package](https://www.npmjs.com/package/@microsoft/fabric-embed); exact tarball and integrity metadata are retained in [SDK provenance](fabric-sdk-provenance.json).

The implemented DOM attribute rule validates the HTTPS origin (or protocol-relative form), optional port 443, and the exact `/itemEmbed` path before a query, fragment, or end of string. The pinned package's `EmbedUrl` hostname validation was also exercised successfully with `app.powerbi.com`, so this SDK-supported alternate host is covered. Neither `/reportEmbed` nor `/view` identifies Fabric.

The SDK can create this iframe only after the surrounding application reaches its embed initialization. Microsoft's preview requires signed-in users with access to the item and supports Real-Time Dashboards; it does not provide anonymous app-owns-data embedding. A public crawler can still identify an iframe created before authentication, but cannot assume it will be created on the logged-out page. [Fabric Embed requirements and limitations](https://learn.microsoft.com/en-us/fabric/embed/what-is-fabric-embed).

Package URL markers for a browser-loaded `@microsoft/fabric-embed` distribution could identify an integration before its iframe renders. Most applications may bundle the package into a generic asset, so CDN-only detection is incomplete. Inspect pinned distributed SDK code before adding a bundle fingerprint. Avoid generic globals such as `EmbedManager` or `Fabric`, and avoid matching a package name in arbitrary prose or HTML code examples.

## Missing product surfaces

| Surface | Documented signal | Recommended channel and caveat |
| --- | --- | --- |
| Fabric Apps | `https://<app>-app.rayfin.windows.net/`, with `/api/graphql`, `/auth`, and `/storage` | Highest-priority new family: `xhr` for observed calls; `xhrUrl` for service paths; exact backend literals in executable bundles as supporting integration evidence. Requires live customer calibration. |
| Regional OneLake | `<region>-onelake.dfs.fabric.microsoft.com`, corresponding Blob endpoints | Add complete hostname forms to `xhr`; do not rely on matching `onelake` inside the region-prefixed label. |
| General OneLake API | `api.onelake.fabric.microsoft.com`, `<region>-api.onelake.fabric.microsoft.com` | Add to `xhr`; retain exact host boundaries. |
| Workspace OneLake | `<workspace>.z<xy>.dfs.fabric.microsoft.com` and Blob forms | Documented endpoints; lower expected public availability, especially with private networking. |
| Eventhouse and KQL databases | `<cluster>.z<digit>.kusto.fabric.microsoft.com` | Add observed browser traffic. Do not classify all `*.kusto.windows.net` as Fabric; Azure Data Explorer is a distinct service. |
| Cosmos DB in Fabric | `sql.cosmos.fabric.microsoft.com` | Genuine additional endpoint; practical public browser visibility remains unmeasured. |
| Warehouse and SQL database | `*.datawarehouse.fabric.microsoft.com`, `*.database.fabric.microsoft.com` | Usually SQL connections, not HTTP browser requests. Useful in explicit configuration or adoption evidence, not a reason to expect an XHR coverage increase. |

Sources: [Fabric Apps overview](https://learn.microsoft.com/en-us/fabric/apps/overview), [OneLake endpoint forms](https://learn.microsoft.com/en-us/fabric/onelake/onelake-access-api), [workspace endpoint forms](https://learn.microsoft.com/en-us/fabric/security/security-workspace-level-private-links-overview), [Fabric service allowlist](https://learn.microsoft.com/en-us/fabric/security/fabric-allow-list-urls), [Warehouse connectivity](https://learn.microsoft.com/en-us/fabric/data-warehouse/how-to-connect).

The implemented patterns are in `technologies/m.json`. They anchor complete hostname forms and restrict shared `api.fabric.microsoft.com` / workspace `w.api.fabric.microsoft.com` URLs to `/v1/workspaces/<UUID>/{lakehouses,warehouses,graphqlapis}`. Generic workspace, item, report, and semantic-model operations are excluded. These observed request paths are supported by the [Lakehouse API](https://learn.microsoft.com/en-us/rest/api/fabric/lakehouse/items/list-lakehouses), [Warehouse API](https://learn.microsoft.com/en-us/rest/api/fabric/warehouse/items/list-warehouses), and [GraphQL application tutorial](https://learn.microsoft.com/en-us/fabric/database/sql/tutorial-create-application). Documented workspace forms are handled explicitly instead of widening every `fabric.microsoft.com` subdomain.

Fabric Apps is particularly relevant because it hosts customer applications rather than only administrative analytics. Microsoft documents optional public access to static assets, while application services retain authentication requirements. Thus a logged-out visitor may retrieve identifying code even when API calls are gated. The documentation does not establish how many deployed apps expose it. [Static hosting and access](https://learn.microsoft.com/en-us/fabric/apps/hosting), [Fabric Apps authentication](https://learn.microsoft.com/en-us/fabric/apps/authentication).

Microsoft documents `@microsoft/rayfin-client`; registry inspection also confirmed this package and its Microsoft repository. Do not match `RayfinClient` alone: the framework supports local development, and a class name does not establish a deployed Fabric backend. Prioritize a correctly bounded deployed Rayfin service host, with package evidence as corroboration. [Fabric Apps client usage](https://learn.microsoft.com/en-us/fabric/apps/read-write-data-graphql).

Fabric GraphQL is another browser integration surface. The implementation covers its dedicated workspace host and `https://api.fabric.microsoft.com/v1/workspaces/<UUID>/graphqlapis/.../graphql` route. A broad GraphQL keyword would add false positives rather than useful coverage. Static application configuration may reveal that exact endpoint before sign-in; browser requests remain the stronger evidence. [SQL application tutorial](https://learn.microsoft.com/en-us/fabric/database/sql/tutorial-create-application), [React application integration](https://learn.microsoft.com/en-us/fabric/data-engineering/connect-apps-api-graphql).

The Fabric workload client SDK identifies another integration class: third-party workload providers whose applications run inside Fabric. These can be valid Fabric integrations, but should be distinguished from ordinary enterprise buyers in sales intelligence. [Workload SDK reference](https://learn.microsoft.com/en-us/javascript/api/%40ms-fabric/workload-client/?view=fabric-extensibility-js-latest).

## Crawler limits that affect this result

These findings apply to the checked-out driver. Confirm the 25-million-domain job used this revision and the same options before attributing its results to these behaviors.

1. `driver.js` analyzes both XHR and fetch hostnames before aborting those requests. An attempted API request can be detected, but its response never arrives. Workflows that need that response to create an iframe or make another request may not reach their later signals.
2. Child-frame requests are blocked. The parent DOM can still expose the iframe URL, but the crawler cannot observe the downstream requests that a successfully loaded analytics frame would initiate.
3. Requests whose URL contains `bundle.js` are unconditionally blocked before request analysis. This can prevent an app from starting and removes that asset's contents from script analysis. It warrants a separate crawler experiment, not an assumption that every Fabric application is affected.
4. Recursive crawling is disabled by default. A company's main marketing page may expose nothing while an analytics portal or nested application page contains the integration. Simply extending a homepage's settle time cannot discover an unvisited route.
5. `scripts` receives inline code and successfully fetched main-frame scripts. There are currently no Fabric `scripts` or `scriptSrc` markers, so dormant SDK/configuration evidence does not fire.

A separate discovery mode should inspect public, first-party linked analytics applications, selectively allow application bootstrap assets and known Fabric frames, and retain request initiator/frame provenance. Avoid globally enabling every third-party frame: shared widgets can otherwise be attributed to the wrong company. Compare these settings in a bounded pilot before changing a 25-million-domain crawl.

Private networking sets an additional hard limit. Microsoft documents configurations where Fabric access requires a private network. Public website crawling cannot recover those internal deployments. [Inbound network protection](https://learn.microsoft.com/en-us/fabric/security/protect-inbound-traffic).

## Live customer sanity check

The current driver checked three public homepages: NIRAS, PERI, and Arvind. Each reached an HTTP 200 page, including PERI's redirect. All three returned no Fabric or Power BI detection. Options and URL outcomes are retained in [homepage probe results](fabric-customer-homepage-probe.json).

Microsoft independently describes these companies using Fabric: [NIRAS](https://www.microsoft.com/en/customers/story/26952-niras-onelake), [PERI](https://www.microsoft.com/en/customers/story/26449-peri-microsoft-fabric), [Arvind](https://www.microsoft.com/en/customers/story/27288-arvind-limited-microsoft-fabric).

This is a purposive illustration of adoption without homepage visibility, not a recall estimate. No authenticated portals, customer internals, or exhaustive route sets were inspected. No live third-party positive was established for the proposed new Rayfin, Kusto, or OneLake variants; their support is documentary, with current misses demonstrated synthetically.

## Increasing company adoption coverage

Joshua's request concerns sales intelligence, so distinguish a page integrating Fabric from an organization reporting Fabric adoption. The latter can be supported by dated first-party architecture disclosures, explicit production announcements, and Microsoft customer stories even when the company's website exposes no technical marker.

Maintain separate evidence records with company identity, canonical company domain, product, source URL, quoted supporting passage, observation/publication date, deployment status, and evidence type. A Microsoft-hosted case study names a customer; it must not become a technical detection on `microsoft.com` or automatically propagate to every subsidiary domain. Distinguish implementation partners, consultants, trials, planned migrations, and production customers.

The repository already has a separate `signals` output and an opt-in `textSignals` path in `scripts/lib/text-signals.js`. Fabric is missing from its vendor map. Adding the qualified name `Microsoft\\s+Fabric` would reuse that mechanism for hiring/stack signals, but its generic context rules can also match desired experience, certification, or consulting work. Treat these as leads requiring review, not confirmed installation. Never match bare `Fabric`: Fabric.js, Fluent UI/Office UI Fabric, Service Fabric, Python Fabric, and ordinary fabric references are unrelated.

For stronger adoption evidence, prioritize explicit statements of current use over job requirements. Do not overload the current hiring classifier to infer adoption from case studies without company extraction and source attribution.

## Implementation and validation order

1. Inspect the sole observed hit: domain, exact URL, channel, matched value, confidence, timestamp, redirect chain, and crawler revision/options. Establish whether it is a customer, provider, Microsoft property, or CSP-only match.
2. Tighten iframe host/path validation, require Fabric-specific paths on shared API hosts, and remove CSP-only confirmed usage. Preserve Power BI separation. These improve trust even if the count initially falls.
3. Add bounded observed-request patterns for deployed Rayfin services, regional/general OneLake, workspace DFS/Blob/GraphQL, Fabric Kusto, and Cosmos endpoints. Test through the engine, including malicious suffixes and mid-label lookalikes. Avoid blanket `*.fabric.microsoft.com` matching.
4. Investigate SDK/configuration markers against pinned releases and real customer assets. Favor executable configuration tied to a Fabric endpoint; exclude documentation and copied examples. Validate minified builds, not only source imports.
5. Run a targeted pilot across known adopters and public analytics routes, then a large negative control set. Compare baseline, marker-only changes, and crawler changes separately. Report observed-request detections, static integration evidence, CSP hints, and adoption evidence independently.
6. Build the company evidence pipeline alongside technical detection. This is the most credible route to substantially broader coverage for internal analytics adoption.

Suggested pilot controls: at least 100 independently evidenced adopters where obtainable; Power BI-only deployments, Microsoft documentation, consulting/training sites, Fabric.js, Service Fabric, and unrelated Microsoft/Azure services as negatives. Track inaccessible or unauthenticated apps separately from genuine observed negatives. Deduplicate at the business entity level and retain the underlying domain/page evidence.

Criteria for claiming measured coverage improvement: no false positives in reviewed pilot controls, a reviewable live customer example for each new marker family, and a measured increase in relevant integrations with provenance. The current implementation passes synthetic controls and has documentary endpoint support; it has not completed a customer coverage pilot. These criteria are not a promise of zero future false positives. At this scale, even tiny false-positive rates can swamp true detections.

No defensible multiplier can be promised from the current evidence. Endpoint expansions fix real missed forms; only a replay or targeted crawl can measure their incremental yield. The 25-million-domain dataset and its sole hit were not available locally.

## Suggested response to Joshua

Microsoft Fabric is now tracked where we can observe a direct website integration. Coverage is limited because much of Fabric runs inside authenticated analytics environments and leaves no public website footprint. We are expanding the identifiable integration signals, including Fabric Apps and additional Fabric service endpoints. We also keep Power BI embeds separate, since those alone do not demonstrate broader Fabric use. For a more complete company adoption view, we would combine direct detections with clearly attributed public deployment evidence.
