# Live marker audit

Reviewed on 2026-07-28. This file records concrete pages and domains retained
for re-checking. It deliberately separates live observation from official
documentation and from synthetic regex tests.


> **These measurements are not tracked.** `data/dns-sweep-{domains.txt,results.json}`
> and `data/xhr-audit-{urls.txt,results.json}` are local-only, so the figures below
> are reproducible rather than independently checkable from a clone. Regenerate with
> `npm run sweep` and `npm run audit:xhr`; `scripts/lib/untracked.js` lists what
> depends on them, and the suites that read them skip with a stated reason. Anyone
> auditing these numbers needs the files, or a re-run.

## Priority findings

| Technology | Real target | Observation | Result |
| --- | --- | --- | --- |
| Samsara | https://encompassnashville.org/transportation | The customer page contains 3 tenant-specific `cloud.samsara.com/o/.../fleet/viewer/...` links. | Accepted as a customer Live Sharing marker. |
| Samsara | https://www.bakerk12.org/departments/transportation/live-bus-routes | The customer page contains 61 tenant-specific Samsara Live Sharing links. | Accepted as a second customer marker. |
| Samsara | https://cloud.samsara.com/signin | The first-party application loads content-hashed bundles from `cloud.samsara.com`. | Accepted as a first-party application marker; no semantic version is exposed. |
| Samsara Assistant | https://cloud.samsara.com/signin | The unauthenticated sign-in page loads `ai-assistant-styles.*.js`. | Rejected as a product-enablement marker. It proves only that the shared app bundle contains Assistant code. |
| Verizon Connect Reveal | https://reveal.fleetmatics.com | Redirects to `https://login.us.vzconnect.com/...` and renders `Log in \| Reveal`. | Accepted. The old rule missed the current final hostname; a current URL marker was added. |
| Verizon Connect Fleet | https://login.telogis.com | Redirects to `https://login.platform.telogis.com/` and loads scripts from `static.telogis.com`. | Accepted. |

Verizon documents `login.us.vzconnect.com` as the Reveal login for the US,
Canada, Australia, and New Zealand:
https://reveal-help.verizonconnect.com/hc/en-us/articles/35332918386067-Logging-in-to-Reveal

## DNS tenant examples

DNS verification records prove that a domain was verified with a vendor. They do
not prove that the public website embeds the product or that a specific feature
is enabled. DNS collection also requires `--probe`.

| Technology | Domain | Retained evidence |
| --- | --- | --- |
| Claude Enterprise | `decagon.ai` | Cloudflare Radar lists two `anthropic-domain-verification-*` TXT records: https://radar.cloudflare.com/domains/domain/decagon.ai |
| Claude Enterprise | `wikimedia.org` | Wikimedia's public DNS change was merged and confirmed verified: https://phabricator.wikimedia.org/T424785 |

### The sweep is now reproducible

The earlier sweep did not retain its corpus, so its markers were marked
`unreproduced-prior-sweep`. That is resolved:

| | |
| --- | --- |
| Corpus | `data/dns-sweep-domains.txt` — 536 domains, untracked (see below) |
| Script | `scripts/dns-sweep.js` — reads tokens **from the catalog**, not a hardcoded list |
| Results | `data/dns-sweep-results.json` — per marker, domain count and examples |
| Provenance | timestamp, corpus SHA-256, marker-set SHA-256, resolver servers, Node version, platform |
| Outcomes | per-domain resolution outcome (`ok`, `nodata`, `nxdomain`, `servfail`, `timeout`), so a failure is never silently counted as "no records" |
| Re-run | `npm run sweep` |
| Verify | `npm run sweep:check` — re-hashes the corpus and marker set and **exits non-zero if the retained results are stale**. No DNS queries. |

Latest run: **513 of 536 domains returned TXT records (23 returned none; 0 failed
to resolve). 94 of 96 catalog markers were observed.**

The accounting for the 55 markers added for this request, stated exactly:

| Verification | Count | Meaning |
| --- | --- | --- |
| `corpus-observed` | 48 | The exact pattern string was seen in the corpus |
| `corpus-observed-via-equivalent` | 5 | The original pattern was superseded as redundant during normalization; the technology is observed via the broader pattern that replaced it (Detectify, Dropbox, Segment, Mixpanel, DocuSign) |
| `live-observed` | 1 | Claude Enterprise, with named example domains |
| `official-documented` | 1 | OpenAI API, verified against vendor docs |

So the accurate claim is **all 55 enriched technologies have at least one observed
retained marker; five original pattern strings were superseded** — not "all 55
markers are corpus-verified", which conflates a technology with a pattern.

These labels are **derived from `data/dns-sweep-results.json` at load time**, not
hard-coded. An earlier version asserted `unreproduced-prior-sweep` in
`scripts/lib/emerging-technologies.js`, which stayed wrong after the sweep became
reproducible and left the coverage report contradicting the evidence on disk. If
the sweep has never been run the label degrades to
`unverified-no-sweep-retained`.

The two unobserved markers are upstream's, not additions here: `Apple iCloud
Mail` (`redirect=icloud\.com`) and `Zoho Mail` (`transmail\.net`). Absence in a
536-domain corpus is weak evidence, so they stay in the catalog — they simply
cannot be described as corpus-verified.

Because the script reads the catalog, it doubles as a regression check: a marker
added later without real-world backing shows up as unobserved.

#### What the sweep caught

Deriving tokens from the catalog exposed **redundant patterns** that a hardcoded
list would have hidden. Upstream ships `mixpanel-domain-verify`; a local
enrichment added `mixpanel-domain-verify=`. Both matched the same 52 domains —
identical counts and examples, one wasted regex per record. The same held for
Segment, Dropbox, Detectify, Cursor and DocuSign.

`dropSubsumedPatterns()` in `scripts/lib/normalize.js` removes a pattern when a
shorter one in the same list already covers it, cleaning **18 redundant patterns**
catalog-wide. Only the longer pattern is ever dropped: given `example\.com` and
`cdn\.example\.com`, the short one is what also matches `www.example.com`.

Three guards were needed. The first two came from checking the output; the third
came from review after the rule had already shipped a regression.

- A pattern carrying `\;version:` is **not** redundant. The first version of the
  rule would have dropped
  `/jquery(?:-(\d+\.\d+\.\d+))[/.-]\;version:\1` because `jquery` subsumes its
  value part — silently destroying jQuery, WooCommerce and Genesys Cloud version
  detection.
- Dropping *in favour of* a tagged pattern can lower confidence.
  `adocean\.pl/files/js/ado\.js` matches at confidence 100, whereas
  `adocean\.pl\;confidence:80` would report the same URL at 80.

- **`dom` and `probe` are excluded entirely, and only literal patterns take part
  at all.** Substring containment is meaningless for CSS selectors:
  `script#apple-pay` does **not** select `id="apple-pay-shop-capabilities"`, and
  `.asciinema-player` does not match `class="asciinema-player-wrapper"` — id and
  class matching is exact, not prefix. Before this exclusion the rule deleted
  three real detections:

  | Technology | Selector deleted | Wrongly assumed covered by |
  | --- | --- | --- |
  | Apple Pay | `script#apple-pay-shop-capabilities` | `script#apple-pay` |
  | Asciinema | `div.asciinema-player-wrapper` | `div.asciinema-player` |
  | Swiper | `div[data-swiper-slide-index]` | `swiper-slide` |

  A pattern now takes part only if it is a plain literal (alphanumerics, `-`, `_`,
  `=`, `:`, `/`, `@` and escaped dots). Anything with alternation, anchors,
  quantifiers, groups or classes is left alone, because containment tells you
  nothing about matching there either. The saving was ~40 regex evaluations
  against the risk of silent false negatives, which is not a trade worth making.

Subsumption is therefore restricted to untagged literal pairs outside `dom` and
`probe`. Verified after the fix: the three selectors above are restored and
detect, jQuery still reports `3.6.0`, AdOcean and Snowplow still report confidence
100, and 18 removals remain — none in `dom` or `probe`, none involving a tagged
pattern. `test/catalog.test.js` asserts both invariants against the retained
catalog.

## Measured: how often xhr-only markers actually fire

126 of the 387 catalog-matchable products resolve to an entry whose **only**
detection channel is `xhr` — a browser request to a vendor API host. The
hostnames are real and vendor-owned, so the markers are correct. The open
question was whether a browser ever sees such a call.

`scripts/xhr-audit.js` measures it against a list
(`data/xhr-audit-urls.txt`) of 29 pages chosen as the **most favourable case**:
AI vendors' own sites and AI-forward products, where a client-side call to the
vendor's own API is most likely. Results are retained in
`data/xhr-audit-results.json`.

| | |
| --- | --- |
| Pages requested | 29 |
| Status codes | 8× 200, 12× 304, 3× 301, 1× 308, 1× 403, 4× no status recorded |
| Distinct hostnames observed | 161 |
| Distinct hostnames reached via an `xhr` request | 47, on 23/29 pages |
| **xhr-only markers seen** | **1 of 85** |

The one seen was `Character.AI`, on `character.ai` itself.

**This is not an observation rate, and must not be quoted as one.** The honest
statement is: *1 of 85 xhr-only markers appeared in this 29-page corpus under the
current request-aborting driver.* Four things stop it being a rate:

- It is a yield against a convenience corpus. Nothing maps each marker to a page
  where its vendor is actually in use, so most markers had no real opportunity.
- `driver.js` aborts every request that is not `document` or `script`. An aborted
  XHR can prevent the follow-on application requests that would have exercised
  other markers, so the figure is a **lower bound** on what a normal browser sees.
- Only 8 of 29 pages returned a clean `200`. Twelve returned `304`, where a cached
  response may fetch fewer subresources than a cold one, and one returned `403`.
- A defensible rate needs controlled marker-to-page opportunities, or a
  representative crawl of company websites rather than vendor homepages.

The retained results record the status distribution, the blocked page and the
pages without a status, so none of this is hidden behind "29/29 scanned".

The channel is demonstrably working — 50 xhr hostnames were collected — but what
it collects is marketing and telemetry infrastructure, not vendor APIs:

```text
px.ads.linkedin.com      pixel-config.reddit.com   cdn.cookielaw.org
l.clarity.ms             app.clearbit.com          c.6sc.co
epsilon.6sense.com       forms.hsforms.com         api.hubapi.com
browser-intake-datadoghq.com   www.google-analytics.com   cmp.osano.com
```

Not one of `api.openai.com`, `api.anthropic.com`, `api.pinecone.io` or their
equivalents appeared — not even on those vendors' own websites. This matches what
the vendors document: OpenAI says API keys must not be exposed client-side, and
Jasper tells client applications to proxy through a back end. The calls are
server-side, so a passive crawler cannot see them.

### What was done about it

The entries were **kept**, not downgraded. They are valid, they cost nothing, and
a genuinely client-side integration does fire them. What changed is the reporting:
`npm run coverage` now states how many products rest on `xhr` alone and attaches
the measurement, and describes the 96% as an upper bound. `test/xhr-audit.test.js`
asserts the caveat is present in both the JSON and markdown outputs, so the
headline cannot be quoted without it.

An earlier run of this audit reported 0/85. That was Chrome missing from the
Puppeteer cache, an infrastructure failure rather than a measurement, and the
result file was discarded rather than retained. A test now asserts the retained
measurement shows a real scan (>50 hostnames, at least one xhr host) so a failed
run cannot be mistaken for evidence.

Two instrumentation bugs also had to be fixed before the number could be trusted:
the driver's `emit()` passes a single object rather than positional arguments, and
more importantly it **aborts every request that is not `document` or `script`**
and only emits for the survivors — so xhr traffic is invisible to an event
listener. The audit now reads `site.analyzedXhr`, the driver's own record of what
it fed to the channel.

## Official endpoint checks

These sources validate that the vendor owns and documents the endpoint. They do
not establish empirical passive-scan coverage. In particular, normal API
integrations are often server-side and invisible to browser XHR collection.

| Technology | Marker | Official source | Audit qualification |
| --- | --- | --- | --- |
| OpenAI API | `api.openai.com` | https://platform.openai.com/docs/api-reference/models/object?lang=curl | Endpoint is correct. OpenAI says API keys must not be exposed client-side. |
| Jasper | `api.jasper.ai` | https://developers.jasper.ai/docs/authentication | Endpoint is correct. Jasper explicitly tells client-side apps to proxy through a back end. |
| Moveworks | `api.moveworks.ai` | https://developer.moveworks.com/creator-studio/reference/rest-api/ | Endpoint is correct; browser visibility is integration-dependent. |
| Harvey | `api.harvey.ai` | https://developers.harvey.ai/guides/vault | Endpoint is correct; browser visibility is integration-dependent. |
| Chroma | `api.trychroma.com` | https://docs.trychroma.com/cloud/getting-started | Endpoint is correct; browser visibility is integration-dependent. |
| Lytx | `api.lytx.com` | https://developer.lytx.com/docs/data_connector | Endpoint is correct; browser visibility is integration-dependent. |

## Regression expectations

- XHR patterns may match a vendor hostname or one of its subdomains, but must
  not match an attacker suffix such as `api.openai.com.attacker.invalid`.
- Script URL patterns for the priority technologies are anchored to the URL
  hostname, so a path such as
  `https://attacker.invalid/cloud.samsara.com/app.js` does not match.
- A generic Samsara sign-in link is not usage evidence. The DOM rule requires
  the tenant-specific `/o/.../fleet/viewer/...` Live Sharing shape.
- `Samsara Assistant` remains taxonomy metadata and maps to the observable
  Samsara platform at `platform-level`; it does not fire as a separate product.

## End-to-end CLI verification

The repository CLI was run with Node 24, Puppeteer 25.4.0, and a local Chrome
binary after the unit tests:

- `https://encompassnashville.org/transportation` returned status 200 and
  detected `Samsara` at 100 confidence.
- `https://login.us.vzconnect.com` followed the live redirect chain through
  `us.vzconnect.com` and `reveal.us.fleetmatics.com`, then detected both
  `Verizon Connect Reveal` and `Verizon Connect` at 100 confidence.
- A direct `cloud.samsara.com/signin` CLI run exceeded the 12-second navigation
  budget. The Assistant rejection is therefore based on the independently
  inspected live browser asset list, while the accepted Samsara customer marker
  has full CLI coverage.

The first Verizon CLI attempt exposed a separate collector defect: an
inaccessible `sessionStorage` global aborted the whole page scan. The JS
collector now skips inaccessible globals instead of failing the page.

The runtime was upgraded from unsupported Puppeteer 19 to 25.4.0. This raises
the required Node version to 22.12.0 and reduces `npm audit` from seven high
severity advisories to zero vulnerabilities.
