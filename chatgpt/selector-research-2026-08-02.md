# Hosted AI selector research — 2026-08-02

## Scope

The workbook `/Users/laptop/Downloads/AI technology_products_for_veridion_070226.xlsx`
contains 402 requested products. The local coverage map currently reports 150
directly detected products and 237 platform-level mappings. The research target
was the AI entries whose existing rules are backend hostname (`xhr`) or DNS-only.

## Live evidence

I opened the first-party pages in the browser and inspected their final URLs,
titles, visible content, scripts, metadata, and redirects.

| Technology | First-party hosted surface observed | Selector merged | Why it is safe | Result |
| --- | --- | --- | --- | --- |
| Anthropic | `https://claude.ai/` | `^https?://claude\\.ai(?:[:/]|$)` | Exact first-party Claude app host; does not match a customer-controlled suffix | Positive on `https://claude.ai/new`; spoof rejected |
| Character.AI | `https://character.ai/` | `^https?://(?:www\\.)?character\\.ai(?:[:/]|$)` | Exact product host with label boundary | Positive on `/character/123`; spoof rejected |
| Pinecone | `https://app.pinecone.io/` redirected to `https://login.pinecone.io/` | `^https?://(?:app|login)\\.pinecone\\.io(?:[:/]|$)` | Covers the dashboard and its observed login redirect only | Positive on both hosts; suffix spoof rejected |
| Qdrant | `https://cloud.qdrant.io/` redirected to `https://login.cloud.qdrant.io/` | `^https?://(?:login\\.)?cloud\\.qdrant\\.io(?:[:/]|$)` | Covers the cloud console and observed login redirect only | Positive on both hosts; suffix spoof rejected |
| Weaviate | `https://weaviate.io/go/console` redirected to `https://console.weaviate.cloud/signin` | `^https?://console\\.weaviate\\.cloud(?:[:/]|$)` | Exact first-party console host | Positive on `/signin`; suffix spoof rejected |
| Copy.ai | `https://app.copy.ai/login` | `^https?://app\\.copy\\.ai(?:[:/]|$)` | Exact first-party application host | CLI positive, HTTP 200; suffix spoof rejected |
| Groq | `https://chat.groq.com/` | `^https?://chat\\.groq\\.com(?:[:/]|$)` | Exact first-party chat application host | CLI positive, HTTP 200; suffix spoof rejected |
| Jasper | `https://app.jasper.ai/auth/signup` | `^https?://app\\.jasper\\.ai(?:[:/]|$)` | Exact first-party application host | CLI positive, HTTP 304; suffix spoof rejected |
| LangSmith | `https://smith.langchain.com/` | `^https?://smith\\.langchain\\.com(?:[:/]|$)` | Exact first-party tracing application host | CLI positive, HTTP 304; suffix spoof rejected |
| Together AI | `https://api.together.ai/playground/` → sign-in | `^https?://api\\.together\\.ai(?:[:/]|$)` plus `xhr: api\\.together\\.(?:ai|xyz)` | Current `.ai` host is live; legacy `.xyz` remains supported | CLI positive through 308/307/200 redirect chain; both XHR hosts unit-tested |

The marketing pages for Chroma, Pinecone, Qdrant, and Weaviate exposed brand
copy and framework/analytics assets, but no customer-side browser marker that
would safely establish use of the backend service. I therefore did not add
generic text, title, Next.js chunk, or vendor-marketing selectors for those
entries. Their existing API-host rules remain the honest signal when a crawl
actually observes client-side traffic.

The real crawler was then run against the hosted surfaces. It returned the
expected technology for Character.AI, Pinecone, Qdrant, and Weaviate, including
the Pinecone and Qdrant login redirects. A scripted Claude crawl initially hit
the local 30-second timeout; a retry with scripts disabled completed at HTTP 200
and returned Anthropic. The connected browser independently loaded Claude's
logged-in app page and exposed the same first-party `assets-proxy.anthropic.com`
app surface.

## Proof kept in the repository

`test/hosted-ai-selectors.test.js` exercises the real catalog and engine against
all positive URLs above and rejects unrelated hosts plus suffix-spoof controls.
The selectors are also covered by the catalog validator and URL false-positive
corpus.

## Limitation

These additions improve detection of first-party hosted app/console domains;
they do not make a server-side Pinecone, Qdrant, Weaviate, or Chroma integration
visible on an unrelated customer website. No selector can recover that signal
from a passive page crawl if the browser never contacts the backend.

## Full-list review

The complete row-level review is in [selector-matrix.md](selector-research/selector-matrix.md), with machine-readable selector patterns and first-party fetch evidence in [selector-matrix.json](selector-research/selector-matrix.json). All 402 workbook rows are included.

The resulting actions are:

| Action | Rows | Meaning |
| --- | ---: | --- |
| Merged and proven hosted surface | 12 | A first-party app/console/API surface was observed and positive plus spoof-negative tests passed. |
| Retain existing browser-visible selector | 183 | The existing DOM, script, HTML, metadata, headers, URL, or URL-aware XHR rule is already the stronger signal. |
| Retain existing mixed selector | 29 | Multiple channels exist; no justified replacement was found. |
| Parent API is best honest signal | 70 | The requested model/feature is externally observable only through its serving platform. |
| Backend API only; no safe browser marker found | 44 | The API hostname is valid when observed, but vendor pages did not expose customer-side evidence. |
| DNS-only; enable probe or accept limit | 45 | TXT verification is the only selector; production must collect DNS for it to fire. |
| No own selector | 19 | The entry is taxonomy-only, implied, or otherwise has no independent web signal. |

The additional proven changes were Copy.ai (`app.copy.ai`), Groq (`chat.groq.com`),
Jasper (`app.jasper.ai`), LangSmith (`smith.langchain.com`), and Together AI
(`api.together.ai`). Together’s XHR rule now accepts both the current `.ai` host
and the retained legacy `.xyz` host. The existing five hosted-surface additions
remain included.

The full static fetch covered 366 distinct vendor URLs: 283 returned 200, 47
returned 403, 28 returned 404, 2 returned 429, and 6 returned other HTTP/error
outcomes. A blocked or missing page was not treated as selector proof.
