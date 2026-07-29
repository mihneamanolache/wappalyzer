# Wappalyzer

[Wappalyzer](https://www.wappalyzer.com/) identifies technologies on websites.

*Note:* The [wappalyzer-core](https://www.npmjs.com/package/wappalyzer-core) package provides a low-level API without dependencies.

## This fork

A fork of Wappalyzer with a locally maintained technology catalog. Technology
definitions are pulled from [enthec/webappanalyzer](https://github.com/enthec/webappanalyzer)
and merged additively with fork-local entries and enrichments.

### Requirements

Node **22.12.0 or newer** (pinned in `.nvmrc` / `.node-version`, enforced by
`engines.node` with `engine-strict=true`). Puppeteer 25 is ESM-only and fails to
load on older runtimes, so `driver.js` checks the version before requiring it and
reports which Node you are on.

```shell
nvm use               # picks up .nvmrc
npm ci
```

```shell
npm test              # unit suite + CLI smoke test
npm run test:unit     # unit suite only
npm run test:cli      # CLI smoke test only (loads the real require chain)
npm run validate      # is the catalog coherent with the engine?
npm run update        # pull upstream, merge, normalize, validate
npm run coverage      # coverage against the local request list, if present
```

`npm run coverage` cross-references a requested product list against the catalog.
That list belongs to a third party, so `data/requested-products.json` and
`scripts/lib/requested-mapping.js` are not tracked here and the command reports
that it has nothing to do. The aggregate result is committed as
**[docs/coverage-summary.md](docs/coverage-summary.md)**; the suites that need the
per-product inputs skip with a reason rather than fail.

The DNS sweep and xhr audit corpora and their retained results are likewise
untracked — they are bulky generated measurements. Regenerate them with
`npm run sweep` and `npm run audit:xhr`. `scripts/lib/untracked.js` is the single
place that records which local-only inputs exist and what skips without them, so a
clone runs a smaller suite with zero failures instead of a broken one.

**[docs/CATALOG.md](docs/CATALOG.md)** documents the detection channels, the
shapes the engine actually reads, the evidence standard for new fingerprints, and
the maintenance workflow. Read it before editing `technologies/*.json` — the
engine ignores unknown fields and wrong-shaped channels without erroring, so a
mistake there costs a detection rather than raising one.

Differences from upstream worth knowing about:

- **Catalog defects are collected, not thrown.** A dangling `implies`/`excludes`
  reference used to abort a whole scan. It is now recorded on
  `Wappalyzer.errors` and surfaced by the validator, so one bad entry cannot take
  down a run. `WAPPALYZER_DEBUG=1` prints them at load time.
- **`saas` and `oss`** are curated in the catalog and included in the output.
  Upstream drops them.
- **Fork-local categories** start at id 200, splitting upstream's single
  "Artificial Intelligence" bucket into finer distinctions.
- **`analyzeJs` and `analyzeDom`** live in `wappalyzer.js` rather than
  `driver.js`, so they are testable without a browser.
- **Text-mined signals** (`textSignals: true`) add a second, lower-confidence
  source for technologies that emit nothing observable — endpoint agents, a
  Postgres extension, a terminal editor. They are returned in a separate
  `signals` array and are never merged into `technologies`.

## Command line

### Installation

```shell
$ npm i -g wappalyzer
```

### Usage

```
wappalyzer <url> [options]
```

#### Options

```
-b, --batch-size=...       Process links in batches
-d, --debug                Output debug messages
-t, --delay=ms             Wait for ms milliseconds between requests
-h, --help                 This text
-H, --header               Extra header to send with requests
--html-max-cols=...        Limit the number of HTML characters per line processed
--html-max-rows=...        Limit the number of HTML lines processed
-D, --max-depth=...        Don't analyse pages more than num levels deep
-m, --max-urls=...         Exit when num URLs have been analysed
-w, --max-wait=...         Wait no more than ms milliseconds for page resources to load
-p, --probe=[basic|full]   Perform a deeper scan by performing additional requests and inspecting DNS records
-P, --pretty               Pretty-print JSON output
--proxy=...                Proxy URL, e.g. 'http://user:pass@proxy:8080'
-r, --recursive            Follow links on pages (crawler)
-a, --user-agent=...       Set the user agent string
-n, --no-scripts           Disabled JavaScript on web pages
-N, --no-redirect          Disable cross-domain redirects
-e, --extended             Output additional information
--local-storage=...        JSON object to use as local storage
--session-storage=...      JSON object to use as session storage
--defer=ms                 Defer scan for ms milliseconds after page load
-T, --text-signals         Also infer technologies from careers/stack page text
                           (returned separately as `signals`, confidence 30)

```


## Dependency

### Installation

```shell
$ npm i wappalyzer
```

### Usage

```javascript
const Wappalyzer = require('wappalyzer')

const url = 'https://www.wappalyzer.com'

const options = {
  debug: false,
  delay: 500,
  headers: {},
  maxDepth: 3,
  maxUrls: 10,
  maxWait: 5000,
  recursive: true,
  probe: true,
  proxy: false,
  userAgent: 'Wappalyzer',
  htmlMaxCols: 2000,
  htmlMaxRows: 2000,
  noScripts: false,
  noRedirect: false,
};

const wappalyzer = new Wappalyzer(options)

;(async function() {
  try {
    await wappalyzer.init()

    // Optionally set additional request headers
    const headers = {}

    // Optionally set local and/or session storage
    const storage = {
      local: {}
      session: {}
    }

    const site = await wappalyzer.open(url, headers, storage)

    // Optionally capture and output errors
    site.on('error', console.error)

    const results = await site.analyze()

    console.log(JSON.stringify(results, null, 2))
  } catch (error) {
    console.error(error)
  }

  await wappalyzer.destroy()
})()
```

Multiple URLs can be processed in parallel:

```javascript
const Wappalyzer = require('wappalyzer');

const urls = ['https://www.wappalyzer.com', 'https://www.example.com']

const wappalyzer = new Wappalyzer()

;(async function() {
  try {
    await wappalyzer.init()

    const results = await Promise.all(
      urls.map(async (url) => {
        const site = await wappalyzer.open(url)

        const results = await site.analyze()

        return { url, results }
      })
    )

    console.log(JSON.stringify(results, null, 2))
  } catch (error) {
    console.error(error)
  }

  await wappalyzer.destroy()
})()
```

### Events

Listen to events with `site.on(eventName, callback)`. Use the `page` parameter to access the Puppeteer page instance ([reference](https://github.com/puppeteer/puppeteer/blob/main/docs/api.md#class-page)).

| Event       | Parameters                     | Description                              |
|-------------|--------------------------------|------------------------------------------|
| `log`       | `message`, `source`            | Debug messages                           |
| `error`     | `message`, `source`            | Error messages                           |
| `request`   | `page`, `request`              | Emitted at the start of a request        |
| `response`  | `page`, `request`              | Emitted upon receiving a server response |
| `goto`      | `page`, `url`, `html`, `cookies`, `scriptsSrc`, `scripts`, `meta`, `js`, `language` `links` | Emitted after a page has been analysed |
| `analyze`   | `urls`, `technologies`, `meta` | Emitted when the site has been analysed |
