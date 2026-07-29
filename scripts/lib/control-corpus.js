'use strict'

/**
 * Shared false-positive policy for URL-shaped detection channels.
 *
 * `url` and `xhrUrl` patterns are tested against full URLs at confidence 100,
 * so a pattern describing only a generic path (`/v1/config`, `/api/2.0/`)
 * detects its vendor on arbitrary domains. This module is the single source of
 * truth for what "too generic" means, shared by:
 *
 *   scripts/lib/normalize.js   drops offending patterns on every merge, so an
 *                              additive upstream sync cannot restore one
 *   test/catalog.test.js       fails if the committed tree contains one
 *   test/sync-safety.test.js   proves an actual upstream merge stays clean
 *
 * Extend CONTROL_URLS when a new generic shape is found; extend
 * SUPPRESSED_PATTERNS when a specific upstream pattern must stay out even if
 * the corpus is later reshuffled.
 */

/**
 * Benign URLs no vendor should ever be detected from. Ordinary pages first,
 * then adversarial generic REST-API shapes, then hostname spoofs that probe
 * for patterns anchored to text fragments instead of DNS labels.
 */
const CONTROL_URLS = [
    'https://example.com/',
    'https://example.com/index.html',
    'https://example.com/about/team',
    'https://cdn.example.com/assets/app.js?v=2',
    'https://example.com/api/v1/users',
    'http://example.com/a/b/c',
    // Generic REST-API shapes on unrelated hosts. A path alone is not a
    // fingerprint — any pattern that fires on one of these would tag
    // arbitrary sites at full confidence.
    'https://example.com/v1/config',
    'https://example.com/v1/status',
    'https://example.com/v1/info',
    'https://example.com/v1/query',
    'https://example.com/v1/statement',
    'https://example.com/v1/namespaces',
    'https://example.com/v1/tables',
    'https://example.com/api/2.0/jobs',
    'https://api.example.com/api/2.1/clusters/list',
    'https://example.com/apiv2/login',
    'https://example.com/apiv2/server_status',
    'https://shop.example.com/cart.js',
    'https://shop.example.com/search/suggest.json',
    'https://shop.example.com/recommendations/products.json',
    'https://example.com/api/v1/status',
    'https://example.com/systems/prod/queries',
    'https://example.com/api/query/systems/prod/queries',
    'https://api.example.com/models/gpt-4/embeddings',
    'https://example.com/ui/',
    'https://example.com/api/v2/users',
    'https://example.com/rest/v1/items',
    'https://example.com/graphql',
    'https://example.com/api/login',
    'https://example.com/v2/config',
    // Hostname spoofs: a vendor domain embedded in an attacker-controlled
    // name. Patterns must anchor at the URL host and respect label
    // boundaries, so none of these may match.
    'https://evilazuredatabricks.net/api/2.0/jobs',
    'https://cloud.databricks.com.evil.example/api/2.0/jobs',
    'https://gcp.databricks.com.evil.example/api/2.1/sql',
    'https://xcloud.databricks.com/api/2.0/workspace',
]

/**
 * Technologies whose `url` patterns are deliberately generic: they describe a
 * page *kind*, not a vendor, so matching a control URL is their job. Nothing
 * on `xhrUrl` is exempt — that channel exists to fingerprint vendor APIs.
 */
const URL_CHANNEL_EXEMPT = new Set(['Cart Functionality', 'JavaScript'])

/**
 * Exact patterns that must never re-enter the catalog, keyed by technology and
 * channel. Each was removed as a false-positive generator (review of
 * 2026-07-29); the additive upstream merge would otherwise restore any of them
 * verbatim. The corpus gate above catches these too — this list is the
 * explicit record, and holds even if CONTROL_URLS is later reshuffled.
 */
const SUPPRESSED_PATTERNS = {
    'Apache Iceberg': {
        xhrUrl: ['/v1/config', '/v1/namespaces', '/v1/tables'],
    },
    Trino: {
        url: ['/ui/', '/v1/info', '/v1/status'],
        xhrUrl: ['/v1/info', '/v1/status', '/v1/statement', '/v1/query'],
    },
    'Open Source Presto': {
        url: ['/ui/(?:index\\.html)?(?:\\?|$)', '/v1/(?:info|query|statement)'],
    },
    Databricks: {
        // The first is path-only; the second anchored text fragments, not DNS
        // labels, so evilazuredatabricks.net matched.
        url: [
            '(?:azuredatabricks\\.net|cloud\\.databricks\\.com|gcp\\.databricks\\.com|databricksapps\\.com)',
        ],
        xhrUrl: [
            '/api/2\\.[01]/(?:jobs|clusters|dbfs|workspace|permissions|sql|secrets|mlflow|serving-endpoints)(?:/|$)',
            '(?:azuredatabricks\\.net|(?:cloud|gcp)\\.databricks\\.com)/api/2\\.[01]/(?:jobs|clusters|dbfs|workspace|permissions|sql|secrets|mlflow|serving-endpoints)(?:/|$)',
        ],
    },
    'Databricks (AWS)': {
        xhrUrl: [
            '/api/2\\.0/',
            '/api/2\\.1/',
            '\\.cloud\\.databricks\\.com/api/2\\.[01]/',
        ],
    },
    Dremio: {
        // The probe on /apiv2/server_status carries the content check; the
        // path alone contains no vendor token.
        xhrUrl: ['/apiv2/server_status', '/apiv2/login'],
    },
    'Shopify Business': {
        xhrUrl: [
            '/cart\\.js',
            '/search/suggest\\.json',
            '/recommendations/products\\.json',
        ],
    },
    'Teradata Vantage': {
        xhrUrl: [
            '/(?:api/query|qs)/systems/[^/]+/(?:queries|sessions|databases|views)(?:[/?]|$)',
            '/systems?/[^/]+/queries(?:[/?]|$)',
        ],
    },
    'Salesforce Sales Cloud Einstein': {
        xhrUrl: [
            '/models/[\\w\\.-]+/(?:generations|chat-generations|embeddings)(?:/|$)',
        ],
    },
}

/** The channels the corpus gate applies to. */
const GUARDED_CHANNELS = ['url', 'xhrUrl']

/**
 * The first control URL a pattern matches, or null. An uncompilable pattern
 * returns null — the validator owns reporting those.
 *
 * @param {string} pattern
 * @param {(pattern: string) => RegExp} compile
 * @returns {string|null}
 */
function matchesControl(pattern, compile) {
    let regex

    try {
        regex = compile(pattern)
    } catch (error) {
        return null
    }

    return CONTROL_URLS.find((control) => regex.test(control)) || null
}

module.exports = {
    CONTROL_URLS,
    GUARDED_CHANNELS,
    SUPPRESSED_PATTERNS,
    URL_CHANNEL_EXEMPT,
    matchesControl,
}
