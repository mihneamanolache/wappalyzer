'use strict'

/**
 * Single source of truth for what wappalyzer.js actually consumes from
 * technologies/*.json, and in what shape.
 *
 * Every other script (validate, normalize, merge) reads this so the catalog
 * schema is defined in exactly one place. If the engine gains a channel, add it
 * here and the rest follows.
 */

/**
 * Detection channels and how the engine matches them:
 *
 *   oo    one-to-one    matched against a single string      (analyzeOneToOne)
 *   om    one-to-many   matched against a list of strings    (analyzeOneToMany)
 *   mm    many-to-many  keyed object; key selects the value  (analyzeManyToMany)
 *   dom   selector list or selector -> rule object
 *   probe keyed by request path -> body pattern
 *
 * The distinction matters because `oo`/`om` take a string or array while `mm`
 * needs a keyed object. Getting it wrong yields a pattern that never matches
 * rather than an error, which is the defect class validate.js exists to catch.
 */
const CHANNELS = {
    certIssuer: 'oo',
    cookies: 'mm',
    css: 'oo',
    dns: 'mm',
    dom: 'dom',
    headers: 'mm',
    html: 'oo',
    js: 'mm',
    meta: 'mm',
    probe: 'probe',
    robots: 'oo',
    scriptSrc: 'om',
    scripts: 'oo',
    text: 'oo',
    url: 'oo',
    xhr: 'oo',
    // Full request URL for the same requests `xhr` sees. `xhr` gets the bare
    // hostname, which is why a pattern needing a path belongs here instead.
    xhrUrl: 'oo',
}

/** Channels whose value is a string, number or array of them. */
const FLAT_CHANNELS = Object.keys(CHANNELS).filter((channel) =>
    ['oo', 'om'].includes(CHANNELS[channel])
)

/** Channels whose value is a keyed object of patterns. */
const KEYED_CHANNELS = Object.keys(CHANNELS).filter((channel) =>
    ['mm', 'probe'].includes(CHANNELS[channel])
)

/** Fields naming another technology. */
const REFERENCE_FIELDS = ['implies', 'excludes', 'requires']

/** Non-pattern fields the engine reads, and the type each must have. */
const METADATA = {
    cats: 'intArray',
    cpe: 'string',
    description: 'string',
    excludes: 'reference',
    icon: 'string',
    implies: 'reference',
    oss: 'boolean',
    pricing: 'stringArray',
    requires: 'reference',
    requiresCategory: 'intArray',
    saas: 'boolean',
    website: 'string',
}

/** Metadata that is a set and should be unioned when merging. */
const LIST_METADATA = ['cats', 'pricing', 'requiresCategory']

/** Metadata that is a single value and cannot be merged, only chosen. */
const SCALAR_METADATA = [
    'cpe',
    'description',
    'icon',
    'oss',
    'saas',
    'website',
]

const KNOWN_FIELDS = new Set([
    ...Object.keys(CHANNELS),
    ...Object.keys(METADATA),
])

/** DOM rule keys the in-page collector understands. */
const DOM_RULES = ['exists', 'text', 'properties', 'attributes']

/**
 * DNS record types driver.js actually resolves. A `dns` key outside this set is
 * never populated, so its patterns cannot fire. Keys are compared lowercased
 * because transformPatterns lowercases keyed-channel keys.
 */
const DNS_RECORDS = ['cname', 'mx', 'ns', 'soa', 'txt']

/**
 * Hostname-shaped candidates used to prove an `xhr` pattern can still fire.
 * Real hostnames observed during the xhr audit, plus generic shapes.
 */
const HOSTNAME_CANDIDATES = [
    'example.com',
    'api.example.com',
    'a.b.c.example.com',
    'tenant.api.example.com',
    'localhost',
    '10.0.0.1',
    'sub.domain.co.uk',
    'x.amazonaws.com',
    'eks.us-east-1.amazonaws.com',
    'runtime.sagemaker.eu-west-1.amazonaws.com',
    'acme.wd5.myworkday.com',
    'gw.tidbcloud.com',
]

/** Crude slash-free expansion of a pattern's literal skeleton. */
function hostnameSkeleton(pattern) {
    const expanded = String(pattern)
        .replace(/\\\//g, '/')
        .replace(/\\\./g, '.')
        .replace(/\(\?:([^)|]*)\|[^)]*\)/g, '$1')
        .replace(/\(\?[:=!][^)]*\)/g, '')
        .replace(/[()[\]{}^$?*+]/g, '')
        .replace(/\\[dw]/g, '1')
        .replace(/\\[sb]/g, '')

    return expanded.split('/')[0]
}

/**
 * Can this pattern match at least one string containing no slash?
 *
 * `xhr` is fed bare hostnames, so a pattern requiring a path or a URL scheme can
 * never fire there and belongs in `xhrUrl`. Finding a slash-free match is proof of
 * life; failing to find one is evidence, not proof, so callers treat an
 * unambiguous case (leading slash, mandatory scheme) as certain and the rest as
 * suspect.
 *
 * @param {string} pattern
 * @param {function(string): RegExp} compile how the engine compiles a pattern
 */
function canMatchHostname(pattern, compile) {
    let regex

    try {
        regex = compile(pattern)
    } catch (error) {
        return true // an uncompilable pattern is reported elsewhere
    }

    return [...HOSTNAME_CANDIDATES, hostnameSkeleton(pattern)]
        .filter((candidate) => candidate && !candidate.includes('/'))
        .some((candidate) => regex.test(candidate))
}

/** Is the pattern unambiguously a path or URL rather than a hostname? */
function requiresPathOrScheme(pattern) {
    const text = String(pattern)

    return /^\^?(?:\\?\/)/.test(text) || /:\\?\/\\?\//.test(text)
}

const isPlainObject = (value) =>
    value !== null && typeof value === 'object' && !Array.isArray(value)

const isScalar = (value) =>
    typeof value === 'string' || typeof value === 'number'

const toArray = (value) => (Array.isArray(value) ? value : [value])

/**
 * Which technologies/*.json file a technology belongs in.
 * @param {string} name
 */
function fileForTechnology(name) {
    const first = String(name).charAt(0).toLowerCase()

    return /^[a-z]$/.test(first) ? `${first}.json` : '_.json'
}

module.exports = {
    CHANNELS,
    HOSTNAME_CANDIDATES,
    canMatchHostname,
    hostnameSkeleton,
    requiresPathOrScheme,
    DNS_RECORDS,
    DOM_RULES,
    FLAT_CHANNELS,
    KEYED_CHANNELS,
    KNOWN_FIELDS,
    LIST_METADATA,
    METADATA,
    REFERENCE_FIELDS,
    SCALAR_METADATA,
    fileForTechnology,
    isPlainObject,
    isScalar,
    toArray,
}
