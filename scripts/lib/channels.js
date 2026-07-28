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
