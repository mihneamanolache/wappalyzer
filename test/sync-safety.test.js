'use strict'

/**
 * Proves an upstream catalog sync cannot restore removed false positives.
 *
 * The merge is additive by design (scripts/lib/merge.js), so deleting an
 * unsafe pattern from the tree is not durable on its own: the next sync
 * unions it straight back in if upstream still ships it. The durable layer is
 * normalize.js, which runs on every merge and applies the shared policy in
 * scripts/lib/control-corpus.js. These tests run the real merge and
 * normalization code paths against an adversarial upstream that ships every
 * historical offender, and assert none of them survive.
 */

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('path')

const Wappalyzer = require('../wappalyzer')
const { loadCatalog } = require('../scripts/lib/catalog')
const { mergeCatalog } = require('../scripts/lib/merge')
const { normalizeCatalog } = require('../scripts/lib/normalize')
const {
    CONTROL_URLS,
    GUARDED_CHANNELS,
    SUPPRESSED_PATTERNS,
    URL_CHANNEL_EXEMPT,
} = require('../scripts/lib/control-corpus')

const ROOT = path.resolve(__dirname, '..')
const local = loadCatalog(path.join(ROOT, 'technologies')).technologies

/**
 * An upstream that ships every suppressed pattern verbatim, in the channel it
 * was removed from — the exact payload a hostile (or merely stale) sync would
 * deliver.
 */
function adversarialUpstream() {
    const upstream = {}

    for (const [name, channels] of Object.entries(SUPPRESSED_PATTERNS)) {
        upstream[name] = { cats: [19] }

        for (const [channel, patterns] of Object.entries(channels)) {
            upstream[name][channel] = [...patterns]
        }
    }

    // A brand-new upstream technology carrying generic markers on both
    // URL-shaped channels, plus a path-dependent xhr pattern that the
    // normalizer relocates into xhrUrl. Every route into the live channels
    // is exercised.
    upstream['Example Emerging Vendor'] = {
        cats: [19],
        xhr: ['/v1/config'],
        xhrUrl: ['/api/2.0/jobs', '/v1/status'],
        url: ['/ui/'],
    }

    return upstream
}

const merged = mergeCatalog(local, adversarialUpstream())
const { technologies } = normalizeCatalog(merged.technologies)

const patternsOf = (value) =>
    value === undefined ? [] : Array.isArray(value) ? value : [value]

test('an upstream merge does not restore any suppressed pattern', () => {
    const restored = []

    for (const [name, channels] of Object.entries(SUPPRESSED_PATTERNS)) {
        const entry = technologies[name]

        assert.ok(entry, `${name} survives the merge`)

        for (const [channel, patterns] of Object.entries(channels)) {
            const merged = patternsOf(entry[channel]).map(String)

            for (const pattern of patterns) {
                if (merged.includes(pattern)) {
                    restored.push(`${name}.${channel}: ${pattern}`)
                }
            }
        }
    }

    assert.deepEqual(restored, [])
})

test('after an upstream merge, no live URL pattern matches a control URL', () => {
    const overBroad = []

    for (const [name, entry] of Object.entries(technologies)) {
        for (const channel of GUARDED_CHANNELS) {
            if (channel === 'url' && URL_CHANNEL_EXEMPT.has(name)) {
                continue
            }

            for (const pattern of patternsOf(entry[channel])) {
                if (typeof pattern !== 'string') {
                    continue
                }

                let regex

                try {
                    ;({ regex } = Wappalyzer.parsePattern(pattern))
                } catch (error) {
                    continue
                }

                const control = CONTROL_URLS.find((url) => regex.test(url))

                if (control) {
                    overBroad.push(`${name}.${channel}: ${pattern} [${control}]`)
                }
            }
        }
    }

    assert.deepEqual(overBroad, [])
})

test('a new upstream technology cannot smuggle generic markers in', () => {
    const entry = technologies['Example Emerging Vendor']

    assert.ok(entry, 'the new upstream technology itself is kept')
    assert.equal(entry.xhrUrl, undefined, 'its generic xhrUrl patterns are dropped')
    assert.equal(entry.url, undefined, 'its generic url pattern is dropped')
    assert.equal(
        entry.xhr,
        undefined,
        'its path-dependent xhr pattern is not relocated into xhrUrl'
    )
})

test('label-anchored Databricks patterns hold against spoofs but keep real hosts', () => {
    const compiled = patternsOf(technologies.Databricks.xhrUrl)
        .concat(patternsOf(technologies['Databricks (AWS)'].xhrUrl))
        .map((pattern) => Wappalyzer.parsePattern(pattern).regex)

    const spoofs = [
        'https://evilazuredatabricks.net/api/2.0/jobs',
        'https://cloud.databricks.com.evil.example/api/2.0/jobs',
        'https://gcp.databricks.com.evil.example/api/2.1/sql',
        'https://xcloud.databricks.com/api/2.0/workspace',
        'https://evil.example/?next=https://adb-1.azuredatabricks.net/api/2.0/jobs',
    ]

    for (const spoof of spoofs) {
        assert.ok(
            compiled.every((regex) => !regex.test(spoof)),
            `spoof must not match: ${spoof}`
        )
    }

    const genuine = [
        'https://dbc-abc123.cloud.databricks.com/api/2.0/jobs/list',
        'https://adb-1234567890.11.azuredatabricks.net/api/2.1/clusters/get',
        'https://123456.7.gcp.databricks.com/api/2.0/workspace/list',
    ]

    for (const url of genuine) {
        assert.ok(
            compiled.some((regex) => regex.test(url)),
            `genuine workspace URL must match: ${url}`
        )
    }
})
