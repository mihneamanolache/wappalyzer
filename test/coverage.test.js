'use strict'

/**
 * Tests for the request-to-catalog mapping and the coverage report.
 *
 * The report is what gets sent onward, so the important property is that it
 * cannot overstate coverage: nothing may be reported as detectable unless the
 * entry it maps to has a real detection channel.
 */

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const path = require('path')
const { execFileSync } = require('child_process')

const { loadCatalog } = require('../scripts/lib/catalog')
const { classify, normalize } = require('../scripts/lib/dnb-mapping')
const { CHANNELS } = require('../scripts/lib/channels')

const ROOT = path.resolve(__dirname, '..')

const request = JSON.parse(
    fs.readFileSync(path.join(ROOT, 'data/dnb-request.json'), 'utf8')
)
const { technologies } = loadCatalog(path.join(ROOT, 'technologies'))

const byNormalizedName = new Map(
    Object.keys(technologies).map((name) => [normalize(name), name])
)

const report = JSON.parse(
    execFileSync(
        process.execPath,
        [path.join(ROOT, 'scripts/coverage-report.js'), '--json'],
        { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }
    )
)

const hasChannel = (name) =>
    Object.keys(CHANNELS).some((channel) => technologies[name][channel] !== undefined)

test('the request data covers the whole source list', () => {
    assert.equal(request.products.length, 402)
    assert.equal(request.priorities.length, 2)
    assert.equal(request.categories.length, 7)
})

test('every product is classified', () => {
    assert.equal(report.products.length, request.products.length)

    const unclassified = report.products.filter(({ status }) => !status)

    assert.deepEqual(unclassified, [])
})

test('nothing reported as detectable lacks a detection path', () => {
    // This is the property that keeps the report honest. A detection path is a
    // channel of the entry's own, or being the target of another technology's
    // implies (PostgreSQL surfaces whenever Supabase or Django is detected).
    const impliedTargets = new Set()

    for (const entry of Object.values(technologies)) {
        const implies = entry.implies

        for (const item of implies === undefined
            ? []
            : Array.isArray(implies)
                ? implies
                : [implies]) {
            impliedTargets.add(String(item).split('\\;')[0].trim())
        }
    }

    const overstated = report.products
        .filter(({ status }) => ['detected', 'platform-level'].includes(status))
        .filter(
            ({ mapsTo }) =>
                !mapsTo ||
                !technologies[mapsTo] ||
                (!hasChannel(mapsTo) && !impliedTargets.has(mapsTo))
        )
        .map(({ product, mapsTo }) => `${product} -> ${mapsTo}`)

    assert.deepEqual(overstated, [])
})

test('every mapping target exists in the catalog', () => {
    const missing = report.products
        .filter(({ mapsTo }) => mapsTo)
        .filter(({ mapsTo }) => !technologies[mapsTo])
        .map(({ product, mapsTo }) => `${product} -> ${mapsTo}`)

    assert.deepEqual(missing, [])
})

test('both flagged priorities resolve to an entry with a channel', () => {
    assert.equal(report.priorities.length, 2)

    for (const priority of report.priorities) {
        assert.ok(
            priority.resolved,
            `priority not resolved: ${priority.request}`
        )
        assert.ok(
            priority.channels.length,
            `${priority.resolved} has no detection channel`
        )
    }

    assert.deepEqual(
        report.priorities.map(({ resolved }) => resolved),
        ['Samsara', 'Verizon Connect']
    )
})

test('the Samsara priority reports a product-level child', () => {
    const [samsara] = report.priorities

    assert.deepEqual(
        samsara.related.map(({ name }) => name),
        ['Samsara Assistant']
    )
    assert.deepEqual(samsara.related[0].channels, [])

    const assistant = report.products.find(
        ({ product }) => product === 'Samsara Assistant'
    )

    assert.equal(assistant.status, 'platform-level')
    assert.equal(assistant.mapsTo, 'Samsara')
})

test('the Verizon Connect priority is distinct from the other Verizon entry', () => {
    const [, verizonConnect] = report.priorities

    assert.equal(verizonConnect.resolved, 'Verizon Connect')

    // The request says "currently track Verizon". There is no `Verizon` entry:
    // what exists is `Verizon Media`, an advertising platform unrelated to
    // fleet telematics. So the two were never conflated, and the new entry does
    // not disturb the existing one.
    assert.equal(technologies.Verizon, undefined)
    assert.ok(technologies['Verizon Media'])
    assert.deepEqual(technologies['Verizon Media'].cats, [36]) // Advertising
    assert.notDeepEqual(
        technologies['Verizon Media'].cats,
        technologies['Verizon Connect'].cats
    )
})

test('a model is reported against the API that serves it, never invented', () => {
    // A model name has no fingerprint. Where the vendor runs a hosted API, that
    // API is the honest answer; the status stays `platform-level` so the report
    // never implies the model itself was fingerprinted.
    const cases = {
        'Llama 4': 'Llama API',
        'Grok 3': 'xAI Grok',
        'GLM-4': 'Zhipu AI',
        'Qwen 2.5': 'Alibaba Cloud Model Studio',
        'Amazon Nova': 'Amazon Bedrock',
    }

    for (const [product, expected] of Object.entries(cases)) {
        const result = classify({ product, vendor: '' }, byNormalizedName)

        assert.equal(result.mapsTo, expected, `${product} should map to ${expected}`)
        assert.equal(result.status, 'platform-level')
    }
})

/**
 * The irreducible set: products with no externally observable signal of any
 * kind. This test exists to stop the number being inflated later by a pattern
 * that cannot fire. Anything removed from here must come with real evidence and
 * a detection test in test/dnb-technologies.test.js.
 */
const UNDETECTABLE = {
    // A Postgres extension and an edge hardware module: nothing is emitted.
    pgvector: 'catalog-only',
    'NVIDIA Jetson Orin': 'catalog-only',
    // A protocol rather than a deployed service; no stable public endpoint.
    'Anthropic MCP': 'catalog-only',
    // Local editors with no web surface.
    Neovim: 'catalog-only',
    Zed: 'catalog-only',
    // Endpoint, network and cloud-posture security. These run as agents or
    // out-of-band scanners. Their consoles are reachable only from inside the
    // customer tenant. The earlier TXT sweep did not retain its input corpus or
    // raw records, so its negative result is not used as release evidence.
    'CrowdStrike Falcon': 'catalog-only',
    'CrowdStrike Charlotte AI': 'catalog-only',
    SentinelOne: 'catalog-only',
    'SentinelOne Purple AI': 'catalog-only',
    'Zscaler AI': 'catalog-only',
    'Netskope SkopeAI': 'catalog-only',
    'Orca Security': 'catalog-only',
    Lacework: 'catalog-only',
    'Abnormal Security AI': 'catalog-only',
    Phind: 'catalog-only',
}

test('the irreducible set is reported as undetectable, not faked', () => {
    for (const [product, expected] of Object.entries(UNDETECTABLE)) {
        const result = classify({ product, vendor: '' }, byNormalizedName)

        assert.equal(
            result.status,
            expected,
            `${product} has no observable signal and must stay ${expected}`
        )
    }
})

test('the report accounts for every product with no gaps', () => {
    const undetectable = report.products.filter(({ status }) =>
        ['model', 'backend', 'endpoint', 'desktop', 'catalog-only'].includes(status)
    )

    // Everything not detectable must be one of the known-impossible cases.
    const unexpected = undetectable
        .filter(({ product }) => !(product in UNDETECTABLE))
        .map(({ product, status }) => `${product} (${status})`)

    assert.deepEqual(
        unexpected,
        [],
        'a new undetectable product appeared; either find a signal or document it'
    )
})

test('an AI feature maps to the platform that is actually observable', () => {
    const cases = {
        'Jira AI': 'Atlassian Jira',
        'Notion AI': 'Notion',
        'Slack AI': 'Slack',
        'Box AI': 'Box',
        'Figma AI': 'Figma',
        'ClickUp Brain': 'ClickUp',
        'Geotab Ace': 'Geotab',
    }

    for (const [product, expected] of Object.entries(cases)) {
        const result = classify({ product, vendor: '' }, byNormalizedName)

        assert.equal(result.mapsTo, expected, `${product} should map to ${expected}`)
        assert.equal(result.status, 'platform-level')
    }
})

test('the markdown report renders without error', () => {
    const markdown = execFileSync(
        process.execPath,
        [path.join(ROOT, 'scripts/coverage-report.js'), '--markdown'],
        { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }
    )

    assert.match(markdown, /^# Emerging technology coverage/)
    assert.match(markdown, /## Flagged priorities/)
    assert.match(markdown, /Samsara/)
    assert.match(markdown, /Verizon Connect/)
})

test('the counts add up to the full list', () => {
    const total = Object.values(report.counts).reduce((sum, n) => sum + n, 0)

    assert.equal(total, request.products.length)
})

test('the report distinguishes catalog reachability from retained live evidence', () => {
    assert.ok(report.evidenceSummary.uniqueMappedTargets > 0)
    assert.deepEqual(
        report.evidenceSummary.liveObservedTargets.sort(),
        [
            'Claude Enterprise',
            'Samsara',
            'Verizon Connect',
            'Verizon Connect Reveal',
        ].sort()
    )
})
