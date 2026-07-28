'use strict'

/**
 * Tests that the DNS tenant markers we ship are backed by retained evidence.
 *
 * A `dns.TXT` marker is a claim about the real world: "companies publish this
 * record". An earlier sweep established that but kept no corpus, so the claim was
 * unverifiable. These tests assert the corpus and results are present, that they
 * cover the markers actually in the catalog, and that no marker added for the
 * request is unobserved.
 *
 * No DNS queries are made here. `node scripts/dns-sweep.js` refreshes the
 * retained results; this suite only checks them.
 */

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const path = require('path')
const { execFileSync } = require('child_process')

const { loadCatalog } = require('../scripts/lib/catalog')
const { TXT, TXT_ENRICH } = require('../scripts/lib/dnb-technologies')

const ROOT = path.resolve(__dirname, '..')
const CORPUS = path.join(ROOT, 'data/dns-sweep-domains.txt')
const RESULTS = path.join(ROOT, 'data/dns-sweep-results.json')

test('the sweep corpus is committed', () => {
    assert.ok(fs.existsSync(CORPUS), 'data/dns-sweep-domains.txt must exist')

    const domains = fs
        .readFileSync(CORPUS, 'utf8')
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#'))

    assert.ok(
        domains.length >= 500,
        `corpus should be substantial, found ${domains.length}`
    )

    const malformed = domains.filter((domain) => !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain))

    assert.deepEqual(malformed, [], 'every corpus line should be a bare domain')

    assert.equal(
        new Set(domains).size,
        domains.length,
        'the corpus should not repeat domains'
    )
})

test('the retained results describe the corpus that produced them', () => {
    assert.ok(fs.existsSync(RESULTS), 'data/dns-sweep-results.json must exist')

    const results = JSON.parse(fs.readFileSync(RESULTS, 'utf8'))

    assert.equal(results.corpus, 'data/dns-sweep-domains.txt')
    assert.ok(results.corpusDomains >= 500)
    assert.ok(
        results.domainsWithTxt > 0 && results.domainsWithTxt <= results.corpusDomains
    )
    assert.ok(results.txtRecordsSeen > 1000, 'a real sweep sees many records')
    assert.equal(
        results.markersObserved + results.markersUnobserved,
        results.markersChecked,
        'observed and unobserved should account for every marker'
    )
})

test('every marker added for this request has retained evidence', () => {
    // Deliberately checks the exact (technology, pattern) pair, not just the
    // technology name. Comparing names alone hid that six original patterns had
    // been superseded during redundancy removal while the name still appeared as
    // observed via a different pattern.
    const { EVIDENCE } = require('../scripts/lib/dnb-technologies')

    const acceptable = new Set([
        'corpus-observed',
        'corpus-observed-via-equivalent',
        'live-observed',
        'official-documented',
    ])

    const added = [...new Set([...Object.keys(TXT), ...Object.keys(TXT_ENRICH)])]
    const unbacked = added
        .filter((technology) => !acceptable.has(EVIDENCE[technology].verification))
        .map((technology) => `${technology}: ${EVIDENCE[technology].verification}`)

    assert.deepEqual(
        unbacked,
        [],
        'these markers have no retained evidence; re-run `npm run sweep` or ' +
            'remove them'
    )
})

test('the exact marker strings still in the catalog are the ones swept', () => {
    // Guards the distinction the previous version of this test missed: a
    // technology counted as observed even when the specific pattern shipped was
    // absent from the sweep.
    const results = JSON.parse(fs.readFileSync(RESULTS, 'utf8'))
    const observedPairs = new Set(
        results.observed.map(({ technology, pattern }) => `${technology} ${pattern}`)
    )

    const { technologies } = loadCatalog(path.join(ROOT, 'technologies'))

    const exact = []
    const viaEquivalent = []

    for (const technology of [
        ...new Set([...Object.keys(TXT), ...Object.keys(TXT_ENRICH)]),
    ]) {
        const entry = technologies[technology]
        const record = entry && entry.dns
        const txt = record && (record.TXT === undefined ? record.txt : record.TXT)

        for (const pattern of txt === undefined
            ? []
            : Array.isArray(txt)
                ? txt
                : [txt]) {
            if (observedPairs.has(`${technology} ${pattern}`)) {
                exact.push(`${technology} ${pattern}`)
            } else {
                viaEquivalent.push(`${technology} ${pattern}`)
            }
        }
    }

    // Every shipped pattern is either observed itself, or belongs to a technology
    // that is observed through another pattern. Nothing is unaccounted for.
    const { EVIDENCE } = require('../scripts/lib/dnb-technologies')

    for (const pair of viaEquivalent) {
        const technology = pair.slice(0, pair.lastIndexOf(' '))

        assert.ok(
            ['corpus-observed-via-equivalent', 'live-observed', 'official-documented']
                .includes(EVIDENCE[technology].verification),
            `${pair} is neither observed nor explained by an equivalent`
        )
    }

    assert.ok(exact.length > 40, `expected most patterns observed exactly, got ${exact.length}`)
})

test('the retained results cover the markers currently in the catalog', () => {
    // Guards against adding a dns.TXT marker and forgetting to re-run the sweep.
    const { technologies } = loadCatalog(path.join(ROOT, 'technologies'))
    const results = JSON.parse(fs.readFileSync(RESULTS, 'utf8'))

    const recorded = new Set(
        [...results.observed, ...results.unobserved].map(
            ({ technology, pattern }) => `${technology} ${pattern}`
        )
    )

    const missing = []

    for (const [technology, entry] of Object.entries(technologies)) {
        const record = entry.dns

        if (!record || typeof record !== 'object' || Array.isArray(record)) {
            continue
        }

        const txt = record.TXT === undefined ? record.txt : record.TXT

        if (txt === undefined) {
            continue
        }

        for (const pattern of Array.isArray(txt) ? txt : [txt]) {
            if (!recorded.has(`${technology} ${pattern}`)) {
                missing.push(`${technology}: ${pattern}`)
            }
        }
    }

    assert.deepEqual(
        missing,
        [],
        'catalog markers absent from the retained sweep; run scripts/dns-sweep.js'
    )
})

test('observed markers carry a domain count and examples', () => {
    const results = JSON.parse(fs.readFileSync(RESULTS, 'utf8'))

    for (const { technology, domainCount, examples } of results.observed) {
        assert.ok(domainCount > 0, `${technology} should have a positive count`)
        assert.ok(examples.length > 0, `${technology} should retain example domains`)
        assert.ok(
            examples.length <= 3,
            `${technology} should retain a few examples, not the whole list`
        )
    }
})

test('no marker is recorded as both observed and unobserved', () => {
    const results = JSON.parse(fs.readFileSync(RESULTS, 'utf8'))
    const key = ({ technology, pattern }) => `${technology} ${pattern}`
    const observed = new Set(results.observed.map(key))
    const overlap = results.unobserved.map(key).filter((k) => observed.has(k))

    assert.deepEqual(overlap, [])
})

test('the retained sweep carries auditable provenance', () => {
    // "Re-runnable" is not the same as "auditable". Without these a reader cannot
    // tell whether the retained file corresponds to the corpus and catalog now on
    // disk, nor which resolver produced it.
    const results = JSON.parse(fs.readFileSync(RESULTS, 'utf8'))

    assert.match(
        results.ranAt,
        /^\d{4}-\d{2}-\d{2}T/,
        'the run should be timestamped'
    )
    assert.match(results.corpusSha256, /^[0-9a-f]{64}$/, 'corpus hash')
    assert.match(results.markerSetSha256, /^[0-9a-f]{64}$/, 'marker set hash')
    assert.ok(Array.isArray(results.resolver.servers), 'resolver should be recorded')
    assert.ok(results.resolver.nodeVersion, 'node version should be recorded')
})

test('every corpus domain is accounted for by a resolution outcome', () => {
    // Previously every DNS failure was collapsed into "no records", so a timeout
    // was indistinguishable from a domain that genuinely publishes no TXT.
    const results = JSON.parse(fs.readFileSync(RESULTS, 'utf8'))
    const total = Object.values(results.resolutionOutcomes).reduce(
        (sum, count) => sum + count,
        0
    )

    assert.equal(
        total,
        results.corpusDomains,
        'outcomes should sum to the corpus size'
    )
    assert.equal(
        results.resolutionOutcomes.ok,
        results.domainsWithTxt,
        '"ok" should mean the domain returned at least one TXT record'
    )
    assert.ok(
        Array.isArray(results.unresolvedDomains),
        'domains that could not be resolved should be listed'
    )
})

test('the retained sweep matches the corpus and catalog on disk', () => {
    // Runs the script's own verification. Fails if the corpus or the catalog's
    // marker set has changed since the sweep, which would make the retained
    // numbers stale rather than evidence.
    assert.doesNotThrow(
        () =>
            execFileSync(
                process.execPath,
                [path.join(ROOT, 'scripts/dns-sweep.js'), '--check'],
                { stdio: 'pipe' }
            ),
        'run `npm run sweep` to refresh the retained results'
    )
})

test('supersession requires literal containment, not a shared name', () => {
    // A technology can carry several unrelated TXT patterns. Treating any observed
    // marker for the same technology as equivalent would lend one pattern's
    // evidence to another — Zoho ships both `zoho-verification=` and a
    // `\.zoho\.com` pattern, which prove different things.
    const { supersedes } = require('../scripts/lib/dnb-technologies')

    assert.equal(supersedes('mixpanel-domain-verify=', 'mixpanel-domain-verify'), true)
    assert.equal(supersedes('docusign=', 'docusign'), true)

    assert.equal(
        supersedes('openai-domain-verification=', 'slack-domain-verification'),
        false,
        'an unrelated vendor marker must never count'
    )
    assert.equal(
        supersedes('zoho-verification=', '\\.zoho\\.com'),
        false,
        'a different pattern for the same vendor must never count'
    )
    assert.equal(supersedes('abc', 'abc'), false, 'identical is not supersession')
    assert.equal(supersedes('abc', 'abcd'), false, 'a longer candidate cannot cover')
    assert.equal(supersedes('abc', ''), false, 'an empty candidate cannot cover')
})

test('the five superseded markers are exactly the expected ones', () => {
    const {
        EVIDENCE,
        EXPECTED_SUPERSESSIONS,
        TXT,
        TXT_ENRICH,
    } = require('../scripts/lib/dnb-technologies')

    const tokens = { ...TXT, ...TXT_ENRICH }
    const actual = [...new Set(Object.keys(tokens))]
        .filter(
            (name) =>
                EVIDENCE[name].verification === 'corpus-observed-via-equivalent'
        )
        .sort()

    assert.deepEqual(
        actual,
        ['Detectify', 'DocuSign', 'Dropbox', 'Mixpanel', 'Segment'],
        'the set of superseded markers changed; update EXPECTED_SUPERSESSIONS'
    )

    // Each substitution matches the documented intent, and is verified by
    // containment rather than assumed from the shared technology name.
    const { supersedes } = require('../scripts/lib/dnb-technologies')

    for (const name of actual) {
        const expected = EXPECTED_SUPERSESSIONS[name]

        assert.deepEqual(
            EVIDENCE[name].supersededBy,
            [expected],
            `${name} should be superseded by ${expected}`
        )
        assert.ok(
            supersedes(tokens[name], expected),
            `${expected} must literally cover ${tokens[name]}`
        )
    }
})

test('the retained provenance digests are full SHA-256', () => {
    // They were truncated to 16 hex characters while still called sha256, which
    // overstated the provenance.
    const results = JSON.parse(fs.readFileSync(RESULTS, 'utf8'))

    assert.match(results.corpusSha256, /^[0-9a-f]{64}$/, 'corpus digest')
    assert.match(results.markerSetSha256, /^[0-9a-f]{64}$/, 'marker set digest')
})
