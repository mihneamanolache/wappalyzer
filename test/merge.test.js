'use strict'

/**
 * Tests for the upstream merge policy.
 *
 * The regression these guard against is concrete: the previous policy replaced
 * any technology that also existed upstream, which discarded locally-authored
 * fingerprints without a trace. Every test here asserts that local detection
 * data survives a merge.
 */

const test = require('node:test')
const assert = require('node:assert/strict')

const {
    mergeCatalog,
    mergeDom,
    mergeEntry,
    mergeKeyed,
    preferLocalShape,
    sameMeaning,
    unionPatterns,
} = require('../scripts/lib/merge')

test('unionPatterns keeps local order and drops duplicates', () => {
    assert.deepEqual(unionPatterns(['a', 'b'], ['b', 'c']), ['a', 'b', 'c'])
})

test('unionPatterns accepts scalars on either side', () => {
    assert.deepEqual(unionPatterns('a', 'b'), ['a', 'b'])
    assert.deepEqual(unionPatterns('a', undefined), ['a'])
    assert.deepEqual(unionPatterns(undefined, 'b'), ['b'])
})

test('mergeKeyed unions keys and patterns per key', () => {
    const merged = mergeKeyed(
        { server: 'nginx', 'x-local': 'yes' },
        { server: 'apache', 'x-upstream': 'yes' }
    )

    assert.deepEqual(merged, {
        server: ['nginx', 'apache'],
        'x-local': 'yes',
        'x-upstream': 'yes',
    })
})

test('mergeKeyed recurses into nested rule objects', () => {
    const merged = mergeKeyed(
        { '.a': { exists: '' } },
        { '.a': { text: 'hello' } }
    )

    assert.deepEqual(merged, { '.a': { exists: '', text: 'hello' } })
})

test('mergeDom unions two selector lists', () => {
    assert.deepEqual(mergeDom(['.a'], ['.b']), ['.a', '.b'])
})

test('mergeDom promotes a selector list when the other side is a rule map', () => {
    const merged = mergeDom(['.a'], { '.b': { text: 'x' } })

    assert.deepEqual(merged, {
        '.a': { exists: '' },
        '.b': { text: 'x' },
    })
})

test('mergeEntry keeps a local channel upstream does not have', () => {
    // The Salesforce Service Cloud case: local carries cookies/dom/meta/xhr
    // patterns that upstream has never had.
    const { entry } = mergeEntry(
        {
            cats: [52],
            scriptSrc: ['service\\.force\\.com/embeddedservice/esw\\.js'],
            cookies: { BrowserId: '' },
            xhr: 'force\\.com',
        },
        {
            cats: [52, 53],
            scriptSrc: ['service\\.force\\.com'],
        }
    )

    assert.deepEqual(entry.cookies, { BrowserId: '' }, 'local cookies survive')
    assert.equal(entry.xhr, 'force\\.com', 'local xhr survives')
    assert.deepEqual(
        entry.scriptSrc,
        [
            'service\\.force\\.com/embeddedservice/esw\\.js',
            'service\\.force\\.com',
        ],
        'both the specific local pattern and the upstream one are kept'
    )
})

test('mergeEntry unions categories rather than replacing them', () => {
    const { entry } = mergeEntry({ cats: [10, 78, 94] }, { cats: [78] })

    assert.deepEqual(entry.cats, [10, 78, 94])
})

test('mergeEntry unions pricing', () => {
    const { entry } = mergeEntry({ pricing: ['freemium'] }, { pricing: ['payg'] })

    assert.deepEqual(entry.pricing, ['freemium', 'payg'])
})

test('mergeEntry unions implies without duplicating', () => {
    const { entry } = mergeEntry({ implies: 'A' }, { implies: ['A', 'B'] })

    assert.deepEqual(entry.implies, ['A', 'B'])
})

test('mergeEntry prefers curated local metadata', () => {
    const { entry } = mergeEntry(
        {
            icon: 'Salesforce-Service-Cloud.svg',
            website: 'https://www.salesforce.com/products/service-cloud/',
            description: 'The local, longer description.',
        },
        {
            icon: 'Salesforce.svg',
            website: 'https://www.salesforce.com/au/products/service-cloud/',
            description: 'Upstream description.',
        }
    )

    assert.equal(entry.icon, 'Salesforce-Service-Cloud.svg')
    assert.equal(entry.description, 'The local, longer description.')
})

test('mergeEntry takes upstream metadata when local is missing or empty', () => {
    const { entry } = mergeEntry(
        { icon: '', description: undefined },
        { icon: 'Upstream.svg', description: 'From upstream.' }
    )

    assert.equal(entry.icon, 'Upstream.svg')
    assert.equal(entry.description, 'From upstream.')
})

test('mergeEntry gains a whole channel that only upstream has', () => {
    const { entry, gained } = mergeEntry(
        { cats: [1] },
        { cats: [1], dns: { TXT: 'example' } }
    )

    assert.deepEqual(entry.dns, { TXT: 'example' })
    assert.ok(gained.includes('dns'))
})

test('mergeEntry collapses a single merged pattern back to a scalar', () => {
    const { entry } = mergeEntry({ html: 'same' }, { html: 'same' })

    assert.equal(entry.html, 'same', 'no gratuitous array wrapping')
})

test('mergeCatalog adds upstream-only, keeps local-only, merges the rest', () => {
    const result = mergeCatalog(
        {
            Both: { cats: [1], html: 'local' },
            LocalOnly: { cats: [1], html: 'mine' },
        },
        {
            Both: { cats: [1], html: 'upstream' },
            UpstreamOnly: { cats: [1], html: 'theirs' },
        }
    )

    assert.deepEqual(Object.keys(result.technologies).sort(), [
        'Both',
        'LocalOnly',
        'UpstreamOnly',
    ])
    assert.deepEqual(result.added, ['UpstreamOnly'])
    assert.deepEqual(result.localOnly, ['LocalOnly'])
    assert.deepEqual(result.technologies.Both.html, ['local', 'upstream'])
})

/* ------------------------------------------------------------- diff hygiene */

test('sameMeaning treats a scalar and a one-element list as equal', () => {
    // "a" and ["a"] compile to the same pattern, so they are the same to the
    // engine. Treating them as different rewrote 5,083 untouched entries.
    assert.equal(sameMeaning('a', ['a']), true)
    assert.equal(sameMeaning(['a'], 'a'), true)
    assert.equal(sameMeaning(['a', 'b'], ['b', 'a']), true, 'order is irrelevant')
    assert.equal(sameMeaning('a', ['a', 'b']), false)
    assert.equal(sameMeaning(undefined, []), true)
    assert.equal(sameMeaning('a', undefined), false)
})

test('preferLocalShape keeps the local form when the merge adds nothing', () => {
    assert.deepEqual(preferLocalShape(['a'], 'a'), ['a'], 'local array is kept')
    assert.deepEqual(preferLocalShape('a', ['a']), 'a', 'local scalar is kept')
})

test('preferLocalShape yields the merged value when something was added', () => {
    assert.deepEqual(preferLocalShape(['a'], ['a', 'b']), ['a', 'b'])
})

test('merging identical entries produces no change at all', () => {
    // The property that keeps an upstream pull reviewable: an entry upstream has
    // not touched must come out byte-identical.
    const local = {
        cats: [1],
        scriptSrc: ['example\\.js'],
        html: 'example',
        dom: ['.marker'],
        headers: { server: 'example' },
    }

    const { entry } = mergeEntry(local, JSON.parse(JSON.stringify(local)))

    assert.equal(
        JSON.stringify(entry),
        JSON.stringify(local),
        'no gratuitous reshaping'
    )
})

test('merging a scalar against an equal one-element list does not reshape', () => {
    const { entry } = mergeEntry({ html: 'same' }, { html: ['same'] })

    assert.equal(entry.html, 'same')

    const { entry: reversed } = mergeEntry({ html: ['same'] }, { html: 'same' })

    assert.deepEqual(reversed.html, ['same'])
})

test('a dom selector list is not reshaped when upstream matches it', () => {
    const { entry } = mergeEntry({ dom: ['.a'] }, { dom: '.a' })

    assert.deepEqual(entry.dom, ['.a'])
})

test('mergeCatalog never drops a local technology', () => {
    const local = {
        A: { cats: [1], html: 'a' },
        B: { cats: [1], html: 'b' },
        C: { cats: [1], html: 'c' },
    }

    const result = mergeCatalog(local, { A: { cats: [1], html: 'a2' } })

    for (const name of Object.keys(local)) {
        assert.ok(result.technologies[name], `${name} must survive the merge`)
    }
})
