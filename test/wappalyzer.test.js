'use strict'

/**
 * Tests for the detection engine.
 *
 * These use small hand-built catalogs rather than the real one so a failure
 * points at engine behaviour, not at a technology definition. Catalog-wide
 * checks live in test/catalog.test.js.
 */

const test = require('node:test')
const assert = require('node:assert/strict')

const Wappalyzer = require('../wappalyzer')

const CATEGORIES = {
    1: { name: 'CMS', priority: 1, groups: [3] },
    19: { name: 'Miscellaneous', priority: 10, groups: [6] },
    59: { name: 'JavaScript libraries', priority: 9, groups: [9] },
}

/** Load a catalog and return a detection for one technology. */
function load(catalog, categories = CATEGORIES) {
    Wappalyzer.setCategories(categories)
    Wappalyzer.setTechnologies(catalog)

    return Wappalyzer
}

function detect(name) {
    const technology = Wappalyzer.getTechnology(name)

    assert.ok(technology, `technology ${name} should exist`)

    return { technology, pattern: { confidence: 100 }, version: '' }
}

test('slugify', () => {
    assert.equal(Wappalyzer.slugify('Google Analytics'), 'google-analytics')
    assert.equal(Wappalyzer.slugify('ASP.NET'), 'asp-net')
    assert.equal(Wappalyzer.slugify('  Trailing- '), 'trailing')
    assert.equal(Wappalyzer.slugify('C++'), 'c')
})

test('parsePattern splits value, confidence and version', () => {
    const parsed = Wappalyzer.parsePattern('wp-content\\;confidence:50\\;version:\\1')

    assert.equal(parsed.value, 'wp-content')
    assert.equal(parsed.confidence, 50)
    assert.equal(parsed.version, '\\1')
    assert.ok(parsed.regex instanceof RegExp)
})

test('parsePattern defaults confidence to 100 and version to empty', () => {
    const parsed = Wappalyzer.parsePattern('jquery')

    assert.equal(parsed.confidence, 100)
    assert.equal(parsed.version, '')
})

test('parsePattern rewrites unbounded quantifiers', () => {
    // Unbounded + and * are capped so a hostile pattern cannot hang a scan.
    assert.equal(Wappalyzer.parsePattern('a+').regex.source, 'a{1,250}')
    assert.equal(Wappalyzer.parsePattern('a*').regex.source, 'a{0,250}')
    // Escaped quantifiers are literal characters and must survive intact.
    assert.equal(Wappalyzer.parsePattern('a\\+').regex.source, 'a\\+')
    assert.equal(Wappalyzer.parsePattern('a\\*').regex.source, 'a\\*')
})

test('parsePattern is case-insensitive', () => {
    assert.ok(Wappalyzer.parsePattern('WordPress').regex.test('wordpress'))
})

test('transformPatterns keeps a bare pattern flat', () => {
    const transformed = Wappalyzer.transformPatterns('jquery')

    assert.ok(Array.isArray(transformed))
    assert.equal(transformed.length, 1)
})

test('transformPatterns keys objects and lowercases unless case-sensitive', () => {
    const insensitive = Wappalyzer.transformPatterns({ 'X-Powered-By': 'php' })
    const sensitive = Wappalyzer.transformPatterns({ jQuery: '' }, true)

    assert.deepEqual(Object.keys(insensitive), ['x-powered-by'])
    assert.deepEqual(Object.keys(sensitive), ['jQuery'])
})

test('transformPatterns returns empty for missing input', () => {
    assert.deepEqual(Wappalyzer.transformPatterns(undefined), [])
    assert.deepEqual(Wappalyzer.transformPatterns(''), [])
})

test('resolveVersion resolves back references', () => {
    const pattern = Wappalyzer.parsePattern('jquery-([\\d.]+)\\.js\\;version:\\1')

    assert.equal(
        Wappalyzer.resolveVersion(pattern, '/js/jquery-3.6.0.js'),
        '3.6.0'
    )
})

test('resolveVersion resolves the ternary form', () => {
    const pattern = Wappalyzer.parsePattern('(?:(v2)|v1)\\;version:\\1?2:1')

    assert.equal(Wappalyzer.resolveVersion(pattern, 'v2'), '2')
    assert.equal(Wappalyzer.resolveVersion(pattern, 'v1'), '1')
})

test('analyzeOneToOne matches a single value and extracts a version', () => {
    load({
        Example: {
            cats: [1],
            scripts: 'example-([\\d.]+)\\.js\\;version:\\1',
        },
    })

    const detections = Wappalyzer.analyze({ scripts: 'var a; /example-2.3.4.js' })

    assert.equal(detections.length, 1)
    assert.equal(detections[0].technology.name, 'Example')
    assert.equal(detections[0].version, '2.3.4')
})

test('xhr patterns only match a complete hostname suffix', () => {
    load({
        Example: {
            cats: [1],
            xhr: 'api\\.example\\.com',
        },
    })

    assert.equal(
        Wappalyzer.analyze({ xhr: 'api.example.com' }).length,
        1
    )
    assert.equal(
        Wappalyzer.analyze({ xhr: 'tenant.api.example.com' }).length,
        1
    )
    assert.equal(
        Wappalyzer.analyze({ xhr: 'api.example.com.attacker.invalid' }).length,
        0
    )
})

test('xhr patterns must start on a DNS label boundary', () => {
    // Anchoring only the end of the match still let a pattern match mid-label,
    // so `tome\.app` matched `nottome.app`. Both ends have to land on a label.
    load({
        Short: { cats: [1], xhr: 'tome\\.app' },
        Dotted: { cats: [1], xhr: '\\.vendor\\.com' },
    })

    assert.equal(Wappalyzer.analyze({ xhr: 'tome.app' }).length, 1)
    assert.equal(
        Wappalyzer.analyze({ xhr: 'nottome.app' }).length,
        0,
        'a glued prefix is a different domain'
    )
    assert.equal(
        Wappalyzer.analyze({ xhr: 'evil-tome.app' }).length,
        0,
        'a hyphen is not a label separator'
    )

    // A pattern written with a leading dot must still match a tenant host: the
    // match begins *on* the dot rather than after one.
    assert.equal(Wappalyzer.analyze({ xhr: 'acme.vendor.com' }).length, 1)
    assert.equal(Wappalyzer.analyze({ xhr: 'notvendor.com' }).length, 0)
})

test('the hostname suffix rule applies only to the xhr channel', () => {
    // scriptSrc and html carry full URLs and free text, where a mid-string match
    // is normal and expected.
    load({ Example: { cats: [1], scriptSrc: 'cdn\\.example\\.com' } })

    assert.equal(
        Wappalyzer.analyze({
            scriptSrc: ['https://cdn.example.com/a.js?v=1'],
        }).length,
        1,
        'a trailing query string must not defeat a scriptSrc match'
    )
})

test('analyzeOneToMany matches each item in a list', () => {
    load({
        Example: { cats: [1], scriptSrc: 'cdn\\.example\\.com' },
    })

    const detections = Wappalyzer.analyze({
        scriptSrc: ['https://other.com/a.js', 'https://cdn.example.com/b.js'],
    })

    assert.equal(detections.length, 1)
})

test('analyzeManyToMany matches by key', () => {
    load({
        Example: { cats: [1], headers: { 'x-powered-by': 'Example' } },
    })

    const hit = Wappalyzer.analyze({ headers: { 'x-powered-by': ['Example/1.0'] } })
    const miss = Wappalyzer.analyze({ headers: { 'x-other': ['Example/1.0'] } })

    assert.equal(hit.length, 1)
    assert.equal(miss.length, 0, 'a value under a different key must not match')
})

test('analyzeManyToMany ignores a channel written as a string or array', () => {
    // This is the shape that silently produced dead patterns: an array yields
    // keys "0", "1", ... which never correspond to a real header or record name.
    load({
        Broken: { cats: [1], dns: ['example.com'] },
        AlsoBroken: { cats: [1], headers: 'server' },
    })

    assert.deepEqual(
        Wappalyzer.analyze({ dns: { CNAME: ['example.com'] } }),
        [],
        'an array dns channel must not match'
    )
    assert.deepEqual(
        Wappalyzer.analyze({ headers: { server: ['server'] } }),
        [],
        'a string headers channel must not match'
    )
})

test('analyzeManyToMany tolerates a missing technology', () => {
    assert.deepEqual(Wappalyzer.analyzeManyToMany(undefined, 'headers', {}), [])
})

test('analyzeOneToOne ignores a channel written as an object', () => {
    load({
        Broken: { cats: [1], scripts: { regex: 'example' } },
    })

    assert.deepEqual(Wappalyzer.analyze({ scripts: 'example' }), [])
})

test('analyze skips channels absent from the collected items', () => {
    load({ Example: { cats: [1], html: 'example' } })

    assert.deepEqual(Wappalyzer.analyze({}), [])
})

test('resolve merges detections and caps confidence at 100', () => {
    load({ Example: { cats: [1], html: ['a', 'b'] } })

    const technology = Wappalyzer.getTechnology('Example')
    const resolved = Wappalyzer.resolve([
        { technology, pattern: { confidence: 60 }, version: '' },
        { technology, pattern: { confidence: 60 }, version: '' },
    ])

    assert.equal(resolved.length, 1)
    assert.equal(resolved[0].confidence, 100)
})

test('resolve prefers the longest plausible version', () => {
    load({ Example: { cats: [1], html: 'a' } })

    const technology = Wappalyzer.getTechnology('Example')
    const resolved = Wappalyzer.resolve([
        { technology, pattern: { confidence: 100 }, version: '1' },
        { technology, pattern: { confidence: 100 }, version: '1.2.3' },
    ])

    assert.equal(resolved[0].version, '1.2.3')
})

test('resolve ignores version strings that look like timestamps', () => {
    load({ Example: { cats: [1], html: 'a' } })

    const technology = Wappalyzer.getTechnology('Example')
    const resolved = Wappalyzer.resolve([
        { technology, pattern: { confidence: 100 }, version: '1699999999999' },
    ])

    assert.equal(resolved[0].version, '')
})

test('resolveImplies pulls in implied technologies', () => {
    load({
        Theme: { cats: [1], html: 'theme', implies: 'Engine' },
        Engine: { cats: [1], html: 'engine' },
    })

    const resolved = Wappalyzer.resolve([detect('Theme')])

    assert.deepEqual(
        resolved.map(({ name }) => name).sort(),
        ['Engine', 'Theme']
    )
})

test('resolveImplies caps implied confidence at the implier confidence', () => {
    load({
        Theme: { cats: [1], html: 'theme', implies: 'Engine\\;confidence:50' },
        Engine: { cats: [1], html: 'engine' },
    })

    const technology = Wappalyzer.getTechnology('Theme')
    const resolved = Wappalyzer.resolve([
        { technology, pattern: { confidence: 30 }, version: '' },
    ])

    const engine = resolved.find(({ name }) => name === 'Engine')

    assert.equal(engine.confidence, 30)
})

test('resolveImplies is transitive', () => {
    load({
        A: { cats: [1], html: 'a', implies: 'B' },
        B: { cats: [1], html: 'b', implies: 'C' },
        C: { cats: [1], html: 'c' },
    })

    const resolved = Wappalyzer.resolve([detect('A')])

    assert.deepEqual(resolved.map(({ name }) => name).sort(), ['A', 'B', 'C'])
})

test('resolveExcludes removes the excluded technology', () => {
    load({
        Winner: { cats: [1], html: 'winner', excludes: 'Loser' },
        Loser: { cats: [1], html: 'loser' },
    })

    const resolved = Wappalyzer.resolve([detect('Winner'), detect('Loser')])

    assert.deepEqual(resolved.map(({ name }) => name), ['Winner'])
})

test('a dangling implies is recorded instead of thrown', () => {
    // A bad reference used to abort the whole scan. It must degrade to a
    // recorded defect so one bad entry cannot take down a run.
    load({ Example: { cats: [1], html: 'a', implies: 'Nope' } })

    Wappalyzer.errors = []

    const resolved = Wappalyzer.resolve([detect('Example')])

    assert.deepEqual(resolved.map(({ name }) => name), ['Example'])
    assert.equal(Wappalyzer.errors.length, 1)
    assert.equal(Wappalyzer.errors[0].type, 'dangling-implies')
})

test('a dangling excludes is recorded instead of thrown', () => {
    load({ Example: { cats: [1], html: 'a', excludes: 'Nope' } })

    Wappalyzer.errors = []

    assert.doesNotThrow(() => Wappalyzer.resolve([detect('Example')]))
    assert.equal(Wappalyzer.errors[0].type, 'dangling-excludes')
})

test('a dangling requires is recorded instead of thrown at load time', () => {
    assert.doesNotThrow(() =>
        load({ Example: { cats: [1], html: 'a', requires: 'Nope' } })
    )

    assert.equal(Wappalyzer.errors[0].type, 'dangling-requires')
})

test('an unknown category is recorded instead of thrown', () => {
    load({ Example: { cats: [999], html: 'a' } })

    Wappalyzer.errors = []

    const resolved = Wappalyzer.resolve([detect('Example')])

    assert.equal(resolved.length, 1)
    assert.deepEqual(resolved[0].categories, [], 'unknown ids are dropped')
    assert.equal(Wappalyzer.errors[0].type, 'unknown-category')
})

test('onError receives recorded defects', () => {
    const seen = []

    Wappalyzer.onError = (error) => seen.push(error)

    try {
        load({ Example: { cats: [1], html: 'a', implies: 'Nope' } })
        Wappalyzer.resolve([detect('Example')])
    } finally {
        Wappalyzer.onError = null
    }

    assert.ok(seen.some(({ type }) => type === 'dangling-implies'))
})

test('setTechnologies is idempotent', () => {
    const catalog = {
        Base: { cats: [1], html: 'base' },
        Extension: { cats: [1], html: 'ext', requires: 'Base' },
    }

    load(catalog)
    const first = Wappalyzer.technologies.length

    load(catalog)

    assert.equal(Wappalyzer.technologies.length, first)
    assert.equal(Wappalyzer.requires.length, 1)
    assert.equal(Wappalyzer.requires[0].name, 'Base')
})

test('technologies gated behind requires are excluded from the default set', () => {
    load({
        Base: { cats: [1], html: 'base' },
        Extension: { cats: [1], html: 'ext', requires: 'Base' },
    })

    assert.deepEqual(
        Wappalyzer.technologies.map(({ name }) => name),
        ['Base'],
        'a required-gated technology must not be scanned unconditionally'
    )
    assert.ok(
        Wappalyzer.getTechnology('Extension'),
        'but it must still be reachable by name'
    )
})

test('requiresCategory gates a technology the same way', () => {
    load({
        Example: { cats: [1], html: 'a', requiresCategory: 1 },
    })

    assert.deepEqual(Wappalyzer.technologies, [])
    assert.equal(Wappalyzer.categoryRequires.length, 1)
    assert.equal(Wappalyzer.categoryRequires[0].categoryId, 1)
})

test('resolve exposes catalog metadata including saas and oss', () => {
    load({
        Example: {
            cats: [1],
            html: 'a',
            website: 'https://example.com',
            description: 'An example.',
            icon: 'Example.svg',
            cpe: 'cpe:2.3:a:example:example:*:*:*:*:*:*:*:*',
            pricing: ['low'],
            saas: true,
            oss: false,
        },
    })

    const [resolved] = Wappalyzer.resolve([detect('Example')])

    assert.equal(resolved.name, 'Example')
    assert.equal(resolved.slug, 'example')
    assert.equal(resolved.website, 'https://example.com')
    assert.equal(resolved.icon, 'Example.svg')
    assert.deepEqual(resolved.pricing, ['low'])
    assert.equal(resolved.saas, true)
    assert.equal(resolved.oss, false)
    assert.deepEqual(resolved.categories.map(({ name }) => name), ['CMS'])
})

test('resolve sorts by category priority', () => {
    load({
        Library: { cats: [59], html: 'lib' },
        Cms: { cats: [1], html: 'cms' },
    })

    const resolved = Wappalyzer.resolve([detect('Library'), detect('Cms')])

    assert.deepEqual(
        resolved.map(({ name }) => name),
        ['Cms', 'Library'],
        'lower priority number sorts first'
    )
})

test('analyzeJs matches a collected property chain', () => {
    load({ Example: { cats: [1], js: { 'Example.version': '^([\\d.]+)$\\;version:\\1' } } })

    const detections = Wappalyzer.analyzeJs([
        { name: 'Example', chain: 'Example.version', value: '4.5.6' },
    ])

    assert.equal(detections.length, 1)
    assert.equal(detections[0].version, '4.5.6')
})

test('analyzeJs treats an empty pattern as an existence check', () => {
    load({ Example: { cats: [1], js: { Example: '' } } })

    const detections = Wappalyzer.analyzeJs([
        { name: 'Example', chain: 'Example', value: true },
    ])

    assert.equal(detections.length, 1)
})

test('analyzeJs ignores a chain whose technology is not loaded', () => {
    load({ Example: { cats: [1], js: { Example: '' } } })

    assert.deepEqual(
        Wappalyzer.analyzeJs([{ name: 'Ghost', chain: 'Ghost', value: true }]),
        []
    )
})

test('analyzeDom matches exists, text, properties and attributes', () => {
    load({
        Example: {
            cats: [1],
            dom: {
                '.marker': { exists: '' },
                h1: { text: 'Example' },
                '#app': { properties: { dataset: '' } },
                'img.logo': { attributes: { src: 'example\\.png' } },
            },
        },
    })

    const detections = Wappalyzer.analyzeDom([
        { name: 'Example', selector: '.marker', exists: '' },
        { name: 'Example', selector: 'h1', text: 'Example heading' },
        { name: 'Example', selector: '#app', property: 'dataset', value: true },
        {
            name: 'Example',
            selector: 'img.logo',
            attribute: 'src',
            value: '/img/example.png',
        },
    ])

    assert.equal(detections.length, 4)
})

test('analyzeDom supports a version pinned to selector existence', () => {
    load({
        Example: { cats: [1], dom: { '.v2': { exists: '\\;version:2' } } },
    })

    const [detection] = Wappalyzer.analyzeDom([
        { name: 'Example', selector: '.v2', exists: '' },
    ])

    assert.equal(detection.version, '2')
})

test('analyzeDom ignores an observation for an unloaded technology', () => {
    load({ Example: { cats: [1], dom: { '.a': { exists: '' } } } })

    assert.deepEqual(
        Wappalyzer.analyzeDom([{ name: 'Ghost', selector: '.a', exists: '' }]),
        []
    )
})

test('dom shorthand promotes a selector list to existence rules', () => {
    load({ Example: { cats: [1], dom: ['.a', '.b'] } })

    const detections = Wappalyzer.analyzeDom([
        { name: 'Example', selector: '.a', exists: '' },
        { name: 'Example', selector: '.b', exists: '' },
    ])

    assert.equal(detections.length, 2)
})
