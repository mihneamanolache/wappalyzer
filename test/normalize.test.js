'use strict'

/**
 * Tests for the normalization rules.
 *
 * Each case corresponds to a shape found in the real catalog that the engine
 * silently ignored. The assertions state both what the shape becomes and, where
 * it matters, that the detection intent was preserved rather than dropped.
 */

const test = require('node:test')
const assert = require('node:assert/strict')

const Wappalyzer = require('../wappalyzer')
const {
    dropSubsumedPatterns,
    isLiteralPattern,
    looksLikeUrl,
    normalizeCatalog,
    normalizeEntry,
    normalizeProbe,
} = require('../scripts/lib/normalize')

const normalize = (name, entry) => normalizeEntry(name, entry).entry

/** Assert that a normalized entry actually detects the given collected items. */
function detects(catalog, items) {
    Wappalyzer.setCategories({ 1: { name: 'CMS', priority: 1, groups: [3] } })
    Wappalyzer.setTechnologies(normalizeCatalog(catalog).technologies)

    return Wappalyzer.analyze(items).map(({ technology }) => technology.name)
}

test('looksLikeUrl separates script URLs from inline script patterns', () => {
    assert.ok(looksLikeUrl('s\\.microad\\.jp'))
    assert.ok(looksLikeUrl('/twilio-video.*\\.js'))
    assert.ok(looksLikeUrl('https?://cdn\\.example\\.com'))
    assert.equal(looksLikeUrl('goToAssistVariable'), false)
    assert.equal(looksLikeUrl('Telerik_Web_UI'), false)
})

test('script becomes scriptSrc when the pattern is a URL', () => {
    const entry = normalize('MicroAd', {
        cats: [1],
        script: ['s\\.microad\\.jp', 'microad\\.jp'],
    })

    assert.equal(entry.script, undefined)
    // Both patterns move to scriptSrc, then the subsumption pass drops
    // `s\.microad\.jp`: these are substring regexes, so the shorter
    // `microad\.jp` already matches everything the longer one does.
    assert.equal(entry.scriptSrc, 'microad\\.jp')
})

test('a pattern already covered by a shorter one is dropped', () => {
    const entry = normalize('Example', {
        cats: [1],
        scriptSrc: ['cdn\\.example\\.com', 'example\\.com', 'other\\.net'],
    })

    assert.deepEqual(
        entry.scriptSrc,
        ['example\\.com', 'other\\.net'],
        'the broader pattern survives; the redundant specific one goes'
    )
})

test('subsumption never narrows coverage', () => {
    // The shorter pattern is the one that also matches www.example.com, so it is
    // the one that must survive. Dropping it would lose detections.
    const { kept, dropped } = dropSubsumedPatterns([
        'example\\.com',
        'cdn\\.example\\.com',
    ])

    assert.deepEqual(kept, ['example\\.com'])
    assert.deepEqual(dropped, [
        { pattern: 'cdn\\.example\\.com', subsumedBy: 'example\\.com' },
    ])
})

test('unrelated patterns are all kept', () => {
    const { kept, dropped } = dropSubsumedPatterns(['alpha', 'beta', 'gamma'])

    assert.deepEqual(kept, ['alpha', 'beta', 'gamma'])
    assert.deepEqual(dropped, [])
})

test('dom selectors are never subsumed', () => {
    // Regression. String containment says nothing about CSS matching:
    // `script#apple-pay` does not select id="apple-pay-shop-capabilities", and
    // `.asciinema-player` does not match class="asciinema-player-wrapper". An
    // earlier version of the rule deleted three real detections this way.
    const cases = {
        'Apple Pay': [
            "[aria-labelledby='pi-apple_pay']",
            'script#apple-pay',
            'script#apple-pay-shop-capabilities',
            'input#applePayMerchantId',
        ],
        Asciinema: ['div.asciinema-player-wrapper', 'div.asciinema-player'],
        Swiper: [
            'div[data-swiper-slide-index]',
            'swiper-container',
            'swiper-slide',
            'div.swiper-wrapper',
        ],
    }

    for (const [name, dom] of Object.entries(cases)) {
        const entry = normalize(name, { cats: [1], dom })

        assert.deepEqual(entry.dom, dom, `${name} selectors must survive intact`)
    }
})

test('probe paths are never subsumed', () => {
    // `/a` and `/ab` are different endpoints.
    const entry = normalize('Example', {
        cats: [1],
        probe: { '/api': 'x', '/api/v2': 'y' },
    })

    assert.deepEqual(Object.keys(entry.probe).sort(), ['/api', '/api/v2'])
})

test('only literal patterns take part in subsumption', () => {
    // A pattern with alternation, anchors, quantifiers, classes or groups has no
    // reliable containment-implies-superset relationship, so it is left alone.
    for (const patterns of [
        ['abc', 'a|abc'],
        ['abc', '^abc$'],
        ['abc', 'abc+'],
        ['abc', 'abc[0-9]'],
        ['abc', '(abc)d'],
        ['abc', 'abc{2}'],
        ['abc', 'abc\\d'],
    ]) {
        const { dropped } = dropSubsumedPatterns(patterns)

        assert.deepEqual(
            dropped,
            [],
            `${JSON.stringify(patterns)} should be left alone`
        )
    }
})

test('an escaped dot is literal but a bare dot is not', () => {
    assert.equal(isLiteralPattern('microad\\.jp'), true)
    assert.equal(isLiteralPattern('api\\.openai\\.com'), true)
    assert.equal(
        isLiteralPattern('div.asciinema-player'),
        false,
        'a bare dot is the wildcard, so the pattern is not literal'
    )
})

test('subsumption removes the redundant TXT tokens the sweep found', () => {
    // Upstream ships `mixpanel-domain-verify`; a local enrichment added
    // `mixpanel-domain-verify=`. The sweep showed both matching the same 52
    // domains, which is how the redundancy was spotted.
    const entry = normalize('Mixpanel', {
        cats: [1],
        dns: {
            TXT: ['mixpanel-domain-verify', 'mixpanel-domain-verify='],
        },
    })

    assert.deepEqual(entry.dns, { TXT: 'mixpanel-domain-verify' })
})

test('script becomes scripts when the pattern is inline content', () => {
    const entry = normalize('GoToAssist', {
        cats: [1],
        script: 'goToAssistVariable',
    })

    assert.equal(entry.scripts, 'goToAssistVariable')
    assert.equal(entry.scriptSrc, undefined)
})

test('script written as an object uses its keys as patterns', () => {
    const entry = normalize('Google Consumer Surveys', {
        cats: [1],
        script: { 'google.com/insights/consumersurveys/': '' },
    })

    assert.equal(entry.scriptSrc, 'google.com/insights/consumersurveys/')
})

test('script merges into an existing scriptSrc without clobbering it', () => {
    const entry = normalize('Example', {
        cats: [1],
        scriptSrc: 'existing\\.js',
        script: 'added\\.js',
    })

    assert.deepEqual(entry.scriptSrc, ['existing\\.js', 'added\\.js'])
})

test('ssl.issuer becomes certIssuer', () => {
    const entry = normalize('GlobalSign EV', {
        cats: [1],
        ssl: { issuer: 'GlobalSign Extended Validation CA' },
    })

    assert.equal(entry.certIssuer, 'GlobalSign Extended Validation CA')
    assert.equal(entry.ssl, undefined)
})

test('ssl without an issuer is dropped', () => {
    const entry = normalize('DiskStation Manager', { cats: [1], ssl: true })

    assert.equal(entry.ssl, undefined)
    assert.equal(entry.certIssuer, undefined)
})

test('env becomes js existence checks', () => {
    const entry = normalize('Digg Digg', {
        cats: [1],
        env: { diggdigg_floatw: '' },
    })

    assert.deepEqual(entry.js, { diggdigg_floatw: '' })
    assert.equal(entry.env, undefined)
})

test('regex wrapping a channel is unwrapped', () => {
    const entry = normalize('Blackbaud Luminate Online', {
        cats: [1],
        regex: { cookies: 'BB_prod_session' },
    })

    assert.deepEqual(entry.cookies, { BB_prod_session: '' })
})

test('tests and rules wrappers are unwrapped onto real channels', () => {
    const tests = normalize('Frontpage Slideshow', {
        cats: [1],
        tests: { html: 'Frontpage Slideshow' },
    })

    assert.equal(tests.html, 'Frontpage Slideshow')

    const rules = normalize('Facebook Chat Plugin', {
        cats: [1],
        rules: {
            scripts: ['connect\\.facebook\\.net/.*/sdk/xfbml\\.customerchat\\.js'],
            html: ['fb\\.customerchat'],
        },
    })

    assert.equal(
        rules.scriptSrc,
        'connect\\.facebook\\.net/.*/sdk/xfbml\\.customerchat\\.js',
        'a scripts list of URLs routes to scriptSrc'
    )
    assert.equal(rules.html, 'fb\\.customerchat')
})

test('stylesheets becomes an html pattern', () => {
    const entry = normalize('Simple Social Icons', {
        cats: [1],
        stylesheets: '/simple-social-icons\\.css',
    })

    assert.equal(entry.html, '/simple-social-icons\\.css')
})

test('categories is renamed to cats', () => {
    const entry = normalize('NetIQ Access Manager', { categories: [28] })

    // This entry is also remapped by name, so only assert the rename happened.
    assert.equal(entry.categories, undefined)
    assert.ok(Array.isArray(entry.cats))
})

test('metadata the engine never reads is dropped', () => {
    const entry = normalize('Example', {
        cats: [1],
        html: 'a',
        npm: 'example',
        keywords: ['a'],
        slug: 'example',
        mime: 'text/plain',
        developer: { name: 'Someone' },
    })

    assert.deepEqual(Object.keys(entry).sort(), ['cats', 'html'])
})

test('a flat channel wrapped in {regex} is unwrapped', () => {
    const entry = normalize('Enfold', {
        cats: [1],
        css: { regex: '/themes/enfold/.*\\.css' },
    })

    assert.equal(entry.css, '/themes/enfold/.*\\.css')
})

test('an empty channel object is removed', () => {
    const entry = normalize('.NET Framework', { cats: [1], scripts: {} })

    assert.equal(entry.scripts, undefined)
})

test('a scripts object of identifiers becomes js', () => {
    const entry = normalize('Salesforce Sales Cloud', {
        cats: [1],
        scripts: { Sfdc: '' },
    })

    assert.deepEqual(entry.js, { Sfdc: '' })
    assert.equal(entry.scripts, undefined)
})

test('a flat channel object of patterns becomes patterns', () => {
    const entry = normalize('Porto', {
        cats: [1],
        css: { 'porto(-.+)?\\.css': '' },
    })

    assert.equal(entry.css, 'porto(-.+)?\\.css')
})

test('a bare dns pattern is keyed by record type', () => {
    const cname = normalize('Blackboard', {
        cats: [1],
        dns: '(?:^|\\.)blackboard\\.',
    })
    const ns = normalize('GoDaddy DNS', {
        cats: [1],
        dns: 'domaincontrol\\.com$',
    })

    assert.deepEqual(cname.dns, { CNAME: ['(?:^|\\.)blackboard\\.'] })
    assert.deepEqual(ns.dns, { NS: ['domaincontrol\\.com$'] })
})

test('a bare cookies list is keyed by cookie name', () => {
    const entry = normalize('Microsoft Commerce Server', {
        cats: [1],
        cookies: ['MSCSProfile'],
    })

    assert.deepEqual(entry.cookies, { MSCSProfile: '' })
})

test('nested js objects are flattened to dotted chains', () => {
    const entry = normalize('Genesys Workforce Management', {
        cats: [1],
        js: { Genesys: { patterns: { WorkforceManagement: '' } } },
    })

    assert.deepEqual(entry.js, { 'Genesys.patterns.WorkforceManagement': '' })
})

test('an empty nested js object becomes an existence check', () => {
    const entry = normalize('Stackify Retrace', {
        cats: [1],
        js: { Stackify: {} },
    })

    assert.deepEqual(entry.js, { Stackify: '' })
})

test('a non-string js leaf becomes an existence check', () => {
    const entry = normalize('Amazon Connect', {
        cats: [1],
        js: { connect: { topLevelDomain: 1 } },
    })

    assert.deepEqual(entry.js, { 'connect.topLevelDomain': '' })
})

test('a dom selector mapped to an empty string becomes an existence rule', () => {
    const entry = normalize('.NET Framework', {
        cats: [1],
        dom: { '[__VIEWSTATE]': '' },
    })

    assert.deepEqual(entry.dom, { '[__VIEWSTATE]': { exists: '' } })
})

test('a dom generator meta selector moves to the meta channel', () => {
    const entry = normalize('Example', {
        cats: [1],
        dom: { "meta[name='generator']": 'Example (\\d+)' },
    })

    assert.deepEqual(entry.meta, { generator: 'Example (\\d+)' })
    assert.equal(entry.dom, undefined)
})

test('a dom content rule on a meta tag moves to the meta channel', () => {
    const entry = normalize('Databricks', {
        cats: [1],
        dom: { 'meta[name="keywords"]': { content: 'Databricks|Lakehouse' } },
    })

    assert.deepEqual(entry.meta, { keywords: 'Databricks|Lakehouse' })
})

test('a bare attribute rule on a non-meta selector becomes attributes', () => {
    const entry = normalize('Example', {
        cats: [1],
        dom: { 'img.logo': { src: 'logo\\.png' } },
    })

    assert.deepEqual(entry.dom, {
        'img.logo': { attributes: { src: 'logo\\.png' } },
    })
})

test('dom exists true becomes an empty pattern', () => {
    const entry = normalize('Amazon Widgets', {
        cats: [1],
        dom: { "div[id^='amzn-assoc-ad-']": { exists: true } },
    })

    assert.deepEqual(entry.dom, {
        "div[id^='amzn-assoc-ad-']": { exists: '' },
    })
})

test('dom exists with a version suffix is left alone', () => {
    const entry = normalize('Magento', {
        cats: [1],
        dom: { 'script[data-requiremodule]': { exists: '\\;version:2' } },
    })

    assert.deepEqual(entry.dom, {
        'script[data-requiremodule]': { exists: '\\;version:2' },
    })
})

test('normalizeProbe converts an array of descriptors', () => {
    const { paths } = normalizeProbe([
        {
            path: '/index.yaml',
            status: 200,
            body: 'apiVersion:\\s*v1',
        },
    ])

    assert.deepEqual(paths, { '/index.yaml': 'apiVersion:\\s*v1' })
})

test('normalizeProbe converts a paths wrapper', () => {
    const { paths } = normalizeProbe({
        paths: [{ path: '/s/sfsites/aura.js' }],
    })

    assert.deepEqual(paths, { '/s/sfsites/aura.js': '' })
})

test('normalizeProbe converts a paths map keyed by path', () => {
    const { paths } = normalizeProbe({
        paths: {
            '/api/now/table/task_sla': { status: [401], body: 'Not Authenticated' },
        },
    })

    assert.deepEqual(paths, {
        '/api/now/table/task_sla': 'Not Authenticated',
    })
})

test('normalizeProbe unescapes and roots a path', () => {
    const { paths } = normalizeProbe({ '\\/now\\/risk': { body: 'risk' } })

    assert.deepEqual(paths, { '/now/risk': 'risk' })
})

test('normalizeProbe reports dropped status and header conditions', () => {
    const { notes } = normalizeProbe([
        { path: '/a', status: 200, headers: { server: 'x' } },
    ])

    assert.ok(
        notes.some((note) => note.includes('status/header conditions dropped'))
    )
})

test('an unmapped category is dropped and a remapped one is rewritten', () => {
    assert.deepEqual(normalize('InstantSearch+', { cats: [10, 117] }).cats, [10, 29])
    assert.deepEqual(normalize('Forcepoint CASB', { cats: [113] }).cats, [16])
})

test('normalizeCatalog drops references to technologies that do not exist', () => {
    const { technologies } = normalizeCatalog({
        Keep: { cats: [1], html: 'a', implies: ['Real', 'Ghost'] },
        Real: { cats: [1], html: 'b' },
        Solo: { cats: [1], html: 'c', excludes: 'Ghost' },
    })

    assert.deepEqual(technologies.Keep.implies, ['Real'])
    assert.equal(
        technologies.Solo.excludes,
        undefined,
        'a reference field with nothing left is removed'
    )
})

test('normalizeCatalog drops a self reference', () => {
    const { technologies } = normalizeCatalog({
        Example: { cats: [1], html: 'a', implies: 'Example' },
    })

    assert.equal(technologies.Example.implies, undefined)
})

/* --------------------------------------------------------- behaviour, not shape */

test('a normalized script channel actually detects', () => {
    assert.deepEqual(
        detects(
            { MicroAd: { cats: [1], script: ['s\\.microad\\.jp'] } },
            { scriptSrc: ['https://s.microad.jp/tag.js'] }
        ),
        ['MicroAd']
    )
})

test('a normalized dns channel actually detects', () => {
    // transformPatterns lowercases keyed-channel keys, and driver.js collects
    // records under lowercase types, so the record type is written uppercase in
    // the catalog but looked up lowercase at scan time.
    assert.deepEqual(
        detects(
            { 'GoDaddy DNS': { cats: [1], dns: 'domaincontrol\\.com$' } },
            { dns: { ns: ['ns01.domaincontrol.com'] } }
        ),
        ['GoDaddy DNS']
    )
})

test('a normalized meta rule actually detects', () => {
    assert.deepEqual(
        detects(
            {
                Databricks: {
                    cats: [1],
                    dom: { 'meta[name="keywords"]': { content: 'Databricks' } },
                },
            },
            { meta: { keywords: ['Databricks, Lakehouse'] } }
        ),
        ['Databricks']
    )
})

test('a normalized nested js chain actually detects', () => {
    assert.deepEqual(
        detects(
            {
                Genesys: {
                    cats: [1],
                    js: { Genesys: { patterns: { WorkforceManagement: '' } } },
                },
            },
            {}
        ),
        [],
        'js is not matched through analyze(); see the analyzeJs tests'
    )

    const [detection] = Wappalyzer.analyzeJs([
        {
            name: 'Genesys',
            chain: 'Genesys.patterns.WorkforceManagement',
            value: true,
        },
    ])

    assert.ok(detection, 'the flattened chain matches a collected property')
})
