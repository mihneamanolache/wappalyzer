'use strict'

/**
 * Tests for the text-mined signal layer.
 *
 * Precision is the point. This layer exists to reach technologies that emit
 * nothing observable, and the only way it earns its place is by refusing to fire
 * on a vendor name that merely appears on a page. Most of these tests are
 * negative cases for that reason.
 */

const test = require('node:test')
const assert = require('node:assert/strict')

const {
    VENDORS,
    analyzeText,
    isEligiblePage,
} = require('../scripts/lib/text-signals')

const names = (signals) => signals.map(({ technology }) => technology).sort()

/** A realistic job posting wrapper around a requirements line. */
const posting = (requirement) =>
    'Senior Security Engineer\n\nResponsibilities:\n' +
    'Own our detection and response tooling.\n\n' +
    `Qualifications:\n- ${requirement}\n- Strong scripting skills\n\n` +
    'We are an equal opportunity employer.'

/* -------------------------------------------------------------- page gating */

test('a job posting URL qualifies', () => {
    assert.ok(isEligiblePage({ url: 'https://acme.com/careers/security-engineer' }))
    assert.ok(isEligiblePage({ url: 'https://acme.com/jobs' }))
    assert.ok(isEligiblePage({ url: 'https://acme.com/join-us/' }))
})

test('job posting text qualifies without a matching URL', () => {
    assert.ok(
        isEligiblePage({
            url: 'https://acme.com/x/1234',
            text: 'Qualifications:\n- 5 years experience',
        })
    )
})

test('an ordinary page does not qualify', () => {
    assert.equal(
        isEligiblePage({
            url: 'https://acme.com/about',
            text: 'Acme is a leader in logistics.',
        }),
        false
    )
})

test('nothing is emitted for a page that does not qualify', () => {
    // The single most important guard: a press release naming a vendor is not
    // evidence of anything.
    const signals = analyzeText({
        url: 'https://acme.com/newsroom/press-release',
        text:
            'Acme today announced a partnership with CrowdStrike. ' +
            'Acme also evaluated SentinelOne and Zscaler during the process.',
    })

    assert.deepEqual(signals, [])
})

/* ------------------------------------------------------------ true positives */

test('experience-with phrasing yields a signal', () => {
    const signals = analyzeText({
        url: 'https://acme.com/careers/secops',
        text: posting('3+ years experience with CrowdStrike Falcon and Splunk'),
    })

    assert.deepEqual(names(signals), ['CrowdStrike Falcon'])
    assert.equal(signals[0].source, 'hiring-signal')
    assert.ok(signals[0].evidence.includes('CrowdStrike'))
})

test('administering phrasing yields a signal', () => {
    const signals = analyzeText({
        url: 'https://acme.com/careers/1',
        text: posting('Responsible for administering Zscaler Internet Access'),
    })

    assert.deepEqual(names(signals), ['Zscaler'])
})

test('role phrasing yields a signal', () => {
    const signals = analyzeText({
        url: 'https://acme.com/careers/1',
        text: posting('SentinelOne administrator with 2 years in the role'),
    })

    assert.deepEqual(names(signals), ['SentinelOne'])
})

test('a stated tech stack yields a signal without a careers URL', () => {
    const signals = analyzeText({
        url: 'https://acme.com/engineering',
        text:
            'Our tech stack\n\nWe use pgvector for semantic search and Neovim ' +
            'across the team.',
    })

    assert.deepEqual(names(signals), ['Neovim', 'pgvector'])
})

test('multiple vendors in one posting each yield a signal', () => {
    const signals = analyzeText({
        url: 'https://acme.com/careers/cloud-security',
        text: posting(
            'Hands-on with Orca Security and Netskope; familiarity with Lacework'
        ),
    })

    assert.deepEqual(names(signals), ['Lacework', 'Netskope', 'Orca Security'])
})

test('each technology is reported at most once', () => {
    const signals = analyzeText({
        url: 'https://acme.com/careers/1',
        text: posting(
            'Experience with CrowdStrike. Managing CrowdStrike Falcon. ' +
            'CrowdStrike administrator preferred.'
        ),
    })

    assert.equal(signals.length, 1)
})

test('confidence is low by default and overridable', () => {
    const [signal] = analyzeText({
        url: 'https://acme.com/careers/1',
        text: posting('Experience with Netskope'),
    })

    assert.equal(signal.confidence, 30, 'an inference must not look like a detection')

    const [tuned] = analyzeText(
        { url: 'https://acme.com/careers/1', text: posting('Experience with Netskope') },
        { confidence: 50 }
    )

    assert.equal(tuned.confidence, 50)
})

/* ----------------------------------------------------------- false positives */

test('a bare vendor mention in a posting is not enough', () => {
    // The vendor name is present and the page qualifies, but there is no tooling
    // language, so nothing fires.
    const signals = analyzeText({
        url: 'https://acme.com/careers/marketing-manager',
        text: posting('Write case studies. Our customers include CrowdStrike.'),
    })

    assert.deepEqual(signals, [])
})

test('a competitor comparison page does not yield signals', () => {
    const signals = analyzeText({
        url: 'https://acme.com/compare',
        text:
            'Acme vs SentinelOne vs CrowdStrike: how the three platforms differ ' +
            'on price and coverage.',
    })

    assert.deepEqual(signals, [])
})

test('Orca is guarded against unrelated meanings', () => {
    const signals = analyzeText({
        url: 'https://acme.com/careers/1',
        text: posting(
            'Experience with Orca Security tooling. Also uses the Orca screen ' +
            'reader for accessibility testing.'
        ),
    })

    assert.equal(
        names(signals).includes('Orca Security'),
        false,
        'the ambiguity guard should suppress this'
    )
})

test('MCP is guarded against Microsoft Certified Professional', () => {
    const signals = analyzeText({
        url: 'https://acme.com/careers/1',
        text: posting('Microsoft Certified Professional (MCP) required'),
    })

    assert.equal(names(signals).includes('Model Context Protocol'), false)
})

test('Zed requires editor context', () => {
    const bare = analyzeText({
        url: 'https://acme.com/careers/1',
        text: posting('Experience with Zed Industries as a supplier'),
    })

    assert.equal(names(bare).includes('Zed'), false)

    const real = analyzeText({
        url: 'https://acme.com/careers/1',
        text: posting('Experience with the Zed editor and Neovim'),
    })

    assert.ok(names(real).includes('Zed'))
})

test('empty or missing text yields nothing', () => {
    assert.deepEqual(analyzeText({}), [])
    assert.deepEqual(analyzeText({ text: '', url: 'https://acme.com/careers' }), [])
})

/* ------------------------------------------------------------------ coverage */

test('every vendor pattern compiles and can produce a signal', () => {
    // Guards against a pattern that is syntactically fine but can never match.
    const unreachable = []

    for (const name of Object.keys(VENDORS)) {
        const probe = {
            'CrowdStrike Falcon': 'experience with CrowdStrike Falcon',
            SentinelOne: 'experience with SentinelOne',
            Zscaler: 'experience with Zscaler',
            Netskope: 'experience with Netskope',
            'Orca Security': 'experience with Orca Security',
            Lacework: 'experience with Lacework',
            'Abnormal Security': 'experience with Abnormal Security',
            pgvector: 'experience with pgvector',
            'NVIDIA Jetson': 'experience with NVIDIA Jetson Orin',
            'Model Context Protocol': 'experience with Model Context Protocol',
            Neovim: 'experience with Neovim',
            Zed: 'experience with the Zed editor',
            Phind: 'experience with Phind',
        }[name]

        const signals = analyzeText({
            url: 'https://acme.com/careers/1',
            text: posting(probe),
        })

        if (!names(signals).includes(name)) {
            unreachable.push(name)
        }
    }

    assert.deepEqual(unreachable, [])
})

test('the layer covers exactly the products the catalog cannot detect', () => {
    const { CATALOG_ONLY } = require('../scripts/lib/emerging-technologies')

    assert.deepEqual(
        Object.keys(VENDORS).sort(),
        Object.keys(CATALOG_ONLY).sort(),
        'every taxonomy-only entry should have a text signal, and vice versa'
    )
})
