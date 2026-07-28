'use strict'

/**
 * Tests for the xhr observability measurement.
 *
 * 126 of the catalog-matchable products resolve to an entry whose only channel is
 * `xhr`. Those markers are correct — the hostnames are real and vendor-owned —
 * but a browser only sees such a call when the integration is client-side, and
 * most are not. This suite pins the measurement so the coverage headline keeps
 * carrying the caveat.
 *
 * No network access here. `node scripts/xhr-audit.js` refreshes the measurement.
 */

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const path = require('path')
const { execFileSync } = require('child_process')

const ROOT = path.resolve(__dirname, '..')
const URLS = path.join(ROOT, 'data/xhr-audit-urls.txt')
const RESULTS = path.join(ROOT, 'data/xhr-audit-results.json')

test('the audit url list is committed', () => {
    assert.ok(fs.existsSync(URLS), 'data/xhr-audit-urls.txt must exist')

    const urls = fs
        .readFileSync(URLS, 'utf8')
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#'))

    assert.ok(urls.length >= 20, `expected a meaningful sample, got ${urls.length}`)

    for (const url of urls) {
        assert.match(url, /^https:\/\//, `${url} should be an https url`)
    }
})

test('the retained measurement is internally consistent', () => {
    assert.ok(fs.existsSync(RESULTS), 'run scripts/xhr-audit.js to produce results')

    const results = JSON.parse(fs.readFileSync(RESULTS, 'utf8'))

    assert.equal(
        results.pagesScanned + results.pagesFailed,
        results.urls,
        'every url should be accounted for'
    )
    assert.equal(
        results.xhrOnlyFired + results.neverFired.length,
        results.xhrOnlyChecked,
        'fired and never-fired should account for every xhr-only technology'
    )
    assert.equal(results.firedTechnologies.length, results.xhrOnlyFired)
})

test('the measurement reflects a real scan, not a failed one', () => {
    // An earlier run reported 0/85 because Chrome was missing. That is an
    // infrastructure failure, not a measurement, and must never be retained as
    // though it were evidence.
    const results = JSON.parse(fs.readFileSync(RESULTS, 'utf8'))

    assert.ok(results.pagesScanned > 0, 'no pages were scanned successfully')
    assert.ok(
        results.distinctHostsObserved > 50,
        `only ${results.distinctHostsObserved} hostnames seen; the scan did not run properly`
    )
    assert.ok(
        results.distinctXhrHostsObserved > 0,
        'no xhr hostnames collected at all, so the xhr channel was not exercised'
    )
})

test('every fired technology cites the pages it fired on', () => {
    const results = JSON.parse(fs.readFileSync(RESULTS, 'utf8'))

    for (const { technology, pages } of results.firedTechnologies) {
        assert.ok(pages.length > 0, `${technology} should cite at least one page`)

        for (const url of pages) {
            assert.match(url, /^https:\/\//)
        }
    }
})

test('the coverage report carries the observability caveat', () => {
    // The point of the exercise: the headline must not be quoted without it.
    const report = JSON.parse(
        execFileSync(
            process.execPath,
            [path.join(ROOT, 'scripts/coverage-report.js'), '--json'],
            { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }
        )
    )

    assert.ok(report.observability, 'the report should expose observability data')
    assert.ok(
        report.observability.weaklyObservable > 0,
        'xhr-only products should be counted'
    )
    assert.ok(
        report.observability.weaklyObservable <= report.observability.detectable,
        'weakly observable is a subset of catalog-matchable'
    )
    assert.ok(
        report.observability.audit,
        'the retained measurement should be attached to the report'
    )
})

test('the markdown report states the caveat in words', () => {
    const markdown = execFileSync(
        process.execPath,
        [path.join(ROOT, 'scripts/coverage-report.js'), '--markdown'],
        { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }
    )

    assert.match(markdown, /Observability caveat/)
    assert.match(markdown, /only through the `xhr` channel/)
    assert.match(markdown, /upper bound/, 'the figure must be framed as a ceiling')
})

test('xhr-only entries are still counted as catalog-matchable', () => {
    // They are not downgraded: the markers are correct, and a client-side
    // integration does fire them. The caveat is about likelihood, not validity.
    const report = JSON.parse(
        execFileSync(
            process.execPath,
            [path.join(ROOT, 'scripts/coverage-report.js'), '--json'],
            { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }
        )
    )

    const weak = report.products.filter(({ weaklyObservable }) => weaklyObservable)

    assert.ok(weak.length > 0)

    for (const { product, status } of weak) {
        assert.ok(
            ['detected', 'platform-level'].includes(status),
            `${product} should remain catalog-matchable, got ${status}`
        )
    }
})
