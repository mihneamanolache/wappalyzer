'use strict'

/**
 * Tests for the analyzedUrls bookkeeping in driver.js.
 *
 * The url list became an array (see the "Refactor urls output format" commit) but
 * the error path still indexed it by href, so the lookup was always undefined and
 * `status ?? 0` overwrote a status that had already been recorded. A page that
 * responded 200 and then threw — a navigation timeout after first byte, say — was
 * reported as status 0. Consumers serialize this field, so the regression was
 * silent and downstream.
 *
 * Site is not otherwise reachable from outside driver.js; it is exported additively
 * for these tests. A real browser is never launched: Site's constructor only reads
 * `options`, `browser` and `init` off the driver it is given.
 */

const test = require('node:test')
const assert = require('node:assert/strict')

const Driver = require('../driver')

const { Site } = Driver

/** A Site backed by a stub driver, so no browser is involved. */
function siteFor(url) {
    return new Site(url, {}, { options: { headers: {} }, browser: null, init: () => {} })
}

test('Site is exported without disturbing the default export', () => {
    assert.equal(typeof Driver, 'function', 'the default export is still Driver')
    assert.equal(typeof Site, 'function', 'Site is reachable for testing')
})

test('a recorded status survives a later error with no status', () => {
    const site = siteFor('https://example.com/')

    site.setUrl('https://example.com/', 200)
    site.setUrl('https://example.com/', undefined, 'Navigation timeout')

    const [entry] = site.analyzedUrls

    assert.equal(site.analyzedUrls.length, 1, 'the url should not be duplicated')
    assert.equal(entry.status, 200, 'the 200 must not be erased by the error path')
    assert.equal(entry.error, 'Navigation timeout')
})

test('a url first seen on the error path records status 0', () => {
    // Nothing is known about it, so 0 remains the honest answer.
    const site = siteFor('https://example.com/')

    site.setUrl('https://example.com/missing', undefined, 'net::ERR_FAILED')

    const [entry] = site.analyzedUrls

    assert.equal(entry.status, 0)
    assert.equal(entry.error, 'net::ERR_FAILED')
})

test('an explicit status still wins over one already recorded', () => {
    const site = siteFor('https://example.com/')

    site.setUrl('https://example.com/', 200)
    site.setUrl('https://example.com/', 404)

    assert.equal(site.analyzedUrls[0].status, 404)
})

test('analyzedUrls is an array of {url, status} and is frozen', () => {
    // The shape consumers depend on, and the getter hands out a frozen copy so
    // callers cannot mutate the driver's bookkeeping.
    const site = siteFor('https://example.com/')

    site.setUrl('https://example.com/', 200)

    const urls = site.analyzedUrls

    assert.ok(Array.isArray(urls))
    assert.deepEqual(urls, [{ url: 'https://example.com/', status: 200 }])
    assert.ok(Object.isFrozen(urls), 'the array should be frozen')
    assert.ok(Object.isFrozen(urls[0]), 'each entry should be frozen')
})

test('the request channel analyzes fetch traffic, not only XHR', () => {
    // Chromium reports fetch() under its own resource type. A channel gated
    // on 'xhr' alone silently drops most modern API calls, and any request
    // audit run through it undercounts.
    const types = Driver.ANALYZED_REQUEST_TYPES

    assert.ok(Array.isArray(types))
    assert.ok(types.includes('xhr'), "the list covers XMLHttpRequest traffic")
    assert.ok(types.includes('fetch'), "the list covers fetch() traffic")
})

test('request interception gates on the shared type list, not an xhr literal', () => {
    // The list above only protects the interception branch if the branch
    // actually consults it. Guard against a regression to the old literal.
    const fs = require('node:fs')
    const source = fs.readFileSync(require.resolve('../driver'), 'utf8')

    assert.ok(
        source.includes('ANALYZED_REQUEST_TYPES.includes(request.resourceType())'),
        'the interception branch consults ANALYZED_REQUEST_TYPES'
    )
    assert.ok(
        !/resourceType\(\)\s*===\s*'xhr'/.test(source),
        "no branch compares resourceType() to the 'xhr' literal alone"
    )
})
