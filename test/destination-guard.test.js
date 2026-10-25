'use strict'

/**
 * Tests for the optional destinationGuard.
 *
 * The guard exists so a caller can refuse to connect to sinkhole, botnet C2 and
 * private addresses. Every path that opens a connection has to consult it: the
 * page load, each browser request let through to the network (redirect hops
 * included), and the Node-side probes. The probes must also connect only to the
 * addresses the guard checked, never to a fresh lookup of the same name.
 *
 * No real browser is launched. Page behaviour is driven through a stub page that
 * replays the request events puppeteer would emit; probes use a real loopback
 * HTTP server so the pinned connection is proven on an actual socket.
 */

const test = require('node:test')
const assert = require('node:assert/strict')
const http = require('node:http')
const { EventEmitter } = require('node:events')

const Driver = require('../driver')
const { Site, DESTINATION_BLOCKED } = Driver
const { checkDestination, pinnedLookup, vetDial } = require('../scripts/lib/destination-guard')
const { collectDomainEvidence } = require('../scripts/lib/domain-evidence')

/** A guard that refuses the listed hostnames and vets everything else to `addresses`. */
function guardFor(blocked, addresses = ['127.0.0.1']) {
    const calls = []
    const guard = async (hostname) => {
        calls.push(hostname)
        return blocked.includes(hostname)
            ? { blocked: true, reason: 'resolves to destination blocklist', address: '192.0.2.1' }
            : { blocked: false, addresses }
    }
    return { guard, calls }
}

/** A Site whose driver never launches a browser. */
function siteFor(url, options = {}) {
    const driver = new Driver({ delay: 0, maxWait: 5000, ...options })
    driver.init = async () => {
        throw new Error('the browser must not be started')
    }
    return new Site(url, {}, driver)
}

/** A request as puppeteer hands it to the interception handler. */
function fakeRequest(page, url, { type = 'document', navigation = true, frame } = {}) {
    const request = {
        outcome: null,
        url: () => url,
        resourceType: () => type,
        isNavigationRequest: () => navigation,
        frame: () => frame || page.mainFrame(),
        headers: () => ({}),
        continue: () => { request.outcome = 'continue' },
        abort: (reason) => { request.outcome = `abort:${reason}` },
    }
    return request
}

/**
 * A page that replays `script(page)` as its navigation: each step emits a
 * request and the interception handler's decision decides whether the next
 * step runs, as Chrome would.
 */
function fakePage(script) {
    const page = new EventEmitter()
    const main = {}
    page.requests = []
    page.mainFrame = () => main
    page.setRequestInterception = async () => {}
    page.isClosed = () => false
    page.close = async () => {}
    page.url = () => 'about:blank'
    page.goto = async () => script(page, async (request) => {
        page.requests.push(request)
        // Handlers are async; let the guard settle before reading the outcome.
        await Promise.all(page.listeners('request').map((listener) => listener(request)))
        return request.outcome
    })
    return page
}

test('no guard means no opinion', async () => {
    assert.deepEqual(await checkDestination(undefined, 'example.com'), { blocked: false })
    assert.deepEqual(await vetDial(undefined, 'https://example.com/'), {})
})

test('a guard that throws refuses the dial instead of permitting it', async () => {
    const verdict = await checkDestination(async () => {
        throw new Error('resolver exploded')
    }, 'example.com')

    assert.equal(verdict.blocked, true)
    assert.match(verdict.reason, /guard error: resolver exploded/)
})

test('IPv6 literals reach the guard without URL brackets', async () => {
    let seen
    await checkDestination(async (hostname) => {
        seen = hostname
        return false
    }, '[2001:DB8::1]')

    assert.equal(seen, '2001:db8::1')
})

test('pinnedLookup hands out only vetted addresses, by family and in both callback forms', async () => {
    const lookup = pinnedLookup(['192.0.2.10', '2001:db8::10', 'not-an-ip'])
    const call = (options) => new Promise((resolve) => lookup('host.example', options, (...args) => resolve(args)))

    assert.deepEqual(await call({}), [null, '192.0.2.10', 4])
    assert.deepEqual(await call({ family: 6 }), [null, '2001:db8::10', 6])
    assert.deepEqual(await call({ family: 'IPv6' }), [null, '2001:db8::10', 6])
    assert.deepEqual(await call({ all: true }), [null, [
        { address: '192.0.2.10', family: 4 },
        { address: '2001:db8::10', family: 6 },
    ]])
})

test('pinnedLookup with nothing vetted fails like NXDOMAIN rather than resolving again', async () => {
    const [error] = await new Promise((resolve) =>
        pinnedLookup([])('host.example', { all: true }, (...args) => resolve(args)))

    assert.equal(error.code, 'ENOTFOUND')
})

test('a refused page is never opened', async () => {
    const { guard } = guardFor(['sinkholed.example'])
    const site = siteFor('http://sinkholed.example/', { destinationGuard: guard })
    let opened = false
    site.newPage = async () => {
        opened = true
        throw new Error('a page was opened for a refused host')
    }

    await assert.rejects(site.goto(new URL('http://sinkholed.example/')), (error) => {
        assert.equal(error.code, DESTINATION_BLOCKED)
        assert.equal(error.hostname, 'sinkholed.example')
        return true
    })
    assert.equal(opened, false)
    assert.deepEqual(site.collectResults().blockedDestinations, [{
        url: 'http://sinkholed.example/',
        hostname: 'sinkholed.example',
        navigation: true,
        reason: 'resolves to destination blocklist',
        address: '192.0.2.1',
    }])
})

test('a redirect hop to a refused host is aborted and reported as the refusal', async () => {
    const { guard } = guardFor(['sinkholed.example'])
    const site = siteFor('http://redirector.example/', { destinationGuard: guard })
    const page = fakePage(async (page, emit) => {
        assert.equal(await emit(fakeRequest(page, 'http://redirector.example/')), 'continue')
        // Chrome surfaces the 302 target as a new navigation request.
        assert.equal(await emit(fakeRequest(page, 'http://sinkholed.example/landing')), 'abort:blockedbyclient')
        throw new Error('net::ERR_BLOCKED_BY_CLIENT at http://redirector.example/')
    })
    site.newPage = async () => page

    await assert.rejects(site.goto(new URL('http://redirector.example/')), (error) => {
        assert.equal(error.code, DESTINATION_BLOCKED)
        assert.equal(error.hostname, 'sinkholed.example')
        return true
    })
    const [entry] = site.collectResults().blockedDestinations
    assert.equal(entry.navigation, true)
    assert.equal(entry.hostname, 'sinkholed.example')
})

test('a script from a refused host is aborted while the page itself loads', async () => {
    const { guard, calls } = guardFor(['c2.example'])
    const site = siteFor('http://shop.example/', { destinationGuard: guard })
    const page = fakePage(async (page, emit) => {
        assert.equal(await emit(fakeRequest(page, 'http://shop.example/')), 'continue')
        const script = { type: 'script', navigation: false }
        assert.equal(await emit(fakeRequest(page, 'http://c2.example/x.js', script)), 'abort:blockedbyclient')
        assert.equal(await emit(fakeRequest(page, 'http://cdn.example/app.js', script)), 'continue')
        assert.equal(await emit(fakeRequest(page, 'http://cdn.example/other.js', script)), 'continue')
        throw new Error('stop after the requests')
    })
    site.newPage = async () => page

    await assert.rejects(site.goto(new URL('http://shop.example/')), (error) => {
        assert.notEqual(error.code, DESTINATION_BLOCKED, 'a refused subresource does not fail the page')
        return true
    })
    assert.deepEqual(site.collectResults().blockedDestinations.map(({ hostname, navigation }) => ({ hostname, navigation })),
        [{ hostname: 'c2.example', navigation: false }])
    assert.equal(calls.filter((name) => name === 'cdn.example').length, 1, 'one verdict per host per site')
})

test('requests that are aborted anyway never reach the guard', async () => {
    const { guard, calls } = guardFor([])
    const site = siteFor('http://shop.example/', { destinationGuard: guard })
    const page = fakePage(async (page, emit) => {
        assert.equal(await emit(fakeRequest(page, 'http://shop.example/')), 'continue')
        await emit(fakeRequest(page, 'http://img.example/a.png', { type: 'image', navigation: false }))
        await emit(fakeRequest(page, 'http://frame.example/', { frame: {} }))
        throw new Error('stop after the requests')
    })
    site.newPage = async () => page

    await assert.rejects(site.goto(new URL('http://shop.example/')))
    assert.deepEqual(calls, ['shop.example'])
})

/** A loopback server that counts what reaches it. */
async function countingServer() {
    const hits = []
    const server = http.createServer((request, response) => {
        hits.push(`${request.headers.host} ${request.url}`)
        response.writeHead(200, { 'Content-Type': 'text/plain' })
        response.end('User-agent: *\n')
    })
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
    return { hits, port: server.address().port, close: () => new Promise((resolve) => server.close(resolve)) }
}

test('the robots probe never dials a refused host', async (t) => {
    // `localhost` really resolves to the server, so only the guard stops it.
    const server = await countingServer()
    t.after(server.close)
    const { guard } = guardFor(['localhost'])
    const site = siteFor(`http://localhost:${server.port}/`, { destinationGuard: guard, probe: 'basic' })

    await site.probe(new URL(`http://localhost:${server.port}/`))

    assert.deepEqual(server.hits, [])
})

test('the robots probe connects only to the address the guard vetted', async (t) => {
    // `vetted.invalid` resolves nowhere, so reaching the server proves the
    // connection used the pinned address rather than a fresh lookup.
    const server = await countingServer()
    t.after(server.close)
    const { guard } = guardFor([], ['127.0.0.1'])
    const site = siteFor(`http://vetted.invalid:${server.port}/`, { destinationGuard: guard, probe: 'basic' })

    await site.probe(new URL(`http://vetted.invalid:${server.port}/`))

    assert.deepEqual(server.hits, [`vetted.invalid:${server.port} /robots.txt`])
})

test('the robots probe is refused when the guard could not vet any address', async (t) => {
    const server = await countingServer()
    t.after(server.close)
    // `localhost` would resolve on its own; nothing vetted must mean no dial.
    const { guard } = guardFor([], [])
    const site = siteFor(`http://localhost:${server.port}/`, { destinationGuard: guard, probe: 'basic' })

    await site.probe(new URL(`http://localhost:${server.port}/`))

    assert.deepEqual(server.hits, [])
})

test('domain evidence documents go through beforeDial and use its pinned lookup', async () => {
    const lookup = async () => []
    const requested = []
    const request = async (source, _timeout, dial) => {
        requested.push({ source, pinned: typeof dial.lookup === 'function' })
        throw new Error('HTTP 404')
    }
    const refused = []
    const beforeDial = async (source) => {
        if (new URL(source).hostname === 'login.sinkholed.example') {
            refused.push(source)
            throw new Error('Destination blocked')
        }
        return { lookup: () => {} }
    }

    await collectDomainEvidence({ url: 'https://login.sinkholed.example/', mode: 'full', lookup, request, beforeDial })
    assert.equal(requested.length, 0, 'no document was requested from a refused host')
    assert.ok(refused.length > 0)

    await collectDomainEvidence({ url: 'https://login.allowed.example/', mode: 'full', lookup, request, beforeDial })
    assert.ok(requested.length > 0)
    assert.ok(requested.every(({ pinned }) => pinned), 'every document request carried the pinned lookup')
})

test('without a guard results still carry an empty blockedDestinations list', () => {
    const site = siteFor('https://example.com/')

    assert.deepEqual(site.collectResults().blockedDestinations, [])
})
