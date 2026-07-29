#!/usr/bin/env node

'use strict'

/**
 * Measures whether `xhr`-only markers actually fire on real pages.
 *
 * 85 of the technologies added for the request are detectable *only* through the
 * `xhr` channel — a browser request to a vendor API host. That is sound in
 * principle, but most API integrations run server-side, where a browser never
 * sees them. Vendors say so themselves: OpenAI tells you not to expose keys
 * client-side, and Jasper tells client apps to proxy through a back end.
 *
 * So "catalog-matchable" and "will be observed in a crawl" are different claims,
 * and until now only the first was measured. This script measures the second.
 *
 * Method: scan a committed list of real pages, chosen to be the *most* favourable
 * case — AI vendors' own sites, playgrounds and AI-forward SaaS. If a vendor's API
 * host is not called from the browser there, it will not be on an ordinary
 * company website. Every third-party hostname observed is recorded, so the result
 * is a measurement rather than a pass/fail.
 *
 * Usage:
 *   node scripts/xhr-audit.js                  # scan and write results
 *   node scripts/xhr-audit.js --check          # report retained results, no network
 *   node scripts/xhr-audit.js --limit=10       # scan the first N urls
 *   node scripts/xhr-audit.js --timeout=20000  # per-page budget, default 25s
 *
 * One page per site, no crawling. Results land in data/xhr-audit-results.json.
 */

const fs = require('fs')
const path = require('path')

const { loadCatalog } = require('./lib/catalog')
const { CHANNELS } = require('./lib/channels')
const { TECHNOLOGIES } = require('./lib/emerging-technologies')

const ROOT = path.resolve(__dirname, '..')
const URLS = path.join(ROOT, 'data/xhr-audit-urls.txt')
const RESULTS = path.join(ROOT, 'data/xhr-audit-results.json')

const args = process.argv.slice(2)
const CHECK_ONLY = args.includes('--check')
const numeric = (flag, fallback) => {
    const arg = args.find((value) => value.startsWith(`--${flag}=`))

    return arg ? Number(arg.split('=')[1]) : fallback
}
const LIMIT = numeric('limit', Infinity)
const TIMEOUT = numeric('timeout', 25000)

/** Technologies whose only detection channel is xhr. */
function xhrOnlyTechnologies() {
    const { technologies } = loadCatalog(path.join(ROOT, 'technologies'))
    const channelsOf = (entry) =>
        Object.keys(CHANNELS).filter((channel) => entry[channel] !== undefined)

    return Object.keys(TECHNOLOGIES)
        .filter((name) => technologies[name])
        .filter((name) => {
            const channels = channelsOf(technologies[name])

            return channels.length === 1 && channels[0] === 'xhr'
        })
        .sort()
}

function readUrls() {
    return fs
        .readFileSync(URLS, 'utf8')
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#'))
        .slice(0, LIMIT)
}

async function scan() {
    // Required lazily: this is the only script that needs a browser.
    const Driver = require('../driver')

    const urls = readUrls()
    const xhrOnly = xhrOnlyTechnologies()

    console.log(
        `Scanning ${urls.length} pages, watching for ${xhrOnly.length} ` +
            `xhr-only technologies (${TIMEOUT}ms per page)\n`
    )

    const pages = []
    const firedBy = new Map(xhrOnly.map((name) => [name, []]))
    const allHosts = new Map()

    for (const [index, url] of urls.entries()) {
        const driver = new Driver({
            maxWait: TIMEOUT,
            maxUrls: 1,
            recursive: false,
            delay: 0,
            batchSize: 1,
        })

        const record = {
            url,
            status: null,
            technologies: [],
            // Hosts reached by *any* request, and separately those reached by a
            // request Chrome classifies as `xhr`. driver.js only feeds the second
            // set to the xhr channel, so that is the number that matters.
            allHosts: [],
            xhrHosts: [],
            error: null,
        }

        try {
            await driver.init()

            const site = await driver.open(url)

            site.on('error', () => {})

            // emit() passes a single object, not positional arguments.
            //
            // This only ever sees `document` and `script` requests: driver.js
            // aborts every other resource type and emits only for the survivors.
            // So it cannot be used to observe xhr traffic — an earlier version of
            // this script reported "0 xhr hosts" purely as an artifact of that.
            site.on('request', ({ request }) => {
                try {
                    const { hostname } = new URL(request.url())

                    if (!record.allHosts.includes(hostname)) {
                        record.allHosts.push(hostname)
                    }
                } catch (error) {
                    // Ignore unparseable request urls.
                }
            })

            const results = await site.analyze()

            record.status = (results.urls[0] && results.urls[0].status) || null
            record.technologies = results.technologies.map(({ name }) => name)

            // The driver's own record of the xhr hostnames it fed to the channel.
            // This is authoritative, unlike anything observable from a listener.
            record.xhrHosts = [
                ...new Set(Object.values(site.analyzedXhr || {}).flat()),
            ]
        } catch (error) {
            record.error = String(error.message || error).slice(0, 200)
        } finally {
            try {
                await driver.destroy()
            } catch (error) {
                // Ignore teardown failures.
            }
        }

        for (const host of record.allHosts) {
            allHosts.set(host, (allHosts.get(host) || 0) + 1)
        }

        for (const name of record.technologies) {
            if (firedBy.has(name)) {
                firedBy.get(name).push(url)
            }
        }

        const hit = record.technologies.filter((name) => firedBy.has(name))

        console.log(
            `  [${index + 1}/${urls.length}] ${record.error ? 'ERR ' : 'ok  '}` +
                `${url}\n        ${record.allHosts.length} hosts, ` +
                `${record.xhrHosts.length} via xhr` +
                `${hit.length ? `, xhr-only hits: ${hit.join(', ')}` : ''}` +
                `${record.error ? `, ${record.error}` : ''}`
        )

        pages.push(record)
    }

    const fired = xhrOnly.filter((name) => firedBy.get(name).length)

    // "Scanned without throwing" is not the same as "usefully loaded". A 403, or
    // a page that produced no hostnames at all, gave the markers no opportunity.
    const rendered = pages.filter(
        ({ error, allHosts, technologies }) =>
            !error && allHosts.length > 0 && technologies.length > 0
    )
    const blocked = pages.filter(
        ({ error, status }) => !error && status !== null && status >= 400
    )
    const noStatus = pages.filter(({ error, status }) => !error && status === null)

    return {
        urls: pages.length,
        pagesScanned: pages.filter(({ error }) => !error).length,
        pagesFailed: pages.filter(({ error }) => error).length,
        pagesRendered: rendered.length,
        pagesBlocked: blocked.map(({ url, status }) => ({ url, status })),
        pagesWithoutStatus: noStatus.map(({ url }) => url),
        statusDistribution: pages.reduce((counts, { status }) => {
            const key = status === null ? 'none' : String(status)

            counts[key] = (counts[key] || 0) + 1

            return counts
        }, {}),
        // Stated so the figure below is never read as an observation rate.
        methodology: {
            claim:
                `${fired.length} of ${xhrOnly.length} xhr-only markers appeared ` +
                `in this ${pages.length}-page corpus under the current ` +
                'request-aborting driver.',
            limitations: [
                'This is a yield against a convenience corpus, not an ' +
                    'observation rate. No mapping guarantees that every marker ' +
                    'had a page where its vendor was actually in use.',
                'driver.js aborts every request that is not document or script. ' +
                    'An aborted XHR can prevent the follow-on application ' +
                    'requests that would have exercised other markers, so this ' +
                    'figure is a lower bound on what a normal browser would see.',
                'Pages returning 304 or a redirect are counted as scanned; a ' +
                    'cached response may fetch fewer subresources than a cold one.',
                'A defensible rate needs controlled marker-to-page opportunities ' +
                    'or a representative crawl of company websites.',
            ],
        },
        xhrOnlyChecked: xhrOnly.length,
        xhrOnlyFired: fired.length,
        firedTechnologies: fired.map((name) => ({
            technology: name,
            pages: firedBy.get(name),
        })),
        neverFired: xhrOnly.filter((name) => !firedBy.get(name).length),
        distinctHostsObserved: allHosts.size,
        distinctXhrHostsObserved: new Set(
            pages.flatMap(({ xhrHosts }) => xhrHosts)
        ).size,
        pagesWithAnyXhr: pages.filter(({ xhrHosts }) => xhrHosts.length).length,
        pages,
    }
}

function report(results) {
    const { xhrOnlyChecked, xhrOnlyFired } = results

    console.log(`\n${'='.repeat(68)}`)
    console.log('XHR-ONLY MARKER AUDIT')
    console.log('='.repeat(68))
    console.log(
        `Pages scanned:            ${results.pagesScanned}/${results.urls}` +
            `${results.pagesFailed ? ` (${results.pagesFailed} failed)` : ''}`
    )
    console.log(
        `  usefully rendered:      ${results.pagesRendered}/${results.urls}` +
            `${results.pagesBlocked.length ? `, ${results.pagesBlocked.length} blocked` : ''}` +
            `${results.pagesWithoutStatus.length ? `, ${results.pagesWithoutStatus.length} without a status` : ''}`
    )
    console.log(
        `  status codes:           ${Object.entries(results.statusDistribution)
            .map(([code, count]) => `${code}:${count}`)
            .join(' ')}`
    )
    console.log(`Distinct hostnames seen:   ${results.distinctHostsObserved}`)
    console.log(
        `  of those via an xhr:     ${results.distinctXhrHostsObserved}` +
            ` (on ${results.pagesWithAnyXhr}/${results.urls} pages)`
    )
    console.log(`xhr-only markers seen:    ${xhrOnlyFired}/${xhrOnlyChecked}`)

    if (results.firedTechnologies.length) {
        console.log('\nFIRED')
        for (const { technology, pages } of results.firedTechnologies) {
            console.log(`  ${technology.padEnd(28)} ${pages.length} page(s)`)
        }
    }

    console.log(`\n${results.methodology.claim}`)
    console.log('\nThis is NOT an observation rate. Limitations:')
    for (const limitation of results.methodology.limitations) {
        console.log(`  - ${limitation}`)
    }
}

async function main() {
    // Untracked measurements: absent is an expected state on a clone.
    if (!fs.existsSync(URLS)) {
        console.log(
            `No url list at ${path.relative(ROOT, URLS)}. It is untracked; ` +
                'restore it locally to audit or verify.'
        )

        return
    }

    if (CHECK_ONLY) {
        if (!fs.existsSync(RESULTS)) {
            console.log(
                `No retained results at ${path.relative(ROOT, RESULTS)}. They are ` +
                    'untracked; run `npm run audit:xhr` to produce them.'
            )

            return
        }

        report(JSON.parse(fs.readFileSync(RESULTS, 'utf8')))
        console.log('\n(--check: retained results, no network access)')

        return
    }

    const results = await scan()

    report(results)

    fs.writeFileSync(RESULTS, `${JSON.stringify(results, null, 2)}\n`)

    console.log(`\nWrote ${path.relative(ROOT, RESULTS)}`)
}

main().catch((error) => {
    console.error(error)
    process.exit(1)
})
