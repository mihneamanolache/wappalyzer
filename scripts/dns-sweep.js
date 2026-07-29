#!/usr/bin/env node

'use strict'

/**
 * Verifies the catalog's `dns.TXT` markers against real company domains.
 *
 * A tenant marker such as `openai-domain-verification=` is only worth shipping if
 * it is actually present in the wild. An earlier sweep established that but did
 * not retain its corpus, so its markers could not be re-checked and had to be
 * labelled `unreproduced-prior-sweep`.
 *
 * This script closes that: the corpus is committed at
 * `data/dns-sweep-domains.txt`, and the tokens are read **from the catalog**
 * rather than a hardcoded list, so it measures exactly what ships. Re-running it
 * reproduces the evidence.
 *
 * Usage:
 *   node scripts/dns-sweep.js                 # sweep and write data/dns-sweep-results.json
 *   node scripts/dns-sweep.js --check         # compare against the retained results, no DNS
 *   node scripts/dns-sweep.js --concurrency=N # default 32
 *
 * Only public DNS TXT records are read. Aggregates are retained rather than
 * every raw record: per marker, how many corpus domains matched and a few
 * examples. The corpus makes the raw form reproducible on demand.
 */

const crypto = require('crypto')
const dns = require('dns').promises
const fs = require('fs')
const path = require('path')

const { loadCatalog } = require('./lib/catalog')

const ROOT = path.resolve(__dirname, '..')
const CORPUS = path.join(ROOT, 'data/dns-sweep-domains.txt')
const RESULTS = path.join(ROOT, 'data/dns-sweep-results.json')

const args = process.argv.slice(2)
const CHECK_ONLY = args.includes('--check')
const CONCURRENCY = Number(
    (args.find((arg) => arg.startsWith('--concurrency=')) || '').split('=')[1] || 32
)

/**
 * Full SHA-256, not a truncated fingerprint.
 *
 * This was previously sliced to 16 hex characters (64 bits) while still being
 * called `sha256`, which overstated the provenance. The whole digest costs
 * nothing to retain and is what a reader will expect the field name to mean.
 */
const sha256 = (buffer) =>
    crypto.createHash('sha256').update(buffer).digest('hex')

/**
 * Stable hash of the corpus, over the parsed domain set rather than the raw
 * file. The results depend on which domains were resolved, not on the comments
 * around them, so editing a comment must not invalidate retained evidence while
 * adding, removing or renaming a domain still must.
 */
function corpusHash(domains) {
    return sha256([...domains].sort().join('\n'))
}

/** Stable hash of the marker set, so a catalog change is detectable. */
function markerSetHash(markers) {
    return sha256(
        markers
            .map(({ technology, pattern }) => `${technology}\u0000${pattern}`)
            .sort()
            .join('\n')
    )
}

/** Domains to resolve, comments and blanks stripped. */
function readCorpus() {
    return fs
        .readFileSync(CORPUS, 'utf8')
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith('#'))
}

/**
 * Every `dns.TXT` pattern in the catalog, keyed by technology.
 * @returns {Array<{technology: string, pattern: string, regex: RegExp}>}
 */
function catalogTxtMarkers() {
    const { technologies } = loadCatalog(path.join(ROOT, 'technologies'))
    const markers = []

    for (const [technology, entry] of Object.entries(technologies)) {
        const record = entry.dns

        if (!record || typeof record !== 'object' || Array.isArray(record)) {
            continue
        }

        // transformPatterns lowercases keyed-channel keys, so accept either case.
        const txt = record.TXT === undefined ? record.txt : record.TXT

        if (txt === undefined) {
            continue
        }

        for (const pattern of Array.isArray(txt) ? txt : [txt]) {
            let regex

            try {
                regex = new RegExp(String(pattern), 'i')
            } catch (error) {
                console.error(`  skipping uncompilable pattern on ${technology}: ${pattern}`)

                continue
            }

            markers.push({ technology, pattern: String(pattern), regex })
        }
    }

    return markers
}

/**
 * Resolve TXT for one domain.
 *
 * The error class matters. "This domain publishes no TXT records" and "the
 * resolver timed out" are different facts, and collapsing both into an empty
 * result silently understates how many domains were actually checked.
 *
 * @returns {{records: string[], outcome: string}}
 */
async function resolveTxt(domain) {
    try {
        const records = await dns.resolveTxt(domain)

        return {
            records: records.map((chunks) => chunks.join('')),
            outcome: records.length ? 'ok' : 'nodata',
        }
    } catch (error) {
        const code = String(error.code || 'UNKNOWN')
        const outcome = {
            ENODATA: 'nodata',
            ENOTFOUND: 'nxdomain',
            ESERVFAIL: 'servfail',
            ETIMEOUT: 'timeout',
            ECONNREFUSED: 'refused',
        }[code] || `error:${code}`

        return { records: [], outcome }
    }
}

/** Run `worker` over `items` with a bounded number in flight. */
async function pooled(items, limit, worker) {
    const queue = [...items]
    const runners = Array.from({ length: Math.min(limit, queue.length) }, async () => {
        while (queue.length) {
            await worker(queue.shift())
        }
    })

    await Promise.all(runners)
}

async function sweep() {
    const domains = readCorpus()
    const markers = catalogTxtMarkers()

    console.log(
        `Resolving TXT for ${domains.length} domains against ` +
            `${markers.length} catalog markers (concurrency ${CONCURRENCY})\n`
    )

    const hits = new Map(
        markers.map(({ technology, pattern }) => [
            `${technology} ${pattern}`,
            { technology, pattern, domains: [] },
        ])
    )

    let resolved = 0
    let withRecords = 0
    let totalRecords = 0
    const outcomes = {}
    const unresolved = []

    await pooled(domains, CONCURRENCY, async (domain) => {
        const { records, outcome } = await resolveTxt(domain)

        resolved++
        outcomes[outcome] = (outcomes[outcome] || 0) + 1

        if (outcome !== 'ok' && outcome !== 'nodata') {
            unresolved.push({ domain, outcome })
        }

        if (records.length) {
            withRecords++
            totalRecords += records.length
        }

        for (const { technology, pattern, regex } of markers) {
            if (records.some((record) => regex.test(record))) {
                hits.get(`${technology} ${pattern}`).domains.push(domain)
            }
        }

        if (resolved % 100 === 0) {
            console.log(`  ${resolved}/${domains.length} domains`)
        }
    })

    const observed = [...hits.values()]
        .filter(({ domains: matched }) => matched.length)
        .sort((a, b) => b.domains.length - a.domains.length)
    const unobserved = [...hits.values()]
        .filter(({ domains: matched }) => !matched.length)
        .sort((a, b) => a.technology.localeCompare(b.technology))

    const results = {
        // Provenance, so a retained result can be audited rather than trusted.
        // Without these a reader cannot tell whether the file matches the corpus
        // and catalog now on disk.
        ranAt: new Date().toISOString(),
        corpus: path.relative(ROOT, CORPUS),
        corpusSha256: corpusHash(domains),
        markerSetSha256: markerSetHash(markers),
        resolver: {
            servers: dns.getServers(),
            nodeVersion: process.version,
            platform: process.platform,
        },
        corpusDomains: domains.length,
        domainsWithTxt: withRecords,
        txtRecordsSeen: totalRecords,
        // Every domain is accounted for by outcome, so "no records" is no longer
        // indistinguishable from a timeout or SERVFAIL.
        resolutionOutcomes: outcomes,
        unresolvedDomains: unresolved,
        markersChecked: markers.length,
        markersObserved: observed.length,
        markersUnobserved: unobserved.length,
        observed: observed.map(({ technology, pattern, domains: matched }) => ({
            technology,
            pattern,
            domainCount: matched.length,
            examples: matched.slice(0, 3),
        })),
        unobserved: unobserved.map(({ technology, pattern }) => ({
            technology,
            pattern,
        })),
    }

    return results
}

function report(results) {
    console.log(
        `\n${results.domainsWithTxt}/${results.corpusDomains} domains had TXT ` +
            `records (${results.txtRecordsSeen} records total)`
    )

    if (results.resolutionOutcomes) {
        console.log(
            `Resolution outcomes: ${Object.entries(results.resolutionOutcomes)
                .sort((a, b) => b[1] - a[1])
                .map(([outcome, count]) => `${outcome}:${count}`)
                .join(' ')}`
        )

        const failed = (results.unresolvedDomains || []).length

        if (failed) {
            console.log(
                `${failed} domain(s) could not be resolved and were not checked ` +
                    'against any marker.'
            )
        }
    }

    console.log()
    console.log(
        `Markers observed:   ${results.markersObserved}/${results.markersChecked}`
    )
    console.log(
        `Markers unobserved: ${results.markersUnobserved}/${results.markersChecked}\n`
    )

    console.log('OBSERVED (technology, domains, examples)')
    for (const { technology, domainCount, examples } of results.observed) {
        console.log(
            `  ${String(domainCount).padStart(4)}  ${technology.padEnd(32)} ${examples.join(', ')}`
        )
    }

    if (results.unobserved.length) {
        console.log('\nNOT OBSERVED IN THIS CORPUS')
        console.log(
            '  Absence here is weak evidence: the corpus is 536 domains, not the web.\n' +
                '  These stay in the catalog but must not be described as corpus-verified.'
        )
        for (const { technology, pattern } of results.unobserved) {
            console.log(`  - ${technology}: ${pattern}`)
        }
    }
}

async function main() {
    // The corpus and results are bulky measurements and are not tracked, so their
    // absence is an expected state on a clone, not a failure.
    if (!fs.existsSync(CORPUS)) {
        console.log(
            `No corpus at ${path.relative(ROOT, CORPUS)}. It is untracked; ` +
                'restore it locally to sweep or verify.'
        )

        return
    }

    if (CHECK_ONLY) {
        if (!fs.existsSync(RESULTS)) {
            console.log(
                `No retained results at ${path.relative(ROOT, RESULTS)}. They are ` +
                    'untracked; run `npm run sweep` to produce them.'
            )

            return
        }

        const retained = JSON.parse(fs.readFileSync(RESULTS, 'utf8'))

        report(retained)

        // Verify, not just display. A retained result is only evidence if it was
        // produced from the corpus and marker set currently on disk.
        const corpusNow = corpusHash(readCorpus())
        const markersNow = markerSetHash(catalogTxtMarkers())
        const problems = []

        if (retained.corpusSha256 !== corpusNow) {
            problems.push(
                `corpus has changed since the sweep (retained ` +
                    `${retained.corpusSha256}, now ${corpusNow})`
            )
        }

        if (retained.markerSetSha256 !== markersNow) {
            problems.push(
                `catalog markers have changed since the sweep (retained ` +
                    `${retained.markerSetSha256}, now ${markersNow})`
            )
        }

        console.log('\n(--check: no DNS queries made)')
        console.log(`Ran at:            ${retained.ranAt || 'unknown'}`)
        console.log(`Corpus hash:       ${retained.corpusSha256} (now ${corpusNow})`)
        console.log(`Marker set hash:   ${retained.markerSetSha256} (now ${markersNow})`)

        if (problems.length) {
            console.error('\nSTALE:')
            for (const problem of problems) {
                console.error(`  - ${problem}`)
            }
            console.error('\nRun `npm run sweep` to refresh.')
            process.exit(1)
        }

        console.log('\nRetained results match the corpus and catalog on disk.')

        return
    }

    const results = await sweep()

    report(results)

    fs.writeFileSync(RESULTS, `${JSON.stringify(results, null, 2)}\n`)

    console.log(`\nWrote ${path.relative(ROOT, RESULTS)}`)
}

main().catch((error) => {
    console.error(error)
    process.exit(1)
})
