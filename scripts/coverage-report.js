#!/usr/bin/env node

/**
 * Cross-references the requested product list against this catalog and reports
 * what can be detected, what rolls up to a parent platform, and what cannot be
 * detected from outside a company at all.
 *
 * It is generated rather than hand-written so it stays true as the catalog
 * changes.
 *
 * The per-product inputs (data/requested-products.json and
 * scripts/lib/requested-mapping.js) name a third party's product list, so they
 * are deliberately untracked. Without them this script reports what it cannot do
 * and exits successfully — the tracked, aggregate-only artifact is
 * docs/coverage-summary.md.
 *
 * Usage:
 *   node scripts/coverage-report.js            # summary
 *   node scripts/coverage-report.js --full     # every product, grouped
 *   node scripts/coverage-report.js --json     # machine-readable
 *   node scripts/coverage-report.js --markdown # markdown, for sending on
 *   node scripts/coverage-report.js --summary  # aggregate counts only, no products
 */

const fs = require('fs')
const path = require('path')

const { loadCatalog } = require('./lib/catalog')
const { CHANNELS } = require('./lib/channels')
const { EVIDENCE } = require('./lib/emerging-technologies')

const { PATHS, hasRequestData, hasSweepData } = require('./lib/untracked')

const ROOT = path.resolve(__dirname, '..')

const args = process.argv.slice(2)
const FULL = args.includes('--full')
const JSON_OUTPUT = args.includes('--json')
const MARKDOWN = args.includes('--markdown')
const SUMMARY_ONLY = args.includes('--summary')

const STATUS_LABELS = {
    detected: 'Detected',
    'platform-level': 'Detected at platform level',
    candidate: 'Candidate, no signal yet',
    'catalog-only': 'Mapped, detection not possible',
    model: 'Not detectable (model)',
    backend: 'Not detectable (back-end infrastructure)',
    endpoint: 'Not detectable (endpoint/network agent)',
    desktop: 'Not detectable (desktop application)',
}

const STATUS_ORDER = [
    'detected',
    'platform-level',
    'candidate',
    'catalog-only',
    'model',
    'backend',
    'endpoint',
    'desktop',
]

/** What each status means, independent of any one product. */
const STATUS_DESCRIPTIONS = {
    detected:
        'A catalog entry exists under this name and has a detection path. This ' +
        'is catalog reachability, not proof that the marker was observed on a ' +
        'real customer site.',
    'platform-level':
        'An AI feature or model inside a platform that is detected. Whether a ' +
        'tenant has the feature enabled is not exposed externally, so it is ' +
        'reported against the parent platform or the API that serves it.',
    candidate:
        'Deliverable over the web, but no signal has been verified yet. These ' +
        'are the realistic next additions.',
    'catalog-only':
        'Carried in the catalog with full taxonomy metadata so the mapping is ' +
        'complete, but the product emits nothing observable, so the entry has ' +
        'no detection pattern and can never fire. Reachable only through a ' +
        'text-mined hiring signal (see scripts/lib/text-signals.js).',
    model:
        'A model name. Models leave no fingerprint of their own; the API that ' +
        'serves them does, and that is what gets detected.',
    backend:
        'Server-side data or ML infrastructure. It runs behind the application ' +
        'and emits nothing observable to a visitor.',
    endpoint:
        'Endpoint, network or cloud-posture security. Runs as an agent or ' +
        'out-of-band scanner with no web-visible footprint.',
    desktop: 'A desktop or command-line application, not a web technology.',
}

/** Which detection channels an entry actually uses. */
function channelsOf(entry) {
    return Object.keys(CHANNELS).filter((channel) => entry[channel] !== undefined)
}

/**
 * An entry detectable only through `xhr` is matchable but rarely observable.
 *
 * scripts/xhr-audit.js measured this: 1 of 85 xhr-only markers appeared in a
 * 29-page corpus under the current request-aborting driver, while 47 distinct xhr
 * hostnames were collected. That is a yield against a convenience corpus, not an
 * observation rate — see docs/live-evidence.md for why. The channel demonstrably
 * works; vendor API calls simply tend to happen server-side.
 *
 * Reported as a caveat on the headline rather than a separate status, because the
 * entries are correct — they are just unlikely to fire in a passive crawl.
 */
const isWeaklyObservable = (channels) =>
    channels.length === 1 && channels[0] === 'xhr'

/** Retained audit measurement, if it has been run. */
function readXhrAudit() {
    const file = path.join(ROOT, 'data/xhr-audit-results.json')

    if (!fs.existsSync(file)) {
        return null
    }

    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'))
    } catch (error) {
        return null
    }
}

function build() {
    // Required lazily: the module is untracked, so it may be absent on a clone.
    const { classify } = require('./lib/requested-mapping')

    const request = JSON.parse(fs.readFileSync(PATHS.request, 'utf8'))
    const { technologies } = loadCatalog(path.join(ROOT, 'technologies'))

    const byNormalizedName = new Map()

    for (const name of Object.keys(technologies)) {
        byNormalizedName.set(name.toLowerCase().replace(/[^a-z0-9]/g, ''), name)
    }

    const results = request.products.map((item) => {
        const classified = classify(item, byNormalizedName)
        const entry = classified.mapsTo ? technologies[classified.mapsTo] : null

        return {
            ...classified,
            channels: entry ? channelsOf(entry) : [],
            evidence: classified.mapsTo ? EVIDENCE[classified.mapsTo] || null : null,
        }
    })

    // Entries with no channel of their own can still be reached through
    // `implies` — PostgreSQL surfaces whenever Supabase, Django or dozens of
    // other detections imply it. Those count as detected, with the channel
    // reported honestly as `implies`.
    const impliedTargets = new Set()

    for (const entry of Object.values(technologies)) {
        const implies = entry.implies

        if (implies === undefined) {
            continue
        }

        for (const item of Array.isArray(implies) ? implies : [implies]) {
            impliedTargets.add(String(item).split('\\;')[0].trim())
        }
    }

    // A product claimed as detected must actually be reachable: through a
    // channel of its own, or through another technology's implies.
    for (const result of results) {
        if (
            ['detected', 'platform-level'].includes(result.status) &&
            !result.channels.length
        ) {
            if (result.mapsTo && impliedTargets.has(result.mapsTo)) {
                result.channels = ['implies']
                result.reason =
                    `${result.mapsTo} has no pattern of its own but is implied ` +
                    'by other detections.'

                continue
            }

            result.status = 'candidate'
            result.reason =
                `Mapped to ${result.mapsTo}, but that entry has no detection ` +
                'channel and nothing implies it.'
        }
    }

    const byStatus = {}

    for (const status of STATUS_ORDER) {
        byStatus[status] = results.filter((result) => result.status === status)
    }

    // The two flagged priorities are on their own tab and are phrased as
    // sentences, so resolve them against the catalog explicitly rather than
    // relying on a name match.
    const priorities = request.priorities.map((text) => {
        const names = Object.keys(technologies).filter((name) =>
            new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i')
                .test(text)
        )

        // Prefer the longest match, then include its product-level children.
        const primary = names.sort((a, b) => b.length - a.length)[0] || null
        const related = primary
            ? Object.keys(technologies).filter(
                (name) => name !== primary && name.startsWith(primary)
            )
            : []

        return {
            request: text,
            resolved: primary,
            channels: primary ? channelsOf(technologies[primary]) : [],
            related: related.map((name) => ({
                name,
                channels: channelsOf(technologies[name]),
            })),
        }
    })

    const uniqueMappedTargets = [
        ...new Set(
            [
                ...results.map(({ mapsTo }) => mapsTo),
                ...priorities.map(({ resolved }) => resolved),
                ...priorities.flatMap(({ related }) =>
                    related.map(({ name }) => name)
                ),
            ].filter(Boolean)
        ),
    ]
    const evidenceCounts = {}

    for (const name of uniqueMappedTargets) {
        const verification = EVIDENCE[name]
            ? EVIDENCE[name].verification
            : 'not-reviewed-in-this-audit'

        evidenceCounts[verification] = (evidenceCounts[verification] || 0) + 1
    }

    const evidenceSummary = {
        uniqueMappedTargets: uniqueMappedTargets.length,
        counts: evidenceCounts,
        liveObservedTargets: uniqueMappedTargets.filter(
            (name) => EVIDENCE[name] && EVIDENCE[name].verification === 'live-observed'
        ),
    }

    for (const result of results) {
        result.weaklyObservable = isWeaklyObservable(result.channels)
    }

    const matchable = [...byStatus.detected, ...byStatus['platform-level']]
    const weak = matchable.filter(({ weaklyObservable }) => weaklyObservable)

    const observability = {
        detectable: matchable.length,
        weaklyObservable: weak.length,
        weaklyObservableProducts: weak.map(({ product, mapsTo }) => ({
            product,
            mapsTo,
        })),
        audit: readXhrAudit(),
    }

    return {
        request,
        results,
        byStatus,
        technologies,
        priorities,
        evidenceSummary,
        observability,
    }
}

function printSummary({
    request,
    results,
    byStatus,
    priorities,
    evidenceSummary,
    observability,
}) {
    const total = results.length

    console.log('EMERGING TECHNOLOGY COVERAGE')
    console.log(`Source: ${request.source}`)
    console.log(`Products requested: ${total}\n`)

    const detectable =
        byStatus.detected.length + byStatus['platform-level'].length

    const mapped = detectable + byStatus['catalog-only'].length

    console.log(
        `Mapped onto the catalog: ${mapped}/${total} ` +
            `(${Math.round((mapped / total) * 100)}%)`
    )
    console.log(
        `Catalog-matchable:       ${detectable}/${total} ` +
            `(${Math.round((detectable / total) * 100)}%)\n`
    )
    console.log(
        'Catalog-matchable means a detection path exists; it is not empirical ' +
        'live-scan coverage.'
    )
    console.log(
        `Live-observed targets retained: ${evidenceSummary.liveObservedTargets.length}/` +
        `${evidenceSummary.uniqueMappedTargets} unique mapped technologies`
    )
    console.log(
        `  ${evidenceSummary.liveObservedTargets.join(', ') || 'none'}`
    )

    const { weaklyObservable, detectable: matchable, audit } = observability

    console.log(
        `\nOf those ${matchable}, ${weaklyObservable} are detectable only via ` +
            'xhr (a browser call to a vendor API host).'
    )

    if (audit) {
        console.log(`  ${audit.methodology ? audit.methodology.claim : ''}`)
        console.log(
            '  That is a yield against a convenience corpus, not an observation ' +
                'rate. See docs/live-evidence.md.'
        )
    }

    console.log()

    for (const status of STATUS_ORDER) {
        const group = byStatus[status]

        if (!group.length) {
            continue
        }

        console.log(
            `  ${String(group.length).padStart(4)}  ${STATUS_LABELS[status]}`
        )
    }

    console.log('\nFLAGGED PRIORITIES')

    for (const { request: text, resolved, channels, related } of priorities) {
        console.log(`  - ${text}`)

        if (resolved) {
            console.log(`      resolved: ${resolved}  [${channels.join(', ') || 'no channel'}]`)

            for (const child of related) {
                console.log(
                    `      product level: ${child.name}  [${child.channels.join(', ') || 'no channel'}]`
                )
            }
        } else {
            console.log('      NOT RESOLVED to any catalog entry')
        }
    }

    console.log('\nCATEGORIES REQUESTED')

    for (const category of request.categories) {
        console.log(`  - ${category}`)
    }

    if (!FULL) {
        console.log('\nRun with --full to list every product.')
    }
}

function printFull({ byStatus }) {
    for (const status of STATUS_ORDER) {
        const group = byStatus[status]

        if (!group.length) {
            continue
        }

        console.log(`\n${'='.repeat(72)}`)
        console.log(`${STATUS_LABELS[status]} (${group.length})`)
        console.log('='.repeat(72))
        console.log(STATUS_DESCRIPTIONS[status])
        console.log()

        for (const result of group) {
            const target =
                result.mapsTo && result.mapsTo !== result.product
                    ? ` -> ${result.mapsTo}`
                    : ''
            const channels = result.channels.length
                ? `  [${result.channels.join(', ')}]`
                : ''

            console.log(`  ${result.product}${target}${channels}`)
        }
    }
}

function printMarkdown({
    request,
    results,
    byStatus,
    priorities,
    evidenceSummary,
    observability,
}) {
    const total = results.length
    const detectable =
        byStatus.detected.length + byStatus['platform-level'].length

    const lines = []

    lines.push('# Emerging technology coverage')
    lines.push('')
    lines.push(`Source list: \`${request.source}\` (${total} products)`)
    lines.push('')
    const mapped = detectable + byStatus['catalog-only'].length

    lines.push(
        `**Mapped onto the catalog: ${mapped} of ${total} ` +
            `(${Math.round((mapped / total) * 100)}%).**`
    )
    lines.push('')
    lines.push(
        `**Catalog-matchable: ${detectable} of ${total} ` +
            `(${Math.round((detectable / total) * 100)}%).**`
    )
    lines.push('')
    lines.push(
        'Catalog-matchable means that a detection path exists in the catalog. ' +
        'It is not empirical live-scan coverage, and many API integrations are ' +
        'normally server-side and therefore invisible to a passive browser scan.'
    )
    lines.push('')
    lines.push(
        `**Live-observed evidence retained for ` +
        `${evidenceSummary.liveObservedTargets.length} of ` +
        `${evidenceSummary.uniqueMappedTargets} unique mapped technologies:** ` +
        `${evidenceSummary.liveObservedTargets.join(', ') || 'none'}.`
    )
    lines.push('')
    lines.push('| Status | Count | What it means |')
    lines.push('| --- | --- | --- |')

    for (const status of STATUS_ORDER) {
        const group = byStatus[status]

        if (!group.length) {
            continue
        }

        lines.push(
            `| ${STATUS_LABELS[status]} | ${group.length} | ` +
                `${STATUS_DESCRIPTIONS[status].replace(/\|/g, '\\|')} |`
        )
    }

    lines.push('')
    lines.push('### Observability caveat')
    lines.push('')
    lines.push(
        `Of the ${observability.detectable} catalog-matchable products, ` +
            `**${observability.weaklyObservable} are detectable only through the ` +
            '`xhr` channel** — a browser request to a vendor API host.'
    )

    if (observability.audit) {
        const a = observability.audit

        lines.push('')
        lines.push(
            `Measured by \`scripts/xhr-audit.js\`: **${a.xhrOnlyFired} of ` +
                `${a.xhrOnlyChecked} xhr-only markers appeared in a ` +
                `${a.urls}-page corpus under the current request-aborting ` +
                `driver**, while ${a.distinctXhrHostsObserved} distinct xhr ` +
                'hostnames were collected.'
        )
        lines.push('')
        lines.push(
            '**That is a yield against a convenience corpus, not an observation ' +
                'rate.** Nothing maps each marker to a page where its vendor is ' +
                'in use; the driver aborts non-document/script requests, which ' +
                'suppresses follow-on calls; and only 8 of 29 pages returned a ' +
                'clean 200. Treat it as a lower bound on browser visibility, and ' +
                'the catalog-matchable figure as an upper bound on coverage. ' +
                'See `docs/live-evidence.md`.'
        )
    }

    lines.push('')
    lines.push('## Flagged priorities')
    lines.push('')
    lines.push('| Request | Resolved to | Detection channels |')
    lines.push('| --- | --- | --- |')

    for (const { request: text, resolved, channels, related } of priorities) {
        lines.push(
            `| ${text.replace(/\|/g, '\\|')} | ${resolved || '**not resolved**'} | ` +
                `${channels.join(', ') || '-'} |`
        )

        for (const child of related) {
            lines.push(
                `| \u21b3 ${child.name} | ${child.name} | ` +
                    `${child.channels.join(', ') || '-'} |`
            )
        }
    }

    for (const status of STATUS_ORDER) {
        const group = byStatus[status]

        if (!group.length) {
            continue
        }

        lines.push('')
        lines.push(`## ${STATUS_LABELS[status]} (${group.length})`)
        lines.push('')
        lines.push('| Product | Reported as | Detection channels |')
        lines.push('| --- | --- | --- |')

        for (const result of group) {
            lines.push(
                `| ${result.product} | ${result.mapsTo || '-'} | ` +
                    `${result.channels.join(', ') || '-'} |`
            )
        }
    }

    process.stdout.write(`${lines.join('\n')}\n`)
}

/**
 * Aggregate counts and caveats, with no per-product rows. This is what the repo
 * can carry publicly: the numbers and their limits, not the requested list.
 */
function printAggregate({ results, byStatus, evidenceSummary, observability }) {
    const lines = [
        '# Coverage summary',
        '',
        'Generated by `npm run coverage -- --summary`. Aggregate counts only:',
        'the requested product list is a third party\'s and is not tracked here,',
        'so the per-product tables cannot be regenerated from a clone alone.',
        '',
        `- Products requested: **${results.length}**`,
        `- Mapped onto the catalog: **${results.filter((r) => r.mapsTo).length}/${results.length}**`,
        '',
        '## By status',
        '',
        '| Status | Products |',
        '| --- | --- |',
    ]

    for (const status of STATUS_ORDER) {
        const group = byStatus[status]

        if (group && group.length) {
            lines.push(`| ${STATUS_LABELS[status] || status} | ${group.length} |`)
        }
    }

    lines.push('', '## Caveats', '')

    if (!hasSweepData()) {
        // Measured: 48 corpus-observed and 5 corpus-observed-via-equivalent
        // collapse into unverified-no-sweep-retained. The 4 live-observed labels
        // name specific targets and are unaffected, so only DNS-corpus evidence
        // is lost here.
        lines.push(
            '- **The DNS sweep results are absent**, so the 53 DNS-corpus evidence' +
                ' labels degrade to `unverified-no-sweep-retained`. The' +
                ' live-observed count below names specific targets and is' +
                ' unaffected. Run `npm run sweep` to restore corpus evidence.'
        )
    }

    lines.push(
        `- Live-observed: **${evidenceSummary.liveObservedTargets.length} of ` +
            `${evidenceSummary.uniqueMappedTargets}** unique mapped technologies.` +
            ' Everything else is hostname-verified and covered by synthetic tests' +
            ' only.'
    )

    lines.push(
        `- **${observability.weaklyObservable}** products rest on a request` +
            ' channel alone, so they need a client-side call to a vendor API host' +
            ' to be seen at all.'
    )

    if (observability.audit) {
        const a = observability.audit

        lines.push(
            `- Measured yield: **${a.xhrOnlyFired} of ${a.xhrOnlyChecked}**` +
                ` request-only markers fired across a ${a.urls}-page corpus,` +
                ` while ${a.distinctXhrHostsObserved} distinct xhr hostnames were` +
                ' collected. That is a yield against a convenience corpus, not an' +
                ' observation rate.'
        )
    }

    process.stdout.write(`${lines.join('\n')}\n`)
}

function main() {
    if (!hasRequestData()) {
        console.log(
            'No request data present, so there is nothing to cross-reference.\n' +
                '\n' +
                'data/requested-products.json and scripts/lib/requested-mapping.js\n' +
                'name a third party\'s product list and are deliberately untracked.\n' +
                'Restore them locally to regenerate the per-product report; the\n' +
                'tracked aggregate artifact is docs/coverage-summary.md.'
        )

        return
    }

    const report = build()

    if (SUMMARY_ONLY) {
        printAggregate(report)

        return
    }

    if (JSON_OUTPUT) {
        process.stdout.write(
            `${JSON.stringify(
                {
                    source: report.request.source,
                    total: report.results.length,
                    counts: Object.fromEntries(
                        Object.entries(report.byStatus).map(([status, group]) => [
                            status,
                            group.length,
                        ])
                    ),
                    evidenceSummary: report.evidenceSummary,
                    priorities: report.priorities,
                    observability: report.observability,
                    products: report.results,
                },
                null,
                2
            )}\n`
        )

        return
    }

    if (MARKDOWN) {
        printMarkdown(report)

        return
    }

    printSummary(report)

    if (FULL) {
        printFull(report)
    }
}

main()
