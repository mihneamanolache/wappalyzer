#!/usr/bin/env node

/**
 * Installs the technologies defined in scripts/lib/emerging-technologies.js into the
 * catalog, then normalizes and validates the result.
 *
 * New entries are added outright. Entries that already exist are merged with the
 * same additive policy used for upstream pulls, so an existing fingerprint is
 * never replaced — a TXT verification pattern is added alongside whatever was
 * already detecting the technology. Evidence quality is tracked separately.
 *
 * Usage:
 *   node scripts/add-technologies.js            # apply
 *   node scripts/add-technologies.js --dry-run  # report only
 */

const fs = require('fs')
const path = require('path')
const { execFileSync } = require('child_process')

const { loadCatalog, saveCatalog } = require('./lib/catalog')
const { mergeEntry } = require('./lib/merge')
const { normalizeCatalog } = require('./lib/normalize')
const {
    CATALOG_ONLY,
    TECHNOLOGIES,
    TXT_ENRICH,
} = require('./lib/emerging-technologies')

const ROOT = path.resolve(__dirname, '..')
const TECHNOLOGIES_DIR = path.join(ROOT, 'technologies')

const DRY_RUN = process.argv.includes('--dry-run')

function main() {
    const { technologies } = loadCatalog(TECHNOLOGIES_DIR)

    const added = []
    const merged = []
    const enriched = []

    for (const [name, entry] of Object.entries(TECHNOLOGIES)) {
        if (technologies[name]) {
            // Local-first merge: the existing entry is the "local" side, so its
            // patterns and metadata win where they conflict.
            const result = mergeEntry(technologies[name], entry)

            technologies[name] = result.entry
            merged.push(`${name} (+${result.gained.join(', +') || 'nothing new'})`)
        } else {
            technologies[name] = entry
            added.push(name)
        }
    }

    // Taxonomy-only entries: metadata so every requested product maps onto the
    // catalog, deliberately with no detection channel.
    const stubs = []

    for (const [name, entry] of Object.entries(CATALOG_ONLY)) {
        if (technologies[name]) {
            const result = mergeEntry(technologies[name], entry)

            technologies[name] = result.entry
        } else {
            technologies[name] = entry
            stubs.push(name)
        }
    }

    // TXT verification patterns for technologies the catalog already tracks.
    for (const [name, token] of Object.entries(TXT_ENRICH)) {
        const entry = technologies[name]

        if (!entry) {
            console.log(`  skipped ${name}: not in the catalog under that name`)

            continue
        }

        const dns = entry.dns && typeof entry.dns === 'object' && !Array.isArray(entry.dns)
            ? { ...entry.dns }
            : {}

        const existing = dns.TXT === undefined
            ? []
            : Array.isArray(dns.TXT)
                ? dns.TXT
                : [dns.TXT]

        if (existing.includes(token)) {
            continue
        }

        dns.TXT = [...existing, token]
        dns.TXT = dns.TXT.length === 1 ? dns.TXT[0] : dns.TXT

        entry.dns = dns
        enriched.push(`${name}: dns.TXT += ${token}`)
    }

    console.log(`ADDED (${added.length})`)
    for (const name of added) {
        console.log(`   + ${name}`)
    }

    console.log(`\nMERGED INTO EXISTING (${merged.length})`)
    for (const line of merged) {
        console.log(`   ~ ${line}`)
    }

    console.log(`\nTAXONOMY-ONLY, NO DETECTION POSSIBLE (${stubs.length})`)
    for (const name of stubs) {
        console.log(`   . ${name}`)
    }

    console.log(`\nENRICHED WITH A TXT VERIFICATION PATTERN (${enriched.length})`)
    for (const line of enriched) {
        console.log(`   ~ ${line}`)
    }

    const normalized = normalizeCatalog(technologies)

    if (DRY_RUN) {
        console.log('\n[dry run] nothing written')

        return
    }

    saveCatalog(TECHNOLOGIES_DIR, normalized.technologies)

    console.log(
        `\nWrote ${Object.keys(normalized.technologies).length} technologies`
    )

    execFileSync(process.execPath, [path.join(__dirname, 'validate.js'), '--quiet'], {
        stdio: 'inherit',
    })
}

main()
