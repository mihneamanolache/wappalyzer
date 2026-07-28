#!/usr/bin/env node

'use strict'

/**
 * Describes the catalog change against a git revision.
 *
 * The raw diff of `technologies/*.json` is ~43k lines, mostly because entries were
 * relocated into their correct letter files. This computes the change by parsing
 * both revisions and comparing entries, so the description is about technologies
 * rather than lines.
 *
 * It exists as a script because the delta was previously produced by hand and went
 * stale twice — it under-reported by seven entries after a later normalization
 * pass. Regenerating is now one command, and `--check` fails if the committed
 * artifacts no longer describe the working tree.
 *
 * Usage:
 *   node scripts/catalog-delta.js              # write changeset/catalog-delta.{json,md}
 *   node scripts/catalog-delta.js --check      # verify the artifacts are current
 *   node scripts/catalog-delta.js --base=<rev> # default: the base recorded in
 *                                              # the artifact, else HEAD
 */

const fs = require('fs')
const os = require('os')
const path = require('path')
const { execFileSync } = require('child_process')

const { loadCatalog } = require('./lib/catalog')
const { CHANNELS } = require('./lib/channels')
const { CATALOG_ONLY, TECHNOLOGIES } = require('./lib/dnb-technologies')

const ROOT = path.resolve(__dirname, '..')
const OUT_JSON = path.join(ROOT, 'changeset/catalog-delta.json')
const OUT_MD = path.join(ROOT, 'changeset/catalog-delta.md')

const args = process.argv.slice(2)
const CHECK_ONLY = args.includes('--check')
const BASE_ARG = (args.find((arg) => arg.startsWith('--base=')) || '').split('=')[1]

/**
 * The revision the delta is measured against.
 *
 * Defaulting to HEAD is wrong once the work is committed: HEAD then points at the
 * change itself and the delta collapses to empty. So the base recorded in the
 * existing artifact wins, which keeps `--check` meaningful across commits. An
 * explicit `--base=` always overrides, and HEAD is only the fallback for a first
 * run with no artifact.
 */
function resolveBase() {
    if (BASE_ARG) {
        return BASE_ARG
    }

    try {
        const recorded = JSON.parse(fs.readFileSync(OUT_JSON, 'utf8')).base

        if (recorded) {
            return recorded
        }
    } catch (error) {
        // No usable artifact yet.
    }

    return 'HEAD'
}

const git = (...argv) =>
    execFileSync('git', argv, { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })

/** Materialise the catalog at `rev` into a temp directory and load it. */
function loadAtRevision(rev) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'catalog-base-'))
    const letters = ['_', ...Array.from({ length: 26 }, (_, i) => String.fromCharCode(97 + i))]

    for (const letter of letters) {
        try {
            fs.writeFileSync(
                path.join(dir, `${letter}.json`),
                git('show', `${rev}:technologies/${letter}.json`)
            )
        } catch (error) {
            fs.writeFileSync(path.join(dir, `${letter}.json`), '{}')
        }
    }

    const categories = JSON.parse(git('show', `${rev}:categories.json`))
    const { technologies } = loadCatalog(dir)

    fs.rmSync(dir, { recursive: true, force: true })

    return { technologies, categories }
}

const channelsOf = (entry) =>
    Object.keys(CHANNELS).filter((channel) => entry[channel] !== undefined)

function build() {
    const BASE = resolveBase()
    const base = loadAtRevision(BASE)
    const head = {
        technologies: loadCatalog(path.join(ROOT, 'technologies')).technologies,
        categories: JSON.parse(
            fs.readFileSync(path.join(ROOT, 'categories.json'), 'utf8')
        ),
    }

    const added = Object.keys(head.technologies)
        .filter((name) => !(name in base.technologies))
        .sort()
    const removed = Object.keys(base.technologies)
        .filter((name) => !(name in head.technologies))
        .sort()
    const changed = Object.keys(head.technologies)
        .filter(
            (name) =>
                name in base.technologies &&
                JSON.stringify(base.technologies[name]) !==
                    JSON.stringify(head.technologies[name])
        )
        .sort()

    const detail = changed.map((name) => {
        const before = new Set(Object.keys(base.technologies[name]))
        const after = new Set(Object.keys(head.technologies[name]))

        return {
            name,
            fieldsAdded: [...after].filter((field) => !before.has(field)),
            fieldsRemoved: [...before].filter((field) => !after.has(field)),
            valuesChanged: [...after].filter(
                (field) =>
                    before.has(field) &&
                    JSON.stringify(base.technologies[name][field]) !==
                        JSON.stringify(head.technologies[name][field])
            ),
        }
    })

    return {
        base: git('rev-parse', '--short', BASE).trim(),
        baseSubject: git('log', '-1', '--format=%s', BASE).trim(),
        before: {
            technologies: Object.keys(base.technologies).length,
            categories: Object.keys(base.categories).length,
        },
        after: {
            technologies: Object.keys(head.technologies).length,
            categories: Object.keys(head.categories).length,
        },
        summary: {
            added: added.length,
            removed: removed.length,
            changed: changed.length,
        },
        newCategories: Object.keys(head.categories)
            .filter((id) => !(id in base.categories))
            .map((id) => ({
                id: Number(id),
                name: head.categories[id].name,
                priority: head.categories[id].priority,
            })),
        addedFromUpstream: added.filter(
            (name) => !(name in TECHNOLOGIES) && !(name in CATALOG_ONLY)
        ),
        addedForRequest: added
            .filter((name) => name in TECHNOLOGIES)
            .map((name) => ({
                name,
                channels: channelsOf(head.technologies[name]),
            })),
        addedTaxonomyOnly: added.filter((name) => name in CATALOG_ONLY),
        removedTechnologies: removed,
        changed: detail,
    }
}

function markdown(delta) {
    const lines = []
    const row = (cells) => lines.push(`| ${cells.join(' | ')} |`)

    lines.push('# Catalog delta')
    lines.push('')
    lines.push(
        `Working tree vs \`${delta.base}\` ("${delta.baseSubject}"). Generated by ` +
            '`npm run delta` — do not edit by hand.'
    )
    lines.push('')
    lines.push(
        'Computed by parsing both revisions and comparing entries, not by reading ' +
            'the textual diff: the raw diff is large mostly because entries were ' +
            'relocated into their correct letter files.'
    )
    lines.push('')
    row(['', 'Before', 'After'])
    row(['---', '---', '---'])
    row(['Technologies', delta.before.technologies, delta.after.technologies])
    row(['Categories', delta.before.categories, delta.after.categories])
    lines.push('')
    row(['Change', 'Count'])
    row(['---', '---'])
    row(['Added', delta.summary.added])
    row(['**Removed**', `**${delta.summary.removed}**`])
    row(['Changed', delta.summary.changed])
    lines.push('')

    if (!delta.summary.removed) {
        lines.push('Nothing was removed from the catalog.')
        lines.push('')
    }

    lines.push(`## Added (${delta.summary.added})`)
    lines.push('')
    lines.push(`### From upstream (${delta.addedFromUpstream.length})`)
    lines.push('')
    lines.push('<details><summary>List</summary>')
    lines.push('')
    for (const name of delta.addedFromUpstream) {
        lines.push(`- ${name}`)
    }
    lines.push('')
    lines.push('</details>')
    lines.push('')
    lines.push(`### Authored for the request (${delta.addedForRequest.length})`)
    lines.push('')
    row(['Technology', 'Detection channels'])
    row(['---', '---'])
    for (const { name, channels } of delta.addedForRequest) {
        row([name, channels.join(', ') || '(none)'])
    }
    lines.push('')
    lines.push(`### Taxonomy-only (${delta.addedTaxonomyOnly.length})`)
    lines.push('')
    lines.push(
        'Full metadata, deliberately **no detection channel** — these products ' +
            'emit nothing observable.'
    )
    lines.push('')
    for (const name of delta.addedTaxonomyOnly) {
        lines.push(`- ${name}`)
    }
    lines.push('')
    lines.push(`## New categories (${delta.newCategories.length})`)
    lines.push('')
    row(['id', 'Name', 'Priority'])
    row(['---', '---', '---'])
    for (const { id, name, priority } of delta.newCategories) {
        row([id, name, priority])
    }
    lines.push('')
    lines.push(`## Changed (${delta.summary.changed})`)
    lines.push('')
    row(['Technology', 'Fields added', 'Fields removed', 'Values changed'])
    row(['---', '---', '---', '---'])
    for (const { name, fieldsAdded, fieldsRemoved, valuesChanged } of delta.changed) {
        row([
            name,
            fieldsAdded.join(', ') || '-',
            fieldsRemoved.join(', ') || '-',
            valuesChanged.join(', ') || '-',
        ])
    }
    lines.push('')

    return `${lines.join('\n')}\n`
}

function main() {
    const delta = build()
    const json = `${JSON.stringify(delta, null, 2)}\n`
    const md = markdown(delta)

    if (CHECK_ONLY) {
        const problems = []

        for (const [file, expected] of [
            [OUT_JSON, json],
            [OUT_MD, md],
        ]) {
            const relative = path.relative(ROOT, file)

            if (!fs.existsSync(file)) {
                problems.push(`${relative} is missing`)
            } else if (fs.readFileSync(file, 'utf8') !== expected) {
                problems.push(`${relative} does not describe the working tree`)
            }
        }

        if (problems.length) {
            console.error('STALE:')
            for (const problem of problems) {
                console.error(`  - ${problem}`)
            }
            console.error('\nRun `npm run delta` to regenerate.')
            process.exit(1)
        }

        console.log(
            `changeset/catalog-delta.{json,md} are current ` +
                `(${delta.summary.added} added, ${delta.summary.changed} changed, ` +
                `${delta.summary.removed} removed)`
        )

        return
    }

    fs.writeFileSync(OUT_JSON, json)
    fs.writeFileSync(OUT_MD, md)

    console.log(
        `Wrote changeset/catalog-delta.{json,md}\n` +
            `  base:    ${delta.base} ("${delta.baseSubject}")\n` +
            `  added:   ${delta.summary.added}\n` +
            `  changed: ${delta.summary.changed}\n` +
            `  removed: ${delta.summary.removed}`
    )
}

main()
