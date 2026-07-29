'use strict'

/**
 * Integrity tests for the real catalog.
 *
 * These are the regression guard for the whole point of the exercise: whatever
 * technologies/*.json says, the engine must be able to load it and produce a
 * result, with no field or pattern silently ignored. Adding a technology with a
 * typo'd field or a wrong-shaped channel fails here.
 */

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const path = require('path')
const { execFileSync } = require('child_process')

const Wappalyzer = require('../wappalyzer')
const { loadCatalog } = require('../scripts/lib/catalog')
const { KNOWN_FIELDS, fileForTechnology } = require('../scripts/lib/channels')
const {
    CONTROL_URLS,
    URL_CHANNEL_EXEMPT,
} = require('../scripts/lib/control-corpus')

const ROOT = path.resolve(__dirname, '..')
const TECHNOLOGIES_DIR = path.join(ROOT, 'technologies')

const catalog = loadCatalog(TECHNOLOGIES_DIR)
const categories = JSON.parse(
    fs.readFileSync(path.join(ROOT, 'categories.json'), 'utf8')
)

test('the validator reports no errors', () => {
    // The full rule set lives in scripts/validate.js; this asserts it passes.
    assert.doesNotThrow(() =>
        execFileSync(process.execPath, [path.join(ROOT, 'scripts/validate.js'), '--quiet'], {
            stdio: 'pipe',
        })
    )
})

test('every letter file the driver reads exists', () => {
    // driver.js loads _ plus a-z unconditionally; a missing file is a crash.
    for (const index of Array(27).keys()) {
        const character = index ? String.fromCharCode(index + 96) : '_'
        const file = path.join(TECHNOLOGIES_DIR, `${character}.json`)

        assert.ok(fs.existsSync(file), `technologies/${character}.json must exist`)
    }
})

test('no technology is defined in more than one file', () => {
    assert.deepEqual(
        catalog.duplicates.map(({ name, files }) => `${name} (${files.join(', ')})`),
        [],
        'a duplicate name means one definition silently wins'
    )
})

test('every technology lives in its correct letter file', () => {
    const misfiled = []

    for (const [name, file] of catalog.provenance) {
        if (file !== fileForTechnology(name)) {
            misfiled.push(`${name}: ${file} should be ${fileForTechnology(name)}`)
        }
    }

    assert.deepEqual(misfiled, [])
})

test('no technology uses a field the engine does not read', () => {
    const unknown = []

    for (const [name, entry] of Object.entries(catalog.technologies)) {
        for (const field of Object.keys(entry)) {
            if (!KNOWN_FIELDS.has(field)) {
                unknown.push(`${name}.${field}`)
            }
        }
    }

    assert.deepEqual(unknown, [])
})

test('the catalog loads without a single defect', () => {
    Wappalyzer.setCategories(categories)
    Wappalyzer.setTechnologies(catalog.technologies)

    assert.deepEqual(Wappalyzer.errors, [])
    assert.ok(Wappalyzer.technologies.length > 7000)
})

test('every technology resolves without throwing or recording a defect', () => {
    Wappalyzer.setCategories(categories)
    Wappalyzer.setTechnologies(catalog.technologies)

    const all = [
        ...Wappalyzer.technologies,
        ...Wappalyzer.requires.map(({ technologies }) => technologies).flat(),
        ...Wappalyzer.categoryRequires
        .map(({ technologies }) => technologies)
        .flat(),
    ]

    const failures = []

    for (const technology of all) {
        Wappalyzer.errors = []

        try {
            const resolved = Wappalyzer.resolve([
                { technology, pattern: { confidence: 100 }, version: '' },
            ])

            if (!resolved.length) {
                failures.push(`${technology.name}: dropped by resolve()`)
            }
        } catch (error) {
            failures.push(`${technology.name}: threw ${error.message}`)
        }

        for (const { type, message } of Wappalyzer.errors) {
            failures.push(`${technology.name}: ${type} ${message}`)
        }
    }

    assert.deepEqual(failures.slice(0, 20), [])
})

test('every category a technology claims exists', () => {
    const ids = new Set(Object.keys(categories).map(Number))
    const missing = new Set()

    for (const entry of Object.values(catalog.technologies)) {
        for (const id of entry.cats || []) {
            if (!ids.has(id)) {
                missing.add(id)
            }
        }
    }

    assert.deepEqual([...missing], [])
})

test('every category has the fields resolve() sorts on', () => {
    for (const [id, category] of Object.entries(categories)) {
        assert.equal(typeof category.name, 'string', `category ${id} needs a name`)
        assert.ok(
            Number.isInteger(category.priority),
            `category ${id} needs an integer priority`
        )
    }
})

test('every implies, excludes and requires target exists', () => {
    const known = new Set(Object.keys(catalog.technologies))
    const dangling = []

    for (const [name, entry] of Object.entries(catalog.technologies)) {
        for (const field of ['implies', 'excludes', 'requires']) {
            const value = entry[field]

            if (value === undefined) {
                continue
            }

            for (const item of Array.isArray(value) ? value : [value]) {
                const target = String(item).split('\\;')[0].trim()

                if (!known.has(target)) {
                    dangling.push(`${name}.${field} -> ${target}`)
                }
            }
        }
    }

    assert.deepEqual(dangling, [])
})

test('every pattern compiles', () => {
    const broken = []

    for (const [name, entry] of Object.entries(catalog.technologies)) {
        try {
            Wappalyzer.setTechnologies({ [name]: entry })
        } catch (error) {
            broken.push(`${name}: ${error.message}`)
        }
    }

    assert.deepEqual(broken, [])
})

test('no pattern was removed from a dom or probe channel', () => {
    // The subsumption optimisation must never touch selector or path channels.
    // Checked against the committed catalog rather than a synthetic entry, so a
    // future rule change that reintroduces the regression fails here.
    const { NO_SUBSUMPTION, normalizeCatalog } = require('../scripts/lib/normalize')

    const { changes } = normalizeCatalog(
        JSON.parse(JSON.stringify(catalog.technologies))
    )

    const offending = changes
        .flatMap(({ name, changes: entryChanges }) =>
            entryChanges.map((message) => ({ name, message }))
        )
        .filter(({ message }) => message.includes('already covered by'))
        .filter(({ message }) => {
            const channel = (/^dropped ([a-zA-Z]+)/.exec(message) || [])[1]

            return NO_SUBSUMPTION.has(channel)
        })
        .map(({ name, message }) => `${name}: ${message}`)

    assert.deepEqual(offending, [])
})

test('normalizing the committed catalog is a fixed point', () => {
    // The catalog on disk has already been normalized, so a second pass must not
    // alter any entry. Compared on the resulting data rather than the change log:
    // name-keyed overrides re-report themselves on every run while writing the
    // same value, which is noise rather than a difference.
    const { normalizeCatalog } = require('../scripts/lib/normalize')

    const { technologies } = normalizeCatalog(
        JSON.parse(JSON.stringify(catalog.technologies))
    )

    const changed = Object.keys(catalog.technologies).filter(
        (name) =>
            JSON.stringify(catalog.technologies[name]) !==
            JSON.stringify(technologies[name])
    )

    assert.deepEqual(
        changed.slice(0, 10),
        [],
        'run `npm run normalize` to bring the catalog in line with the rules'
    )
})

test('the committed catalog delta describes the current tree', () => {
    // The delta was hand-produced twice and went stale twice, most recently
    // under-reporting by seven entries after a later normalization pass. It is now
    // generated by scripts/catalog-delta.js, and this runs its own --check.
    assert.doesNotThrow(
        () =>
            execFileSync(
                process.execPath,
                [path.join(ROOT, 'scripts/catalog-delta.js'), '--check'],
                { stdio: 'pipe' }
            ),
        'run `npm run delta` to regenerate docs/catalog-delta.{json,md}'
    )
})

test('no xhr pattern requires a path or scheme', () => {
    // The xhr channel only ever receives a bare hostname. 123 patterns across 56
    // technologies required a path and could never fire; they now live in xhrUrl.
    const { canMatchHostname } = require('../scripts/lib/channels')
    const compile = (pattern) => Wappalyzer.parsePattern(pattern).regex
    const unmatchable = []

    for (const [name, entry] of Object.entries(catalog.technologies)) {
        const value = entry.xhr

        for (const pattern of value === undefined
            ? []
            : Array.isArray(value)
                ? value
                : [value]) {
            if (typeof pattern === 'string' && !canMatchHostname(pattern, compile)) {
                unmatchable.push(`${name}: ${pattern}`)
            }
        }
    }

    assert.deepEqual(unmatchable.slice(0, 10), [])
})

test('no xhrUrl pattern matches a benign control URL', () => {
    // Guards the risk introduced by relocation: a pattern that was harmlessly
    // dead in xhr becomes a false-positive generator once xhrUrl makes it live.
    // The corpus lives in scripts/lib/control-corpus.js, shared with the
    // normalizer, so the merge pipeline enforces the same rule this asserts.
    const overBroad = []

    for (const [name, entry] of Object.entries(catalog.technologies)) {
        const value = entry.xhrUrl

        for (const pattern of value === undefined
            ? []
            : Array.isArray(value)
                ? value
                : [value]) {
            const { regex } = Wappalyzer.parsePattern(pattern)

            if (CONTROL_URLS.some((control) => regex.test(control))) {
                overBroad.push(`${name}: ${pattern}`)
            }
        }
    }

    assert.deepEqual(overBroad, [])
})

test('no url pattern outside the exempt set matches a benign control URL', () => {
    // The url channel has the same failure mode — a page-URL pattern like
    // /ui/ or /v1/info tags any site with that path. Category-style entries
    // (URL_CHANNEL_EXEMPT) intentionally describe generic page kinds and are
    // the only allowed matches.
    const overBroad = []

    for (const [name, entry] of Object.entries(catalog.technologies)) {
        if (URL_CHANNEL_EXEMPT.has(name)) {
            continue
        }

        const value = entry.url

        for (const pattern of value === undefined
            ? []
            : Array.isArray(value)
                ? value
                : [value]) {
            const { regex } = Wappalyzer.parsePattern(pattern)

            if (CONTROL_URLS.some((control) => regex.test(control))) {
                overBroad.push(`${name}: ${pattern}`)
            }
        }
    }

    assert.deepEqual(overBroad, [])
})
