'use strict'

/**
 * Reading and writing technologies/*.json.
 *
 * The letter files are a storage detail: the engine flattens all of them into
 * one namespace, so a name defined in two files silently resolves to whichever
 * loaded last. Loading here surfaces those collisions, and saving puts every
 * entry in its correct bucket so the layout stops drifting.
 */

const fs = require('fs')
const path = require('path')

const { fileForTechnology } = require('./channels')

/** Every bucket the engine reads, in the order driver.js loads them. */
const FILES = [
    '_.json',
    ...Array.from({ length: 26 }, (_, index) =>
        `${String.fromCharCode(97 + index)}.json`
    ),
]

/**
 * Load a technologies directory.
 * @param {string} directory
 * @returns {{technologies: object, byFile: object, duplicates: Array, provenance: Map}}
 */
function loadCatalog(directory) {
    const technologies = {}
    const byFile = {}
    const duplicates = []
    const provenance = new Map()

    const files = fs
        .readdirSync(directory)
        .filter((file) => file.endsWith('.json'))
        .sort()

    for (const file of files) {
        const parsed = JSON.parse(
            fs.readFileSync(path.join(directory, file), 'utf8')
        )

        byFile[file] = parsed

        for (const [name, entry] of Object.entries(parsed)) {
            if (provenance.has(name)) {
                duplicates.push({
                    name,
                    files: [provenance.get(name), file],
                })
            }

            // Last write wins, matching how the engine flattens the buckets.
            technologies[name] = entry
            provenance.set(name, file)
        }
    }

    return { technologies, byFile, duplicates, provenance, files }
}

/**
 * Write a flat catalog back out, one bucket per leading letter, names sorted
 * case-insensitively so diffs stay readable.
 * @param {string} directory
 * @param {Object<string, object>} technologies
 * @param {{dryRun?: boolean}} options
 * @returns {Object<string, number>} entries written per file
 */
function saveCatalog(directory, technologies, options = {}) {
    const buckets = {}

    for (const file of FILES) {
        buckets[file] = {}
    }

    for (const name of Object.keys(technologies).sort((a, b) =>
        a.toLowerCase().localeCompare(b.toLowerCase())
    )) {
        const file = fileForTechnology(name)

        buckets[file] = buckets[file] || {}
        buckets[file][name] = technologies[name]
    }

    const written = {}

    for (const [file, entries] of Object.entries(buckets)) {
        const target = path.join(directory, file)
        const count = Object.keys(entries).length

        written[file] = count

        // Every bucket is written even when empty: driver.js reads all 27 files
        // unconditionally, so a missing one is a load-time crash.
        if (!options.dryRun) {
            fs.writeFileSync(target, `${JSON.stringify(entries, null, 2)}\n`)
        }
    }

    return written
}

/**
 * Merge category definitions. Local wins on conflict (ids in use here must keep
 * their meaning), upstream contributes anything new, and `extra` adds the
 * fork's own categories.
 * @param {object} local
 * @param {object} upstream
 * @param {object} extra
 */
function mergeCategories(local, upstream = {}, extra = {}) {
    const merged = { ...upstream, ...local, ...extra }

    return Object.keys(merged)
        .sort((a, b) => Number(a) - Number(b))
        .reduce((sorted, id) => ({ ...sorted, [id]: merged[id] }), {})
}

module.exports = {
    FILES,
    loadCatalog,
    mergeCategories,
    saveCatalog,
}
