'use strict'

/**
 * Merge policy for pulling upstream (enthec/webappanalyzer) into this fork.
 *
 * The previous policy was "upstream wins for any shared technology", which
 * silently discarded local work. Salesforce Service Cloud, for example, carries
 * locally-authored cookies/dom/meta/text/xhr patterns and a scriptSrc list far
 * more specific than upstream's single `service\.force\.com`; a wholesale
 * overwrite threw all of that away with no trace.
 *
 * The policy here is additive instead:
 *
 *   detection channels  union of local and upstream patterns
 *   list metadata       union (cats, pricing, requiresCategory)
 *   reference fields    union (implies, excludes, requires)
 *   scalar metadata     local wins when set, upstream fills the gaps
 *
 * Union means an upstream pattern improvement is picked up without dropping a
 * local one. It can leave redundant patterns behind, which costs a little scan
 * time but never costs a detection.
 */

const {
    CHANNELS,
    FLAT_CHANNELS,
    KEYED_CHANNELS,
    LIST_METADATA,
    REFERENCE_FIELDS,
    SCALAR_METADATA,
    isPlainObject,
    isScalar,
    toArray,
} = require('./channels')

/** Union of two pattern lists, keeping local order first and dropping repeats. */
function unionPatterns(local, upstream) {
    const out = []
    const seen = new Set()

    for (const value of [
        ...(local === undefined ? [] : toArray(local)),
        ...(upstream === undefined ? [] : toArray(upstream)),
    ]) {
        const key = JSON.stringify(value)

        if (!seen.has(key)) {
            seen.add(key)
            out.push(value)
        }
    }

    return out
}

/** Collapse a single-element list back to a scalar, matching catalog style. */
function simplify(list) {
    return list.length === 1 && isScalar(list[0]) ? list[0] : list
}

/**
 * Two channel values that mean the same thing to the engine.
 * `"a"` and `["a"]` compile identically, so treating them as different would
 * rewrite thousands of untouched entries on every upstream merge and bury the
 * real changes in an unreviewable diff.
 */
function sameMeaning(a, b) {
    const key = (value) =>
        JSON.stringify(
            (value === undefined ? [] : toArray(value))
                .map((item) => JSON.stringify(item))
                .sort()
        )

    return key(a) === key(b)
}

/**
 * The merged value, preserving the local representation when the merge added
 * nothing. Keeps diffs limited to entries that actually changed.
 */
function preferLocalShape(local, merged) {
    return sameMeaning(local, merged) ? local : merged
}

/** Key-wise union of two keyed channels (headers, cookies, js, meta, dns...). */
function mergeKeyed(local, upstream) {
    if (!isPlainObject(local)) {
        return isPlainObject(upstream) ? upstream : local
    }

    if (!isPlainObject(upstream)) {
        return local
    }

    const out = { ...local }

    for (const [key, value] of Object.entries(upstream)) {
        if (!(key in out)) {
            out[key] = value

            continue
        }

        // Nested objects appear in probe (`{status, body}`) and dom rules.
        out[key] =
            isPlainObject(out[key]) && isPlainObject(value)
                ? mergeKeyed(out[key], value)
                : preferLocalShape(
                    out[key],
                    simplify(unionPatterns(out[key], value))
                )
    }

    return out
}

/**
 * `dom` accepts a selector list or a selector -> rule map. Merge like with like,
 * and when the two sides disagree keep the richer map form.
 */
function mergeDom(local, upstream) {
    const isMap = (value) => isPlainObject(value)

    if (isMap(local) && isMap(upstream)) {
        return mergeKeyed(local, upstream)
    }

    if (!isMap(local) && !isMap(upstream)) {
        return preferLocalShape(local, simplify(unionPatterns(local, upstream)))
    }

    // One side is a bare selector list. Promote it to `{selector: {exists: ''}}`
    // so nothing is lost, then merge as maps.
    const promote = (value) =>
        isMap(value)
            ? value
            : toArray(value).reduce(
                (map, selector) => ({ ...map, [selector]: { exists: '' } }),
                {}
            )

    return mergeKeyed(promote(local), promote(upstream))
}

/**
 * Merge one technology entry.
 * @param {object} local
 * @param {object} upstream
 * @returns {{entry: object, gained: string[], kept: string[]}}
 */
function mergeEntry(local = {}, upstream = {}) {
    const entry = {}
    const gained = []
    const kept = []

    const fields = new Set([...Object.keys(local), ...Object.keys(upstream)])

    for (const field of fields) {
        const hasLocal = field in local
        const hasUpstream = field in upstream

        if (!hasLocal) {
            entry[field] = upstream[field]
            gained.push(field)

            continue
        }

        if (!hasUpstream) {
            entry[field] = local[field]
            kept.push(field)

            continue
        }

        if (field === 'dom') {
            entry[field] = mergeDom(local[field], upstream[field])
        } else if (KEYED_CHANNELS.includes(field)) {
            entry[field] = mergeKeyed(local[field], upstream[field])
        } else if (
            FLAT_CHANNELS.includes(field) ||
            REFERENCE_FIELDS.includes(field) ||
            LIST_METADATA.includes(field)
        ) {
            const union = unionPatterns(local[field], upstream[field])

            // cats/pricing/refs are sets and stay arrays; pattern channels
            // collapse back to a scalar when only one pattern survives.
            const merged = LIST_METADATA.includes(field) ||
                REFERENCE_FIELDS.includes(field)
                ? union
                : simplify(union)

            entry[field] = preferLocalShape(local[field], merged)
        } else if (SCALAR_METADATA.includes(field)) {
            // Local metadata is deliberately curated here (better icons, more
            // categories, fuller descriptions), so it wins when present.
            const value = local[field]

            entry[field] =
                value === undefined || value === null || value === ''
                    ? upstream[field]
                    : value
        } else {
            // Unknown field: keep local so normalize.js can deal with it.
            entry[field] = local[field]
        }

        if (JSON.stringify(entry[field]) !== JSON.stringify(local[field])) {
            gained.push(field)
        } else {
            kept.push(field)
        }
    }

    return { entry, gained, kept }
}

/**
 * Merge two full catalogs.
 * @param {Object<string, object>} local
 * @param {Object<string, object>} upstream
 * @returns {{technologies: object, added: string[], merged: object[], localOnly: string[]}}
 */
function mergeCatalog(local, upstream) {
    const technologies = {}
    const added = []
    const merged = []
    const localOnly = []

    for (const [name, entry] of Object.entries(local)) {
        if (!(name in upstream)) {
            technologies[name] = entry
            localOnly.push(name)

            continue
        }

        const result = mergeEntry(entry, upstream[name])

        technologies[name] = result.entry

        if (result.gained.length) {
            merged.push({ name, gained: result.gained })
        }
    }

    for (const [name, entry] of Object.entries(upstream)) {
        if (!(name in local)) {
            technologies[name] = entry
            added.push(name)
        }
    }

    return { technologies, added, merged, localOnly }
}

module.exports = {
    mergeCatalog,
    mergeDom,
    mergeEntry,
    mergeKeyed,
    preferLocalShape,
    sameMeaning,
    unionPatterns,
}
