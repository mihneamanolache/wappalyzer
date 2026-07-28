#!/usr/bin/env node

/**
 * Validates technologies/*.json against what wappalyzer.js actually consumes.
 *
 * The catalog is data, and the engine reads only a fixed set of fields in a
 * fixed set of shapes. Anything else is silently ignored at scan time, which is
 * how typo'd fields and wrong-shaped channels turn into patterns that can never
 * match. This script makes that class of defect loud.
 *
 * Usage:
 *   node scripts/validate.js               # human-readable report, exits 1 on error
 *   node scripts/validate.js --json        # machine-readable
 *   node scripts/validate.js --quiet       # errors only, no warnings
 *   node scripts/validate.js --strict      # treat warnings as errors
 */

const fs = require('fs')
const path = require('path')
const Wappalyzer = require('../wappalyzer')
const {
    CHANNELS,
    DNS_RECORDS,
    DOM_RULES,
    KNOWN_FIELDS,
    METADATA,
    fileForTechnology,
} = require('./lib/channels')

const TECHNOLOGIES_DIR = path.resolve(__dirname, '../technologies')
const CATEGORIES_FILE = path.resolve(__dirname, '../categories.json')

const args = process.argv.slice(2)
const JSON_OUTPUT = args.includes('--json')
const QUIET = args.includes('--quiet')
const STRICT = args.includes('--strict')

const findings = []

function report(severity, code, technology, message, file) {
    findings.push({ severity, code, technology, message, file })
}

const error = (...args) => report('error', ...args)
const warn = (...args) => report('warning', ...args)

/* ------------------------------------------------------------------ loading */

function loadCatalog() {
    const files = fs
        .readdirSync(TECHNOLOGIES_DIR)
        .filter((file) => file.endsWith('.json'))
        .sort()

    const entries = new Map() // name -> { entry, file }
    const duplicates = []
    const byFile = {}

    for (const file of files) {
        let parsed

        try {
            parsed = JSON.parse(
                fs.readFileSync(path.join(TECHNOLOGIES_DIR, file), 'utf8')
            )
        } catch (err) {
            error('E_INVALID_JSON', file, err.message, file)
            continue
        }

        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            error('E_INVALID_JSON', file, 'Top level must be an object', file)
            continue
        }

        byFile[file] = parsed

        for (const [name, entry] of Object.entries(parsed)) {
            if (entries.has(name)) {
                duplicates.push({ name, files: [entries.get(name).file, file] })
            }

            entries.set(name, { entry, file })
        }
    }

    return { entries, duplicates, byFile, files }
}

/* ------------------------------------------------------- shape / leaf checks */

const isPlainObject = (value) =>
    value !== null && typeof value === 'object' && !Array.isArray(value)

const isScalarPattern = (value) =>
    typeof value === 'string' || typeof value === 'number'

const kindOf = (channel) => CHANNELS[channel]

/** Values that may legally sit where a pattern is expected. */
function collectScalars(value, trail, leaves, onBadShape) {
    if (isScalarPattern(value)) {
        leaves.push({ trail, value })
    } else if (Array.isArray(value)) {
        value.forEach((item, index) => {
            if (isScalarPattern(item)) {
                leaves.push({ trail: `${trail}[${index}]`, value: item })
            } else {
                onBadShape(`${trail}[${index}]`, item)
            }
        })
    } else {
        onBadShape(trail, value)
    }
}

/**
 * Walk one channel, verifying its shape and collecting every pattern string so
 * the regexes can be compiled the same way the engine compiles them.
 */
function walkChannel(name, channel, value, file) {
    const kind = CHANNELS[channel]
    const leaves = []

    const badShape = (trail, offender) =>
        error(
            'E_CHANNEL_SHAPE',
            name,
            `${trail} must be a string, number or array of them, got ${
                Array.isArray(offender) ? 'array' : typeof offender
            }`,
            file
        )

    if (kind === 'oo' || kind === 'om') {
        if (isPlainObject(value)) {
            error(
                'E_CHANNEL_SHAPE',
                name,
                `${channel} is an object, but the engine matches it against a ` +
                    'single value; it must be a string, number or array. ' +
                    'As written it can never match.',
                file
            )

            return leaves
        }

        collectScalars(value, channel, leaves, badShape)

        return leaves
    }

    if (kind === 'mm') {
        if (!isPlainObject(value)) {
            error(
                'E_CHANNEL_SHAPE',
                name,
                `${channel} must be a keyed object (the key selects which value ` +
                    `to match), got ${Array.isArray(value) ? 'array' : typeof value}. ` +
                    'As written it can never match.',
                file
            )

            return leaves
        }

        for (const [key, patterns] of Object.entries(value)) {
            // driver.js resolves a fixed set of record types; anything else is a
            // key that never receives values.
            if (channel === 'dns' && !DNS_RECORDS.includes(key.toLowerCase())) {
                error(
                    'E_DNS_RECORD',
                    name,
                    `dns.${key} is not a record type the driver resolves ` +
                        `(expected ${DNS_RECORDS.join(', ')})`,
                    file
                )
            }

            // The key is looked up literally (items[key]), so regex syntax in a
            // header/cookie/JS-chain name never matches. This is upstream's
            // semantics too, so it is reported rather than rewritten.
            if (/[*?[\]|]|\\[.dws+]/.test(key)) {
                warn(
                    'W_REGEX_KEY',
                    name,
                    `${channel}.${key} looks like a regex, but keys are matched ` +
                        'literally, so this never fires',
                    file
                )
            }

            collectScalars(patterns, `${channel}.${key}`, leaves, badShape)
        }

        return leaves
    }

    if (kind === 'probe') {
        // driver.js does Object.keys(technology.probe) and treats each key as a
        // request path, so an array yields requests to "/0", "/1", ...
        if (!isPlainObject(value)) {
            error(
                'E_CHANNEL_SHAPE',
                name,
                `probe must be an object keyed by request path, got ${
                    Array.isArray(value) ? 'array' : typeof value
                }. As written the driver would request "/0", "/1", ...`,
                file
            )

            return leaves
        }

        for (const [requestPath, patterns] of Object.entries(value)) {
            if (!requestPath.startsWith('/')) {
                error(
                    'E_PROBE_PATH',
                    name,
                    `probe key ${JSON.stringify(requestPath)} is not a request path`,
                    file
                )
            }

            collectScalars(patterns, `probe.${requestPath}`, leaves, badShape)
        }

        return leaves
    }

    if (kind === 'dom') {
        // A selector list is shorthand for "these selectors must exist".
        if (isScalarPattern(value) || Array.isArray(value)) {
            return leaves
        }

        if (!isPlainObject(value)) {
            error('E_CHANNEL_SHAPE', name, `dom has invalid type ${typeof value}`, file)

            return leaves
        }

        for (const [selector, spec] of Object.entries(value)) {
            for (const rule of Array.isArray(spec) ? spec : [spec]) {
                if (!isPlainObject(rule)) {
                    error(
                        'E_CHANNEL_SHAPE',
                        name,
                        `dom.${selector} must be an object with exists/text/` +
                            'properties/attributes',
                        file
                    )

                    continue
                }

                for (const [key, sub] of Object.entries(rule)) {
                    if (key === 'exists') {
                        // The collector reports existence as an empty string, so
                        // the pattern part must be empty. A `\;version:` suffix is
                        // still allowed — that is how a version is pinned to the
                        // presence of a selector.
                        if (typeof sub !== 'string' || sub.split('\\;')[0] !== '') {
                            error(
                                'E_DOM_EXISTS',
                                name,
                                `dom.${selector}.exists must be "" (optionally with ` +
                                    `a \\;version: suffix), got ${JSON.stringify(sub)}; ` +
                                    'as written it never matches',
                                file
                            )
                        }
                    } else if (key === 'text') {
                        collectScalars(sub, `dom.${selector}.text`, leaves, badShape)
                    } else if (key === 'properties' || key === 'attributes') {
                        if (!isPlainObject(sub)) {
                            error(
                                'E_CHANNEL_SHAPE',
                                name,
                                `dom.${selector}.${key} must be a keyed object`,
                                file
                            )

                            continue
                        }

                        for (const [subKey, patterns] of Object.entries(sub)) {
                            collectScalars(
                                patterns,
                                `dom.${selector}.${key}.${subKey}`,
                                leaves,
                                badShape
                            )
                        }
                    } else {
                        error(
                            'E_DOM_KEY',
                            name,
                            `dom.${selector}.${key} is not a recognised rule ` +
                                `(expected ${DOM_RULES.join(', ')})`,
                            file
                        )
                    }
                }
            }
        }
    }

    return leaves
}

/* ------------------------------------------------------------- entry checks */

function refNames(value) {
    if (value === undefined || value === null) {
        return []
    }

    return (Array.isArray(value) ? value : [value])
        .filter((item) => typeof item === 'string')
        .map((item) => item.split('\\;')[0].trim())
}

function validateEntry(name, entry, file, known, categoryIds) {
    if (!isPlainObject(entry)) {
        error('E_INVALID_ENTRY', name, 'Entry must be an object', file)

        return
    }

    let channelCount = 0

    for (const [field, value] of Object.entries(entry)) {
        if (!KNOWN_FIELDS.has(field)) {
            // The single highest-value check: the engine destructures a fixed
            // field list, so anything else is dropped without a word.
            const suggestion = closestField(field)

            error(
                'E_UNKNOWN_FIELD',
                name,
                `"${field}" is not read by the engine and is silently dropped` +
                    (suggestion ? `; did you mean "${suggestion}"?` : ''),
                file
            )

            continue
        }

        if (CHANNELS[field]) {
            channelCount++

            const leaves = walkChannel(name, field, value, file)

            for (const { trail, value: pattern } of leaves) {
                // In a keyed channel an empty pattern is the idiomatic "this key
                // just has to be present". In a one-to-one/one-to-many channel
                // there is no key, so an empty pattern matches every page.
                if (pattern === '' && (kindOf(field) === 'oo' || kindOf(field) === 'om')) {
                    error(
                        'E_EMPTY_PATTERN',
                        name,
                        `${trail} is empty, which matches every value`,
                        file
                    )

                    continue
                }

                try {
                    Wappalyzer.parsePattern(pattern)
                } catch (err) {
                    error(
                        'E_INVALID_REGEX',
                        name,
                        `${trail} does not compile: ${err.message}`,
                        file
                    )
                }
            }

            continue
        }

        validateMetadata(name, field, value, file, known, categoryIds)
    }

    if (!channelCount) {
        // Legitimate for entries only reachable through `implies`, so this is a
        // warning: it flags catalog rows that can never be detected on their own.
        warn(
            'W_NO_DETECTION',
            name,
            'Has no detection channel, so it can only surface via implies',
            file
        )
    }
}

function validateMetadata(name, field, value, file, known, categoryIds) {
    const type = METADATA[field]

    if (type === 'intArray' && field === 'cats') {
        if (!Array.isArray(value) || !value.length) {
            error('E_NO_CATEGORY', name, 'cats must be a non-empty array', file)

            return
        }

        for (const id of value) {
            if (!Number.isInteger(id)) {
                error('E_NO_CATEGORY', name, `cats contains non-integer ${id}`, file)
            } else if (!categoryIds.has(id)) {
                error(
                    'E_UNKNOWN_CATEGORY',
                    name,
                    `cats references category ${id}, which is not in categories.json`,
                    file
                )
            }
        }

        return
    }

    if (type === 'intArray' && field === 'requiresCategory') {
        for (const id of Array.isArray(value) ? value : [value]) {
            if (!categoryIds.has(Number(id))) {
                error(
                    'E_UNKNOWN_CATEGORY',
                    name,
                    `requiresCategory references category ${id}, which is not in ` +
                        'categories.json',
                    file
                )
            }
        }

        return
    }

    if (type === 'reference') {
        for (const target of refNames(value)) {
            if (!target) {
                error('E_EMPTY_REF', name, `${field} contains an empty name`, file)
            } else if (target === name) {
                error('E_SELF_REFERENCE', name, `${field} references itself`, file)
            } else if (!known.has(target)) {
                error(
                    `E_DANGLING_${field.toUpperCase()}`,
                    name,
                    `${field} references "${target}", which does not exist`,
                    file
                )
            }
        }

        return
    }

    if (type === 'boolean' && typeof value !== 'boolean') {
        error('E_FIELD_TYPE', name, `${field} must be a boolean`, file)

        return
    }

    // The engine coerces a missing scalar to null, so an explicit null is fine.
    if (type === 'string' && value !== null && typeof value !== 'string') {
        error('E_FIELD_TYPE', name, `${field} must be a string`, file)

        return
    }

    if (type === 'stringArray' && !Array.isArray(value)) {
        error('E_FIELD_TYPE', name, `${field} must be an array`, file)
    }
}

/** Cheap edit-distance suggestion, to make typo'd fields obvious. */
function closestField(field) {
    const lower = field.toLowerCase()

    let best = null
    let bestScore = Infinity

    for (const candidate of KNOWN_FIELDS) {
        const target = candidate.toLowerCase()

        if (target === lower) {
            return candidate
        }

        const score = target.startsWith(lower) || lower.startsWith(target)
            ? Math.abs(target.length - lower.length)
            : Infinity

        if (score < bestScore) {
            bestScore = score
            best = candidate
        }
    }

    return bestScore <= 3 ? best : null
}

/* ------------------------------------------------------------ catalog checks */

function validateCategories(categories) {
    const ids = new Set()

    for (const [key, category] of Object.entries(categories)) {
        const id = Number(key)

        if (!Number.isInteger(id)) {
            error('E_CATEGORY_ID', key, 'Category id must be an integer', 'categories.json')

            continue
        }

        ids.add(id)

        if (!category || typeof category.name !== 'string' || !category.name) {
            error('E_CATEGORY_SHAPE', key, 'Category needs a name', 'categories.json')
        }

        if (!Number.isInteger(category && category.priority)) {
            error(
                'E_CATEGORY_SHAPE',
                key,
                'Category needs an integer priority (resolve() sorts on it)',
                'categories.json'
            )
        }
    }

    return ids
}

/**
 * Load the whole catalog through the engine and resolve every technology in
 * isolation. This is the end-to-end coherence check: whatever the catalog says,
 * the engine must be able to load it and emit a result without defects.
 */
function validateAgainstEngine(rawTechnologies, categories) {
    Wappalyzer.setCategories(categories)

    try {
        Wappalyzer.setTechnologies(rawTechnologies)
    } catch (err) {
        error('E_ENGINE_LOAD', '(catalog)', `setTechnologies() threw: ${err.message}`)

        return
    }

    for (const { type, technology, message } of Wappalyzer.errors) {
        error(`E_ENGINE_${type.toUpperCase().replace(/-/g, '_')}`, technology, message)
    }

    const all = [
        ...Wappalyzer.technologies,
        ...Wappalyzer.requires.map(({ technologies }) => technologies).flat(),
        ...Wappalyzer.categoryRequires
        .map(({ technologies }) => technologies)
        .flat(),
    ]

    for (const technology of all) {
        Wappalyzer.errors = []

        let resolved

        try {
            resolved = Wappalyzer.resolve([
                { technology, pattern: { confidence: 100 }, version: '' },
            ])
        } catch (err) {
            error(
                'E_RESOLVE_THROWS',
                technology.name,
                `resolve() threw: ${err.message}`
            )

            continue
        }

        for (const { type, message } of Wappalyzer.errors) {
            error(
                `E_RESOLVE_${type.toUpperCase().replace(/-/g, '_')}`,
                technology.name,
                message
            )
        }

        if (!resolved.length) {
            error(
                'E_RESOLVE_EMPTY',
                technology.name,
                'resolve() dropped the technology entirely'
            )
        }
    }
}

/* -------------------------------------------------------------------- output */

function main() {
    const categories = JSON.parse(fs.readFileSync(CATEGORIES_FILE, 'utf8'))
    const categoryIds = validateCategories(categories)

    const { entries, duplicates, byFile } = loadCatalog()
    const known = new Set(entries.keys())

    for (const { name, files } of duplicates) {
        error(
            'E_DUPLICATE_NAME',
            name,
            `Defined in ${files.join(' and ')}; whichever loads last silently wins`,
            files[1]
        )
    }

    for (const [name, { entry, file }] of entries) {
        validateEntry(name, entry, file, known, categoryIds)

        if (file !== fileForTechnology(name)) {
            warn(
                'W_MISFILED',
                name,
                `Lives in ${file} but belongs in ${fileForTechnology(name)}`,
                file
            )
        }
    }

    const flat = {}

    for (const parsed of Object.values(byFile)) {
        Object.assign(flat, parsed)
    }

    validateAgainstEngine(flat, categories)

    const errors = findings.filter(({ severity }) => severity === 'error')
    const warnings = findings.filter(({ severity }) => severity === 'warning')

    if (JSON_OUTPUT) {
        process.stdout.write(
            `${JSON.stringify(
                {
                    technologies: entries.size,
                    categories: categoryIds.size,
                    errors: errors.length,
                    warnings: warnings.length,
                    findings: QUIET ? errors : findings,
                },
                null,
                2
            )}\n`
        )
    } else {
        printReport(entries.size, categoryIds.size, errors, warnings)
    }

    const failed = errors.length || (STRICT && warnings.length)

    process.exit(failed ? 1 : 0)
}

function printReport(technologyCount, categoryCount, errors, warnings) {
    const groups = {}

    for (const finding of QUIET ? errors : [...errors, ...warnings]) {
        groups[finding.code] = groups[finding.code] || []
        groups[finding.code].push(finding)
    }

    const codes = Object.keys(groups).sort(
        (a, b) => groups[b].length - groups[a].length
    )

    console.log(`Validating ${technologyCount} technologies against ${categoryCount} categories\n`)

    for (const code of codes) {
        const group = groups[code]
        const label = group[0].severity === 'error' ? 'ERROR' : 'warn '

        console.log(`${label} ${code} (${group.length})`)

        for (const { technology, message, file } of group.slice(0, 10)) {
            console.log(`      ${technology}${file ? ` [${file}]` : ''}`)
            console.log(`        ${message}`)
        }

        if (group.length > 10) {
            console.log(`      ... and ${group.length - 10} more`)
        }

        console.log()
    }

    if (!errors.length && !warnings.length) {
        console.log('No problems found.')
    } else {
        console.log(`${errors.length} error(s), ${warnings.length} warning(s)`)
    }
}

main()
