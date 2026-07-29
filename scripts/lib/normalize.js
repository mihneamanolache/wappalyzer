'use strict'

/**
 * Rewrites catalog entries into the shapes wappalyzer.js actually reads.
 *
 * Upstream and hand-edited entries accumulate fields and shapes the engine does
 * not consume: a `script` key where `scriptSrc` was meant, a `dns` array where a
 * record-keyed object is required, a `dom` rule using `content` instead of
 * `attributes.content`. None of these error — they just never match. This module
 * converts them, preserving the detection intent wherever it is recoverable and
 * reporting every change so it can be reviewed.
 *
 * It runs as part of `npm run update` because upstream keeps reintroducing the
 * same shapes, so this is maintenance, not a one-off migration.
 */

const Wappalyzer = require('../../wappalyzer')
const {
    CHANNELS,
    DNS_RECORDS,
    canMatchHostname,
    requiresPathOrScheme,
    DOM_RULES,
    FLAT_CHANNELS,
    isPlainObject,
    isScalar,
    toArray,
} = require('./channels')

/** Aliases seen in the catalog for DNS record types the driver resolves. */
const DNS_RECORD_ALIASES = {
    nameserver: 'NS',
    nameservers: 'NS',
    ns1: 'NS',
    cnames: 'CNAME',
    txts: 'TXT',
}

/** Fields carrying no detection signal the engine can use. */
const DROP_FIELDS = new Set([
    'apps',
    'category',
    'developer',
    'enhanced',
    'examples',
    'keywords',
    'language',
    'mime',
    'name',
    'npm',
    'schemaOrg',
    'slug',
    'tags',
    'uncat',
    'version',
])

/** Straight renames to the field the engine reads. */
const RENAME_FIELDS = {
    categories: 'cats',
    icons: 'icon',
}

/** Categories referenced by entries but absent from categories.json. */
const CATEGORY_REMAP = {
    0: null, // no meaning; entries carrying it are remapped by name below
    113: 16, // -> Security
    117: 29, // -> Search engines
}

/**
 * Case-specific rewrites where the intent cannot be inferred from shape alone.
 * Keyed by technology name; each entry replaces the listed fields.
 */
const OVERRIDES = {
    // `cats: [0]` is not a category. Both entries below are metadata-only rows.
    'Thomson Reuters ONESOURCE': { cats: [55] }, // Accounting
    'Accenture Duck Creek': { cats: [19] }, // Miscellaneous
    // `categories: [28]` (Operating systems) is wrong for a web access manager.
    'NetIQ Access Manager': { cats: [69] }, // Authentication

    // A `dom` version rule is not a thing the collector reports. Each of these
    // is expressible as a pattern on a channel that does extract versions.
    'Easy FancyBox': {
        dom: undefined,
        scriptSrc: [
            '/easy-fancybox/([\\d.]+)/\\;version:\\1',
            'jquery\\.fancybox(?:\\.pack)?\\.js(?:\\?ver=([\\d.]+))?\\;version:\\1',
        ],
    },
    'CCH Site Builder': {
        dom: undefined,
        meta: { generator: 'CCH Site Builder\\s*([\\d.]+)?\\;version:\\1' },
    },
    'Microsoft FrontPage': {
        dom: undefined,
        meta: { generator: 'FrontPage(?:[\\s.]*([\\d.]+))?\\;version:\\1' },
    },
    Customizr: {
        dom: undefined,
        meta: {
            generator:
                '(?:^|\\s)Customizr(?:\\s+(\\d+\\.\\d+(?:\\.\\d+)*))?(?:\\s|$)\\;version:\\1',
        },
    },

    // `scripts` here holds JS globals, not inline script bodies.
    'Salesforce Sales Cloud': { scripts: undefined, js: { Sfdc: '' } },
    Casewise: { scripts: undefined, js: { Casewise: '' } },
    'Oracle Endeca Information Discovery': {
        scripts: undefined,
        js: { EndecaPage: '' },
    },
    SmarterStats: { scripts: undefined, js: { STKey: '', STKey2: '' } },

    // `ssl: true` carries no issuer to match against.
    'DiskStation Manager': { ssl: undefined },
    'OpenText WEM': { regex: undefined },

    // The dns key was written as the pattern. An Azure SQL hostname shows up as
    // a CNAME target, which is the record the driver resolves for the host.
    'Microsoft SQL Server': {
        dns: { CNAME: '\\.database\\.windows\\.net' },
    },

    // Channels are OR'd, so any one of Helm's markers alone was enough to detect
    // it. `content-type: yaml` fires on any YAML endpoint, `entries:` on any page
    // containing that word, and a `<title>Helm</title>` on any page about Helm.
    // The probe patterns are the real signal: a chart repository index whose body
    // carries the `apiVersion: v1 ... entries:` signature.
    Helm: {
        headers: undefined,
        text: undefined,
        dom: undefined,
        url: undefined,
        meta: undefined,
    },

    // A probe with an empty pattern matches any 2xx response at that path, and
    // `/config` returning 200 is unremarkable. The specific API paths remain on
    // xhrUrl, and the header and hostname markers are untouched.
    Databricks: {
        probe: undefined,
    },
}

/**
 * DNS record type to assume when a `dns` channel was written as a bare pattern.
 * Nameserver-provider entries describe NS records; everything else here is a
 * hostname alias, which is a CNAME.
 */
const DNS_RECORD_OVERRIDES = {
    'Alfahosting DNS': 'NS',
    'Azure DNS': 'NS',
    'Dinahosting DNS': 'NS',
    'Forpsi DNS': 'NS',
    'GoDaddy DNS': 'NS',
    'Hetzner DNS': 'NS',
    'HiChina DNS': 'NS',
    'Hostpoint DNS': 'NS',
    'Namecheap DNS': 'NS',
    OVH: 'NS',
}

/** Looks like a script URL or filename rather than inline script content. */
function looksLikeUrl(pattern) {
    return /\\?\/|\\?\.(?:js|com|net|org|io|jp|de)\b|https?|cdn|\.js/i.test(
        String(pattern)
    )
}

/** Merge a pattern (or list) into a flat channel, without duplicates. */
function addFlat(entry, channel, patterns) {
    const existing = entry[channel] === undefined ? [] : toArray(entry[channel])
    const merged = [...existing]

    for (const pattern of toArray(patterns)) {
        if (!merged.some((value) => JSON.stringify(value) === JSON.stringify(pattern))) {
            merged.push(pattern)
        }
    }

    entry[channel] = merged.length === 1 ? merged[0] : merged
}

/** Merge keys into a keyed channel, without dropping what is already there. */
function addKeyed(entry, channel, values) {
    entry[channel] = entry[channel] && isPlainObject(entry[channel])
        ? { ...entry[channel] }
        : {}

    for (const [key, value] of Object.entries(values)) {
        if (!(key in entry[channel])) {
            entry[channel][key] = value
        }
    }
}

/**
 * Channels this optimisation must never touch.
 *
 * `dom` holds CSS selectors, where string containment says nothing about what is
 * matched. `script#apple-pay` does **not** select
 * `id="apple-pay-shop-capabilities"`, and `.asciinema-player` does not match
 * `class="asciinema-player-wrapper"` — a class or id match is exact, not a
 * prefix. Applying substring logic here deleted three real detections
 * (Apple Pay, Asciinema, Swiper) before this exclusion existed.
 *
 * `probe` keys are request paths, where `/a` and `/ab` are different endpoints.
 */
const NO_SUBSUMPTION = new Set(['dom', 'probe'])

/**
 * Is this pattern a plain literal, with no regex operators?
 *
 * Substring containment only implies matching-superset behaviour for literals. As
 * soon as a pattern contains alternation, anchors, quantifiers, groups or classes,
 * the relationship between "contains this text" and "matches a superset" breaks
 * down. Escaped dots are treated as literal, since that is how the catalog writes
 * hostnames.
 *
 * @param {string} pattern
 */
function isLiteralPattern(pattern) {
    // An escaped dot is a literal dot; a bare `.` is the wildcard, so it must
    // disqualify the pattern. Substitute the escaped form out of the way first,
    // then require every remaining character to be inert.
    const escapedDotsRemoved = String(pattern).replace(/\\\./g, '')

    return /^[A-Za-z0-9_\-=:/@ ]*$/.test(escapedDotsRemoved)
}

/**
 * Drop patterns that another pattern in the same list already covers.
 *
 * These arise from additive merges: upstream ships `mixpanel-domain-verify` and a
 * local enrichment adds `mixpanel-domain-verify=`. Both are substring regexes, so
 * anything the longer one matches the shorter one matches too — the longer is pure
 * redundancy. The DNS sweep surfaced these as pairs with identical domain counts.
 *
 * Deliberately conservative. It applies only to literal patterns, and never to
 * `dom` or `probe`. The saving is a handful of regex evaluations; the cost of
 * being wrong is a silent false negative, so the trade only makes sense where
 * subsumption is provable by inspection.
 *
 * Only the *longer* pattern is removed. Dropping the shorter one would narrow
 * coverage: given `example\.com` and `cdn\.example\.com`, the short pattern is the
 * one that also matches `www.example.com`.
 *
 * @param {Array} patterns
 * @returns {{kept: Array, dropped: Array}}
 */
function dropSubsumedPatterns(patterns) {
    // A pattern may carry `\;version:` or `\;confidence:` tags, which change what
    // a match *means*. Two patterns are only interchangeable when neither is
    // tagged, so subsumption is restricted to untagged pairs:
    //
    //   dropping a tagged pattern loses version extraction
    //     `jquery` detects jQuery; `/jquery-(\d+\.\d+\.\d+)[/.-]\;version:\1`
    //     is what reports which version.
    //
    //   dropping in favour of a tagged subsumer can lower confidence
    //     `adocean\.pl/files/js/ado\.js` matches at confidence 100, while
    //     `adocean\.pl\;confidence:80` would report the same URL at 80.
    const isTagged = (value) => String(value).includes('\\;')

    const valueOf = (pattern) => String(pattern).split('\\;')[0]

    const candidates = patterns.filter(isScalar).map((pattern) => ({
        raw: String(pattern),
        value: valueOf(pattern),
    }))

    const kept = []
    const dropped = []

    for (const pattern of patterns) {
        if (!isScalar(pattern)) {
            kept.push(pattern)

            continue
        }

        const raw = String(pattern)

        if (isTagged(raw) || !isLiteralPattern(raw)) {
            kept.push(pattern)

            continue
        }

        const value = valueOf(raw)
        const subsumer = candidates.find(
            (other) =>
                other.raw !== raw &&
                !isTagged(other.raw) &&
                isLiteralPattern(other.raw) &&
                other.value.length < value.length &&
                value.includes(other.value)
        )

        if (subsumer) {
            dropped.push({ pattern: raw, subsumedBy: subsumer.raw })
        } else {
            kept.push(pattern)
        }
    }

    return { kept, dropped }
}

/**
 * Normalize one technology entry.
 * @param {string} name
 * @param {object} original
 * @returns {{entry: object, changes: string[]}}
 */
function normalizeEntry(name, original) {
    const entry = JSON.parse(JSON.stringify(original))
    const changes = []
    const note = (message) => changes.push(message)

    /* ---------------------------------------------- field-level conversions */

    // `script` is not a channel. The values are script URL patterns in almost
    // every case, and inline-script patterns in the rest.
    if ('script' in entry) {
        const raw = entry.script
        const patterns = isPlainObject(raw) ? Object.keys(raw) : toArray(raw)

        delete entry.script

        for (const pattern of patterns) {
            const target = looksLikeUrl(pattern) ? 'scriptSrc' : 'scripts'

            addFlat(entry, target, pattern)
            note(`script -> ${target}: ${JSON.stringify(pattern)}`)
        }
    }

    // Old-style `env` listed global JS variables, which is the `js` channel.
    if ('env' in entry) {
        const env = entry.env

        delete entry.env

        if (isPlainObject(env)) {
            addKeyed(
                entry,
                'js',
                Object.keys(env).reduce((js, key) => ({ ...js, [key]: '' }), {})
            )
            note(`env -> js: ${Object.keys(env).join(', ')}`)
        }
    }

    // `ssl.issuer` is the certIssuer channel.
    if ('ssl' in entry) {
        const ssl = entry.ssl

        delete entry.ssl

        if (isPlainObject(ssl) && ssl.issuer) {
            addFlat(entry, 'certIssuer', ssl.issuer)
            note(`ssl.issuer -> certIssuer: ${JSON.stringify(ssl.issuer)}`)
        } else {
            note('dropped ssl (no issuer to match)')
        }
    }

    // `regex: { <channel>: <pattern> }` is a channel written one level too deep.
    if ('regex' in entry) {
        const regex = entry.regex

        delete entry.regex

        if (isPlainObject(regex)) {
            for (const [channel, pattern] of Object.entries(regex)) {
                if (CHANNELS[channel] === 'mm') {
                    addKeyed(entry, channel, { [pattern]: '' })
                    note(`regex.${channel} -> ${channel}[${pattern}]`)
                } else if (CHANNELS[channel]) {
                    addFlat(entry, channel, pattern)
                    note(`regex.${channel} -> ${channel}`)
                }
            }
        } else {
            note('dropped empty regex')
        }
    }

    // `tests` / `rules` wrap real channels.
    for (const wrapper of ['tests', 'rules']) {
        if (!(wrapper in entry)) {
            continue
        }

        const wrapped = entry[wrapper]

        delete entry[wrapper]

        if (!isPlainObject(wrapped)) {
            continue
        }

        for (const [channel, value] of Object.entries(wrapped)) {
            // A `scripts` list holding URLs belongs in scriptSrc.
            const target =
                channel === 'scripts' && toArray(value).every(looksLikeUrl)
                    ? 'scriptSrc'
                    : channel

            if (!CHANNELS[target]) {
                continue
            }

            if (CHANNELS[target] === 'mm') {
                if (isPlainObject(value)) {
                    addKeyed(entry, target, value)
                }
            } else {
                addFlat(entry, target, value)
            }

            note(`${wrapper}.${channel} -> ${target}`)
        }
    }

    // No stylesheet-URL channel exists; the <link> tag is visible in the HTML.
    if ('stylesheets' in entry) {
        const stylesheets = entry.stylesheets

        delete entry.stylesheets

        addFlat(entry, 'html', stylesheets)
        note('stylesheets -> html')
    }

    for (const [from, to] of Object.entries(RENAME_FIELDS)) {
        if (from in entry) {
            if (!(to in entry)) {
                entry[to] = entry[from]
                note(`${from} -> ${to}`)
            } else {
                note(`dropped ${from} (${to} already set)`)
            }

            delete entry[from]
        }
    }

    for (const field of DROP_FIELDS) {
        if (field in entry) {
            delete entry[field]
            note(`dropped ${field} (not read by the engine)`)
        }
    }

    /* ------------------------------------------------ channel shape repairs */

    for (const channel of FLAT_CHANNELS) {
        if (!(channel in entry) || !isPlainObject(entry[channel])) {
            continue
        }

        const value = entry[channel]
        const keys = Object.keys(value)

        if (!keys.length) {
            delete entry[channel]
            note(`dropped empty ${channel} object`)

            continue
        }

        // `{ "regex": "<pattern>" }` is a pattern wrapped in a stray object.
        if (keys.length === 1 && keys[0] === 'regex') {
            entry[channel] = value.regex
            note(`${channel}.regex -> ${channel}`)

            continue
        }

        // `{ "<pattern>": "" }` is a pattern that ended up as a key. When the key
        // reads as a JS identifier chain it was meant for the js channel.
        const identifiers = keys.every((key) =>
            /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$/.test(key)
        )

        delete entry[channel]

        if (identifiers && channel === 'scripts') {
            addKeyed(
                entry,
                'js',
                keys.reduce((js, key) => ({ ...js, [key]: '' }), {})
            )
            note(`${channel} object of identifiers -> js: ${keys.join(', ')}`)
        } else {
            addFlat(entry, channel, keys)
            note(`${channel} object keys -> ${channel} patterns`)
        }
    }

    // Benign URLs no vendor should ever be detected from. A relocated pattern that
    // matches one of these is a catch-all: harmless while it was dead in `xhr`,
    // but a false-positive generator once `xhrUrl` makes it live. Those are
    // dropped rather than moved.
    const CONTROL_URLS = [
        'https://example.com/',
        'https://example.com/index.html',
        'https://example.com/about/team',
        'https://cdn.example.com/assets/app.js?v=2',
        'https://example.com/api/v1/users',
        'http://example.com/a/b/c',
    ]

    // `xhr` receives a bare hostname, so a pattern describing an API path cannot
    // fire there. Most were written expecting a full URL, which is what `xhrUrl`
    // carries — so relocate rather than delete, preserving the intent. Upstream
    // keeps shipping these, which is why it runs on every merge.
    if (entry.xhr !== undefined) {
        const compile = (pattern) => Wappalyzer.parsePattern(pattern).regex
        const keep = []
        const relocate = []

        for (const pattern of toArray(entry.xhr)) {
            if (!isScalar(pattern)) {
                keep.push(pattern)
            } else if (canMatchHostname(pattern, compile)) {
                keep.push(pattern)
            } else {
                relocate.push(pattern)
            }
        }

        // Relocating makes a dead pattern live, so over-broad ones must be
        // dropped instead of promoted.
        const tooBroad = []

        for (let index = relocate.length - 1; index >= 0; index--) {
            let regex

            try {
                regex = compile(relocate[index])
            } catch (error) {
                continue
            }

            if (CONTROL_URLS.some((control) => regex.test(control))) {
                tooBroad.push(relocate.splice(index, 1)[0])
            }
        }

        if (relocate.length || tooBroad.length) {
            if (keep.length) {
                entry.xhr = keep.length === 1 ? keep[0] : keep
            } else {
                delete entry.xhr
            }

            for (const pattern of tooBroad) {
                note(
                    `dropped xhr ${JSON.stringify(pattern)}: it matches benign ` +
                        'URLs, so relocating it to xhrUrl would generate false ' +
                        'positives'
                )
            }

            for (const pattern of relocate) {
                addFlat(entry, 'xhrUrl', pattern)
                note(
                    `xhr -> xhrUrl: ${JSON.stringify(pattern)} needs ` +
                        `${requiresPathOrScheme(pattern) ? 'a path or scheme' : 'a path'}, ` +
                        'which the hostname-only xhr channel never receives'
                )
            }
        }
    }

    // driver.js only resolves cname/mx/ns/soa/txt, so any other dns key is a
    // channel that never receives values. Map the known aliases across.
    if (isPlainObject(entry.dns)) {
        const dns = {}

        for (const [record, patterns] of Object.entries(entry.dns)) {
            const alias = DNS_RECORD_ALIASES[record.toLowerCase()]

            if (alias) {
                dns[alias] = patterns
                note(`dns.${record} -> dns.${alias}`)
            } else {
                dns[record] = patterns
            }
        }

        entry.dns = dns
    }

    // The `js` channel is keyed by a flat property chain. A nested object reads
    // naturally but the collector never walks into it, so flatten to dotted
    // chains. A non-string leaf is not a usable regex, so it becomes an
    // existence check.
    if (isPlainObject(entry.js)) {
        const flattened = {}

        const walk = (value, chain) => {
            if (isPlainObject(value)) {
                const keys = Object.keys(value)

                if (!keys.length) {
                    flattened[chain] = ''
                    note(`js.${chain} was an empty object -> existence check`)

                    return
                }

                for (const key of keys) {
                    walk(value[key], `${chain}.${key}`)
                }

                return
            }

            if (typeof value === 'string') {
                flattened[chain] = value
            } else {
                flattened[chain] = ''
                note(`js.${chain} value ${JSON.stringify(value)} -> existence check`)
            }
        }

        for (const [chain, value] of Object.entries(entry.js)) {
            if (isPlainObject(value)) {
                note(`js.${chain} nested object -> dotted chain(s)`)
            }

            walk(value, chain)
        }

        entry.js = flattened
    }

    // Keyed channels written as a bare pattern have no key to match on.
    for (const channel of ['cookies', 'headers', 'meta', 'js', 'dns']) {
        if (!(channel in entry) || isPlainObject(entry[channel])) {
            continue
        }

        const patterns = toArray(entry[channel]).filter(isScalar)

        delete entry[channel]

        if (!patterns.length) {
            note(`dropped ${channel} (no usable pattern)`)

            continue
        }

        if (channel === 'dns') {
            // A bare dns pattern is a record value; pick the record type it
            // describes rather than guessing at scan time.
            const record = DNS_RECORD_OVERRIDES[name] || 'CNAME'

            addKeyed(entry, 'dns', { [record]: patterns })
            note(`dns -> dns.${record} (${patterns.length} pattern(s))`)
        } else {
            // The pattern was the name to look for, so it becomes the key.
            addKeyed(
                entry,
                channel,
                patterns.reduce((keyed, key) => ({ ...keyed, [key]: '' }), {})
            )
            note(`${channel} -> keyed by name (${patterns.join(', ')})`)
        }
    }

    /* ----------------------------------------------------------- dom repairs */

    if (isPlainObject(entry.dom)) {
        const dom = {}

        for (const [selector, spec] of Object.entries(entry.dom)) {
            // `{ "<selector>": "" }` means "this selector must exist".
            if (spec === '') {
                dom[selector] = { exists: '' }
                note(`dom[${selector}] -> exists`)

                continue
            }

            // `{ "<selector>": "<pattern>" }` — the selector already encodes what
            // to look for, so existence is the recoverable intent. A generator
            // meta tag is better served by the meta channel.
            if (isScalar(spec)) {
                const meta = /^meta\[name=['"]?([\w-]+)['"]?\]$/i.exec(selector)

                if (meta) {
                    addKeyed(entry, 'meta', { [meta[1]]: spec })
                    note(`dom[${selector}] -> meta.${meta[1]}`)
                } else if (/^scripts?$/i.test(selector)) {
                    addFlat(entry, 'scripts', spec)
                    note(`dom[${selector}] -> scripts`)
                } else {
                    dom[selector] = { exists: '' }
                    note(`dom[${selector}] -> exists (pattern was redundant)`)
                }

                continue
            }

            const rules = []

            for (const rule of toArray(spec)) {
                if (!isPlainObject(rule)) {
                    continue
                }

                const repaired = {}

                for (const [key, value] of Object.entries(rule)) {
                    if (key === 'exists') {
                        // The collector reports existence as an empty string, so
                        // the pattern must be empty (a `\;version:` suffix is the
                        // one legitimate addition). `true` never matches.
                        if (typeof value === 'string' && value.split('\\;')[0] === '') {
                            repaired.exists = value
                        } else {
                            repaired.exists = ''
                            note(
                                `dom[${selector}].exists ${JSON.stringify(value)} -> ""`
                            )
                        }

                        continue
                    }

                    if (DOM_RULES.includes(key)) {
                        repaired[key] = value

                        continue
                    }

                    // A bare attribute name where `attributes` was meant. For a
                    // meta tag the meta channel is cheaper and browser-free.
                    const meta = /^meta\[name=['"]?([\w-]+)['"]?\]$/i.exec(selector)

                    if (key === 'content' && meta) {
                        addKeyed(entry, 'meta', { [meta[1]]: value })
                        note(`dom[${selector}].content -> meta.${meta[1]}`)

                        continue
                    }

                    repaired.attributes = {
                        ...(repaired.attributes || {}),
                        [key]: value,
                    }
                    note(`dom[${selector}].${key} -> attributes.${key}`)
                }

                if (Object.keys(repaired).length) {
                    rules.push(repaired)
                }
            }

            if (rules.length) {
                dom[selector] = rules.length === 1 ? rules[0] : rules
            }
        }

        if (Object.keys(dom).length) {
            entry.dom = dom
        } else {
            delete entry.dom
        }
    }

    /* --------------------------------------------------------- probe repairs */

    if ('probe' in entry) {
        const repaired = normalizeProbe(entry.probe)

        if (repaired.paths) {
            entry.probe = repaired.paths
        } else {
            delete entry.probe
        }

        for (const message of repaired.notes) {
            note(message)
        }
    }

    /* --------------------------------------------- redundant pattern cleanup */

    for (const channel of Object.keys(CHANNELS)) {
        if (!(channel in entry) || NO_SUBSUMPTION.has(channel)) {
            continue
        }

        const value = entry[channel]

        // Keyed channels: dedupe within each key's pattern list.
        if (CHANNELS[channel] === 'mm' && isPlainObject(value)) {
            for (const [key, patterns] of Object.entries(value)) {
                if (!Array.isArray(patterns)) {
                    continue
                }

                const { kept, dropped } = dropSubsumedPatterns(patterns)

                if (!dropped.length) {
                    continue
                }

                value[key] = kept.length === 1 ? kept[0] : kept

                for (const { pattern, subsumedBy } of dropped) {
                    note(
                        `dropped ${channel}.${key} ${JSON.stringify(pattern)}: ` +
                            `already covered by ${JSON.stringify(subsumedBy)}`
                    )
                }
            }

            continue
        }

        // Flat channels: dedupe the list itself.
        if (Array.isArray(value)) {
            const { kept, dropped } = dropSubsumedPatterns(value)

            if (!dropped.length) {
                continue
            }

            entry[channel] = kept.length === 1 ? kept[0] : kept

            for (const { pattern, subsumedBy } of dropped) {
                note(
                    `dropped ${channel} ${JSON.stringify(pattern)}: ` +
                        `already covered by ${JSON.stringify(subsumedBy)}`
                )
            }
        }
    }

    /* ------------------------------------------------------------ categories */

    if (Array.isArray(entry.cats)) {
        const cats = []

        for (const id of entry.cats) {
            const mapped = id in CATEGORY_REMAP ? CATEGORY_REMAP[id] : id

            if (mapped === null || mapped === undefined) {
                note(`dropped unmapped category ${id}`)

                continue
            }

            if (mapped !== id) {
                note(`category ${id} -> ${mapped}`)
            }

            if (!cats.includes(mapped)) {
                cats.push(mapped)
            }
        }

        entry.cats = cats
    }

    /* ------------------------------------------------------------- overrides */

    if (OVERRIDES[name]) {
        for (const [field, value] of Object.entries(OVERRIDES[name])) {
            if (value === undefined) {
                if (field in entry) {
                    delete entry[field]
                    note(`override: removed ${field}`)
                }
            } else {
                entry[field] = value
                note(`override: set ${field}`)
            }
        }
    }

    return { entry, changes }
}

/**
 * The engine reads `probe` as `{ "/path": "<body pattern>" }`. Several other
 * shapes exist in the catalog (an array of path objects, a `paths` wrapper, and
 * per-path `{status, headers, body}` objects). Convert them, keeping the body
 * pattern where there is one — an empty pattern still means something, because
 * the driver only reaches the match when the request returned a 2xx.
 * @param {*} probe
 */
function normalizeProbe(probe) {
    const paths = {}
    const notes = []

    const addPath = (requestPath, pattern) => {
        if (typeof requestPath !== 'string' || !requestPath) {
            return
        }

        // Some paths were written pre-escaped as if they were regexes.
        const clean = requestPath.replace(/\\\//g, '/')

        paths[clean.startsWith('/') ? clean : `/${clean}`] = pattern || ''
    }

    const fromDescriptor = (descriptor) => {
        if (typeof descriptor === 'string') {
            addPath(descriptor, '')

            return
        }

        if (!isPlainObject(descriptor)) {
            return
        }

        if (descriptor.path) {
            addPath(descriptor.path, descriptor.body)

            if (descriptor.headers || descriptor.mustHeaders || descriptor.status) {
                notes.push(
                    `probe ${descriptor.path}: status/header conditions dropped ` +
                        '(the engine matches the response body only)'
                )
            }
        }
    }

    if (Array.isArray(probe)) {
        probe.forEach(fromDescriptor)
        notes.push('probe array -> path-keyed object')
    } else if (isPlainObject(probe) && probe.paths) {
        const wrapped = probe.paths

        if (Array.isArray(wrapped)) {
            wrapped.forEach(fromDescriptor)
        } else if (isPlainObject(wrapped)) {
            for (const [requestPath, spec] of Object.entries(wrapped)) {
                addPath(requestPath, isPlainObject(spec) ? spec.body : spec)

                if (isPlainObject(spec) && (spec.status || spec.headers)) {
                    notes.push(
                        `probe ${requestPath}: status/header conditions dropped ` +
                            '(the engine matches the response body only)'
                    )
                }
            }
        }

        notes.push('probe.paths -> path-keyed object')
    } else if (isPlainObject(probe)) {
        for (const [requestPath, spec] of Object.entries(probe)) {
            if (isPlainObject(spec)) {
                addPath(requestPath, spec.body)

                if (spec.status || spec.headers) {
                    notes.push(
                        `probe ${requestPath}: status/header conditions dropped ` +
                            '(the engine matches the response body only)'
                    )
                }
            } else {
                addPath(requestPath, spec)
            }
        }
    }

    return {
        paths: Object.keys(paths).length ? paths : null,
        notes,
    }
}

/**
 * Normalize a whole catalog, then drop references to technologies that do not
 * exist. Dangling references are resolved last because they can only be judged
 * once every entry is known.
 * @param {Object<string, object>} catalog
 * @returns {{technologies: object, changes: object[]}}
 */
function normalizeCatalog(catalog) {
    const technologies = {}
    const changes = []

    for (const [name, original] of Object.entries(catalog)) {
        const { entry, changes: entryChanges } = normalizeEntry(name, original)

        technologies[name] = entry

        if (entryChanges.length) {
            changes.push({ name, changes: entryChanges })
        }
    }

    const known = new Set(Object.keys(technologies))

    for (const [name, entry] of Object.entries(technologies)) {
        for (const field of ['implies', 'excludes', 'requires']) {
            if (!(field in entry)) {
                continue
            }

            const kept = []
            const dropped = []

            for (const value of toArray(entry[field])) {
                const target = String(value).split('\\;')[0].trim()

                if (target && target !== name && known.has(target)) {
                    kept.push(value)
                } else {
                    dropped.push(value)
                }
            }

            if (!dropped.length) {
                continue
            }

            if (kept.length) {
                entry[field] = kept
            } else {
                delete entry[field]
            }

            const record = changes.find((change) => change.name === name)
            const messages = dropped.map(
                (value) => `dropped ${field} -> ${JSON.stringify(value)} (no such technology)`
            )

            if (record) {
                record.changes.push(...messages)
            } else {
                changes.push({ name, changes: messages })
            }
        }
    }

    return { technologies, changes }
}

module.exports = {
    CATEGORY_REMAP,
    NO_SUBSUMPTION,
    dropSubsumedPatterns,
    isLiteralPattern,
    DROP_FIELDS,
    OVERRIDES,
    looksLikeUrl,
    normalizeCatalog,
    normalizeEntry,
    normalizeProbe,
}
