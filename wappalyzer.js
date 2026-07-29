'use strict'

function toArray(value) {
    return Array.isArray(value) ? value : [value]
}

const benchmarkEnabled =
    typeof process !== 'undefined' ? !!process.env.WAPPALYZER_BENCHMARK : false

let benchmarks = []

function benchmark(duration, pattern, value = '', technology) {
    if (!benchmarkEnabled) {
        return
    }

    benchmarks.push({
        duration,
        pattern: String(pattern.regex),
        value: String(value).slice(0, 100),
        valueLength: value.length,
        technology: technology.name,
    })
}

function benchmarkSummary() {
    if (!benchmarkEnabled) {
        return
    }

    const totalPatterns = Object.values(benchmarks).length
    const totalDuration = Object.values(benchmarks).reduce(
        (sum, { duration }) => sum + duration,
        0
    )

    // eslint-disable-next-line no-console
    console.log({
        totalPatterns,
        totalDuration,
        averageDuration: Math.round(totalDuration / totalPatterns),
        slowestTechnologies: Object.values(
            benchmarks.reduce((benchmarks, { duration, technology }) => {
                if (benchmarks[technology]) {
                    benchmarks[technology].duration += duration
                } else {
                    benchmarks[technology] = { technology, duration }
                }

                return benchmarks
            }, {})
        )
        .sort(({ duration: a }, { duration: b }) => (a > b ? -1 : 1))
        .filter(({ duration }) => duration)
        .slice(0, 5)
        .reduce(
            (technologies, { technology, duration }) => ({
                ...technologies,
                [technology]: duration,
            }),
            {}
        ),
        slowestPatterns: Object.values(benchmarks)
        .sort(({ duration: a }, { duration: b }) => (a > b ? -1 : 1))
        .filter(({ duration }) => duration)
        .slice(0, 5),
    })
}

/**
 * Does a regex match cover a whole DNS-label suffix of an observed hostname?
 *
 * XHR observations are hostnames, not arbitrary text, so a catalog pattern has to
 * match whole labels at the right-hand end. Two distinct spoofs are rejected:
 *
 *   api.vendor.com.attacker.example   the match does not reach the end
 *   nottome.app  (pattern tome\.app)  the match starts mid-label
 *
 * Tenant subdomains must still match, so a match may begin at the start of the
 * hostname, at a dot, or immediately after one — `acme.api.vendor.com` and a
 * pattern written as `\.vendor\.com` both remain valid.
 *
 * This applies to `xhr` only. A pattern that needs a path belongs in `xhrUrl`,
 * which receives the full request URL and is matched without this constraint.
 *
 * @param {string} value observed hostname
 * @param {Array} matches result of RegExp#exec
 */
function isHostnameSuffix(value, matches) {
    const hostname = String(value)
    const { index } = matches
    const reachesEnd = index + matches[0].length === hostname.length

    if (!reachesEnd) {
        return false
    }

    return index === 0 || hostname[index] === '.' || hostname[index - 1] === '.'
}

const Wappalyzer = {
    technologies: [],
    categories: [],
    requires: [],
    categoryRequires: [],

    /**
     * Catalog defects found while loading or resolving technologies.
     * A malformed entry must never abort a scan, so problems are collected
     * here instead of thrown. `scripts/validate.js` asserts this stays empty.
     * @type {Array<{type: string, technology: string, message: string}>}
     */
    errors: [],

    /**
     * Optional sink for catalog defects, set by consumers that want to log them.
     * @type {?function({type: string, technology: string, message: string}): void}
     */
    onError: null,

    /**
     * Record a catalog defect.
     * @param {string} type
     * @param {string} technology
     * @param {string} message
     */
    error(type, technology, message) {
        const error = { type, technology, message }

        Wappalyzer.errors.push(error)

        if (Wappalyzer.onError) {
            Wappalyzer.onError(error)
        }
    },

    slugify: (string) =>
        string
        .toLowerCase()
        .replace(/[^a-z0-9-]/g, '-')
        .replace(/--+/g, '-')
        .replace(/(?:^-|-$)/g, ''),

    getTechnology: (name) =>
        [
            ...Wappalyzer.technologies,
            ...Wappalyzer.requires.map(({ technologies }) => technologies).flat(),
            ...Wappalyzer.categoryRequires
            .map(({ technologies }) => technologies)
            .flat(),
        ].find(({ name: _name }) => name === _name),

    getCategory: (id) => Wappalyzer.categories.find(({ id: _id }) => id === _id),

    /**
   * Resolve promises for implied technology.
   * @param {Array} detections
   */
    resolve(detections = []) {
        const resolved = detections.reduce((resolved, { technology, lastUrl }) => {
            if (
                resolved.findIndex(
                    ({ technology: { name } }) => name === technology?.name
                ) === -1
            ) {
                let version = ''
                let confidence = 0
                let rootPath

                detections
                    .filter(
                        ({ technology: _technology }) =>
                            _technology && _technology.name === technology.name
                    )
                    .forEach(
                        ({
                            technology: { name },
                            pattern,
                            version: _version = '',
                            rootPath: _rootPath,
                        }) => {
                            confidence = Math.min(100, confidence + pattern.confidence)
                            version =
                                _version.length > version.length &&
                                    _version.length <= 15 &&
                                    (parseInt(_version, 10) || 0) < 10000 // Ignore long numeric strings like timestamps
                                    ? _version
                                    : version
                            rootPath = rootPath || _rootPath || undefined
                        }
                    )

                resolved.push({ technology, confidence, version, rootPath, lastUrl })
            }

            return resolved
        }, [])

        Wappalyzer.resolveExcludes(resolved)
        Wappalyzer.resolveImplies(resolved)

        /**
         * Categories an entry claims that actually exist. Reported here rather
         * than in the priority sort below, because a sort comparator is not
         * called at all when there is only one detection.
         */
        const categoriesOf = ({ name, categories }) =>
            categories.reduce((valid, id) => {
                const category = Wappalyzer.getCategory(id)

                if (category) {
                    valid.push(category)
                } else {
                    Wappalyzer.error(
                        'unknown-category',
                        name,
                        `Category does not exist: ${id}`
                    )
                }

                return valid
            }, [])

        // Resolve categories once per detection so an unknown id is reported a
        // single time, then reuse them for both the sort and the output.
        const withCategories = resolved.map((detection) => ({
            detection,
            categories: categoriesOf(detection.technology),
        }))

        const priority = ({ categories }) =>
            categories.reduce((max, { priority }) => Math.max(max, priority), 0)

        return withCategories
            .sort((a, b) => (priority(a) > priority(b) ? 1 : -1))
            .map(
                ({
                    categories,
                    detection: {
                        technology: {
                            name,
                            description,
                            slug,
                            icon,
                            website,
                            pricing,
                            cpe,
                            saas,
                            oss,
                        },
                        confidence,
                        version,
                        rootPath,
                        lastUrl,
                    },
                }) => ({
                        name,
                        description,
                        slug,
                        categories,
                        confidence,
                        version,
                        icon,
                        website,
                        pricing,
                        cpe,
                        saas,
                        oss,
                        rootPath,
                        lastUrl,
                    })
            )
    },

    /**
   * Resolve promises for version of technology.
   * @param {Promise} resolved
   * @param match
   */
    resolveVersion({ version, regex }, match) {
        let resolved = version

        if (version) {
            const matches = regex.exec(match)

            if (matches) {
                matches.forEach((match, index) => {
                    if (String(match).length > 10) {
                        return
                    }

                    // Parse ternary operator
                    const ternary = new RegExp(`\\\\${index}\\?([^:]+):(.*)$`).exec(
                        version
                    )

                    if (ternary && ternary.length === 3) {
                        resolved = version.replace(
                            ternary[0],
                            match ? ternary[1] : ternary[2]
                        )
                    }

                    // Replace back references
                    resolved = resolved
                        .trim()
                        .replace(new RegExp(`\\\\${index}`, 'g'), match || '')
                })

                // Remove unmatched back references
                resolved = resolved.replace(/\\\d/, '')
            }
        }

        return resolved
    },

    /**
   * Resolve promises for excluded technology.
   * @param {Promise} resolved
   */
    resolveExcludes(resolved) {
        resolved.forEach(({ technology }) => {
            technology.excludes.forEach(({ name }) => {
                const excluded = Wappalyzer.getTechnology(name)

                if (!excluded) {
                    Wappalyzer.error(
                        'dangling-excludes',
                        technology.name,
                        `Excluded technology does not exist: ${name}`
                    )

                    return
                }

                let index

                do {
                    index = resolved.findIndex(
                        ({ technology: { name } }) => name === excluded.name
                    )

                    if (index !== -1) {
                        resolved.splice(index, 1)
                    }
                } while (index !== -1)
            })
        })
    },

    /**
   * Resolve promises for implied technology.
   * @param {Promise} resolved
   */
    resolveImplies(resolved) {
        let done = false

        do {
            done = true

            resolved.forEach(({ technology, confidence, lastUrl }) => {
                technology.implies.forEach(
                    ({ name, confidence: _confidence, version }) => {
                        const implied = Wappalyzer.getTechnology(name)

                        if (!implied) {
                            Wappalyzer.error(
                                'dangling-implies',
                                technology.name,
                                `Implied technology does not exist: ${name}`
                            )

                            return
                        }

                        if (
                            resolved.findIndex(
                                ({ technology: { name } }) => name === implied.name
                            ) === -1
                        ) {
                            resolved.push({
                                technology: implied,
                                confidence: Math.min(confidence, _confidence),
                                version: version || '',
                                lastUrl,
                            })

                            done = false
                        }
                    }
                )
            })
        } while (resolved.length && !done)
    },

    /**
   * Initialize analyzation.
   * @param {*} param0
   */
    analyze(items, technologies = Wappalyzer.technologies) {
        benchmarks = []

        const oo = Wappalyzer.analyzeOneToOne
        const om = Wappalyzer.analyzeOneToMany
        const mm = Wappalyzer.analyzeManyToMany

        const relations = {
            certIssuer: oo,
            cookies: mm,
            css: oo,
            dns: mm,
            headers: mm,
            html: oo,
            meta: mm,
            probe: mm,
            robots: oo,
            scriptSrc: om,
            scripts: oo,
            text: oo,
            url: oo,
            xhr: oo,
            xhrUrl: oo,
        }

        try {
            const detections = technologies
            .map((technology) =>
                Object.keys(relations)
                .map(
                    (type) =>
                        items[type] && relations[type](technology, type, items[type])
                )
                .flat()
            )
            .flat()
            .filter((technology) => technology)

            benchmarkSummary()

            return detections
        } catch (error) {
            throw new Error(error.message || error.toString())
        }
    },

    /**
   * Extract technologies from data collected.
   * @param {object} data
   */
    setTechnologies(data) {
        const transform = Wappalyzer.transformPatterns

        // Reset derived state so setTechnologies() is idempotent and can be
        // called more than once (e.g. by tests or a reload).
        Wappalyzer.requires = []
        Wappalyzer.categoryRequires = []
        Wappalyzer.errors = []

        Wappalyzer.technologies = Object.keys(data).reduce((technologies, name) => {
            const {
                cats,
                certIssuer,
                cookies,
                cpe,
                css,
                description,
                dns,
                dom,
                excludes,
                headers,
                html,
                icon,
                implies,
                js,
                meta,
                oss,
                pricing,
                probe,
                requires,
                requiresCategory,
                robots,
                saas,
                scriptSrc,
                scripts,
                text,
                url,
                website,
                xhr,
                xhrUrl,
            } = data[name]

            technologies.push({
                categories: cats || [],
                certIssuer: transform(certIssuer),
                cookies: transform(cookies),
                cpe: cpe || null,
                css: transform(css),
                description: description || null,
                dns: transform(dns),
                dom: transform(
                    typeof dom === 'string' || Array.isArray(dom)
                        ? toArray(dom).reduce(
                            (dom, selector) => ({ ...dom, [selector]: { exists: '' } }),
                            {}
                        )
                        : dom,
                    true,
                    false
                ),
                excludes: transform(excludes).map(({ value }) => ({ name: value })),
                headers: transform(headers),
                html: transform(html),
                icon: icon || 'default.svg',
                implies: transform(implies).map(({ value, confidence, version }) => ({
                    name: value,
                    confidence,
                    version,
                })),
                js: transform(js, true),
                meta: transform(meta),
                name,
                // Deployment-model metadata curated in technologies/*.json.
                // Kept verbatim (not a pattern) and surfaced through resolve().
                oss: typeof oss === 'boolean' ? oss : null,
                saas: typeof saas === 'boolean' ? saas : null,
                pricing: pricing || [],
                probe: transform(probe, true),
                requires: transform(requires).map(({ value }) => ({ name: value })),
                requiresCategory: transform(requiresCategory).map(({ value }) => ({
                    id: value,
                })),
                robots: transform(robots),
                scriptSrc: transform(scriptSrc),
                scripts: transform(scripts),
                slug: Wappalyzer.slugify(name),
                text: transform(text),
                url: transform(url),
                website: website || null,
                xhr: transform(xhr),
                xhrUrl: transform(xhrUrl),
            })

            return technologies
        }, [])

        Wappalyzer.technologies
            .filter(({ requires }) => requires.length)
            .forEach((technology) =>
                technology.requires.forEach(({ name }) => {
                    if (!Wappalyzer.getTechnology(name)) {
                        // A dangling reference must not make the catalog unloadable:
                        // driver.js calls setTechnologies() at require time.
                        Wappalyzer.error(
                            'dangling-requires',
                            technology.name,
                            `Required technology does not exist: ${name}`
                        )

                        return
                    }

                    Wappalyzer.requires[name] = Wappalyzer.requires[name] || []

                    Wappalyzer.requires[name].push(technology)
                })
            )

        Wappalyzer.requires = Object.keys(Wappalyzer.requires).map((name) => ({
            name,
            technologies: Wappalyzer.requires[name],
        }))

        Wappalyzer.technologies
            .filter(({ requiresCategory }) => requiresCategory.length)
            .forEach((technology) =>
                technology.requiresCategory.forEach(({ id }) => {
                    Wappalyzer.categoryRequires[id] =
                        Wappalyzer.categoryRequires[id] || []

                    Wappalyzer.categoryRequires[id].push(technology)
                })
            )

        Wappalyzer.categoryRequires = Object.keys(Wappalyzer.categoryRequires).map(
            (id) => ({
                categoryId: parseInt(id, 10),
                technologies: Wappalyzer.categoryRequires[id],
            })
        )

        Wappalyzer.technologies = Wappalyzer.technologies.filter(
            ({ requires, requiresCategory }) =>
                !requires.length && !requiresCategory.length
        )
    },

    /**
   * Assign categories for data.
   * @param {Object} data
   */
    setCategories(data) {
        Wappalyzer.categories = Object.keys(data)
            .reduce((categories, id) => {
                const category = data[id]

                categories.push({
                    id: parseInt(id, 10),
                    slug: Wappalyzer.slugify(category.name),
                    ...category,
                })

                return categories
            }, [])
            .sort(({ priority: a }, { priority: b }) => (a > b ? -1 : 0))
    },

    /**
   * Transform patterns for internal use.
   * @param {string|array} patterns
   * @param {boolean} caseSensitive
   */
    transformPatterns(patterns, caseSensitive = false, isRegex = true) {
        if (!patterns) {
            return []
        }

        if (
            typeof patterns === 'string' ||
                typeof patterns === 'number' ||
                Array.isArray(patterns)
        ) {
            patterns = { main: patterns }
        }

        const parsed = Object.keys(patterns).reduce((parsed, key) => {
            parsed[caseSensitive ? key : key.toLowerCase()] = toArray(
                patterns[key]
            ).map((pattern) => Wappalyzer.parsePattern(pattern, isRegex))

            return parsed
        }, {})

        return 'main' in parsed ? parsed.main : parsed
    },

    /**
   * Extract information from regex pattern.
   * @param {string|object} pattern
   */
    parsePattern(pattern, isRegex = true) {
        if (typeof pattern === 'object') {
            return Object.keys(pattern).reduce(
                (parsed, key) => ({
                    ...parsed,
                    [key]: Wappalyzer.parsePattern(pattern[key]),
                }),
                {}
            )
        } else {
            const { value, regex, confidence, version } = pattern
            .toString()
            .split('\\;')
            .reduce((attrs, attr, i) => {
                if (i) {
                    // Key value pairs
                    attr = attr.split(':')

                    if (attr.length > 1) {
                        attrs[attr.shift()] = attr.join(':')
                    }
                } else {
                    attrs.value = typeof pattern === 'number' ? pattern : attr

                    attrs.regex = new RegExp(
                        isRegex
                            ? attr
                            // Escape slashes
                            .replace(/\//g, '\\/')
                            // Optimise quantifiers for long strings
                            .replace(/\\\+/g, '__escapedPlus__')
                            .replace(/\+/g, '{1,250}')
                            .replace(/\\\*/g, '__escapedStar__')
                            .replace(/\[([a-z0-9_-]+)\*\s*=\s*(['"])([^'"]+?)\2\]/gi,
                                (_m, attr, quote, val) =>
                                    `\\[${attr}\\s*=\\s*${quote}[^${quote}]*${val}[^${quote}]*${quote}\\]`
                            )
                            .replace(/\*/g, '{0,250}')
                            .replace(/__escapedStar__/g, '\\*')
                            .replace(/__escapedPlus__/g, '\\+')
                            : '',
                        'i'
                    )
                }

                return attrs
            }, {})

            return {
                value,
                regex,
                confidence: parseInt(confidence || 100, 10),
                version: version || '',
            }
        }
    },

    /**
   * @todo describe
   * @param {Object} technology
   * @param {String} type
   * @param {String} value
   */
    analyzeOneToOne(technology, type, value) {
        if (!Array.isArray(technology[type])) {
            return [];
        }
        return technology[type].reduce((technologies, pattern) => {
            const startTime = Date.now()

            const matches = pattern.regex.exec(value)

            if (matches && type === 'xhr' && !isHostnameSuffix(value, matches)) {
                benchmark(Date.now() - startTime, pattern, value, technology)

                return technologies
            }

            if (matches) {
                technologies.push({
                    technology,
                    pattern: {
                        ...pattern,
                        type,
                        value,
                        match: matches[0],
                    },
                    version: Wappalyzer.resolveVersion(pattern, value),
                })
            }

            benchmark(Date.now() - startTime, pattern, value, technology)

            return technologies
        }, [])
    },

    /**
   * @todo update
   * @param {Object} technology
   * @param {String} type
   * @param {Array} items
   */
    analyzeOneToMany(technology, type, items = []) {
        return items.reduce((technologies, value) => {
            const patterns = technology[type] || []
            if (!Array.isArray(patterns)) {
                return technologies
            }
            patterns.forEach((pattern) => {
                const startTime = Date.now()

                const matches = pattern.regex.exec(value)

                if (matches) {
                    technologies.push({
                        technology,
                        pattern: {
                            ...pattern,
                            type,
                            value,
                            match: matches[0],
                        },
                        version: Wappalyzer.resolveVersion(pattern, value),
                    })
                }

                benchmark(Date.now() - startTime, pattern, value, technology)
            })

            return technologies
        }, [])
    },

    /**
   *
   * @param {Object} technology
   * @param {string} types
   * @param {Array} items
   */
    analyzeManyToMany(technology, types, items = {}) {
        if (!technology) {
            return []
        }

        const [type, ...subtypes] = types.split('.')

        const channel = technology[type]

        // Many-to-many channels must be keyed objects (header name, cookie name,
        // DNS record type, JS chain, DOM selector). A string or array here means
        // the catalog entry uses the wrong shape, so there is nothing to key on.
        // scripts/validate.js reports these as `channel-shape` errors.
        if (!channel || typeof channel !== 'object' || Array.isArray(channel)) {
            return []
        }

        return Object.keys(channel).reduce((technologies, key) => {
            const patterns = channel[key] || []
            const values = items[key] || []
            if (!Array.isArray(patterns)) {
                return technologies
            }
            patterns.forEach((_pattern) => {
                const pattern = (subtypes || []).reduce(
                    (pattern, subtype) => pattern[subtype] || {},
                    _pattern
                )

                // Walking the subtype path can land on a branch the entry does
                // not define, leaving no regex to match against.
                if (!pattern || !pattern.regex) {
                    return
                }

                values.forEach((value) => {
                    const startTime = Date.now()

                    const matches = pattern.regex.exec(value)

                    if (matches) {
                        technologies.push({
                            technology,
                            pattern: {
                                ...pattern,
                                type,
                                value,
                                match: matches[0],
                            },
                            version: Wappalyzer.resolveVersion(pattern, value),
                        })
                    }

                    benchmark(Date.now() - startTime, pattern, value, technology)
                })
            })

            return technologies
        }, [])
    },

    /**
   * Match JS property values collected from a page against the `js` channel.
   * Kept here rather than in driver.js so it is testable without a browser.
   * @param {Array} js Results of the in-page collector, as {name, chain, value}
   * @param {Array} technologies
   */
    analyzeJs(js = [], technologies = Wappalyzer.technologies) {
        return js
            .map(({ name, chain, value }) =>
                Wappalyzer.analyzeManyToMany(
                    technologies.find(({ name: _name }) => name === _name),
                    'js',
                    { [chain]: [value] }
                )
            )
            .flat()
    },

    /**
   * Match DOM observations collected from a page against the `dom` channel.
   * Kept here rather than in driver.js so it is testable without a browser.
   * @param {Array} dom Results of the in-page collector
   * @param {Array} technologies
   */
    analyzeDom(dom = [], technologies = Wappalyzer.technologies) {
        return dom
            .map(({ name, selector, exists, text, property, attribute, value }) => {
                const technology = technologies.find(
                    ({ name: _name }) => name === _name
                )

                if (!technology) {
                    return []
                }

                if (typeof exists !== 'undefined') {
                    return Wappalyzer.analyzeManyToMany(technology, 'dom.exists', {
                        [selector]: [''],
                    })
                }

                if (typeof text !== 'undefined') {
                    return Wappalyzer.analyzeManyToMany(technology, 'dom.text', {
                        [selector]: [text],
                    })
                }

                if (typeof property !== 'undefined') {
                    return Wappalyzer.analyzeManyToMany(
                        technology,
                        `dom.properties.${property}`,
                        { [selector]: [value] }
                    )
                }

                if (typeof attribute !== 'undefined') {
                    return Wappalyzer.analyzeManyToMany(
                        technology,
                        `dom.attributes.${attribute}`,
                        { [selector]: [value] }
                    )
                }

                return []
            })
            .flat()
    },
}

if (typeof module !== 'undefined') {
    module.exports = Wappalyzer
}
