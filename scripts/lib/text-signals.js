'use strict'

/**
 * Text-mined technology signals — a second, lower-confidence source.
 *
 * Some technologies emit nothing a crawler can see: an EDR agent, a Postgres
 * extension, a terminal editor. But companies *write about* the tools they run,
 * most reliably on their own careers pages. "5+ years experience administering
 * CrowdStrike Falcon" is strong evidence the company runs CrowdStrike, even
 * though no packet on their website will ever say so.
 *
 * This is deliberately a separate layer from the pattern catalog:
 *
 *   - The catalog answers "this page is running X" and is held to zero false
 *     positives.
 *   - This module answers "this company appears to use X" and is explicitly an
 *     inference, carrying a low confidence and the sentence it came from.
 *
 * They must not be merged. A hiring signal is not a detection, and reporting it
 * as one would poison the catalog's precision. driver.js keeps them in a
 * separate `signals` array.
 *
 * Two gates have to pass before anything is emitted:
 *
 *   1. The page has to read like a job posting or a stated tech stack. A vendor
 *      name in a press release or a customer story means nothing.
 *   2. The vendor name has to sit inside tooling language ("experience with",
 *      "administering", "our stack"), not merely appear on the page.
 *
 * Both gates are necessary. Either one alone produces the false positives this
 * whole exercise has been avoiding.
 */

/** The page is a job posting, or explicitly describes a tech stack. */
const PAGE_GATES = {
    url: /\/(?:careers?|jobs?|vacanc(?:y|ies)|join-?us|opportunities|positions?|hiring|openings?)(?:\/|$|\?)/i,
    text: new RegExp(
        [
            'job\\s+description',
            'apply\\s+now',
            'we(?:\\047|\')?re\\s+hiring',
            'equal\\s+opportunity\\s+employer',
            'what\\s+you(?:\\047|\')?ll\\s+(?:do|bring)',
            'responsibilities\\s*[:\\n]',
            'qualifications\\s*[:\\n]',
            'requirements\\s*[:\\n]',
            'minimum\\s+qualifications',
            'our\\s+(?:tech(?:nology)?\\s+)?stack',
            'technologies\\s+we\\s+use',
            'tools\\s+we\\s+use',
        ].join('|'),
        'i'
    ),
}

/**
 * Language that puts a vendor name in a tooling context.
 * `%s` is replaced by the vendor pattern.
 */
const CONTEXTS = [
    // "experience with X", "proficiency in X", "familiarity with X"
    '(?:experience|proficiency|familiarity|fluency|expertise|competency|hands[- ]on)\\s+(?:with|in|using|of)\\s+(?:[^.;\\n]{0,80}?\\b)?%s',
    // "knowledge of X", "working knowledge of X"
    '(?:working\\s+)?knowledge\\s+of\\s+(?:[^.;\\n]{0,80}?\\b)?%s',
    // "administering X", "managing X", "deploying X", "operating X"
    '(?:administer(?:ing)?|manag(?:e|ing)|deploy(?:ing)?|operat(?:e|ing)|maintain(?:ing)?|configur(?:e|ing)|tun(?:e|ing)|monitor(?:ing)?)\\s+(?:[^.;\\n]{0,60}?\\b)?%s',
    // "X administrator", "X engineer", "X certified"
    '%s\\s+(?:administrator|admin|engineer|architect|analyst|specialist|developer|certified|certification|expert)\\b',
    // "certified in X"
    'certifi(?:ed|cation)\\s+(?:in|for)\\s+%s',
    // "we use X", "our stack includes X", "powered by X"
    '(?:we\\s+(?:use|run|leverage)|our\\s+stack\\s+includes?|stack\\s*:|built\\s+(?:on|with)|powered\\s+by|standardi[sz]ed\\s+on)\\s+(?:[^.;\\n]{0,80}?\\b)?%s',
    // bullet lists: "- X" alongside other tooling is too weak on its own, but
    // "X (EDR)"-style parentheticals name the category explicitly
    '%s\\s*\\((?:EDR|XDR|SIEM|CASB|SASE|CSPM|RPA|MDM|IdP|CNAPP)\\)',
]

/**
 * Vendor patterns for technologies that cannot be detected any other way.
 * Keyed by the catalog technology name so a signal joins the taxonomy cleanly.
 *
 * Patterns are word-anchored and specific: `Zed` would match far too much text,
 * so it requires a qualifier.
 */
const VENDORS = {
    'CrowdStrike Falcon': 'CrowdStrike(?:\\s+Falcon)?',
    SentinelOne: 'SentinelOne(?:\\s+Singularity)?',
    Zscaler: 'Zscaler(?:\\s+(?:Internet\\s+Access|Private\\s+Access|ZIA|ZPA))?',
    Netskope: 'Netskope',
    'Orca Security': 'Orca\\s+Security',
    Lacework: 'Lacework',
    'Abnormal Security': 'Abnormal\\s+Security',
    pgvector: 'pgvector',
    'NVIDIA Jetson': '(?:NVIDIA\\s+)?Jetson(?:\\s+(?:Orin|Nano|Xavier|AGX))?',
    'Model Context Protocol': '(?:Model\\s+Context\\s+Protocol|\\bMCP\\b)',
    Neovim: '(?:Neovim|\\bnvim\\b)',
    // "Zed" alone is a common word fragment; require the editor context.
    Zed: 'Zed\\s+(?:editor|IDE)|\\bZed\\b(?=[^.;\\n]{0,40}editor)',
    Phind: 'Phind',
}

/**
 * Vendors whose names are also ordinary words or other companies. A match here
 * is discarded even if a context pattern fired.
 */
const AMBIGUITY_GUARDS = {
    // Orca is a whale, a Kubernetes tool, and a screen reader.
    'Orca Security': /orca\s+(?:whale|screen\s+reader)/i,
    // MCP is also "Microsoft Certified Professional" and "master control program".
    'Model Context Protocol': /microsoft\s+certified|master\s+control/i,
}

const escapeVendor = (pattern) => pattern

/** Compile the context patterns for one vendor. */
function compile(vendorPattern) {
    return CONTEXTS.map(
        (context) =>
            new RegExp(context.replace(/%s/g, `(?:${escapeVendor(vendorPattern)})`), 'i')
    )
}

const COMPILED = Object.entries(VENDORS).map(([name, pattern]) => ({
    name,
    patterns: compile(pattern),
    guard: AMBIGUITY_GUARDS[name] || null,
}))

/**
 * Does this page qualify as a hiring or stated-stack page?
 * @param {{text?: string, url?: string}} page
 */
function isEligiblePage({ text = '', url = '' }) {
    return PAGE_GATES.url.test(url) || PAGE_GATES.text.test(text)
}

/** Trim a matched region down to a readable sentence for the evidence field. */
function snippet(text, index, length) {
    const start = Math.max(0, index - 40)
    const end = Math.min(text.length, index + length + 40)

    return text
        .slice(start, end)
        .replace(/\s+/g, ' ')
        .trim()
}

/**
 * Extract technology signals from page text.
 *
 * @param {{text?: string, url?: string}} page
 * @param {{confidence?: number}} options
 * @returns {Array<{technology: string, confidence: number, source: string, evidence: string}>}
 *   Empty when the page does not qualify.
 */
function analyzeText(page, options = {}) {
    const { text = '', url = '' } = page

    if (!text || !isEligiblePage({ text, url })) {
        return []
    }

    // Confidence stays low on purpose: this is what a company says about itself,
    // not something observed running.
    const confidence = options.confidence === undefined ? 30 : options.confidence

    const signals = []

    for (const { name, patterns, guard } of COMPILED) {
        if (guard && guard.test(text)) {
            continue
        }

        for (const pattern of patterns) {
            const match = pattern.exec(text)

            if (!match) {
                continue
            }

            signals.push({
                technology: name,
                confidence,
                source: 'hiring-signal',
                evidence: snippet(text, match.index, match[0].length),
            })

            break
        }
    }

    return signals
}

module.exports = {
    AMBIGUITY_GUARDS,
    CONTEXTS,
    PAGE_GATES,
    VENDORS,
    analyzeText,
    isEligiblePage,
}
