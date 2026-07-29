'use strict'

/**
 * Local-only inputs, and whether they are present.
 *
 * Two kinds of file are deliberately not tracked:
 *
 *   - data/requested-products.json and scripts/lib/requested-mapping.js
 *     enumerate a third party's product list.
 *   - the DNS sweep and xhr audit corpora and their retained results, which are
 *     bulky generated measurements.
 *
 * A clone therefore lacks them, and everything that reads them has to degrade
 * rather than fail. This module exists so "is it present?" is answered in exactly
 * one place instead of being reimplemented per caller, and so every skip carries
 * a reason — a silently absent check is worse than a loud one.
 */

const fs = require('fs')
const path = require('path')

const ROOT = path.resolve(__dirname, '../..')

const PATHS = {
    request: path.join(ROOT, 'data/requested-products.json'),
    mapping: path.join(ROOT, 'scripts/lib/requested-mapping.js'),
    sweepCorpus: path.join(ROOT, 'data/dns-sweep-domains.txt'),
    sweepResults: path.join(ROOT, 'data/dns-sweep-results.json'),
    auditUrls: path.join(ROOT, 'data/xhr-audit-urls.txt'),
    auditResults: path.join(ROOT, 'data/xhr-audit-results.json'),
}

const present = (...keys) => keys.every((key) => fs.existsSync(PATHS[key]))

/** The per-product request inputs. */
const hasRequestData = () => present('request', 'mapping')

/** The DNS TXT sweep corpus and its retained results. */
const hasSweepData = () => present('sweepCorpus', 'sweepResults')

/** The xhr audit corpus and its retained results. */
const hasAuditData = () => present('auditUrls', 'auditResults')

const reason = (what, files) =>
    `${what} (${files}) are untracked; regenerate or restore them locally to ` +
    'run this suite'

const REQUEST_SKIP = reason(
    'the per-product request inputs',
    'data/requested-products.json, scripts/lib/requested-mapping.js'
)

const SWEEP_SKIP = reason(
    'the DNS sweep corpus and results',
    'data/dns-sweep-domains.txt, data/dns-sweep-results.json — `npm run sweep`'
)

const AUDIT_SKIP = reason(
    'the xhr audit corpus and results',
    'data/xhr-audit-urls.txt, data/xhr-audit-results.json — `npm run audit:xhr`'
)

/** `{}` when present, a node:test skip option when not. */
const skipUnless = (available, why) => (available() ? {} : { skip: why })

module.exports = {
    AUDIT_SKIP,
    PATHS,
    REQUEST_SKIP,
    SWEEP_SKIP,
    hasAuditData,
    hasRequestData,
    hasSweepData,
    skipUnless,
}
