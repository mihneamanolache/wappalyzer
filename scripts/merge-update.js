#!/usr/bin/env node

/**
 * Pulls technology definitions from upstream (enthec/webappanalyzer) into this
 * fork without losing local work, then normalizes and validates the result.
 *
 * The merge is additive at field level. The previous version replaced any shared
 * technology with upstream's copy, which quietly discarded locally-authored
 * fingerprints: Salesforce Service Cloud and Microsoft Application Insights, for
 * example, both carry local cookie/dom/meta/xhr patterns and far more specific
 * scriptSrc lists than upstream ships. See scripts/lib/merge.js for the policy.
 *
 * Usage:
 *   node scripts/merge-update.js              # merge, normalize, validate
 *   node scripts/merge-update.js --dry-run    # report only, touch nothing
 *   node scripts/merge-update.js --report     # upstream diff summary and stop
 *   node scripts/merge-update.js --no-backup  # skip the timestamped backup
 *   node scripts/merge-update.js --normalize  # normalize locally, no clone
 */

const fs = require('fs')
const os = require('os')
const path = require('path')
const { execFileSync } = require('child_process')

const { loadCatalog, saveCatalog, mergeCategories } = require('./lib/catalog')
const { mergeCatalog } = require('./lib/merge')
const { normalizeCatalog } = require('./lib/normalize')
const { EXTRA_CATEGORIES } = require('./lib/categories-extra')

const UPSTREAM_REPO = 'https://github.com/enthec/webappanalyzer.git'
const ROOT = path.resolve(__dirname, '..')
const TECHNOLOGIES_DIR = path.join(ROOT, 'technologies')
const CATEGORIES_FILE = path.join(ROOT, 'categories.json')
const BACKUP_DIR = path.join(ROOT, 'backup')

const args = process.argv.slice(2)
const DRY_RUN = args.includes('--dry-run')
const REPORT_ONLY = args.includes('--report')
const NO_BACKUP = args.includes('--no-backup')
const NORMALIZE_ONLY = args.includes('--normalize')
const VERBOSE = args.includes('--verbose')

const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
}

function log(message, color = 'reset') {
    console.log(`${colors[color]}${message}${colors.reset}`)
}

function section(title) {
    console.log(`\n${'='.repeat(64)}`)
    log(title, 'cyan')
    console.log('='.repeat(64))
}

function list(items, limit, color) {
    for (const item of items.slice(0, limit)) {
        log(`   - ${item}`, color)
    }

    if (items.length > limit) {
        log(`   ... and ${items.length - limit} more`, color)
    }
}

/** Clone upstream into a fresh temporary directory and return its path. */
function cloneUpstream() {
    section('Fetching upstream')

    const target = fs.mkdtempSync(path.join(os.tmpdir(), 'webappanalyzer-'))

    log(`Cloning ${UPSTREAM_REPO}`, 'blue')

    execFileSync(
        'git',
        ['clone', '--depth=1', '--quiet', UPSTREAM_REPO, target],
        { stdio: 'pipe' }
    )

    const revision = execFileSync('git', ['-C', target, 'rev-parse', '--short', 'HEAD'], {
        encoding: 'utf8',
    }).trim()

    log(`Cloned at ${revision}`, 'green')

    return target
}

/** Copy the current catalog to backup/backup-<timestamp>/. */
function createBackup() {
    section('Backing up')

    const stamp = new Date().toISOString().replace(/[:.]/g, '-')
    const target = path.join(BACKUP_DIR, `backup-${stamp}`)

    fs.mkdirSync(path.join(target, 'technologies'), { recursive: true })

    for (const file of fs.readdirSync(TECHNOLOGIES_DIR)) {
        if (file.endsWith('.json')) {
            fs.copyFileSync(
                path.join(TECHNOLOGIES_DIR, file),
                path.join(target, 'technologies', file)
            )
        }
    }

    fs.copyFileSync(CATEGORIES_FILE, path.join(target, 'categories.json'))

    log(`Backup written to ${path.relative(ROOT, target)}`, 'green')

    return target
}

function reportMerge(result, localCount, upstreamCount) {
    section('Upstream diff')

    console.log(`   local technologies:    ${localCount}`)
    console.log(`   upstream technologies: ${upstreamCount}`)
    console.log(`   local-only (kept):     ${result.localOnly.length}`)
    console.log(`   new from upstream:     ${result.added.length}`)
    console.log(`   enriched by upstream:  ${result.merged.length}`)

    if (result.added.length) {
        console.log('\nNEW FROM UPSTREAM')
        list(result.added, VERBOSE ? result.added.length : 25, 'blue')
    }

    if (result.merged.length) {
        console.log('\nENRICHED (local patterns kept, upstream patterns added)')
        list(
            result.merged.map(
                ({ name, gained }) => `${name}: +${gained.join(', +')}`
            ),
            VERBOSE ? result.merged.length : 20,
            'yellow'
        )
    }
}

function reportNormalize(changes) {
    section('Normalization')

    if (!changes.length) {
        log('Nothing to normalize', 'green')

        return
    }

    const total = changes.reduce((sum, { changes: list }) => sum + list.length, 0)

    log(`${total} change(s) across ${changes.length} technologies`, 'yellow')

    for (const { name, changes: entryChanges } of changes.slice(
        0,
        VERBOSE ? changes.length : 25
    )) {
        log(`   ${name}`, 'yellow')

        for (const change of entryChanges) {
            console.log(`      ${change}`)
        }
    }

    if (!VERBOSE && changes.length > 25) {
        log(`   ... and ${changes.length - 25} more (use --verbose)`, 'yellow')
    }
}

function runValidator() {
    section('Validating')

    try {
        execFileSync(process.execPath, [path.join(__dirname, 'validate.js')], {
            stdio: 'inherit',
        })

        log('\nCatalog is coherent with the engine', 'green')

        return true
    } catch (error) {
        log('\nValidation failed - see errors above', 'red')

        return false
    }
}

function main() {
    log('WAPPALYZER CATALOG UPDATE', 'magenta')

    if (DRY_RUN) {
        log('DRY RUN - nothing will be written', 'yellow')
    }

    const local = loadCatalog(TECHNOLOGIES_DIR)
    const localCategories = JSON.parse(fs.readFileSync(CATEGORIES_FILE, 'utf8'))

    if (local.duplicates.length) {
        section('Duplicate definitions')
        log(
            `${local.duplicates.length} technology name(s) defined in more than one ` +
                'file; the later file wins and the earlier copy is dropped',
            'yellow'
        )
        list(
            local.duplicates.map(({ name, files }) => `${name} (${files.join(', ')})`),
            VERBOSE ? local.duplicates.length : 15,
            'yellow'
        )
    }

    let technologies = local.technologies
    let categories = localCategories
    let upstreamDir = null

    if (!NORMALIZE_ONLY) {
        upstreamDir = cloneUpstream()

        const upstream = loadCatalog(path.join(upstreamDir, 'src/technologies'))
        const upstreamCategories = JSON.parse(
            fs.readFileSync(path.join(upstreamDir, 'src/categories.json'), 'utf8')
        )

        const result = mergeCatalog(local.technologies, upstream.technologies)

        reportMerge(
            result,
            Object.keys(local.technologies).length,
            Object.keys(upstream.technologies).length
        )

        technologies = result.technologies
        categories = mergeCategories(
            localCategories,
            upstreamCategories,
            EXTRA_CATEGORIES
        )

        if (REPORT_ONLY) {
            fs.rmSync(upstreamDir, { recursive: true, force: true })
            log('\nReport mode - nothing written', 'green')

            return
        }
    } else {
        categories = mergeCategories(localCategories, {}, EXTRA_CATEGORIES)
    }

    const normalized = normalizeCatalog(technologies)

    reportNormalize(normalized.changes)

    if (!DRY_RUN && !NO_BACKUP) {
        createBackup()
    }

    section('Writing catalog')

    const written = saveCatalog(TECHNOLOGIES_DIR, normalized.technologies, {
        dryRun: DRY_RUN,
    })

    const total = Object.values(written).reduce((sum, count) => sum + count, 0)

    log(
        `${DRY_RUN ? '[dry run] ' : ''}${total} technologies across ` +
            `${Object.keys(written).length} files`,
        'green'
    )

    if (!DRY_RUN) {
        fs.writeFileSync(
            CATEGORIES_FILE,
            `${JSON.stringify(categories, null, 2)}\n`
        )
    }

    log(
        `${DRY_RUN ? '[dry run] ' : ''}${Object.keys(categories).length} categories`,
        'green'
    )

    if (upstreamDir) {
        fs.rmSync(upstreamDir, { recursive: true, force: true })
    }

    if (DRY_RUN) {
        log('\nDry run complete', 'green')

        return
    }

    if (!runValidator()) {
        process.exitCode = 1
    }
}

try {
    main()
} catch (error) {
    log(`\nFailed: ${error.message}`, 'red')
    console.error(error)
    process.exit(1)
}
