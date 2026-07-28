#!/usr/bin/env node

'use strict'

/**
 * Whitespace check over the branch's commit range.
 *
 * `git diff --check` on a clean worktree compares the worktree to HEAD and so
 * checks nothing at all — quoting its exit code after committing is meaningless.
 * The meaningful comparison is the base of the branch against HEAD.
 *
 * `changeset/*.diff` are excluded because they are verbatim captures of other
 * files' diffs: the whitespace inside them belongs to the captured content, not to
 * anything authored here. Everything else must be clean.
 *
 * Usage:
 *   node scripts/check-whitespace.js              # base from changeset/catalog-delta.json
 *   node scripts/check-whitespace.js --base=<rev>
 */

const fs = require('fs')
const path = require('path')
const { execFileSync, spawnSync } = require('child_process')

const ROOT = path.resolve(__dirname, '..')
const DELTA = path.join(ROOT, 'changeset/catalog-delta.json')

/** Files whose content is literal diff text, so whitespace in them is data. */
const CAPTURED_DIFFS = /^changeset\/\d+-.*\.diff$/

const args = process.argv.slice(2)
const baseArg = (args.find((arg) => arg.startsWith('--base=')) || '').split('=')[1]

function resolveBase() {
    if (baseArg) {
        return baseArg
    }

    try {
        return JSON.parse(fs.readFileSync(DELTA, 'utf8')).base
    } catch (error) {
        throw new Error(
            'No base revision available. Pass --base=<rev> or generate ' +
                'changeset/catalog-delta.json with `npm run delta`.'
        )
    }
}

function main() {
    const base = resolveBase()

    // --check exits 2 when it finds problems, so the status is expected, not fatal.
    const result = spawnSync(
        'git',
        ['diff', '--check', `${base}..HEAD`],
        { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }
    )

    if (result.error) {
        throw result.error
    }

    // Only `path:line: message` lines are warnings; the rest is offending content.
    const warnings = (result.stdout || '')
        .split('\n')
        .filter((line) => /^[^\s+-][^:]*:\d+: /.test(line))

    const captured = warnings.filter((line) =>
        CAPTURED_DIFFS.test(line.slice(0, line.indexOf(':')))
    )
    const authored = warnings.filter((line) => !captured.includes(line))

    const range = `${base}..HEAD`

    console.log(`git diff --check ${range}`)
    console.log(`  total warnings:              ${warnings.length}`)
    console.log(`  inside captured diff files:  ${captured.length} (ignored)`)
    console.log(`  in authored files:           ${authored.length}`)

    if (authored.length) {
        console.error('\nWhitespace problems in authored files:')
        for (const warning of authored) {
            console.error(`  ${warning}`)
        }
        process.exit(1)
    }

    console.log('\nNo whitespace problems in authored files.')
}

try {
    main()
} catch (error) {
    console.error(error.message || String(error))
    process.exit(1)
}
