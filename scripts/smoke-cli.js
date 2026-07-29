#!/usr/bin/env node

'use strict'

/**
 * CLI smoke test.
 *
 * The unit suite exercises pure functions and never loads `driver.js`, so it
 * cannot catch a broken require chain. That is how an unsupported Node runtime
 * shipped: `npm test` passed on Node 20 while `wappalyzer <url>` died with
 * ERR_REQUIRE_ESM from inside Puppeteer.
 *
 * This spawns the real CLI so the whole chain — cli.js -> driver.js -> puppeteer
 * -> the catalog — is loaded and executed. No network access is needed.
 *
 * Usage: node scripts/smoke-cli.js
 */

const path = require('path')
const { spawnSync } = require('child_process')

const ROOT = path.resolve(__dirname, '..')
const CLI = path.join(ROOT, 'cli.js')

const checks = []

function check(name, fn) {
    try {
        fn()
        checks.push({ name, ok: true })
    } catch (error) {
        checks.push({ name, ok: false, message: error.message })
    }
}

const run = (args, options = {}) =>
    spawnSync(process.execPath, [CLI, ...args], {
        cwd: ROOT,
        encoding: 'utf8',
        timeout: 60000,
        ...options,
    })

check('cli.js loads driver.js, puppeteer and the catalog', () => {
    const result = run(['--help'])

    if (result.error) {
        throw result.error
    }

    // A failed require surfaces here, not as a usage message.
    if (/ERR_REQUIRE_ESM|Cannot find module|SyntaxError/.test(result.stderr)) {
        throw new Error(`require chain broken: ${result.stderr.trim().split('\n')[0]}`)
    }

    if (result.status !== 0) {
        throw new Error(
            `--help exited ${result.status}: ${(result.stderr || result.stdout).trim().slice(0, 200)}`
        )
    }

    if (!/wappalyzer <url> \[options\]/.test(result.stdout)) {
        throw new Error('usage text missing from --help output')
    }
})

check('the documented flags are all listed', () => {
    const { stdout } = run(['--help'])

    for (const flag of ['--probe', '--recursive', '--text-signals', '--pretty']) {
        if (!stdout.includes(flag)) {
            throw new Error(`${flag} missing from --help`)
        }
    }
})

check('a missing url exits non-zero with usage', () => {
    const result = run([])

    if (result.status === 0) {
        throw new Error('expected a non-zero exit with no url')
    }
})

check('an invalid url is rejected before launching a browser', () => {
    const result = run(['not-a-url'])

    if (result.status === 0) {
        throw new Error('expected a non-zero exit for an invalid url')
    }
})

check('the runtime guard names the required Node version', () => {
    // Simulated rather than run on an old Node: assert the guard produces an
    // actionable message instead of leaving ERR_REQUIRE_ESM as the first symptom.
    const { assertSupportedNode } = require('./lib/engine')

    let message = ''

    try {
        assertSupportedNode('>=22.12.0', '20.9.0')
    } catch (error) {
        message = error.message
    }

    if (!message.includes('22.12.0') || !message.includes('20.9.0')) {
        throw new Error('guard message should name both versions')
    }

    if (!message.includes('.nvmrc')) {
        throw new Error('guard message should point at the pinned version')
    }
})

let failed = 0

for (const { name, ok, message } of checks) {
    if (ok) {
        console.log(`ok    ${name}`)
    } else {
        failed++
        console.error(`FAIL  ${name}\n      ${message}`)
    }
}

console.log(`\n${checks.length - failed}/${checks.length} CLI smoke checks passed`)

process.exit(failed ? 1 : 0)
