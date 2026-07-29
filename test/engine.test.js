'use strict'

/**
 * Tests for the Node runtime guard.
 *
 * The guard exists because `npm test` passed on Node 20 while the CLI died with
 * ERR_REQUIRE_ESM from inside Puppeteer — `engines.node` was declared but never
 * enforced. These tests pin the comparison and the message.
 */

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const path = require('path')

const {
    assertSupportedNode,
    minimumFromRange,
    parseVersion,
    satisfiesMinimum,
} = require('../scripts/lib/engine')

const ROOT = path.resolve(__dirname, '..')
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'))

test('parseVersion handles the forms Node reports', () => {
    assert.deepEqual(parseVersion('22.12.0'), [22, 12, 0])
    assert.deepEqual(parseVersion('v24.18.0'), [24, 18, 0])
    assert.deepEqual(parseVersion('22.12.0-nightly'), [22, 12, 0])
    assert.deepEqual(parseVersion('22'), [22, 0, 0])
    assert.deepEqual(parseVersion('nonsense'), [0, 0, 0])
})

test('satisfiesMinimum compares each component numerically', () => {
    assert.equal(satisfiesMinimum('22.12.0', '22.12.0'), true, 'equal passes')
    assert.equal(satisfiesMinimum('24.18.0', '22.12.0'), true)
    assert.equal(satisfiesMinimum('22.13.0', '22.12.0'), true)
    assert.equal(satisfiesMinimum('22.12.1', '22.12.0'), true)

    assert.equal(satisfiesMinimum('20.9.0', '22.12.0'), false, 'the reported failure')
    assert.equal(satisfiesMinimum('22.11.0', '22.12.0'), false)
    assert.equal(satisfiesMinimum('22.12.0', '22.12.1'), false)
})

test('satisfiesMinimum is not a string comparison', () => {
    // "9" > "22" lexically, which is the classic way this check goes wrong.
    assert.equal(satisfiesMinimum('9.0.0', '22.12.0'), false)
    assert.equal(satisfiesMinimum('100.0.0', '22.12.0'), true)
})

test('minimumFromRange reads the range this project declares', () => {
    assert.equal(minimumFromRange('>=22.12.0'), '22.12.0')
    assert.equal(minimumFromRange('>= 22.12.0'), '22.12.0')
    assert.equal(minimumFromRange('>=v22.12.0'), '22.12.0')
})

test('minimumFromRange stays quiet on ranges it cannot read', () => {
    // Guessing at a complex range risks blocking a runtime that would work.
    for (const range of ['^22.12.0', '22.x', '>=20 <23', '', null, undefined]) {
        assert.equal(minimumFromRange(range), null, `should not parse ${range}`)
    }
})

test('assertSupportedNode passes on a supported runtime', () => {
    assert.doesNotThrow(() => assertSupportedNode('>=22.12.0', '22.12.0'))
    assert.doesNotThrow(() => assertSupportedNode('>=22.12.0', '24.18.0'))
})

test('assertSupportedNode names both versions and the fix', () => {
    assert.throws(
        () => assertSupportedNode('>=22.12.0', '20.9.0'),
        (error) => {
            assert.match(error.message, /22\.12\.0/, 'required version')
            assert.match(error.message, /20\.9\.0/, 'running version')
            assert.match(error.message, /ERR_REQUIRE_ESM/, 'the symptom it prevents')
            assert.match(error.message, /\.nvmrc/, 'where the pin lives')

            return true
        }
    )
})

test('assertSupportedNode does nothing when the range is unparseable', () => {
    assert.doesNotThrow(() => assertSupportedNode('^22.12.0', '18.0.0'))
})

test('the running Node satisfies the declared engines range', () => {
    // If this fails, the test suite itself is running on an unsupported runtime.
    assert.doesNotThrow(() => assertSupportedNode(pkg.engines.node))
})

/* --------------------------------------------------------- the pin is present */

test('the runtime is pinned in a file tooling will read', () => {
    const pins = ['.nvmrc', '.node-version'].map((name) => ({
        name,
        value: fs.existsSync(path.join(ROOT, name))
            ? fs.readFileSync(path.join(ROOT, name), 'utf8').trim()
            : null,
    }))

    for (const { name, value } of pins) {
        assert.ok(value, `${name} should exist so 'nvm use' resolves a version`)
    }

    // Every pin must itself satisfy the declared minimum, or following the pin
    // still lands you on a broken runtime.
    for (const { name, value } of pins) {
        assert.ok(
            assertSupportedNode(pkg.engines.node, value) === undefined,
            `${name} (${value}) must satisfy engines.node (${pkg.engines.node})`
        )
    }

    assert.equal(
        new Set(pins.map(({ value }) => value)).size,
        1,
        'the pin files must agree with each other'
    )
})

test('npm is configured to enforce engines on install', () => {
    const npmrc = path.join(ROOT, '.npmrc')

    assert.ok(fs.existsSync(npmrc), '.npmrc should exist')
    assert.match(
        fs.readFileSync(npmrc, 'utf8'),
        /^\s*engine-strict\s*=\s*true\s*$/m,
        'engine-strict makes npm refuse an unsupported runtime instead of warning'
    )
})

test('the shipped file list includes the runtime guard', () => {
    // driver.js requires it, so omitting it breaks the published package.
    assert.ok(
        pkg.files.includes('scripts/lib/engine.js'),
        'scripts/lib/engine.js must be published'
    )
})

test('npm test runs the CLI smoke test as well as the unit suite', () => {
    // The whole point: a unit-only `npm test` is what let the broken runtime ship.
    assert.match(pkg.scripts.test, /smoke-cli/, 'npm test must include the CLI check')
})
