'use strict'

/**
 * Node runtime guard.
 *
 * `package.json` declares `engines.node`, but nothing enforces it at runtime.
 * On an unsupported Node the first symptom is `ERR_REQUIRE_ESM` thrown from deep
 * inside Puppeteer's module graph, which says nothing about the actual cause.
 * Checking before that require turns it into an actionable message.
 *
 * The check lives in its own module so the comparison is unit-testable without
 * spawning a second Node process.
 */

/**
 * Parse a semver-ish version into comparable numbers. Any pre-release or build
 * suffix is ignored — `22.12.0-nightly` counts as `22.12.0`.
 * @param {string} version
 * @returns {number[]} [major, minor, patch]
 */
function parseVersion(version) {
    const match = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(String(version))

    if (!match) {
        return [0, 0, 0]
    }

    return [match[1], match[2], match[3]].map((part) => parseInt(part || '0', 10))
}

/**
 * Is `current` at least `minimum`?
 * @param {string} current
 * @param {string} minimum
 */
function satisfiesMinimum(current, minimum) {
    const a = parseVersion(current)
    const b = parseVersion(minimum)

    for (let index = 0; index < 3; index++) {
        if (a[index] !== b[index]) {
            return a[index] > b[index]
        }
    }

    return true
}

/**
 * The minimum version from an `engines.node` range.
 * Only the `>=x.y.z` form this project uses is understood; anything else yields
 * null so the guard stays quiet rather than guessing.
 * @param {?string} range
 * @returns {?string}
 */
function minimumFromRange(range) {
    const match = /^\s*>=\s*v?(\d+(?:\.\d+){0,2})\s*$/.exec(String(range || ''))

    return match ? match[1] : null
}

/**
 * Throw a message naming the required and running versions when Node is too old.
 * @param {string} range an `engines.node` value
 * @param {string} current defaults to the running Node version
 */
function assertSupportedNode(range, current = process.versions.node) {
    const minimum = minimumFromRange(range)

    if (!minimum || satisfiesMinimum(current, minimum)) {
        return
    }

    throw new Error(
        `Node ${minimum} or newer is required, but this process is running ` +
            `Node ${current}. Puppeteer will fail to load with ERR_REQUIRE_ESM ` +
            'on older runtimes. Use the version in .nvmrc (nvm use) and reinstall ' +
            'dependencies.'
    )
}

module.exports = {
    assertSupportedNode,
    minimumFromRange,
    parseVersion,
    satisfiesMinimum,
}
