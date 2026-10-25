'use strict'

const { isIP } = require('node:net')

// Optional per-destination dial guard.
//
// A caller that must never connect to certain addresses (sinkholes, botnet C2,
// private ranges) passes `destinationGuard: async (hostname) => verdict` to the
// Driver. It is consulted before the page load, before every browser request
// that is let through to the network (redirect hops included), and before every
// HTTP probe. The verdict is `{ blocked, reason?, address?, addresses? }`:
//
// - `blocked` refuses the dial.
// - `addresses` are the addresses the guard checked. Node probes connect only to
//   these, so a name that resolves somewhere else a moment later (round robin,
//   rebinding) cannot slip past the check. An empty array means "nothing was
//   verified" and the probe is refused. Leaving it out opts out of pinning.
//
// The browser resolves names itself, so a page request is checked but cannot be
// pinned. Without a guard nothing here changes behaviour.

const DESTINATION_BLOCKED = 'WAPPALYZER_DESTINATION_BLOCKED'

class DestinationBlockedError extends Error {
    constructor(hostname, verdict = {}) {
        super(`Destination blocked (${hostname}): ${verdict.reason || 'refused by destinationGuard'}`)
        this.name = 'DestinationBlockedError'
        this.code = DESTINATION_BLOCKED
        this.hostname = hostname
        this.reason = verdict.reason || null
        this.address = verdict.address || null
    }
}

// URL hostnames keep IPv6 literals in brackets; resolvers and guards do not.
function bareHostname(hostname) {
    return String(hostname || '').replace(/^\[(.*)\]$/, '$1').toLowerCase()
}

// Asks the guard about one hostname. A guard that throws refuses the dial: it
// exists to prevent a connection, so its failure must not quietly permit one.
async function checkDestination(guard, hostname) {
    if (typeof guard !== 'function') {
        return { blocked: false }
    }

    try {
        const verdict = await guard(bareHostname(hostname))

        if (verdict && typeof verdict === 'object') {
            return { ...verdict, blocked: Boolean(verdict.blocked) }
        }

        return { blocked: Boolean(verdict) }
    } catch (error) {
        return { blocked: true, reason: `guard error: ${error.message || error}` }
    }
}

function familyOf(options) {
    const family = typeof options === 'object' && options !== null ? options.family : options

    if (family === 'IPv4') return 4
    if (family === 'IPv6') return 6

    return Number(family) || 0
}

// A net/http `lookup` that only ever hands out addresses the guard checked.
// Node's own lookup would resolve the name again and could land on an address
// nobody vetted. No usable address fails like NXDOMAIN instead of falling back.
function pinnedLookup(addresses) {
    const entries = (addresses || [])
        .filter((address) => isIP(address))
        .map((address) => ({ address, family: isIP(address) }))

    return (hostname, options, callback) => {
        if (typeof options === 'function') {
            callback = options
            options = {}
        }

        const family = familyOf(options)
        const usable = entries.filter((entry) => !family || entry.family === family)

        if (!usable.length) {
            const error = new Error(`No vetted address for ${hostname}`)

            error.code = 'ENOTFOUND'
            error.hostname = hostname

            process.nextTick(callback, error)

            return
        }

        if (options && options.all) {
            process.nextTick(callback, null, usable)
        } else {
            process.nextTick(callback, null, usable[0].address, usable[0].family)
        }
    }
}

// What a Node-side dial to `url` may use: `{}` without a guard, `{ lookup }`
// pinned to the vetted addresses with one, or a DestinationBlockedError.
async function vetDial(guard, url, verdict) {
    if (typeof guard !== 'function') {
        return {}
    }

    const target = url instanceof URL ? url : new URL(url)
    const decision = verdict || (await checkDestination(guard, target.hostname))

    if (decision.blocked) {
        throw new DestinationBlockedError(bareHostname(target.hostname), decision)
    }

    return Array.isArray(decision.addresses)
        ? { lookup: pinnedLookup(decision.addresses) }
        : {}
}

module.exports = {
    DESTINATION_BLOCKED,
    DestinationBlockedError,
    bareHostname,
    checkDestination,
    pinnedLookup,
    vetDial,
}
