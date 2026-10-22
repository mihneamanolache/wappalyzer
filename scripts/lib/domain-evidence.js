'use strict'

const { Resolver } = require('node:dns').promises
const https = require('node:https')
const { isIP } = require('node:net')
const { NAMED_DNS_QUERIES } = require('./channels')

// Fixed, documented names only. No guessed tenant names or user enumeration.
const WELL_KNOWN_PATHS = [
    '/.well-known/microsoft-identity-association.json',
    '/.well-known/apple-app-site-association',
    '/.well-known/assetlinks.json',
    '/.well-known/openid-configuration',
    '/adfs/.well-known/openid-configuration',
    '/.well-known/okta-organization',
    '/.well-known/security.txt',
]
const cache = new Map()
const MAX_CACHE = 2048
const MAX_BODY = 100000
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i
const hostname = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i

function publicHostname(value) {
    return typeof value === 'string' && value.length <= 253 && hostname.test(value) && !isIP(value) &&
        !/(?:^|\.)(?:localhost|local|internal|test|invalid)$/i.test(value)
}

function normalizeRecords(type, records) {
    return records.slice(0, 64).flatMap((value) => {
        if (type === 'TXT') return [Array.isArray(value) ? value.join('') : String(value)]
        if (type === 'CNAME' || type === 'NS') return [String(value).toLowerCase().replace(/\.$/, '')]
        if (type === 'SRV' && value && hostname.test(String(value.name).replace(/\.$/, '')) &&
            [value.priority, value.weight, value.port].every((n) => Number.isInteger(n) && n >= 0 && n <= 65535)) {
            return [`${value.priority} ${value.weight} ${value.port} ${value.name.toLowerCase().replace(/\.$/, '')}`]
        }
        return []
    }).filter((value) => value.length <= 4096)
}

// Keep DNS lookups cancellable and coalesce concurrent requests to one name.
// CNAME/TXT replies do not expose TTLs through Node's resolver, so use a short
// 60-second cache cap, not an invented authoritative DNS TTL. Errors aren't cached.
async function lookupDns(name, type, timeout = 1500) {
    const key = `${type} ${name}`
    const previous = cache.get(key)
    if (previous && previous.expires > Date.now()) return previous.promise
    const resolver = new Resolver({ timeout, tries: 1 })
    const promise = new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            resolver.cancel()
            reject(new Error('DNS deadline exceeded'))
        }, timeout)
        resolver.resolve(name, type).then(resolve, reject).finally(() => clearTimeout(timer))
    })
    if (cache.size >= MAX_CACHE) cache.delete(cache.keys().next().value)
    cache.set(key, { expires: Date.now() + 60000, promise })
    try {
        return await promise
    } catch (error) {
        if (cache.get(key)?.promise === promise) cache.delete(key)
        throw error
    }
}

// Strict HTTPS, a size cap, a real deadline, and no redirects or credentials.
function getDocument(url, timeout = 1500) {
    return new Promise((resolve, reject) => {
        const request = https.get(url, { headers: { Accept: 'application/json, text/plain' } }, (response) => {
            if (response.statusCode !== 200) {
                response.destroy()
                reject(new Error(`HTTP ${response.statusCode}`))
                return
            }
            const chunks = []
            let length = 0
            response.on('data', (chunk) => {
                length += chunk.length
                if (length > MAX_BODY) request.destroy(new Error('Document too large'))
                else chunks.push(chunk)
            })
            response.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
            response.on('error', reject)
        })
        const timer = setTimeout(() => request.destroy(new Error('Document deadline exceeded')), timeout)
        request.on('error', reject)
        request.on('close', () => clearTimeout(timer))
    })
}

function dmarcReports(values) {
    const policies = values.filter((value) => /^v=DMARC1\s*(?:;|$)/.test(value))
    if (policies.length !== 1) return []
    const tags = {}
    for (const part of policies[0].split(';').map((s) => s.trim()).filter(Boolean)) {
        const match = /^([a-z]+)\s*=\s*(.*)$/i.exec(part)
        if (!match || Object.hasOwn(tags, match[1].toLowerCase())) return []
        tags[match[1].toLowerCase()] = match[2]
    }
    if (tags.v !== 'DMARC1' || !['none', 'quarantine', 'reject'].includes(tags.p)) return []
    return ['rua', 'ruf'].flatMap((tag) => (tags[tag] || '').split(',').flatMap((uri) => {
        const match = /^mailto:([^\s@,;!?]+)@([a-z0-9.-]+)(!\d+[kmgt]?)?$/i.exec(uri.trim())
        if (!match || !publicHostname(match[2])) return []
        return [`v=DMARC1; p=${tags.p}; ${tag}=mailto:${match[1]}@${match[2].toLowerCase()}${match[3] || ''}`]
    }))
}

function microsoftTenant(values) {
    for (const value of values) {
        const match = /^selector[12]-[a-z0-9-]+\._domainkey\.([a-z0-9-]+)\.(?:onmicrosoft\.com|[a-z]-v1\.dkim\.mail\.microsoft)$/i.exec(value)
        if (match) return `${match[1].toLowerCase()}.onmicrosoft.com`
    }
    return null
}

function httpsUrl(value) {
    if (typeof value !== 'string') return null
    try {
        const url = new URL(value)
        return url.protocol === 'https:' && !url.username && !url.password &&
            (!url.port || url.port === '443') && publicHostname(url.hostname) ? url : null
    } catch { return null }
}

function parseDocument(path, body, source) {
    if (typeof body !== 'string' || Buffer.byteLength(body) > MAX_BODY) return null
    if (path === '/.well-known/mta-sts.txt') {
        const lines = body.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
        const fields = {}
        for (const line of lines) {
            const match = /^(version|mode|mx|max_age):\s*(\S+)$/.exec(line)
            if (!match || (match[1] !== 'mx' && fields[match[1]])) return null
            ;(fields[match[1]] ||= []).push(match[2])
        }
        if (fields.version?.[0] !== 'STSv1' || !['testing', 'enforce', 'none'].includes(fields.mode?.[0]) ||
            !/^\d+$/.test(fields.max_age?.[0]) || Number(fields.max_age[0]) > 31557600 ||
            (fields.mode[0] !== 'none' && !fields.mx?.length) ||
            (fields.mx || []).some((mx) => !publicHostname(mx.replace(/^\*\./, '')))) return null
        return { kind: 'mta-sts-policy', mode: fields.mode[0], mx: fields.mx || [], maxAge: Number(fields.max_age[0]) }
    }
    if (path === '/.well-known/security.txt') {
        const contacts = [...body.matchAll(/^Contact:\s*(\S+)\s*$/gm)].map((m) => m[1])
        const expiry = /^Expires:\s*(\S+)\s*$/m.exec(body)?.[1]
        const validContacts = contacts.filter((contact) => httpsUrl(contact) || /^mailto:[^\s@]+@[^\s@]+$/.test(contact))
        if (!validContacts.length || !expiry || !Number.isFinite(Date.parse(expiry))) return null
        return { kind: 'security-contact', contacts: validContacts.slice(0, 20), expires: expiry }
    }
    let value
    try { value = JSON.parse(body) } catch { return null }
    if (!value || typeof value !== 'object') return null
    if (path.endsWith('/microsoft-identity-association.json')) {
        const applicationIds = Array.isArray(value.associatedApplications) ?
            value.associatedApplications.map((app) => app?.applicationId).filter((id) => typeof id === 'string' && uuid.test(id)) : []
        return applicationIds.length ? { kind: 'entra-app-association', applicationIds: [...new Set(applicationIds)].slice(0, 50) } : null
    }
    if (path.endsWith('/apple-app-site-association')) {
        const details = value.applinks?.details
        const ids = Array.isArray(details) ? details.flatMap((item) => [item?.appID, ...(Array.isArray(item?.appIDs) ? item.appIDs : [])]) : []
        for (const section of ['webcredentials', 'activitycontinuation']) {
            if (Array.isArray(value[section]?.apps)) ids.push(...value[section].apps)
        }
        const appIds = [...new Set(ids.filter((id) => typeof id === 'string' && /^[A-Z0-9]{10}\.[A-Za-z0-9.-]+$/.test(id)))].slice(0, 50)
        return appIds.length ? { kind: 'apple-app-association', appIds } : null
    }
    if (path.endsWith('/assetlinks.json')) {
        const apps = Array.isArray(value) ? value.filter((item) =>
            Array.isArray(item?.relation) && item.relation.includes('delegate_permission/common.handle_all_urls') &&
            item.target?.namespace === 'android_app' && /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$/.test(item.target.package_name) &&
            Array.isArray(item.target.sha256_cert_fingerprints) &&
            item.target.sha256_cert_fingerprints.some((fp) => /^(?:[a-f0-9]{2}:){31}[a-f0-9]{2}$/i.test(fp))
        ).map((item) => item.target.package_name) : []
        return apps.length ? { kind: 'android-app-association', packages: [...new Set(apps)].slice(0, 50) } : null
    }
    if (path.endsWith('/openid-configuration')) {
        const issuer = httpsUrl(value.issuer)
        const authorization = httpsUrl(value.authorization_endpoint)
        const jwks = httpsUrl(value.jwks_uri)
        if (!issuer || !authorization || !jwks || issuer.origin !== new URL(source).origin ||
            authorization.origin !== issuer.origin || jwks.origin !== issuer.origin ||
            !Array.isArray(value.response_types_supported) || !value.response_types_supported.length ||
            !value.response_types_supported.every((type) => typeof type === 'string')) return null
        return { kind: 'oidc-provider', issuer: issuer.href, authorizationEndpoint: authorization.href, jwksUri: jwks.href }
    }
    if (path.endsWith('/okta-organization')) {
        const organization = httpsUrl(value._links?.organization?.href)
        if (typeof value.id !== 'string' || !/^00o[a-zA-Z0-9]+$/.test(value.id) || !organization ||
            !/^[a-z0-9-]+\.(?:okta|oktapreview|okta-emea)\.com$/.test(organization.hostname)) return null
        return { kind: 'okta-organization', organizationId: value.id, organizationUrl: organization.href }
    }
    return null
}

async function collectDomainEvidence({ url, mode, timeout = 4000, lookup = lookupDns,
    request = getDocument, onObservation = async () => {} }) {
    const target = new URL(url)
    const domain = target.hostname.toLowerCase().replace(/^www\./, '')
    if (!mode || !publicHostname(domain)) return []
    const evidence = []
    const deadline = Date.now() + Math.min(Math.max(timeout, 1), 4000)
    const dnsTasks = Object.entries(NAMED_DNS_QUERIES).filter(([, query]) => !query.full || mode === 'full')
        .map(([key, query]) => async (remaining) => {
            const name = `${query.prefix}.${domain}`
            const values = normalizeRecords(query.type, await lookup(name, query.type, remaining))
            if (!values.length) return
            const observation = { kind: 'dns-configuration', name, recordType: query.type, values, observedAt: new Date().toISOString() }
            const tenant = microsoftTenant(values)
            if (tenant && query.prefix.endsWith('._domainkey')) observation.microsoftTenant = tenant
            evidence.push(observation)
            const detectedValues = key === 'txt _dmarc' ? dmarcReports(values) : values
            await onObservation({ dns: { [key]: detectedValues } }, observation)
            if (key === 'txt _mta-sts' && values.length === 1 && /^v=STSv1;\s*id=[a-z0-9]+;?$/i.test(values[0]) && Date.now() < deadline) {
                const path = '/.well-known/mta-sts.txt'
                const source = `https://mta-sts.${domain}${path}`
                const policy = parseDocument(path, await request(source, Math.max(1, Math.min(1500, deadline - Date.now()))), source)
                if (policy) {
                    policy.url = source
                    policy.observedAt = new Date().toISOString()
                    evidence.push(policy)
                    await onObservation({}, policy)
                }
            }
        })
    const httpTasks = []
    if (mode === 'full') {
        for (const path of WELL_KNOWN_PATHS) {
            httpTasks.push(async (remaining) => {
                const source = new URL(path, `https://${target.hostname}`).href
                const observation = parseDocument(path, await request(source, remaining), source)
                if (!observation) return
                observation.url = source
                observation.observedAt = new Date().toISOString()
                evidence.push(observation)
                // Only parsed, canonical JSON reaches these catalog probes.
                await onObservation({ probe: { [path]: [JSON.stringify(observation)] } }, observation)
            })
        }
    }
    // Alternate full HTTP and DNS work so slow DNS cannot starve every HTTP probe.
    const tasks = []
    for (let i = 0; i < Math.max(dnsTasks.length, httpTasks.length); i++) {
        if (dnsTasks[i]) tasks.push(dnsTasks[i])
        if (httpTasks[i]) tasks.push(httpTasks[i])
    }
    let index = 0
    await Promise.all(Array.from({ length: Math.min(6, tasks.length) }, async () => {
        while (index < tasks.length && Date.now() < deadline) {
            const task = tasks[index++]
            try { await task(Math.max(1, Math.min(1500, deadline - Date.now()))) } catch { /* Missing optional configuration is normal. */ }
        }
    }))
    return evidence
}

module.exports = { WELL_KNOWN_PATHS, collectDomainEvidence, dmarcReports, microsoftTenant,
    normalizeRecords, parseDocument, publicHostname, getDocument }
