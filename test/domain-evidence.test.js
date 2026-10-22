'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const { EventEmitter } = require('node:events')
const https = require('node:https')
const { NAMED_DNS_QUERIES, DNS_RECORDS } = require('../scripts/lib/channels')
const { collectDomainEvidence, normalizeRecords, dmarcReports, microsoftTenant,
    parseDocument, getDocument, WELL_KNOWN_PATHS } = require('../scripts/lib/domain-evidence')
const { loadCatalog } = require('../scripts/lib/catalog')
const Wappalyzer = require('../wappalyzer')
const { Site } = require('../driver')

Wappalyzer.setCategories(require('../categories.json'))
Wappalyzer.setTechnologies(loadCatalog(require('node:path').join(__dirname, '../technologies')).technologies)
const detect = (items) => Wappalyzer.resolve(Wappalyzer.analyze(items)).map(({ name }) => name)
const dnsDetect = (key, value) => detect({ dns: { [key.toLowerCase()]: [value] } })
const document = (path, value, origin = 'https://login.example.com') =>
    parseDocument(path, typeof value === 'string' ? value : JSON.stringify(value), origin + path)
const paths = {
    entra: '/.well-known/microsoft-identity-association.json',
    apple: '/.well-known/apple-app-site-association',
    android: '/.well-known/assetlinks.json',
    oidc: '/.well-known/openid-configuration',
    okta: '/.well-known/okta-organization',
    mta: '/.well-known/mta-sts.txt',
}

test('named DNS keys are an explicit fixed whitelist', () => {
    assert.ok(DNS_RECORDS.includes('txt _dmarc'))
    assert.ok(DNS_RECORDS.includes('srv _ldap._tcp'))
    for (const key of ['srv', 'txt arbitrary', 'cname ../../tenant', 'txt _github-challenge-guessed']) {
        assert.ok(!DNS_RECORDS.includes(key))
    }
})

test('DNS normalization preserves split TXT strings and validates SRV values', () => {
    assert.deepEqual(normalizeRecords('TXT', [['v=DMARC1; p=none; ru', 'a=mailto:a@vali.email']]),
        ['v=DMARC1; p=none; rua=mailto:a@vali.email'])
    assert.deepEqual(normalizeRecords('CNAME', ['EnterpriseRegistration.Windows.NET.']), ['enterpriseregistration.windows.net'])
    assert.deepEqual(normalizeRecords('SRV', [
        { priority: 10, weight: 5, port: 5061, name: 'SipFed.Online.Lync.com.' },
        { priority: 10, weight: 5, port: 99999, name: 'example.com' },
        { priority: 10, weight: 5, port: 443, name: '.' },
    ]), ['10 5 5061 sipfed.online.lync.com'])
})

test('Microsoft records identify specific configurations without Fabric or Premium', () => {
    const rows = [
        ['cname enterpriseenrollment', 'enterpriseenrollment-s.manage.microsoft.com', 'Microsoft Intune'],
        ['cname enterpriseenrollment', 'enterpriseenrollment.manage.microsoft.com', 'Microsoft Intune'],
        ['cname enterpriseregistration', 'enterpriseregistration.windows.net', 'Microsoft Entra ID'],
        ['cname autodiscover', 'autodiscover.outlook.com', 'Microsoft Exchange Online'],
        ['cname selector1._domainkey', 'selector1-example-com._domainkey.original.onmicrosoft.com', 'Microsoft 365'],
        ['cname selector2._domainkey', 'selector2-example-com._domainkey.original.r-v1.dkim.mail.microsoft', 'Microsoft 365'],
    ]
    for (const [key, value, name] of rows) {
        const result = dnsDetect(key, value)
        assert.ok(result.includes(name), value)
        for (const falsePositive of ['Microsoft Fabric', 'Microsoft Power BI', 'Microsoft SharePoint', 'Microsoft Azure Active Directory Premium']) {
            assert.ok(!result.includes(falsePositive), `${value}: ${falsePositive}`)
        }
        for (const spoof of [`${value}.attacker.example`, `attacker.${value}`, `https://${value}/`, `x ${value}`]) {
            assert.ok(!dnsDetect(key, spoof).includes(name), spoof)
        }
    }
    assert.deepEqual(dnsDetect('cname enterpriseregistration', 'enterpriseenrollment.manage.microsoft.com'), [])
    assert.deepEqual(dnsDetect('cname autodiscover', 'mail.example.com'), [])
    assert.equal(microsoftTenant(['selector1-example-com._domainkey.original.onmicrosoft.com']), 'original.onmicrosoft.com')
    assert.equal(microsoftTenant(['selector2-example-com._domainkey.original.r-v1.dkim.mail.microsoft']), 'original.onmicrosoft.com')
    assert.equal(microsoftTenant(['selector2-example-com._domainkey.original.onmicrosoft.com.attacker.example']), null)
})

const vendors = [
    ['dmarc-reports.cloudflare.net', 'Cloudflare DMARC Management'],
    ['corp-ag-in.dmarcian.com', 'dmarcian'],
    ['vali.email', 'Valimail'],
    ['rua.agari.com', 'Agari DMARC Protection'],
    ['emaildefense.proofpoint.com', 'Proofpoint Email Fraud Defense'],
]
const fromDmarc = (values) => detect({ dns: { 'txt _dmarc': dmarcReports(values) } })
test('DMARC providers match parsed reporting addresses, including multiple recipients and limits', () => {
    const policy = `v=DMARC1; p=none; rua=${vendors.map(([host]) => `mailto:reports@${host}!10m`).join(',')}`
    assert.deepEqual(fromDmarc([policy]).sort(), vendors.map(([, name]) => name).sort())
    for (const [host, name] of vendors) {
        assert.ok(fromDmarc([`v=DMARC1; p=reject; ruf=mailto:report@${host}`]).includes(name))
        for (const bad of [
            `v=DMARC1; p=reject; rua=mailto:report@${host}.attacker.example`,
            `v=DMARC1; p=reject; rua=https://${host}/report`,
            `v=DMARC1; p=reject; rua=mailto:${host}@attacker.example`,
            `v=DMARC1; p=reject; x=${host}; rua=mailto:report@attacker.example`,
            `v=DMARC1; p=reject; rua=mailto:report@attacker.example?x=@${host}`,
            `v=DMARC1; p=invalid; rua=mailto:report@${host}`,
            `v=DMARC1; rua=mailto:report@${host}`,
            `v=DMARC1; p=none; p=reject; rua=mailto:report@${host}`,
        ]) assert.ok(!fromDmarc([bad]).includes(name), bad)
        assert.deepEqual(fromDmarc([policy, `v=DMARC1; p=none; rua=mailto:report@${host}`]), [])
    }
    assert.ok(dnsDetect('ns _dmarc', 'ns.vali.email').includes('Valimail'))
    assert.ok(dnsDetect('cname _dmarc', 'example.com._dmarca.vali.email').includes('Valimail'))
    assert.ok(!dnsDetect('ns _dmarc', 'ns.vali.email.attacker.example').includes('Valimail'))
    assert.ok(!dnsDetect('txt', policy).some((name) => vendors.some(([, v]) => v === name)), 'wrong DNS owner')
})

test('retained public DNS records exercise the new Zoom, Webex and DMARC markers', () => {
    const { results } = require('../docs/research/domain-evidence-observations.json')
    const found = new Set()
    for (const { name, values } of results) {
        for (const technology of name.startsWith('_dmarc.') ? fromDmarc(values) : detect({ dns: { txt: values } })) found.add(technology)
    }
    for (const name of ['Zoom', 'Cisco Webex', ...vendors.map(([, name]) => name)]) assert.ok(found.has(name), name)
    for (const value of ['Some text ZOOM_verify_abcdefghijklmnop', 'ZOOM_verify_short', 'example=cisco-ci-domain-verification=abc', 'webexdomainverification.=not-a-uuid']) {
        assert.ok(!dnsDetect('txt', value).includes('Cisco Webex'), value)
        assert.ok(!dnsDetect('txt', value).includes('Zoom'), value)
    }
})

test('association documents expose identifiers without attributing product use', () => {
    const entra = document(paths.entra, { associatedApplications: [{ applicationId: '12345678-90ab-cdef-1234-567890abcdef' }, { applicationId: 'invalid' }] })
    assert.equal(entra.kind, 'entra-app-association')
    assert.equal(entra.applicationIds.length, 1)
    assert.equal(document(paths.entra, { associatedApplications: [{ applicationId: 'not-a-guid' }] }), null)
    assert.deepEqual(document(paths.apple, { applinks: { details: [{ appIDs: ['ABCDE12345.com.example.app'] }] } }).appIds, ['ABCDE12345.com.example.app'])
    const android = { relation: ['delegate_permission/common.handle_all_urls'], target: { namespace: 'android_app', package_name: 'com.example.app', sha256_cert_fingerprints: [Array(32).fill('AB').join(':')] } }
    assert.deepEqual(document(paths.android, [android]).packages, ['com.example.app'])
    assert.equal(document(paths.android, [{ ...android, target: { ...android.target, sha256_cert_fingerprints: ['AB:CD'] } }]), null)
    assert.deepEqual(detect({ probe: { [paths.entra]: [JSON.stringify(entra)] } }), [])
})

test('OIDC metadata requires consistent HTTPS origins and actual discovery fields', () => {
    const value = { issuer: 'https://login.example.com/realms/acme', authorization_endpoint: 'https://login.example.com/realms/acme/protocol/openid-connect/auth', jwks_uri: 'https://login.example.com/realms/acme/protocol/openid-connect/certs', response_types_supported: ['code'] }
    assert.equal(document(paths.oidc, value).kind, 'oidc-provider')
    assert.equal(document('/adfs/.well-known/openid-configuration', value).kind, 'oidc-provider')
    for (const field of ['issuer', 'authorization_endpoint', 'jwks_uri']) {
        for (const bad of ['http://login.example.com/', 'https://login.example.com.attacker.example/', 'https://user:pass@login.example.com/', 'https://127.0.0.1/', 'not a URL']) {
            assert.equal(document(paths.oidc, { ...value, [field]: bad }), null, `${field}: ${bad}`)
        }
    }
    assert.equal(document(paths.oidc, { ...value, response_types_supported: [] }), null)
})

test('Okta needs structured organization metadata with a vendor-owned organization URL', () => {
    const value = { id: '00o123456789abcdef', _links: { organization: { href: 'https://example.okta.com' } } }
    const parsed = document(paths.okta, value)
    assert.ok(detect({ probe: { [paths.okta]: [JSON.stringify(parsed)] } }).includes('Okta'))
    for (const bad of ['https://example.okta.com.attacker.example/', 'https://example.com/?next=okta.com', 'http://example.okta.com']) {
        assert.equal(document(paths.okta, { ...value, _links: { organization: { href: bad } } }), null)
    }
    for (const path of WELL_KNOWN_PATHS) {
        assert.equal(document(path, '<html>Okta login.microsoftonline.com ABCDE12345.com.example.app</html>'), null)
        assert.equal(document(path, '{}'), null)
    }
})

test('MTA-STS and security contacts are configuration metadata, not security scores', () => {
    assert.deepEqual(document(paths.mta, 'version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400\n'), { kind: 'mta-sts-policy', mode: 'enforce', mx: ['*.example.com'], maxAge: 86400 })
    for (const policy of ['version: STSv1\nmode: enforce\nmax_age: 100', 'version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 999999999', '<html>version: STSv1</html>']) assert.equal(document(paths.mta, policy), null)
    assert.equal(document('/.well-known/security.txt', 'Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n').kind, 'security-contact')
    assert.equal(document('/.well-known/security.txt', 'Contact: javascript:alert(1)\nExpires: 2027-01-01T00:00:00Z\n'), null)
})

test('basic mode collects fixed DNS names at the exact domain, never guessed tenants or parents', async () => {
    const calls = [], detections = []
    const evidence = await collectDomainEvidence({ url: 'https://www.customer.example.com/path', mode: 'basic',
        lookup: async (name, type) => {
            calls.push([name, type])
            if (name.startsWith('selector1.')) return ['selector1-customer-example-com._domainkey.original.onmicrosoft.com.']
            if (name.startsWith('_dmarc.')) return [['v=DMARC1; p=none; rua=mailto:a@', 'vali.email']]
            throw new Error('ENODATA')
        }, request: async () => assert.fail('basic mode must not fetch well-known files'),
        onObservation: async (items) => detections.push(...detect(items)),
    })
    assert.equal(calls.length, Object.values(NAMED_DNS_QUERIES).filter((query) => !query.full).length)
    assert.ok(calls.every(([name]) => name.endsWith('.customer.example.com')))
    assert.ok(detections.includes('Microsoft 365'))
    assert.ok(detections.includes('Valimail'))
    assert.equal(evidence.find((item) => item.microsoftTenant).microsoftTenant, 'original.onmicrosoft.com')
    assert.ok(!JSON.stringify(evidence).includes('sharepoint'))
})

test('full mode bounds concurrency, ignores failed probes and fetches MTA-STS on its mandated host', async () => {
    let active = 0, peak = 0
    const calls = [], observations = []
    const wait = async () => { active++; peak = Math.max(peak, active); await new Promise((r) => setTimeout(r, 2)); active-- }
    const evidence = await collectDomainEvidence({ url: 'https://example.com/', mode: 'full',
        lookup: async (name) => { await wait(); if (name === '_mta-sts.example.com') return [['v=STSv1; id=123']]; return [] },
        request: async (url) => { calls.push(url); await wait(); return url.startsWith('https://mta-sts.') ? 'version: STSv1\nmode: testing\nmx: mx.example.com\nmax_age: 100' : '<html>fallback</html>' },
        onObservation: async (items) => observations.push(items),
    })
    assert.ok(peak <= 6)
    assert.ok(calls.includes('https://mta-sts.example.com/.well-known/mta-sts.txt'))
    assert.ok(!calls.includes('https://example.com/.well-known/mta-sts.txt'))
    assert.ok(evidence.some(({ kind }) => kind === 'mta-sts-policy'))
    assert.ok(!observations.some(({ probe }) => probe), 'HTML fallback never reaches catalog probes')
})

test('disabled probes and non-public hostnames do no work; expired budget stops scheduling', async () => {
    for (const [url, mode] of [['https://example.com', false], ['https://localhost', 'full'], ['https://127.0.0.1', 'basic'], ['https://app.internal', 'full']]) {
        assert.deepEqual(await collectDomainEvidence({ url, mode, lookup: () => assert.fail('DNS'), request: () => assert.fail('HTTP') }), [])
    }
    let calls = 0
    const slow = async () => { calls++; await new Promise((r) => setTimeout(r, 15)); return [] }
    await collectDomainEvidence({ url: 'https://example.com', mode: 'full', timeout: 5, lookup: slow, request: slow })
    assert.ok(calls <= 6, 'no new work starts after the budget')
})

test('HTTP reader rejects redirects, oversized bodies and stalled responses', async (t) => {
    let scenario = 'redirect', destroyed = false
    t.mock.method(https, 'get', (_url, _options, callback) => {
        const request = new EventEmitter()
        request.destroy = (error) => { destroyed = true; if (error) request.emit('error', error); request.emit('close') }
        process.nextTick(() => {
            if (scenario === 'stall') return
            const response = new EventEmitter()
            response.statusCode = scenario === 'redirect' ? 302 : 200
            response.destroy = () => request.destroy()
            callback(response)
            if (scenario === 'large') response.emit('data', Buffer.alloc(100001))
            if (scenario === 'ok') { response.emit('data', Buffer.from('{}')); response.emit('end'); request.emit('close') }
        })
        return request
    })
    await assert.rejects(getDocument('https://example.com/x', 30), /HTTP 302/)
    assert.ok(destroyed)
    scenario = 'large'
    await assert.rejects(getDocument('https://example.com/x', 30), /too large/)
    scenario = 'stall'
    await assert.rejects(getDocument('https://example.com/x', 10), /deadline/)
    scenario = 'ok'
    assert.equal(await getDocument('https://example.com/x', 30), '{}')
})

test('Site results preserve domain evidence separately from technology detections', async () => {
    const site = new Site('https://example.com/', {}, { options: { headers: {} }, browser: null, init: () => {} })
    site.domainEvidence.push({ kind: 'entra-app-association', applicationIds: ['12345678-90ab-cdef-1234-567890abcdef'] })
    const result = await site.collectResults()
    assert.deepEqual(result.domainEvidence, site.domainEvidence)
    assert.ok(!result.technologies.some(({ name }) => name === 'Microsoft Entra ID'))
})
