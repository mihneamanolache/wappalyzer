'use strict'

const test = require('node:test')
const assert = require('node:assert/strict')
const Wappalyzer = require('../wappalyzer')
const { loadCatalog } = require('../scripts/lib/catalog')
const path = require('path')
const { getDom } = require('../driver')

const FABRIC = 'Microsoft Fabric'
const POWER_BI = 'Microsoft Power BI'
const { technologies } = loadCatalog(path.join(__dirname, '../technologies'))
Wappalyzer.setCategories(require('../categories.json'))
Wappalyzer.setTechnologies(technologies)

const names = (detections) => Wappalyzer.resolve(detections).map(({ name }) => name)
const detect = (items) => names(Wappalyzer.analyze(items))
// Observation shape emitted by driver.js for an iframe's src attribute.
// scripts/fabric-detection-audit.js also exercises the selector in Chromium.
const fromIframe = (src) => names(Wappalyzer.analyzeDom([{
    name: FABRIC,
    selector: 'iframe[src]',
    attribute: 'src',
    value: src,
}]))

// Documented endpoints, not measured customer deployments. Sources and the
// resulting public-crawl limits are recorded in docs/research/microsoft-fabric-detection.md.
const workspace = '1234567890abcdef1234567890abcdef.z12'
const workspaceId = '12345678-90ab-cdef-1234-567890abcdef'
const apiHosts = ['api.fabric.microsoft.com', `${workspace}.w.api.fabric.microsoft.com`]
const hosts = [
    'onelake.dfs.fabric.microsoft.com',
    'onelake.blob.fabric.microsoft.com',
    'westus-onelake.dfs.fabric.microsoft.com',
    'westeurope-onelake.blob.fabric.microsoft.com',
    'api.onelake.fabric.microsoft.com',
    'westus-api.onelake.fabric.microsoft.com',
    `${workspace}.dfs.fabric.microsoft.com`,
    `${workspace}.blob.fabric.microsoft.com`,
    `${workspace}.onelake.fabric.microsoft.com`,
    `${workspace}.graphql.fabric.microsoft.com`,
    'cluster.z1.kusto.fabric.microsoft.com',
    'ingest-cluster.z9.kusto.fabric.microsoft.com',
    'sql.cosmos.fabric.microsoft.com',
    'customer-app.rayfin.windows.net',
]

test('Fabric detects documented service requests without implying Power BI', () => {
    for (const xhr of hosts) {
        const result = detect({ xhr })
        assert.ok(result.includes(FABRIC), xhr)
        assert.ok(!result.includes(POWER_BI), xhr)
    }
})

test('Fabric request hosts reject attacker suffixes and unverified subdomains', () => {
    for (const host of hosts) {
        for (const xhr of [`${host}.attacker.example`, `attacker.${host}`]) {
            assert.ok(!detect({ xhr }).includes(FABRIC), xhr)
        }
    }
    for (const xhr of [
        'notapi.fabric.microsoft.com',
        'notonelake.dfs.fabric.microsoft.com',
        'sql.cosmos.fabric.microsoft.com.example',
        'customer-app.rayfin.windows.net.example',
        'customer.rayfin.windows.net',
        'rayfin.windows.net',
        'cluster.kusto.fabric.microsoft.com',
        'not-a-workspace.z12.dfs.fabric.microsoft.com',
    ]) {
        assert.ok(!detect({ xhr }).includes(FABRIC), xhr)
    }
})

test('Power BI and shared Azure infrastructure do not identify Fabric', () => {
    for (const xhr of [
        ...apiHosts,
        'app.fabric.microsoft.com',
        'app.powerbi.com',
        'api.powerbi.com',
        'wabi-west-europe-api.analysis.windows.net',
        'example.pbidedicated.windows.net',
        'content.powerapps.com',
        'cluster.westeurope.kusto.windows.net',
        'example.blob.core.windows.net',
        'login.microsoftonline.com',
    ]) {
        assert.ok(!detect({ xhr }).includes(FABRIC), xhr)
    }
})

test('shared Fabric API hosts require a Fabric-specific item path', () => {
    for (const host of apiHosts) {
        for (const item of ['lakehouses', 'warehouses', 'graphqlapis']) {
            for (const suffix of ['', '?continuationToken=example', '/item-id', '/item-id/graphql']) {
                const xhrUrl = `https://${host}/v1/workspaces/${workspaceId}/${item}${suffix}`
                const result = detect({ xhr: host, xhrUrl })
                assert.ok(result.includes(FABRIC), xhrUrl)
                assert.ok(!result.includes(POWER_BI), xhrUrl)
            }
        }
    }
})

test('Power BI and generic REST APIs on the Fabric hostname are not Fabric evidence', () => {
    for (const host of apiHosts) {
        for (const route of [
            '',
            '/v1/workspaces',
            `/v1/workspaces/${workspaceId}`,
            `/v1/workspaces/${workspaceId}/items`,
            `/v1/workspaces/${workspaceId}/reports/report-id`,
            `/v1/workspaces/${workspaceId}/semanticModels/model-id`,
            `/v1/workspaces/${workspaceId}/reports?next=/lakehouses`,
            `/v1/workspaces/${workspaceId}/lakehousesLookalike`,
            '/v1/workspaces/example/lakehouses',
            '/unrelated?next=/v1/workspaces/' + workspaceId + '/lakehouses',
        ]) {
            const xhrUrl = `https://${host}${route}`
            assert.ok(!detect({ xhr: host, xhrUrl }).includes(FABRIC), xhrUrl)
        }
    }
})

test('Fabric item URLs validate scheme, host and path boundaries', () => {
    const route = `/v1/workspaces/${workspaceId}/lakehouses`
    assert.ok(detect({ xhrUrl: `https://api.fabric.microsoft.com:443${route}` }).includes(FABRIC))
    for (const origin of [
        'http://api.fabric.microsoft.com',
        'https://api.fabric.microsoft.com:8443',
        'https://api.fabric.microsoft.com.attacker.example',
        'https://api.fabric.microsoft.com@attacker.example',
        'https://attacker.example/api.fabric.microsoft.com',
        'https://notapi.fabric.microsoft.com',
        'https://attacker.api.fabric.microsoft.com',
    ]) {
        assert.ok(!detect({ xhrUrl: `${origin}${route}` }).includes(FABRIC), origin)
    }
    const graphqlPath = `/v1/workspaces/${workspaceId}/graphqlapis/${workspaceId}/graphql`
    assert.ok(!detect({ xhrUrl: `https://example.com${graphqlPath}` }).includes(FABRIC))
})

test('Fabric recognizes its SDK iframe including query, fragment and protocol-relative URLs', () => {
    for (const host of ['app.fabric.microsoft.com', 'app.powerbi.com']) {
        for (const src of [
            `https://${host}/itemEmbed`,
            `https://${host}/itemEmbed?workspaceId=example`,
            `https://${host}/itemEmbed#dashboard`,
            `https://${host}:443/itemEmbed`,
            `//${host}/itemEmbed`,
        ]) {
            const result = fromIframe(src)
            assert.ok(result.includes(FABRIC), src)
            assert.ok(!result.includes(POWER_BI), src)
        }
    }
})

test('Fabric iframe matching validates the host and path instead of a substring', () => {
    for (const src of [
        'https://example.com/redirect?next=https://app.fabric.microsoft.com/itemEmbed',
        'https://example.com/app.fabric.microsoft.com/itemEmbed',
        'https://app.fabric.microsoft.com.attacker.example/itemEmbed',
        'https://app.fabric.microsoft.com@attacker.example/itemEmbed',
        'https://notapp.fabric.microsoft.com/itemEmbed',
        'https://app.fabric.microsoft.com/itemEmbedLookalike',
        'https://app.fabric.microsoft.com/itemEmbed@attacker.example/',
        'https://app.fabric.microsoft.com/itemEmbed/../view?r=example',
        'https://app.fabric.microsoft.com/?next=/itemEmbed',
        'https://app.fabric.microsoft.com:8443/itemEmbed',
        'https://app.powerbi.com.attacker.example/itemEmbed',
        'https://app.powerbi.com@attacker.example/itemEmbed',
        'https://app.powerbi.com/itemEmbedLookalike',
        '/itemEmbed',
        'javascript:void("https://app.fabric.microsoft.com/itemEmbed")',
    ]) {
        assert.ok(!fromIframe(src).includes(FABRIC), src)
    }
})

test('an unrelated iframe cannot hide a later Fabric iframe during collection', async () => {
    const sources = [
        'https://example.com/unrelated',
        'https://app.fabric.microsoft.com/itemEmbedLookalike',
        'https://app.fabric.microsoft.com/itemEmbed?workspaceId=example',
        'https://app.fabric.microsoft.com/itemEmbed?workspaceId=example',
    ]
    const nodes = sources.map((src) => ({
        hasAttribute: (name) => name === 'src',
        getAttribute: (name) => name === 'src' ? src : null,
    }))
    // Execute the real collector callback with a minimal document. No network
    // or Chromium dependency in the unit suite; the audit checks real selectors.
    const page = {
        evaluate(callback, technologies) {
            const previous = Object.getOwnPropertyDescriptor(globalThis, 'document')
            Object.defineProperty(globalThis, 'document', {
                configurable: true,
                value: { querySelectorAll: (selector) => selector === 'iframe[src]' ? nodes : [] },
            })
            try {
                return callback(technologies)
            } finally {
                if (previous) {
                    Object.defineProperty(globalThis, 'document', previous)
                } else {
                    delete globalThis.document
                }
            }
        },
    }
    const observations = await getDom(page, [Wappalyzer.getTechnology(FABRIC)])
    assert.deepEqual(observations.map(({ value }) => value), sources.slice(0, 3))
    assert.ok(names(Wappalyzer.analyzeDom(observations)).includes(FABRIC))
})

test('Power BI embed paths on either portal are not Fabric embeds', () => {
    for (const host of ['app.powerbi.com', 'app.fabric.microsoft.com']) {
        for (const route of ['view?r=example', 'reportEmbed?reportId=example']) {
            const src = `https://${host}/${route}`
            assert.ok(!fromIframe(src).includes(FABRIC), src)
        }
    }
    // A matched Power BI DOM observation must not imply the Fabric platform.
    const result = names(Wappalyzer.analyzeDom([{
        name: POWER_BI,
        selector: technologies[POWER_BI].dom[0],
        exists: '',
    }]))
    assert.ok(result.includes(POWER_BI))
    assert.ok(!result.includes(FABRIC))
})

test('CSP permissions, report destinations and spoofed hosts never confirm Fabric', () => {
    for (const value of [
        "connect-src https://api.fabric.microsoft.com",
        "connect-src https://onelake.dfs.fabric.microsoft.com",
        "frame-src https://app.fabric.microsoft.com",
        "connect-src *.fabric.microsoft.com *.analysis.windows.net",
        "connect-src https://api.fabric.microsoft.com.attacker.example",
        "connect-src https://notapi.fabric.microsoft.com",
        "report-uri https://example.com/log/api.fabric.microsoft.com",
        "report-uri https://onelake.dfs.fabric.microsoft.com/",
        "connect-src https://westus-onelake.dfs.fabric.microsoft.com",
        "connect-src https://customer-app.rayfin.windows.net",
    ]) {
        for (const key of ['content-security-policy', 'content-security-policy-report-only']) {
            assert.ok(!detect({ headers: { [key]: [value] } }).includes(FABRIC), value)
        }
    }
})

test('documentation, dormant configuration and Microsoft identity evidence are not Fabric use', () => {
    const result = detect({
        html: '<a href="https://app.fabric.microsoft.com/itemEmbed">Fabric embed example</a>',
        text: 'Microsoft Fabric, Fabric.js, Office UI Fabric and Service Fabric',
        scripts: 'const endpoint = "https://api.fabric.microsoft.com/v1/workspaces";',
        scriptSrc: ['https://cdn.example.com/@microsoft/fabric-embed/index.js'],
        dns: { txt: ['MS=ms12345678'] },
    })
    assert.ok(!result.includes(FABRIC))
})

test('Rayfin config probes, SDK strings and outbound links do not prove a deployed Fabric app', () => {
    for (const xhrUrl of [
        'https://example.com/rayfin.config.json',
        'https://example.com/rayfin.config.json?v=1',
        'http://localhost:5173/rayfin.config.json',
    ]) {
        assert.ok(!detect({ xhrUrl }).includes(FABRIC), xhrUrl)
    }
    const result = detect({
        html: '<a href="https://example.webapp.fabricapps.net">Example Fabric app</a>',
        scripts: 'const config = "/rayfin.config.json"; const sdk = "@trident/embed-core";',
        scriptSrc: ['https://cdn.example.com/@microsoft/rayfin-client/index.js'],
    })
    assert.ok(!result.includes(FABRIC))
})
