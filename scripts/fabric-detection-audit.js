#!/usr/bin/env node
'use strict'

// Research harness: observes the CURRENT catalog without changing fingerprints.
// DOM cases use the real collector in Chromium; retain baseline results separately.
// Run: node scripts/fabric-detection-audit.js > docs/research/fabric-marker-audit-after.json
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const puppeteer = require('puppeteer')
const Wappalyzer = require('../wappalyzer')
const { getDom } = require('../driver')
const assert = require('node:assert/strict')

async function main() {
    const catalogPath = path.join(__dirname, '../technologies/m.json')
    const catalog = JSON.parse(fs.readFileSync(catalogPath, 'utf8'))
    const name = 'Microsoft Fabric'
    Wappalyzer.setCategories(JSON.parse(fs.readFileSync(path.join(__dirname, '../categories.json'), 'utf8')))
    Wappalyzer.setTechnologies({ [name]: catalog[name], 'Microsoft Power BI': catalog['Microsoft Power BI'] })
    const detect = (items) => Wappalyzer.resolve(Wappalyzer.analyze(items))
        .map(({ name, confidence }) => ({ name, confidence }))
    const cases = []
    for (const hostname of [
        'api.fabric.microsoft.com',
        'onelake.dfs.fabric.microsoft.com',
        'onelake.blob.fabric.microsoft.com',
        'westus-onelake.dfs.fabric.microsoft.com',
        'api.onelake.fabric.microsoft.com',
        'westus-api.onelake.fabric.microsoft.com',
        '1234567890abcdef1234567890abcdef.z12.dfs.fabric.microsoft.com',
        '1234567890abcdef1234567890abcdef.z12.graphql.fabric.microsoft.com',
        'cluster.z1.kusto.fabric.microsoft.com',
        'sql.cosmos.fabric.microsoft.com',
        'example-app.rayfin.windows.net',
        'app.fabric.microsoft.com',
        'api.powerbi.com',
        'api.fabric.microsoft.com.attacker.example',
        'notapi.fabric.microsoft.com',
    ]) {
        cases.push({ channel: 'xhr', input: hostname, detected: detect({ xhr: hostname }) })
    }
    for (const xhrUrl of [
        'https://api.fabric.microsoft.com/v1/workspaces/12345678-90ab-cdef-1234-567890abcdef/lakehouses',
        'https://api.fabric.microsoft.com/v1/workspaces/12345678-90ab-cdef-1234-567890abcdef/reports',
        'https://api.fabric.microsoft.com.attacker.example/v1/workspaces/12345678-90ab-cdef-1234-567890abcdef/lakehouses',
        'https://example.com/rayfin.config.json',
    ]) {
        cases.push({ channel: 'xhrUrl', input: xhrUrl, detected: detect({ xhrUrl }) })
    }
    for (const value of [
        "connect-src https://api.fabric.microsoft.com",
        "connect-src https://api.fabric.microsoft.com.attacker.example",
        "connect-src https://notapi.fabric.microsoft.com",
        "report-uri https://example.com/log/api.fabric.microsoft.com",
        "connect-src https://westus-onelake.dfs.fabric.microsoft.com",
    ]) {
        cases.push({ channel: 'headers', input: value, detected: detect({ headers: { 'content-security-policy': [value] } }) })
    }
    const browser = await puppeteer.launch({ headless: true })
    try {
        const page = await browser.newPage()
        await page.setRequestInterception(true)
        page.on('request', (request) => request.abort())
        for (const [src, expected] of [
            ['https://app.fabric.microsoft.com/itemEmbed', 'Microsoft Fabric'],
            ['https://app.fabric.microsoft.com/itemEmbed?x=1', 'Microsoft Fabric'],
            ['//app.fabric.microsoft.com/itemEmbed', 'Microsoft Fabric'],
            ['https://app.powerbi.com/itemEmbed', 'Microsoft Fabric'],
            ['https://app.powerbi.com/itemEmbed?x=1', 'Microsoft Fabric'],
            ['https://app.fabric.microsoft.com/view?r=example', 'Microsoft Power BI'],
            ['https://app.fabric.microsoft.com/reportEmbed?reportId=example', 'Microsoft Power BI'],
            ['https://app.powerbi.com/view?r=example', 'Microsoft Power BI'],
            ['https://app.powerbi.com/reportEmbed?reportId=example', 'Microsoft Power BI'],
            ['https://example.com/redirect?next=https://app.fabric.microsoft.com/itemEmbed', null],
            ['https://app.fabric.microsoft.com/itemEmbedLookalike', null],
            ['https://app.fabric.microsoft.com/itemEmbed@attacker.example/', null],
        ]) {
            // Assign as a property rather than interpolating HTML.
            await page.evaluate((src) => {
                document.body.replaceChildren()
                // A preceding unrelated frame must not suppress later values.
                const unrelated = document.createElement('iframe')
                unrelated.src = 'https://example.com/unrelated'
                document.body.appendChild(unrelated)
                const iframe = document.createElement('iframe')
                iframe.setAttribute('src', src)
                document.body.appendChild(iframe)
            }, src)
            const observations = await getDom(page)
            const detected = Wappalyzer.resolve(Wappalyzer.analyzeDom(observations))
                .map(({ name, confidence }) => ({ name, confidence }))
            assert.deepEqual(detected.map(({ name }) => name), expected ? [expected] : [], src)
            cases.push({ channel: 'dom', input: src, observations, detected })
        }
    } finally {
        await browser.close()
    }
    for (const source of [
        'import { EmbedManager } from "@microsoft/fabric-embed";',
        'const endpoint = "https://api.fabric.microsoft.com/v1/workspaces/abc/graphqlapis/def/graphql";',
        'const backend = "https://example-app.rayfin.windows.net";',
    ]) {
        cases.push({ channel: 'scripts', input: source, detected: detect({ scripts: source }) })
    }
    console.log(JSON.stringify({
        collectedAt: new Date().toISOString(),
        catalogSha256: crypto.createHash('sha256').update(fs.readFileSync(catalogPath)).digest('hex'),
        driverSha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(__dirname, '../driver.js'))).digest('hex'),
        method: 'Synthetic inputs through the real detection engine; DOM selectors evaluated in Chromium. Not live customer detections or coverage measurements.',
        cases,
    }, null, 2))
}

main().catch((error) => { console.error(error); process.exitCode = 1 })
