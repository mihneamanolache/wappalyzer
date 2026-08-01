import fs from 'node:fs/promises'
import path from 'node:path'

const root = '/Users/laptop/Desktop/mihnea.dev/wappalyzer'
const workbook = JSON.parse(await fs.readFile('/tmp/wappalyzer-workbook-rows.json', 'utf8'))
const coverage = JSON.parse(await fs.readFile('/tmp/wappalyzer-coverage-full.json', 'utf8'))
const surfaces = JSON.parse(await fs.readFile('/tmp/wappalyzer-vendor-surfaces.json', 'utf8'))
const surfaceByUrl = new Map(surfaces.map((surface) => [surface.url, surface]))

const catalog = {}
for (const file of (await fs.readdir(path.join(root, 'technologies'))).filter((file) => file.endsWith('.json'))) {
    Object.assign(catalog, JSON.parse(await fs.readFile(path.join(root, 'technologies', file), 'utf8')))
}

const browserChannels = new Set(['cookies', 'dom', 'headers', 'html', 'js', 'meta', 'robots', 'scriptSrc', 'scripts', 'text', 'url', 'xhrUrl'])
const merged = new Set(['Anthropic', 'Character.AI', 'Copy.ai', 'Groq', 'Jasper', 'LangSmith', 'Pinecone', 'Qdrant', 'Together AI', 'Weaviate'])

function channelsOf(name) {
    const entry = catalog[name] || {}
    return Object.keys(entry).filter((key) => !['cats', 'description', 'website', 'icon', 'pricing', 'saas', 'oss', 'cpe', 'implies', 'excludes', 'requires', 'requiresCategory'].includes(key))
}

function patternsOf(value) {
    if (value === undefined) return []
    if (Array.isArray(value)) return value
    if (typeof value === 'object' && value !== null) return Object.keys(value)
    return [value]
}

function selectorSummary(name) {
    const entry = catalog[name] || {}
    return Object.fromEntries(channelsOf(name).map((channel) => [channel, patternsOf(entry[channel]).slice(0, 12)]))
}

function classify(result) {
    const channels = result.channels || []
    const ownBrowser = channels.some((channel) => browserChannels.has(channel))
    if (merged.has(result.mapsTo)) return 'merged-and-proven-hosted-surface'
    if (!channels.length || channels.every((channel) => channel === 'implies')) return 'no-own-selector'
    if (channels.every((channel) => channel === 'dns')) return 'dns-only-enable-probe-or-accept-limit'
    if (channels.every((channel) => channel === 'xhr')) {
        if (result.status === 'platform-level') return 'parent-api-is-best-honest-signal'
        return 'backend-api-only-no-safe-browser-marker-found'
    }
    if (ownBrowser) return 'retain-existing-browser-visible-selector'
    return 'retain-existing-mixed-selector'
}

const rows = workbook.products.map((source, index) => {
    const result = coverage.products[index]
    const surface = surfaceByUrl.get(source.vendorUrl) || null
    return {
        row: index + 2,
        product: source.product,
        vendor: source.vendor,
        vendorUrl: source.vendorUrl,
        catalogEntry: result.mapsTo || null,
        status: result.status,
        channels: result.channels || [],
        selectorSummary: result.mapsTo ? selectorSummary(result.mapsTo) : {},
        action: classify(result),
        firstPartySurface: surface ? {
            status: surface.status,
            finalUrl: surface.finalUrl,
            title: surface.title || null,
            scriptHosts: [...new Set((surface.scripts || []).map((url) => { try { return new URL(url).hostname } catch { return null } }).filter(Boolean))].slice(0, 20),
            iframeHosts: [...new Set((surface.iframes || []).map((url) => { try { return new URL(url).hostname } catch { return null } }).filter(Boolean))],
            error: surface.error || null,
        } : null,
        evidence: merged.has(result.mapsTo)
            ? 'Live browser/crawler positive plus repository positive and suffix-spoof tests.'
            : (result.evidence || 'Static first-party fetch reviewed; no selector merged for this row.'),
    }
})

const summary = rows.reduce((out, row) => {
    out[row.action] = (out[row.action] || 0) + 1
    return out
}, {})

const output = { generated: '2026-08-02', source: workbook.products.length + ' workbook rows', summary, rows }
await fs.writeFile('/Users/laptop/Desktop/mihnea.dev/wappalyzer/chatgpt/selector-research/selector-matrix.json', JSON.stringify(output, null, 2))

const grouped = Object.keys(summary).sort().map((action) => {
    const items = rows.filter((row) => row.action === action)
    const lines = items.map((row) => `| ${row.product.replace(/\|/g, '\\|')} | ${row.vendor.replace(/\|/g, '\\|')} | ${row.catalogEntry || '-'} | ${row.channels.join(', ') || '-'} | ${row.vendorUrl} |`)
    return [`### ${action} (${items.length})`, '', '| Product | Vendor | Catalog entry | Channels | Vendor URL |', '| --- | --- | --- | --- | --- |', ...lines, ''].join('\n')
}).join('\n')

const markdown = `# Selector research matrix — 2026-08-02\n\nSource: /Users/laptop/Downloads/AI technology_products_for_veridion_070226.xlsx (402 products).\n\nThis matrix separates a selector that is technically matchable from one that is observable on a normal customer page. Existing API-host rules remain the best honest signal for server-side integrations; model and product-feature rows inherit their externally observable parent.\n\n## Summary\n\n${Object.entries(summary).map(([key, value]) => `- ${key}: ${value}`).join('\\n')}\n\n${grouped}`
await fs.writeFile('/Users/laptop/Desktop/mihnea.dev/wappalyzer/chatgpt/selector-research/selector-matrix.md', markdown)
console.log(JSON.stringify({ summary, rows: rows.length }))
