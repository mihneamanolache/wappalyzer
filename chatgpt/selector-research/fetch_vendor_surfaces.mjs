import fs from 'node:fs/promises'

const inputPath = '/tmp/wappalyzer-workbook-rows.json'
const outputPath = '/tmp/wappalyzer-vendor-surfaces.json'
const rows = JSON.parse(await fs.readFile(inputPath, 'utf8')).products
const urls = [...new Set(rows.map((row) => row.vendorUrl).filter(Boolean))]

const timeoutMs = 12000
const concurrency = 8

function decode(value) {
    return String(value || '')
        .replace(/&amp;/gi, '&')
        .replace(/&quot;/gi, '"')
        .replace(/&#39;/gi, "'")
        .replace(/&lt;/gi, '<')
        .replace(/&gt;/gi, '>')
}

function unique(values) {
    return [...new Set(values.filter(Boolean))]
}

function extract(html, baseUrl) {
    const title = decode((/<title[^>]*>([\s\S]*?)<\/title>/i.exec(html) || [])[1])
        .replace(/\s+/g, ' ')
        .trim()
    const meta = [...html.matchAll(/<meta\b[^>]*>/gi)].map(([tag]) => {
        const get = (name) => decode((new RegExp(`${name}\\s*=\\s*["']([^"']*)`, 'i').exec(tag) || [])[1])
        return { name: get('name'), property: get('property'), content: get('content') }
    }).filter((item) => item.name || item.property || item.content)
    const absolute = (value) => {
        try { return new URL(decode(value), baseUrl).href } catch { return null }
    }
    const scripts = unique([...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)/gi)].map((m) => absolute(m[1])))
    const links = unique([...html.matchAll(/<link\b[^>]*\bhref\s*=\s*["']([^"']+)/gi)].map((m) => absolute(m[1])))
    const iframes = unique([...html.matchAll(/<iframe\b[^>]*\bsrc\s*=\s*["']([^"']+)/gi)].map((m) => absolute(m[1])))
    const headings = [...html.matchAll(/<h[1-3]\b[^>]*>([\s\S]*?)<\/h[1-3]>/gi)].map((m) => decode(m[1].replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim()).filter(Boolean).slice(0, 30)
    const text = decode(html.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim()
    return { title, meta: meta.slice(0, 60), scripts: scripts.slice(0, 80), links: links.slice(0, 80), iframes, headings, text: text.slice(0, 3000) }
}

async function fetchOne(url) {
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), timeoutMs)
    try {
        const response = await fetch(url, {
            signal: controller.signal,
            redirect: 'follow',
            headers: { 'user-agent': 'Mozilla/5.0 Wappalyzer selector research' },
        })
        const html = await response.text()
        return { url, finalUrl: response.url, status: response.status, ...extract(html, response.url), bytes: html.length }
    } catch (error) {
        return { url, finalUrl: null, status: null, error: String(error.message || error).slice(0, 240) }
    } finally {
        clearTimeout(timer)
    }
}

const results = []
let cursor = 0
async function worker() {
    while (cursor < urls.length) {
        const index = cursor++
        results[index] = await fetchOne(urls[index])
    }
}
await Promise.all(Array.from({ length: concurrency }, () => worker()))
await fs.writeFile(outputPath, JSON.stringify(results, null, 2))
const distribution = results.reduce((out, row) => {
    const key = row.error ? 'error' : String(row.status)
    out[key] = (out[key] || 0) + 1
    return out
}, {})
console.log(JSON.stringify({ urls: urls.length, distribution, outputPath }))
