'use strict'

/**
 * Regression coverage for first-party hosted app URL selectors researched on
 * 2026-08-02. These are deliberately limited to product app/login hosts; a
 * vendor marketing page is not evidence that an arbitrary customer uses the
 * backend service.
 */

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('path')

const Wappalyzer = require('../wappalyzer')
const { loadCatalog } = require('../scripts/lib/catalog')

const ROOT = path.resolve(__dirname, '..')
const catalog = loadCatalog(path.join(ROOT, 'technologies')).technologies
const names = [
    'Anthropic',
    'Character.AI',
    'Copy.ai',
    'Groq',
    'Jasper',
    'LangSmith',
    'Pinecone',
    'Qdrant',
    'Together AI',
    'Weaviate',
]

const hostedCatalog = Object.fromEntries(names.map((name) => [name, catalog[name]]))

test('first-party hosted app URLs detect the intended technology', () => {
    Wappalyzer.setTechnologies(hostedCatalog)

    const cases = [
        ['Anthropic', 'https://claude.ai/new'],
        ['Character.AI', 'https://character.ai/character/123'],
        ['Copy.ai', 'https://app.copy.ai/login'],
        ['Groq', 'https://chat.groq.com/'],
        ['Jasper', 'https://app.jasper.ai/auth/signup'],
        ['LangSmith', 'https://smith.langchain.com/'],
        ['Pinecone', 'https://login.pinecone.io/login'],
        ['Pinecone', 'https://app.pinecone.io/'],
        ['Qdrant', 'https://login.cloud.qdrant.io/u/login'],
        ['Qdrant', 'https://cloud.qdrant.io/'],
        ['Together AI', 'https://api.together.ai/playground'],
        ['Weaviate', 'https://console.weaviate.cloud/signin'],
    ]

    for (const [expected, url] of cases) {
        assert.deepEqual(
            Wappalyzer.analyze({ url }).map(({ technology }) => technology.name),
            [expected],
            `${url} should detect ${expected}`
        )
    }
})

test('hosted app URL selectors reject lookalike and unrelated hosts', () => {
    Wappalyzer.setTechnologies(hostedCatalog)

    const controls = [
        'https://example.com/',
        'https://evilcharacter.ai/',
        'https://character.ai.evil.example/',
        'https://app.copy.ai.evil.example/',
        'https://chat.groq.com.evil.example/',
        'https://app.jasper.ai.evil.example/',
        'https://smith.langchain.com.evil.example/',
        'https://app.pinecone.io.evil.example/',
        'https://cloud.qdrant.io.evil.example/',
        'https://console.weaviate.cloud.evil.example/',
        'https://claude.ai.evil.example/',
        'https://api.together.ai.evil.example/playground',
    ]

    for (const url of controls) {
        assert.deepEqual(
            Wappalyzer.analyze({ url }),
            [],
            `${url} must not match a hosted app selector`
        )
    }
})

test('Together AI recognizes the current and legacy API hostnames', () => {
    Wappalyzer.setTechnologies(hostedCatalog)

    for (const hostname of ['api.together.ai', 'api.together.xyz']) {
        assert.deepEqual(
            Wappalyzer.analyze({ xhr: hostname }).map(({ technology }) => technology.name),
            ['Together AI'],
            `${hostname} should detect Together AI`
        )
    }
})
