'use strict'

/**
 * Coverage for the customer-visible markers added on 2026-08-03.
 *
 * The 2026-08-02 DQ found that 128 of the 154 AI entries never fired across
 * 1.87M crawled domains, because most of them matched a back-end API hostname
 * that a visitor's browser never contacts. Each selector below is the opposite:
 * something a *customer's own page* carries. The point of these tests is to pin
 * that property — every positive case is markup or a request that appears on
 * the site of a company using the product, not on the vendor's site.
 *
 * Every selector also gets a negative case. An embed host that also matches a
 * page merely writing about the vendor would reintroduce, in the other
 * direction, exactly the precision problem this catalog exists to avoid.
 */

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const path = require('path')

const Wappalyzer = require('../wappalyzer')
const { loadCatalog } = require('../scripts/lib/catalog')
const {
    CUSTOMER_VISIBLE,
    EVIDENCE,
} = require('../scripts/lib/emerging-technologies')

const ROOT = path.resolve(__dirname, '..')

Wappalyzer.setCategories(
    JSON.parse(fs.readFileSync(path.join(ROOT, 'categories.json'), 'utf8'))
)
Wappalyzer.setTechnologies(loadCatalog(path.join(ROOT, 'technologies')).technologies)

/** Names detected from a set of collected items. */
const detect = (items) =>
    Wappalyzer.resolve(Wappalyzer.analyze(items)).map(({ name }) => name)

/** Names detected from a DOM selector match. */
const fromDom = (name, selector) =>
    Wappalyzer.resolve(
        Wappalyzer.analyzeDom([{ name, selector, exists: '' }])
    ).map((technology) => technology.name)

/**
 * Positive cases. Each entry is [technology, collected items, what the page is].
 * The third element is documentation: it has to describe a customer's page.
 */
const POSITIVE = [
    [
        'Google Vertex AI',
        {
            scriptSrc: [
                'https://www.gstatic.com/dialogflow-console/fast/df-messenger/prod/v1/df-messenger.js',
            ],
        },
        'a company embedding a Dialogflow CX / Vertex AI Agent Builder chat widget',
    ],
    [
        'Google Vertex AI',
        {
            scriptSrc: [
                'https://www.gstatic.com/dialogflow-console/fast/messenger/bootstrap.js',
            ],
        },
        'the older Dialogflow Messenger bootstrap, same widget',
    ],
    [
        'IBM watsonx',
        {
            scriptSrc: [
                'https://web-chat.global.assistant.watson.appdomain.cloud/versions/8.5.0/WatsonAssistantChatEntry.js',
            ],
        },
        'a company embedding the watsonx Assistant web chat',
    ],
    [
        'IBM Cloud',
        { xhr: 'my-app.eu-gb.mybluemix.appdomain.cloud' },
        'a front end calling its own IBM Cloud-hosted back end',
    ],
    [
        'MuleSoft',
        { xhr: 'orders-api.us-e2.cloudhub.io' },
        'a front end calling its own CloudHub-deployed API',
    ],
    [
        'Postman',
        { scriptSrc: ['https://run.pstmn.io/button.js'] },
        'a company\'s API documentation carrying a Run in Postman button',
    ],
    [
        'Postman',
        { html: '<div class="postman-run-button" data-postman-action="collection/fork"></div><img src="https://run.pstmn.io/button.svg">' },
        'the same button in its no-script form',
    ],
    [
        'Monday.com',
        { html: '<iframe src="https://forms.monday.com/forms/embed/abc123?r=use1"></iframe>' },
        'a monday.com work form embedded on a company site',
    ],
    [
        'Monday.com',
        { html: '<iframe src="https://view.monday.com/embed/9876543210-abcdef"></iframe>' },
        'a shared monday.com board view',
    ],
    [
        'Wrike',
        { html: '<iframe src="https://www.wrike.com/frontend/requestforms/index.html?key=abc"></iframe>' },
        'a Wrike request form on a company contact page',
    ],
    [
        'Zapier',
        { scriptSrc: ['https://zapier.com/apps/embed/widget.js?services=acme&limit=10'] },
        'the Zapier app-directory widget on a product page',
    ],
    [
        'Zapier',
        {
            scriptSrc: [
                'https://interfaces.zapier.com/assets/web-components/zapier-interfaces/zapier-interfaces.esm.js',
            ],
        },
        'a Zapier Interfaces chatbot embed',
    ],
    [
        'Make',
        { xhr: 'hook.eu1.make.com' },
        'a form on a company page posting to its Make webhook',
    ],
    [
        'Make',
        { xhr: 'hook.integromat.com' },
        'the legacy Integromat webhook host',
    ],
    [
        'Superblocks',
        { html: '<iframe src="https://app.superblocks.com/embed/applications/1a2b3c"></iframe>' },
        'a Superblocks app embedded in a customer portal',
    ],
    [
        'Amazon Q',
        { html: '<iframe src="https://abc123.chat.qbusiness.us-east-1.on.aws/"></iframe>' },
        'an Amazon Q Business anonymous web experience embedded on a public site',
    ],
    [
        'Autodesk',
        {
            scriptSrc: [
                'https://developer.api.autodesk.com/modelderivative/v2/viewers/7.108.0/viewer3D.min.js',
            ],
        },
        'a company showing CAD models through the APS viewer',
    ],
    [
        'SAP SuccessFactors',
        { html: '<a href="https://career5.successfactors.eu/career?company=acme">Open roles</a>' },
        'a tenant careers link from a company site',
    ],
    [
        'HackerOne',
        {
            html: '<iframe src="https://hackerone.com/acme-corp/embedded_submissions/new?token=x"></iframe>',
        },
        'an embedded vulnerability submission form on a company security page',
    ],
    [
        'Replicate',
        { html: '<img src="https://replicate.delivery/pbxt/abc/out-0.png">' },
        'model output served on a company page',
    ],
    [
        'Ideogram',
        { html: '<img src="https://ideogram.ai/assets/image/lossless/response/abc123">' },
        'an Ideogram-generated image on a company page',
    ],
    [
        'ClickHouse',
        { headers: { 'x-clickhouse-summary': ['{"read_rows":"1"}'] } },
        'a customer-exposed ClickHouse HTTP endpoint',
    ],
    [
        'ClickHouse',
        { headers: { 'x-clickhouse-server-display-name': ['ch-prod-01'] } },
        'the same endpoint identifying its server',
    ],
    [
        'dbt',
        {
            html: '<html dir="ltr" lang="en-US" ng-app=\'dbt\'><head><title>dbt Docs</title></head>',
        },
        'a dbt docs site published by the company that runs dbt',
    ],
    [
        'Unleash',
        { meta: { unleashtoken: ['default:development.abc'] } },
        'a self-hosted Unleash UI',
    ],
    [
        'Unleash',
        { xhr: 'acme.app.unleash-hosted.com' },
        'the browser SDK calling the hosted frontend API from a customer page',
    ],
    [
        'Metaflow',
        { html: '<head><title>Metaflow UI</title></head>' },
        'a published Metaflow UI',
    ],
    [
        'Kedro',
        { html: '<head><title>Kedro-Viz</title></head>' },
        'a Kedro-Viz static export',
    ],
    [
        'ZenML',
        { html: '<title>fraud_pipeline - ZenML Deployment</title>' },
        'a ZenML deployment dashboard',
    ],
]

test('every customer-visible marker fires on the page shape it was written for', () => {
    for (const [name, items, page] of POSITIVE) {
        assert.ok(
            detect(items).includes(name),
            `${name} should be detected on ${page}`
        )
    }
})

test('the Vertex AI and Zapier widget elements are detected in the DOM', () => {
    // driver.js reports the selector exactly as the catalog spells it, so the
    // lookup is keyed on the stored string rather than one branch of it.
    for (const name of ['Google Vertex AI', 'Zapier']) {
        const selectors = Object.keys(Wappalyzer.getTechnology(name).dom)

        for (const selector of selectors) {
            assert.ok(
                fromDom(name, selector).includes(name),
                `${name} should be detected from ${selector}`
            )
        }
    }
})

/**
 * Negative cases. Prose about a vendor, a link to its marketing site, and
 * lookalike hostnames must all stay silent — the failure mode that made the
 * self-hosted UI rules safe applies here too.
 */
test('writing about a vendor is not using it', () => {
    const prose =
        '<html><body><h1>How we chose our stack</h1><p>We evaluated ' +
        'monday.com, Wrike, Zapier, Make, Postman, dbt, ClickHouse, Unleash, ' +
        'Kedro, Metaflow, ZenML, Superblocks, HackerOne, Replicate, Ideogram, ' +
        'Amazon Q, IBM watsonx and Vertex AI before deciding. Read more at ' +
        '<a href="https://www.wrike.com/">wrike.com</a> and ' +
        '<a href="https://monday.com/">monday.com</a>.</p></body></html>'

    const detected = detect({ html: prose, url: 'https://example.com/blog/stack' })
    const vendors = [
        'Monday.com',
        'Wrike',
        'Zapier',
        'Make',
        'Postman',
        'dbt',
        'ClickHouse',
        'Unleash',
        'Kedro',
        'Metaflow',
        'ZenML',
        'Superblocks',
        'HackerOne',
        'Replicate',
        'Ideogram',
        'Amazon Q',
        'IBM watsonx',
        'Google Vertex AI',
    ]

    assert.deepEqual(
        vendors.filter((name) => detected.includes(name)),
        [],
        'a page discussing these products must detect none of them'
    )
})

test('lookalike and suffix-spoofed hostnames do not match', () => {
    const controls = [
        'hook.eu1.make.com.evil.example',
        'orders-api.us-e2.cloudhub.io.evil.example',
        'my-app.appdomain.cloud.evil.example',
        'acme.app.unleash-hosted.com.evil.example',
    ]

    for (const xhr of controls) {
        assert.deepEqual(
            detect({ xhr }),
            [],
            `${xhr} must not match a customer-visible selector`
        )
    }

    const htmlControls = [
        '<img src="https://notreplicate.delivery.example/x.png">',
        '<iframe src="https://forms.monday.com.evil.example/forms/embed/1"></iframe>',
        '<a href="https://careers.example.com/successfactors-migration">SuccessFactors migration</a>',
    ]

    for (const html of htmlControls) {
        const detected = detect({ html })

        assert.deepEqual(
            ['Replicate', 'Monday.com', 'SAP SuccessFactors'].filter((name) =>
                detected.includes(name)
            ),
            [],
            `${html} must not match a customer-visible selector`
        )
    }
})

test('every customer-visible marker carries a reviewed evidence record', () => {
    const missing = Object.keys(CUSTOMER_VISIBLE).filter((name) => {
        const evidence = EVIDENCE[name]

        return (
            !evidence ||
            evidence.verification === 'catalog-pattern-only' ||
            !evidence.reviewedAt
        )
    })

    assert.deepEqual(
        missing,
        [],
        'a marker without a dated, reviewed observation is a guess'
    )
})

test('every customer-visible marker reached the catalog', () => {
    const unapplied = []

    for (const [name, patch] of Object.entries(CUSTOMER_VISIBLE)) {
        const entry = Wappalyzer.getTechnology(name)

        if (!entry) {
            unapplied.push(`${name}: absent from the catalog`)

            continue
        }

        for (const channel of Object.keys(patch)) {
            const key = channel === 'scriptSrc' ? 'scriptSrc' : channel
            const value = entry[key]

            if (!value || (Array.isArray(value) && !value.length)) {
                unapplied.push(`${name}: ${channel} not applied`)
            }
        }
    }

    assert.deepEqual(unapplied, [])
})
