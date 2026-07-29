'use strict'

/**
 * Detection tests for the technologies added for the emerging-tech request.
 *
 * These run against the real catalog and assert two things: that each signal
 * produces the expected detection, and that the deliberately narrow signals do
 * not fire on look-alike input. The negative cases matter as much as the
 * positive ones, because a fingerprint that over-matches is worse than none.
 */

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('fs')
const path = require('path')

const Wappalyzer = require('../wappalyzer')
const { loadCatalog } = require('../scripts/lib/catalog')
const {
    EVIDENCE,
    TECHNOLOGIES,
    TXT,
    TXT_ENRICH,
} = require('../scripts/lib/emerging-technologies')

const ROOT = path.resolve(__dirname, '..')

Wappalyzer.setCategories(
    JSON.parse(fs.readFileSync(path.join(ROOT, 'categories.json'), 'utf8'))
)
Wappalyzer.setTechnologies(loadCatalog(path.join(ROOT, 'technologies')).technologies)

/** Names detected from a set of collected items. */
function detect(items) {
    return Wappalyzer.resolve(Wappalyzer.analyze(items)).map(({ name }) => name)
}

/** Names detected from a DNS TXT record. */
const fromTxt = (record) => detect({ dns: { txt: [record] } })

test('every added technology is present in the catalog', () => {
    const missing = Object.keys(TECHNOLOGIES).filter(
        (name) => !Wappalyzer.getTechnology(name)
    )

    assert.deepEqual(missing, [])
})

test('every enrichment target is present in the catalog', () => {
    const missing = Object.keys(TXT_ENRICH).filter(
        (name) => !Wappalyzer.getTechnology(name)
    )

    assert.deepEqual(missing, [], 'a renamed upstream entry would silently skip')
})

test('every custom technology has an explicit evidence-quality record', () => {
    const missing = Object.keys(TECHNOLOGIES).filter((name) => !EVIDENCE[name])
    const invalid = Object.entries(EVIDENCE)
        .filter(([, evidence]) => !evidence.verification || !evidence.observed)
        .map(([name]) => name)

    assert.deepEqual(missing, [])
    assert.deepEqual(invalid, [])
})

/* ------------------------------------------------------------- priority one */

test('Samsara is detected from its app asset host', () => {
    assert.ok(
        detect({
            scriptSrc: ['https://static.cloud.samsara.com/deploys/app.CllSA3nk.js'],
        }).includes('Samsara')
    )
})

test('Samsara is detected from an API call in either region', () => {
    assert.ok(detect({ xhr: 'api.samsara.com' }).includes('Samsara'))
    assert.ok(detect({ xhr: 'api.eu.samsara.com' }).includes('Samsara'))
})

test('Samsara is detected from an embedded Live Sharing iframe', () => {
    const detected = Wappalyzer.resolve(
        Wappalyzer.analyzeDom([
            {
                name: 'Samsara',
                selector:
                    "iframe[src*='cloud.samsara.com/o/'][src*='/fleet/viewer/']",
                exists: '',
            },
        ])
    ).map(({ name }) => name)

    assert.ok(detected.includes('Samsara'))
})

test('Samsara is detected from a real public Live Sharing link shape', () => {
    const detected = Wappalyzer.resolve(
        Wappalyzer.analyzeDom([
            {
                name: 'Samsara',
                selector:
                    "a[href*='cloud.samsara.com/o/'][href*='/fleet/viewer/']",
                exists: '',
            },
        ])
    ).map(({ name }) => name)

    assert.ok(detected.includes('Samsara'))
})

test('Samsara does not fire on an unrelated host', () => {
    assert.equal(detect({ xhr: 'api.samsaraexample.org' }).includes('Samsara'), false)
    assert.equal(
        detect({ xhr: 'api.samsara.com.attacker.invalid' }).includes('Samsara'),
        false
    )
    assert.equal(
        detect({
            scriptSrc: ['https://attacker.invalid/cloud.samsara.com/app.js'],
        }).includes('Samsara'),
        false
    )
})

test('Verizon Connect is detected separately from Verizon', () => {
    const detected = detect({
        scriptSrc: ['https://reveal.fleetmatics.com/app.js'],
    })

    assert.ok(detected.includes('Verizon Connect'))
    assert.ok(
        detected.includes('Verizon Connect Reveal'),
        'the Reveal product line is reported at product level'
    )
})

test('Verizon Connect is detected from the Telogis product line', () => {
    assert.ok(detect({ xhr: 'api.telogis.com' }).includes('Verizon Connect'))
})

test('Verizon Connect Reveal is detected from the current official login URL', () => {
    for (const url of [
        'https://login.us.vzconnect.com/u/login/identifier',
        'https://us.vzconnect.com/',
        'https://reveal.us.fleetmatics.com/error/closeAndRedirect.html',
    ]) {
        const detected = detect({ url })

        assert.ok(detected.includes('Verizon Connect'), url)
        assert.ok(detected.includes('Verizon Connect Reveal'), url)
    }
})

test('fleet hostname patterns reject attacker-controlled suffixes', () => {
    assert.equal(
        detect({ xhr: 'api.telogis.com.attacker.invalid' })
            .includes('Verizon Connect'),
        false
    )
    assert.equal(
        detect({
            scriptSrc: ['https://attacker.invalid/reveal.fleetmatics.com/app.js'],
        }).includes('Verizon Connect'),
        false
    )
})

/* ----------------------------------------------- TXT verification record class */

test('each TXT verification token detects its technology', () => {
    const failures = []

    for (const [name, token] of Object.entries(TXT)) {
        // Turn the stored pattern into a plausible real record.
        const record = `${token.replace('[a-z0-9]{6}', 'a1b2c3')}sampleValue123`

        if (!fromTxt(record).includes(name)) {
            failures.push(`${name} not detected from ${record}`)
        }
    }

    assert.deepEqual(failures, [])
})

test('each enrichment TXT token detects its technology', () => {
    const failures = []

    for (const [name, token] of Object.entries(TXT_ENRICH)) {
        // Tokens are regexes: expand the common metacharacters into a
        // realistic record value before matching.
        const record = `${token
            .replace('[a-z0-9]{6}', 'a1b2c3')
            .replace('\\d+', '92847034')
            .replace(/^\^/, '')}sampleValue123`

        if (!fromTxt(record).includes(name)) {
            failures.push(`${name} not detected from ${record}`)
        }
    }

    assert.deepEqual(failures, [])
})

test('a TXT record for one vendor does not detect another', () => {
    const detected = fromTxt('openai-domain-verification=abc123')

    assert.ok(detected.includes('OpenAI API'))
    assert.equal(detected.includes('Cursor'), false)
    assert.equal(detected.includes('Wiz'), false)
})

test('an unrelated TXT record detects nothing new', () => {
    assert.deepEqual(fromTxt('v=spf1 include:_spf.google.com ~all'), [])
})

/* --------------------------------------------------- vendor hostname class */

test('AI platform API hosts are detected on the xhr channel', () => {
    const cases = {
        'api.openai.com': 'OpenAI API',
        'api.anthropic.com': 'Anthropic API',
        'generativelanguage.googleapis.com': 'Google Gemini API',
        'api.mistral.ai': 'Mistral AI',
        'api.cohere.com': 'Cohere',
        'api.groq.com': 'Groq',
        'api.together.xyz': 'Together AI',
        'api.deepseek.com': 'DeepSeek',
        'api.elevenlabs.io': 'ElevenLabs',
        'api.assemblyai.com': 'AssemblyAI',
        'api.replicate.com': 'Replicate',
        'api.smith.langchain.com': 'LangSmith',
    }

    const failures = []

    for (const [host, name] of Object.entries(cases)) {
        if (!detect({ xhr: host }).includes(name)) {
            failures.push(`${host} did not detect ${name}`)
        }
    }

    assert.deepEqual(failures, [])
})

test('vector database hosts are detected', () => {
    const cases = {
        'my-index-abc.svc.aped-1234.pinecone.io': 'Pinecone',
        'xyz.eu-central.aws.cloud.qdrant.io': 'Qdrant',
        'abc.weaviate.cloud': 'Weaviate',
        'api.trychroma.com': 'Chroma',
    }

    const failures = []

    for (const [host, name] of Object.entries(cases)) {
        if (!detect({ xhr: host }).includes(name)) {
            failures.push(`${host} did not detect ${name}`)
        }
    }

    assert.deepEqual(failures, [])
})

test('fleet and telematics hosts are detected', () => {
    assert.ok(detect({ xhr: 'my.geotab.com' }).includes('Geotab'))
    assert.ok(detect({ xhr: 'api.gomotive.com' }).includes('Motive'))
    assert.ok(detect({ xhr: 'api.lytx.com' }).includes('Lytx'))
})

test('the ElevenLabs conversational widget is detected from its element', () => {
    const detected = Wappalyzer.resolve(
        Wappalyzer.analyzeDom([
            { name: 'ElevenLabs', selector: 'elevenlabs-convai', exists: '' },
        ])
    ).map(({ name }) => name)

    assert.ok(detected.includes('ElevenLabs'))
})

test('GitHub is detected from served assets, not from a mere repository link', () => {
    assert.ok(
        detect({ scriptSrc: ['https://github.githubassets.com/assets/x.js'] })
            .includes('GitHub')
    )
    assert.ok(detect({ xhr: 'api.github.com' }).includes('GitHub'))
    assert.equal(
        detect({ html: '<a href="https://github.com/acme/repo">source</a>' })
            .includes('GitHub'),
        false,
        'linking to a repository is not evidence of running on GitHub'
    )
})

/* ------------------------------------------------- batch 2: tenant signals */

test('Microsoft 365 tenancy is detected from the MS= verification record', () => {
    assert.ok(fromTxt('MS=ms92847034').includes('Microsoft 365'))
    // Not from an unrelated record that merely starts with MS.
    assert.equal(fromTxt('MSFT-something=1').includes('Microsoft 365'), false)
})

test('Google Workspace tenancy uses the GWS-specific record only', () => {
    assert.ok(
        fromTxt('google-gws-recovery-domain-verification=abc')
            .includes('Google Workspace')
    )
    // google-site-verification is Search Console, not Workspace tenancy.
    assert.equal(
        fromTxt('google-site-verification=abc').includes('Google Workspace'),
        false
    )
})

test('Adobe enterprise tenancy is detected from the IdP record', () => {
    assert.ok(
        fromTxt('adobe-idp-site-verification=abc123')
            .includes('Adobe Identity Management')
    )
})

/* ---------------------------------------------- batch 2: hostname signals */

test('cloud AI service endpoints are detected on the xhr channel', () => {
    const cases = {
        'bedrock-runtime.us-east-1.amazonaws.com': 'Amazon Bedrock',
        'us-central1-aiplatform.googleapis.com': 'Google Vertex AI',
        'myresource.openai.azure.com': 'Azure OpenAI Service',
        'integrate.api.nvidia.com': 'NVIDIA NIM',
        'eu-de.ml.cloud.ibm.com': 'IBM watsonx',
    }

    const failures = []

    for (const [host, name] of Object.entries(cases)) {
        if (!detect({ xhr: host }).includes(name)) {
            failures.push(`${host} did not detect ${name}`)
        }
    }

    assert.deepEqual(failures, [])
})

test('AI writing and assistant platforms are detected', () => {
    const cases = {
        'api.writer.com': 'Writer',
        'api.copy.ai': 'Copy.ai',
        'api.jasper.ai': 'Jasper',
        'api.otter.ai': 'Otter.ai',
        'api.harvey.ai': 'Harvey',
        'api.you.com': 'You.com',
        'api.moveworks.ai': 'Moveworks',
    }

    const failures = []

    for (const [host, name] of Object.entries(cases)) {
        if (!detect({ xhr: host }).includes(name)) {
            failures.push(`${host} did not detect ${name}`)
        }
    }

    assert.deepEqual(failures, [])
})

test('workflow automation platforms are detected', () => {
    assert.ok(detect({ xhr: 'hook.us1.make.com' }).includes('Make'))
    assert.ok(detect({ xhr: 'webhooks.workato.com' }).includes('Workato'))
    assert.ok(detect({ xhr: 'api.tray.io' }).includes('Tray.io'))
    assert.ok(detect({ xhr: 'cloud.uipath.com' }).includes('UiPath'))
    assert.ok(detect({ xhr: 'acme.tines.com' }).includes('Tines'))
})

test('Kong is detected with a version from the via header', () => {
    const resolved = Wappalyzer.resolve(
        Wappalyzer.analyze({ headers: { via: ['kong/3.4.2'] } })
    )
    const kong = resolved.find(({ name }) => name === 'Kong')

    assert.ok(kong, 'Kong not detected')
    assert.equal(kong.version, '3.4.2')
})

test('Grammarly is detected from its editor SDK', () => {
    assert.ok(
        detect({ scriptSrc: ['https://js.grammarly.com/grammarly-editor.js'] })
            .includes('Grammarly')
    )
})

test('sales platforms are detected from their API hosts', () => {
    assert.ok(detect({ xhr: 'api.outreach.io' }).includes('Outreach'))
    assert.ok(detect({ xhr: 'copilot.clari.com' }).includes('Clari'))
    assert.ok(detect({ xhr: 'appcenter.intuit.com' }).includes('Intuit QuickBooks'))
})

/* ------------------------------------------------- self-hosted operator UIs */

/** Names detected from a served HTML document. */
const fromHtml = (html) => detect({ html })

test('self-hosted operator UIs are detected from their shipped markup', () => {
    const cases = [
        [
            'Apache Airflow',
            '<html><head><title>Airflow</title>' +
                '<link rel="icon" href="/static/pin_32.png"></head>',
        ],
        [
            'Apache Superset',
            '<title>Superset</title><div id="app" data-bootstrap="{}">',
        ],
        [
            'MLflow',
            '<title>MLflow</title><div id="root" class="mlflow-ui-container">',
        ],
        [
            'ArgoCD',
            "<title>Argo CD</title><link rel='icon' " +
                "href='assets/favicon/favicon-32x32.png'/>",
        ],
        ['Metabase', '<script type="application/json" id="_metabaseBootstrap">'],
        ['Prometheus', "const GLOBAL_LOOKBACKDELTA='5m';"],
        ['Prefect', '<title>Prefect Server</title>'],
        ['Kiali', '<title>Kiali</title>'],
        ['Ray', '<title>Ray Dashboard</title>'],
        ['Kubeflow', '<title>Kubeflow Central Dashboard</title>'],
    ]

    const failures = []

    for (const [name, html] of cases) {
        if (!fromHtml(html).includes(name)) {
            failures.push(`${name} not detected from its markup`)
        }
    }

    assert.deepEqual(failures, [])
})

test('a page merely writing about these tools does not match', () => {
    // The reason every pattern is anchored to a title tag or a unique id/class
    // rather than a bare product name.
    const article =
        '<html><head><title>Our data stack | Acme Corp</title></head><body>' +
        '<p>We run Apache Airflow, Apache Superset, MLflow, Metabase, ' +
        'Prometheus, Prefect, Kiali, Ray and Kubeflow in production.</p>' +
        '</body></html>'

    const detected = fromHtml(article)

    for (const name of [
        'Apache Airflow',
        'Apache Superset',
        'MLflow',
        'Metabase',
        'Prometheus',
        'Prefect',
        'Kiali',
        'Ray',
        'Kubeflow',
    ]) {
        assert.equal(
            detected.includes(name),
            false,
            `${name} must not match prose that merely names it`
        )
    }
})

test('Airbyte reports a real version from its meta tag', () => {
    const resolved = Wappalyzer.resolve(
        Wappalyzer.analyze({ meta: { 'airbyte:version': ['1.7.2'] } })
    )
    const airbyte = resolved.find(({ name }) => name === 'Airbyte')

    assert.ok(airbyte, 'Airbyte not detected')
    assert.equal(
        airbyte.version,
        '1.7.2',
        'Airbyte is one of the few products on the list that exposes a version'
    )
})

test('Kiali implies Istio, and Istio is detected from its gateway header', () => {
    assert.ok(fromHtml('<title>Kiali</title>').includes('Istio'))
    assert.ok(detect({ headers: { server: ['istio-envoy'] } }).includes('Istio'))
    assert.equal(
        detect({ headers: { server: ['nginx/1.24'] } }).includes('Istio'),
        false
    )
})

test('operator UI session cookies are detected', () => {
    assert.ok(detect({ cookies: { 'argocd.token': ['x'] } }).includes('ArgoCD'))
    assert.ok(
        detect({ cookies: { 'metabase.session': ['x'] } }).includes('Metabase')
    )
})

/* ------------------------------------ hosted control planes & embed surfaces */

test('managed data and ML control planes are detected', () => {
    const cases = {
        'api.wandb.ai': 'Weights & Biases',
        'app.pulumi.com': 'Pulumi',
        'api.dagster.cloud': 'Dagster',
        'cloud.getdbt.com': 'dbt',
        'api.fivetran.com': 'Fivetran',
        'api.modal.com': 'Modal',
        'app.datarobot.com': 'DataRobot',
        'app.sigmacomputing.com': 'Sigma Computing',
        'acme.thoughtspot.cloud': 'ThoughtSpot',
        'acme.chronosphere.io': 'Chronosphere',
        'api.cerebras.ai': 'Cerebras',
        'cloud.lambdalabs.com': 'Lambda Cloud',
        'api.scale.com': 'Scale AI',
        'cloud.scylladb.com': 'ScyllaDB',
        'gw.tidbcloud.com': 'TiDB',
        'api.planetscale.com': 'PlanetScale',
        'anypoint.mulesoft.com': 'MuleSoft',
        'bigquery.googleapis.com': 'Google BigQuery',
        'redshift-data.us-east-1.amazonaws.com': 'Amazon Redshift',
        'runtime.sagemaker.eu-west-1.amazonaws.com': 'Amazon SageMaker',
        'objectstorage.us-phoenix-1.oraclecloud.com': 'Oracle Cloud Infrastructure',
        'acme.wd5.myworkday.com': 'Workday',
    }

    const failures = []

    for (const [host, name] of Object.entries(cases)) {
        if (!detect({ xhr: host }).includes(name)) {
            failures.push(`${host} did not detect ${name}`)
        }
    }

    assert.deepEqual(failures, [])
})

test('CI and security badges are detected from their served images', () => {
    const cases = {
        CircleCI: "img[src*='dl.circleci.com/status-badge']",
        Buildkite: "img[src*='badge.buildkite.com']",
        'Travis CI': "img[src*='api.travis-ci.com']",
        Snyk: "img[src*='snyk.io/test/']",
    }

    const failures = []

    for (const [name, selector] of Object.entries(cases)) {
        const detected = Wappalyzer.resolve(
            Wappalyzer.analyzeDom([{ name, selector, exists: '' }])
        ).map((technology) => technology.name)

        if (!detected.includes(name)) {
            failures.push(`${name} not detected from its badge`)
        }
    }

    assert.deepEqual(failures, [])
})

test('Workday is detected from a careers link', () => {
    const detected = Wappalyzer.resolve(
        Wappalyzer.analyzeDom([
            { name: 'Workday', selector: "a[href*='myworkdayjobs.com']", exists: '' },
        ])
    ).map(({ name }) => name)

    assert.ok(detected.includes('Workday'))
})

test('Kubernetes platform consoles are detected and imply Kubernetes', () => {
    for (const html of [
        '<title>Kubernetes Dashboard</title>',
        '<title>Red Hat OpenShift</title>',
        '<title>OKD</title>',
    ]) {
        assert.ok(
            fromHtml(html).includes('Kubernetes'),
            `${html} should imply Kubernetes`
        )
    }

    assert.ok(fromHtml('<title>Red Hat OpenShift</title>').includes('Red Hat OpenShift'))
})

test('remaining cloud AI planes are detected', () => {
    const cases = {
        'ml.azure.com': 'Azure AI Foundry',
        'ws.dev.azuresynapse.net': 'Azure Synapse Analytics',
        'abc.chat.qbusiness.us-east-1.on.aws': 'Amazon Q',
        'build.nvidia.com': 'NVIDIA AI Enterprise',
        'aihub.qualcomm.com': 'Qualcomm AI Hub',
        'developer.c3.ai': 'C3 AI',
        'internal.dedicated.h2o.ai': 'H2O.ai',
    }

    const failures = []

    for (const [host, name] of Object.entries(cases)) {
        if (!detect({ xhr: host }).includes(name)) {
            failures.push(`${host} did not detect ${name}`)
        }
    }

    assert.deepEqual(failures, [])
})

test('engines are detected from their exposed operator UIs', () => {
    const cases = [
        [
            'Apache Spark',
            '<script src="/static/spark-dag-viz.js"></script>' +
                '<img class="spark-logo" src="/static/spark-logo.svg">',
        ],
        ['Apache Flink', '<title>Apache Flink Web Dashboard</title>'],
        ['Rancher', '<title>Rancher</title><div id="slides"></div>'],
        ['Kedro-Viz', '<title>Kedro-Viz</title>'],
        ['AutoGPT Platform', '<title>AutoGPT Platform</title>'],
    ]

    const failures = []

    for (const [name, html] of cases) {
        if (!fromHtml(html).includes(name)) {
            failures.push(`${name} not detected`)
        }
    }

    assert.deepEqual(failures, [])
})

test('generated media identifies the generator that produced it', () => {
    const cases = {
        Midjourney: '<img src="https://cdn.midjourney.com/a/0_0.png">',
        'Leonardo AI': '<img src="https://cdn.leonardo.ai/x.jpg">',
        Suno: '<audio src="https://cdn2.suno.ai/x.mp3">',
        'Kling AI': '<video src="https://cdn.klingai.com/x.mp4">',
        Pika: '<video src="https://cdn.pika.art/x.mp4">',
        'fal.ai': '<img src="https://v3.fal.media/files/x.png">',
        AlphaFold: '<iframe src="https://alphafold.ebi.ac.uk/entry/P12345">',
    }

    const failures = []

    for (const [name, html] of Object.entries(cases)) {
        if (!fromHtml(html).includes(name)) {
            failures.push(`${name} not detected from its media URL`)
        }
    }

    assert.deepEqual(failures, [])
})

test('model provider APIs are detected on the xhr channel', () => {
    const cases = {
        'api.x.ai': 'xAI Grok',
        'api.llama.com': 'Llama API',
        'dashscope.aliyuncs.com': 'Alibaba Cloud Model Studio',
        'aip.baidubce.com': 'Baidu ERNIE',
        'ark.cn-beijing.volces.com': 'Volcengine Ark',
        'open.bigmodel.cn': 'Zhipu AI',
        'api.ai21.com': 'AI21 Labs',
        'api.aleph-alpha.com': 'Aleph Alpha',
        'api.reka.ai': 'Reka AI',
        'api.inflection.ai': 'Inflection AI',
        'api.runwayml.com': 'Runway',
        'api.lumalabs.ai': 'Luma AI',
        'api.ideogram.ai': 'Ideogram',
        'api.stability.ai': 'Stability AI',
        'api.synthesia.io': 'Synthesia',
        'api.sas.com': 'SAS Viya',
        'api.outerbounds.dev': 'Metaflow',
    }

    const failures = []

    for (const [host, name] of Object.entries(cases)) {
        if (!detect({ xhr: host }).includes(name)) {
            failures.push(`${host} did not detect ${name}`)
        }
    }

    assert.deepEqual(failures, [])
})

test('service mesh and model serving paths are detected', () => {
    assert.ok(
        detect({ headers: { 'l5d-dst-override': ['svc.cluster.local'] } })
            .includes('Linkerd')
    )
    assert.ok(
        detect({ url: 'https://ml.acme.com/seldon/prod/iris/api/v1.0/predictions' })
            .includes('Seldon Core')
    )
    assert.ok(
        detect({ url: 'https://dss.acme.com/public-webapps/proj/abc/' })
            .includes('Dataiku')
    )
    // A bare predictions path is not Seldon.
    assert.equal(
        detect({ url: 'https://acme.com/api/v1.0/predictions' }).includes('Seldon Core'),
        false
    )
})

test('vendor cloud tenancy records are detected', () => {
    assert.ok(fromTxt('cloudhealth=7fe179e6-9085').includes('VMware Cloud'))
    assert.ok(fromTxt('ibmid=8938274b-09d1').includes('IBM Cloud'))
    assert.ok(
        fromTxt('successfactors-site-verification=NDZlMDhk')
            .includes('SAP SuccessFactors')
    )
    assert.ok(
        fromTxt('ecostruxure-it-verification=4069a037')
            .includes('Schneider EcoStruxure')
    )
})

/* ----------------------------------------------------------- product level */

test('Samsara Assistant is taxonomy-only because its bundle is globally shipped', () => {
    const assistant = Wappalyzer.getTechnology('Samsara Assistant')

    assert.ok(assistant)
    assert.equal(assistant.scriptSrc.length, 0)
    assert.equal(assistant.requires.length, 0)
    assert.equal(assistant.implies.length, 0)
})

test('added technologies carry the metadata the taxonomy needs', () => {
    const incomplete = []

    for (const name of Object.keys(TECHNOLOGIES)) {
        const technology = Wappalyzer.getTechnology(name)

        if (!technology.categories.length) {
            incomplete.push(`${name}: no category`)
        }

        if (!technology.description) {
            incomplete.push(`${name}: no description`)
        }

        if (!technology.website) {
            incomplete.push(`${name}: no website`)
        }

        if (technology.saas === null && technology.oss === null) {
            incomplete.push(`${name}: no deployment model`)
        }
    }

    assert.deepEqual(incomplete, [])
})
