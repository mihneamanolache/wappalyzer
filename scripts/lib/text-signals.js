'use strict'

/**
 * Text-mined technology signals — a second, lower-confidence source.
 *
 * Some technologies emit nothing a crawler can see: an EDR agent, a Postgres
 * extension, a terminal editor. But companies *write about* the tools they run,
 * most reliably on their own careers pages. "5+ years experience administering
 * CrowdStrike Falcon" is strong evidence the company runs CrowdStrike, even
 * though no packet on their website will ever say so.
 *
 * This is deliberately a separate layer from the pattern catalog:
 *
 *   - The catalog answers "this page is running X" and is held to zero false
 *     positives.
 *   - This module answers "this company appears to use X" and is explicitly an
 *     inference, carrying a low confidence and the sentence it came from.
 *
 * They must not be merged. A hiring signal is not a detection, and reporting it
 * as one would poison the catalog's precision. driver.js keeps them in a
 * separate `signals` array.
 *
 * Two gates have to pass before anything is emitted:
 *
 *   1. The page has to read like a job posting or a stated tech stack. A vendor
 *      name in a press release or a customer story means nothing.
 *   2. The vendor name has to sit inside tooling language ("experience with",
 *      "administering", "our stack"), not merely appear on the page.
 *
 * Both gates are necessary. Either one alone produces the false positives this
 * whole exercise has been avoiding.
 */

/** The page is a job posting, or explicitly describes a tech stack. */
const PAGE_GATES = {
    url: /\/(?:careers?|jobs?|vacanc(?:y|ies)|join-?us|opportunities|positions?|hiring|openings?)(?:\/|$|\?)/i,
    text: new RegExp(
        [
            'job\\s+description',
            'apply\\s+now',
            'we(?:\\047|\')?re\\s+hiring',
            'equal\\s+opportunity\\s+employer',
            'what\\s+you(?:\\047|\')?ll\\s+(?:do|bring)',
            'responsibilities\\s*[:\\n]',
            'qualifications\\s*[:\\n]',
            'requirements\\s*[:\\n]',
            'minimum\\s+qualifications',
            'our\\s+(?:tech(?:nology)?\\s+)?stack',
            'technologies\\s+we\\s+use',
            'tools\\s+we\\s+use',
        ].join('|'),
        'i'
    ),
}

/**
 * Language that puts a vendor name in a tooling context.
 * `%s` is replaced by the vendor pattern.
 */
const CONTEXTS = [
    // "experience with X", "proficiency in X", "familiarity with X"
    '(?:experience|proficiency|familiarity|fluency|expertise|competency|hands[- ]on)\\s+(?:with|in|using|of)\\s+(?:[^.;\\n]{0,80}?\\b)?%s',
    // "knowledge of X", "working knowledge of X"
    '(?:working\\s+)?knowledge\\s+of\\s+(?:[^.;\\n]{0,80}?\\b)?%s',
    // "administering X", "managing X", "deploying X", "operating X"
    '(?:administer(?:ing)?|manag(?:e|ing)|deploy(?:ing)?|operat(?:e|ing)|maintain(?:ing)?|configur(?:e|ing)|tun(?:e|ing)|monitor(?:ing)?)\\s+(?:[^.;\\n]{0,60}?\\b)?%s',
    // "X administrator", "X engineer", "X certified"
    '%s\\s+(?:administrator|admin|engineer|architect|analyst|specialist|developer|certified|certification|expert)\\b',
    // "certified in X"
    'certifi(?:ed|cation)\\s+(?:in|for)\\s+%s',
    // "we use X", "our stack includes X", "powered by X"
    '(?:we\\s+(?:use|run|leverage)|our\\s+stack\\s+includes?|stack\\s*:|built\\s+(?:on|with)|powered\\s+by|standardi[sz]ed\\s+on)\\s+(?:[^.;\\n]{0,80}?\\b)?%s',
    // bullet lists: "- X" alongside other tooling is too weak on its own, but
    // "X (EDR)"-style parentheticals name the category explicitly
    '%s\\s*\\((?:EDR|XDR|SIEM|CASB|SASE|CSPM|RPA|MDM|IdP|CNAPP)\\)',
]

/**
 * Vendor patterns for technologies that cannot be detected any other way.
 * Keyed by the catalog technology name so a signal joins the taxonomy cleanly.
 *
 * Patterns are word-anchored and specific: `Zed` would match far too much text,
 * so it requires a qualifier.
 */
const VENDORS = {
    'CrowdStrike Falcon': 'CrowdStrike(?:\\s+Falcon)?',
    /* ------------------------------------------------------------------ */
    /* Added 2026-08-03. The DQ found ~70 AI entries detectable only by a  */
    /* back-end API hostname the browser never contacts. Where a           */
    /* customer-visible marker existed it was added to the catalog         */
    /* instead (see CUSTOMER_VISIBLE in emerging-technologies.js); the     */
    /* products below have none, so a hiring/stack mention is the only     */
    /* honest signal available. Confidence stays 30 and they are never     */
    /* merged into `technologies`.                                         */
    /*                                                                     */
    /* Names that are also ordinary words carry their qualifier inline     */
    /* rather than relying on the context patterns alone.                  */
    /* ------------------------------------------------------------------ */

    /* vector databases and data platforms */
    Pinecone: 'Pinecone',
    Weaviate: 'Weaviate',
    Qdrant: 'Qdrant',
    Chroma: 'ChromaDB|Chroma\\s+(?:vector|DB)',
    Snowflake: 'Snowflake',
    'Google BigQuery': 'BigQuery',
    'Azure Synapse Analytics': 'Azure\\s+Synapse(?:\\s+Analytics)?',
    Fivetran: 'Fivetran',
    'Apache Kafka': '(?:Apache\\s+)?Kafka',
    ClickHouse: 'ClickHouse',
    CockroachDB: 'CockroachDB|Cockroach\\s+Labs',
    ScyllaDB: 'ScyllaDB',
    TiDB: 'TiDB',
    Neon: 'Neon\\s+(?:Postgres|serverless|database)|neon\\.tech',
    PlanetScale: 'PlanetScale',
    Turso: 'Turso',

    /* model providers and AI platforms */
    'Amazon Bedrock': '(?:Amazon|AWS)\\s+Bedrock',
    'Azure OpenAI Service': 'Azure\\s+OpenAI(?:\\s+Service)?',
    'Azure AI Foundry': 'Azure\\s+AI\\s+Foundry',
    'Google Vertex AI': '(?:Google\\s+)?Vertex\\s+AI',
    'Amazon SageMaker': '(?:Amazon|AWS)\\s+SageMaker',
    'IBM watsonx': 'watsonx',
    Cohere: 'Cohere',
    'Mistral AI': 'Mistral(?:\\s+AI)?',
    DeepSeek: 'DeepSeek',
    'AI21 Labs': 'AI21(?:\\s+Labs)?',
    'Aleph Alpha': 'Aleph\\s+Alpha',
    'xAI Grok': 'Grok|xAI',
    'Zhipu AI': 'Zhipu(?:\\s+AI)?|GLM-[0-9]',
    'Baidu ERNIE': 'ERNIE(?:\\s+Bot)?',
    'Alibaba Cloud Model Studio': 'Model\\s+Studio|DashScope',
    'Volcengine Ark': 'Volcengine(?:\\s+Ark)?',
    'Reka AI': 'Reka\\s+(?:AI|Core|Flash)',
    'Inflection AI': 'Inflection\\s+AI',
    'Llama API': 'Llama\\s+API',
    Cerebras: 'Cerebras',
    'C3 AI': 'C3\\s+AI|C3\\.ai',
    DataRobot: 'DataRobot',
    'H2O.ai': 'H2O\\.ai|H2O\\s+Driverless',
    'SAS Viya': 'SAS\\s+Viya',
    'Scale AI': 'Scale\\s+AI',
    'Stability AI': 'Stability\\s+AI',
    'NVIDIA NIM': 'NVIDIA\\s+NIM|NIM\\s+microservices?',
    'NVIDIA AI Enterprise': 'NVIDIA\\s+AI\\s+Enterprise',
    'Qualcomm AI Hub': 'Qualcomm\\s+AI\\s+Hub',
    'Lambda Cloud': 'Lambda\\s+(?:Cloud|Labs)',
    Modal: 'Modal\\s+Labs|modal\\.com',
    Anyscale: 'Anyscale',
    Replicate: 'Replicate\\s+(?:API|models?)|replicate\\.com',

    /* ML/data engineering tooling */
    BentoML: 'BentoML',
    DVC: '\\bDVC\\b|Data\\s+Version\\s+Control',
    Dagster: 'Dagster',
    Metaflow: 'Metaflow',
    ZenML: 'ZenML',
    Kedro: 'Kedro',
    LangGraph: 'LangGraph',
    CrewAI: 'CrewAI|Crew\\s+AI',
    Crossplane: 'Crossplane',
    Pulumi: 'Pulumi',
    dbt: '\\bdbt\\b(?:\\s+(?:Core|Cloud|models?))?',

    /* coding assistants — local tools, nothing is emitted to a visitor */
    Cursor: 'Cursor\\s+(?:IDE|editor|AI)|\\bCursor\\b(?=[^.;\\n]{0,40}(?:IDE|editor|AI\\s+cod))',
    Windsurf: 'Windsurf(?:\\s+(?:IDE|editor))?',
    Tabnine: 'Tabnine',
    'JetBrains IDEs': 'JetBrains(?:\\s+(?:IDEs?|IntelliJ|Rider|GoLand|PyCharm))?',
    'Sourcegraph Amp': 'Sourcegraph(?:\\s+Amp)?',

    /* workflow automation and agents */
    Workato: 'Workato',
    Tines: '\\bTines\\b',
    'Automation Anywhere': 'Automation\\s+Anywhere',
    Moveworks: 'Moveworks',
    Writer: 'Writer\\s+(?:AI|platform)|writer\\.com',
    Harvey: 'Harvey\\s+AI',
    'Amazon Q': 'Amazon\\s+Q(?:\\s+(?:Business|Developer))?',
    Clari: '\\bClari\\b',
    Outreach: 'Outreach\\.io',

    /* security and endpoint */
    Wiz: 'Wiz\\.io|\\bWiz\\b(?=[^.;\\n]{0,40}(?:CNAPP|cloud\\s+security))',
    'Island Enterprise Browser': 'Island\\s+Enterprise\\s+Browser',
    Jamf: 'Jamf(?:\\s+(?:Pro|Now))?',
    '1Password': '1Password',
    HackerOne: 'HackerOne',

    /* enterprise cloud and engineering suites */
    'VMware Cloud': 'VMware\\s+Cloud',
    'HPE GreenLake': 'HPE\\s+GreenLake',
    'Dell Technologies Cloud': 'Dell\\s+Technologies\\s+Cloud|Dell\\s+APEX',
    'Cisco Cloud': 'Cisco\\s+(?:Cloud|Intersight)',
    'Schneider EcoStruxure': 'EcoStruxure',
    'Siemens Xcelerator': 'Siemens\\s+Xcelerator',
    'SAP SuccessFactors': 'SuccessFactors',
    Autodesk: 'Autodesk(?:\\s+(?:Construction\\s+Cloud|Platform\\s+Services|Forge))?',

    /* observability */
    Honeycomb: 'Honeycomb\\.io|Honeycomb\\s+(?:observability|tracing)',
    Chronosphere: 'Chronosphere',

    /*
     * Hosted APIs a browser *can* call, so their xhr rule is not hopeless — but
     * the normal integration is server-side, which is why they returned zero.
     * A stated-stack mention is the complementary signal.
     */
    'OpenAI API': 'OpenAI\\s+API',
    'Anthropic API': 'Anthropic\\s+API',
    'Google Gemini API': 'Gemini\\s+API',
    AssemblyAI: 'AssemblyAI',
    'Claude Enterprise': 'Claude\\s+Enterprise',
    'Perplexity Enterprise': 'Perplexity\\s+(?:Enterprise|Pro)',
    'You.com': 'You\\.com',
    Runway: 'Runway\\s*ML|Runway\\s+(?:Gen-[0-9]|video)',
    'HashiCorp Cloud Platform': 'HashiCorp\\s+Cloud(?:\\s+Platform)?|\\bHCP\\b',
    'Adobe Identity Management': 'Adobe\\s+Identity\\s+Management',
    'Adobe Acrobat Sign': 'Adobe\\s+(?:Acrobat\\s+)?Sign',
    'IBM Cloud': 'IBM\\s+Cloud',
    MuleSoft: 'MuleSoft|Anypoint',
    Kubernetes: 'Kubernetes|\\bK8s\\b',
    SentinelOne: 'SentinelOne(?:\\s+Singularity)?',
    Zscaler: 'Zscaler(?:\\s+(?:Internet\\s+Access|Private\\s+Access|ZIA|ZPA))?',
    Netskope: 'Netskope',
    'Orca Security': 'Orca\\s+Security',
    Lacework: 'Lacework',
    'Abnormal Security': 'Abnormal\\s+Security',
    pgvector: 'pgvector',
    'NVIDIA Jetson': '(?:NVIDIA\\s+)?Jetson(?:\\s+(?:Orin|Nano|Xavier|AGX))?',
    'Model Context Protocol': '(?:Model\\s+Context\\s+Protocol|\\bMCP\\b)',
    Neovim: '(?:Neovim|\\bnvim\\b)',
    // "Zed" alone is a common word fragment; require the editor context.
    Zed: 'Zed\\s+(?:editor|IDE)|\\bZed\\b(?=[^.;\\n]{0,40}editor)',
    Phind: 'Phind',
}

/**
 * Vendors whose names are also ordinary words or other companies. A match here
 * is discarded even if a context pattern fired.
 */
const AMBIGUITY_GUARDS = {
    // Orca is a whale, a Kubernetes tool, and a screen reader.
    'Orca Security': /orca\s+(?:whale|screen\s+reader)/i,
    // MCP is also "Microsoft Certified Professional" and "master control program".
    'Model Context Protocol': /microsoft\s+certified|master\s+control/i,
    // "Snowflake" is also a schema shape and a data-modelling term.
    Snowflake: /snowflake\s+schema/i,
    // Kafka the author, and Kafkaesque.
    'Apache Kafka': /franz\s+kafka|kafkaesque/i,
    // Grok is also an ordinary verb ("grok the codebase").
    'xAI Grok': /\bgrok(?:king|ked)?\s+(?:the|our|this)\b/i,
    // Cohere shares a stem with "coherent"/"cohesion"; require the company.
    Cohere: /coheren(?:t|ce)|cohesive/i,
    // Mistral is also a wind and a common French name.
    'Mistral AI': /mistral\s+wind/i,
    // Neon as a colour or sign.
    Neon: /neon\s+(?:sign|light|colou?r|green|blue|pink)/i,
    // Amazon Q vs. a literal question numbering ("Q1", "Q&A").
    'Amazon Q': /\bQ[1-4]\b|\bQ\s*&\s*A\b/i,
    // Modal as a UI dialog or a logic term.
    Modal: /modal\s+(?:dialog|window|component|verb|logic)/i,
    // Replicate the verb.
    Replicate: /replicat(?:e|ing|ion)\s+(?:the|this|data|across|our)/i,
    // Writer the job title.
    Writer: /(?:technical|content|copy|staff|senior)\s+writer/i,
    // Island as a geographic word, and "island" architecture in front end.
    'Island Enterprise Browser': /islands?\s+architecture/i,
    // Tines shares a stem with "tine"; and it is a surname.
    Tines: /\btines\s+of\b/i,
    // Chroma key / chromatic.
    Chroma: /chroma\s*key|chromatic/i,
    // "Harvey" is a common personal name; the qualifier already requires "AI",
    // but a person called Harvey AI-something would still slip through.
    Harvey: /harvey\s+(?:nichols|weinstein|milk)/i,
}

/**
 * A sentence that must produce a signal, per vendor.
 *
 * The default is "experience with <name>", which works for any vendor whose
 * pattern is just its name. Everything listed here needs a qualifier — either
 * because the pattern demands one (`Cursor IDE`, `Wiz.io`) or because the
 * catalog name is not what a job posting writes. The test asserts every vendor
 * has a reachable probe, which is what stops a pattern that compiles but can
 * never match.
 */
const PROBE_OVERRIDES = {
    'NVIDIA Jetson': 'experience with NVIDIA Jetson Orin',
    Zed: 'experience with the Zed editor',
    Chroma: 'experience with ChromaDB',
    Neon: 'experience with Neon Postgres',
    Modal: 'experience with Modal Labs',
    Replicate: 'experience with the Replicate API',
    Cursor: 'experience with the Cursor IDE',
    Writer: 'experience with the Writer platform',
    Harvey: 'experience with Harvey AI',
    Outreach: 'experience with Outreach.io',
    Wiz: 'experience with Wiz.io',
    Honeycomb: 'experience with Honeycomb.io',
    Runway: 'experience with RunwayML',
}

/** The sentence used to prove a vendor pattern is reachable. */
const probeFor = (name) => PROBE_OVERRIDES[name] || `experience with ${name}`

/**
 * Vendors that the catalog *can* match, but only on a surface a root-domain
 * crawl will usually not see. A hiring signal is complementary there, not a
 * substitute — so each one is declared with the reason, and anything not
 * declared has to be genuinely undetectable (CATALOG_ONLY) or channel-less.
 *
 * Without this list the layer would drift into duplicating the catalog for
 * products that are already detected on ordinary pages, which is noise.
 */
const COMPLEMENTARY = {
    Pinecone: 'only the app.pinecone.io console is matchable, never a customer page',
    Weaviate: 'only the console.weaviate.cloud surface is matchable',
    Qdrant: 'only the cloud.qdrant.io surface is matchable',
    Snowflake: 'the script host appears on Snowflake-hosted surfaces, not on a customer site',
    ClickHouse: 'the X-ClickHouse-* headers and /play markup need the endpoint to be exposed',
    'Google Vertex AI': 'the df-messenger widget covers Agent Builder only, not other Vertex usage',
    'IBM watsonx': 'the web chat covers watsonx Assistant only',
    Replicate: 'replicate.delivery only appears when model output is served on the page',
    Metaflow: 'the UI is an operator surface, usually on an internal subdomain',
    ZenML: 'the dashboard is an operator surface, usually on an internal subdomain',
    Kedro: 'Kedro-Viz is published as a static export only sometimes',
    dbt: 'dbt docs are published only by some teams; the rest runs entirely server-side',
    'Amazon Q': 'the iframe covers the anonymous web experience only',
    HackerOne: 'the embedded form covers only programs that use it',
    'SAP SuccessFactors': 'the careers link is present only where recruiting is public',
    Autodesk: 'the APS viewer covers embedded model viewing only',
    'Adobe Acrobat Sign': 'the esignWidget iframe covers web forms only, not ordinary send-for-signature use',
    'IBM Cloud': 'the *.appdomain.cloud host only shows where an app is served from or called',
}

const escapeVendor = (pattern) => pattern

/** Compile the context patterns for one vendor. */
function compile(vendorPattern) {
    return CONTEXTS.map(
        (context) =>
            new RegExp(context.replace(/%s/g, `(?:${escapeVendor(vendorPattern)})`), 'i')
    )
}

const COMPILED = Object.entries(VENDORS).map(([name, pattern]) => ({
    name,
    patterns: compile(pattern),
    guard: AMBIGUITY_GUARDS[name] || null,
}))

/**
 * Does this page qualify as a hiring or stated-stack page?
 * @param {{text?: string, url?: string}} page
 */
function isEligiblePage({ text = '', url = '' }) {
    return PAGE_GATES.url.test(url) || PAGE_GATES.text.test(text)
}

/** Trim a matched region down to a readable sentence for the evidence field. */
function snippet(text, index, length) {
    const start = Math.max(0, index - 40)
    const end = Math.min(text.length, index + length + 40)

    return text
        .slice(start, end)
        .replace(/\s+/g, ' ')
        .trim()
}

/**
 * Extract technology signals from page text.
 *
 * @param {{text?: string, url?: string}} page
 * @param {{confidence?: number}} options
 * @returns {Array<{technology: string, confidence: number, source: string, evidence: string}>}
 *   Empty when the page does not qualify.
 */
function analyzeText(page, options = {}) {
    const { text = '', url = '' } = page

    if (!text || !isEligiblePage({ text, url })) {
        return []
    }

    // Confidence stays low on purpose: this is what a company says about itself,
    // not something observed running.
    const confidence = options.confidence === undefined ? 30 : options.confidence

    const signals = []

    for (const { name, patterns, guard } of COMPILED) {
        if (guard && guard.test(text)) {
            continue
        }

        for (const pattern of patterns) {
            const match = pattern.exec(text)

            if (!match) {
                continue
            }

            signals.push({
                technology: name,
                confidence,
                source: 'hiring-signal',
                evidence: snippet(text, match.index, match[0].length),
            })

            break
        }
    }

    return signals
}

module.exports = {
    AMBIGUITY_GUARDS,
    COMPLEMENTARY,
    CONTEXTS,
    PAGE_GATES,
    PROBE_OVERRIDES,
    probeFor,
    VENDORS,
    analyzeText,
    isEligiblePage,
}
