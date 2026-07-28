'use strict'

/**
 * Maps the requested product list onto this catalog's taxonomy.
 *
 * The request mixes several kinds of thing under one heading, and they have
 * genuinely different detectability from outside a company:
 *
 *   detected            A catalog entry exists and can fire on observable evidence.
 *
 *   platform-level      The product is an AI feature *inside* a platform that is
 *                       detected. Jira AI is not separately observable from
 *                       outside — a site either shows Jira or it does not, and
 *                       whether the tenant has the AI add-on enabled is not
 *                       exposed. Reported against the parent.
 *
 *   model               A model name (GPT-5, Claude Opus 4, Llama 4, Mistral
 *                       Large). Models leave no fingerprint; the *API* that
 *                       serves them does, and that is what gets detected.
 *
 *   backend             Server-side data or ML infrastructure (Spark, Airflow,
 *                       MLflow, Bedrock, SageMaker). It runs behind the app and
 *                       emits nothing to a visitor.
 *
 *   endpoint            Endpoint, network or cloud-posture security that runs as
 *                       an agent or out-of-band scanner (CrowdStrike Falcon,
 *                       Zscaler, Netskope). No web-visible footprint. Some
 *                       vendors are still reachable via a tenant TXT record,
 *                       which is why a few security products are `detected`.
 *
 *   desktop             A desktop or CLI application (VS Code, Neovim, Zed,
 *                       Claude Code). Not a web technology.
 *
 * Only `detected` products can produce a hit. The rest are reported honestly
 * rather than given a pattern that would never fire, or worse, one that fires on
 * a marketing page that merely mentions the vendor.
 */

const { CATALOG_ONLY } = require('./dnb-technologies')

/**
 * Product name in the request -> technology name in this catalog.
 * Used where the two taxonomies name the same thing differently.
 */
const ALIASES = {
    /* fleet and connected operations */
    'Samsara Assistant': 'Samsara Assistant',
    'Motive AI Dashcam': 'Motive',
    'Geotab Ace': 'Geotab',
    'Lytx Machine Vision + AI': 'Lytx',

    /* generative AI accessed over an API */
    'GPT-5': 'OpenAI API',
    'GPT-4o': 'OpenAI API',
    'GPT-4 Turbo': 'OpenAI API',
    'OpenAI o1': 'OpenAI API',
    'OpenAI o3': 'OpenAI API',
    'DALL-E 3': 'OpenAI API',
    Sora: 'OpenAI API',
    Whisper: 'OpenAI API',
    Codex: 'OpenAI API',
    'ChatGPT Enterprise': 'OpenAI API',
    'Claude Opus 4': 'Anthropic API',
    'Claude Sonnet 4': 'Anthropic API',
    'Claude 3.5 Sonnet': 'Anthropic API',
    'Claude 3.5 Haiku': 'Anthropic API',
    'Claude Fable 5': 'Anthropic API',
    'Claude Enterprise': 'Claude Enterprise',
    'Gemini 2.5 Pro': 'Google Gemini API',
    'Gemini 2.0 Flash': 'Google Gemini API',
    'Gemini Ultra': 'Google Gemini API',
    'Gemini Enterprise': 'Google Gemini API',
    'Google AI Studio': 'Google Gemini API',
    'Imagen 3': 'Google Gemini API',
    'Veo 2': 'Google Gemini API',
    'Mistral Large': 'Mistral AI',
    'Mistral Medium 3.5': 'Mistral AI',
    'Mistral Small 4': 'Mistral AI',
    'Le Chat': 'Mistral AI',
    Codestral: 'Mistral AI',
    'Devstral 2': 'Mistral AI',
    'Mixtral 8x22B': 'Mistral AI',
    Pixtral: 'Mistral AI',
    'Cohere Command R': 'Cohere',
    'Command R+': 'Cohere',
    'Command A': 'Cohere',
    'Cohere Embed': 'Cohere',
    'Cohere Rerank': 'Cohere',
    'Cohere North': 'Cohere',
    Aya: 'Cohere',
    'DeepSeek V3': 'DeepSeek',
    'DeepSeek R1': 'DeepSeek',
    'DeepSeek Coder': 'DeepSeek',
    GroqCloud: 'Groq',
    Groq: 'Groq',
    'Together Inference': 'Together AI',
    'Anyscale Endpoints': 'Anyscale',
    'Perplexity Enterprise Pro': 'Perplexity Enterprise',
    'Perplexity Pro': 'Perplexity Enterprise',
    ElevenLabs: 'ElevenLabs',
    'Assembly AI': 'AssemblyAI',
    Replicate: 'Replicate',
    'Hugging Face Inference Endpoints': 'Hugging Face',
    'Hugging Face Enterprise Hub': 'Hugging Face',

    /* AI coding */
    Cursor: 'Cursor',
    Windsurf: 'Windsurf',
    Codeium: 'Windsurf',
    Cody: 'Sourcegraph Amp',
    'Sourcegraph Cody': 'Sourcegraph Amp',
    Tabnine: 'Tabnine',
    'JetBrains IDEs': 'JetBrains IDEs',

    /* vector and data */
    Pinecone: 'Pinecone',
    Qdrant: 'Qdrant',
    Weaviate: 'Weaviate',
    Chroma: 'Chroma',
    ClickHouse: 'ClickHouse',
    CockroachDB: 'CockroachDB',
    Neon: 'Neon',
    Turso: 'Turso',
    Snowflake: 'Snowflake',
    LangSmith: 'LangSmith',

    /* security */
    Wiz: 'Wiz',
    'Wiz AI-SPM': 'Wiz',
    'Palo Alto Networks Cortex XSIAM': 'Palo Alto Networks',
    'Palo Alto Cortex AgentiX': 'Palo Alto Networks',
    'Palo Alto Prisma AIRS': 'Palo Alto Networks',
    'Palo Alto Precision AI': 'Palo Alto Networks',
    'Island Enterprise Browser AI': 'Island Enterprise Browser',

    /* collaboration and workflow */
    Figma: 'Figma',
    'Figma AI': 'Figma',
    Miro: 'Miro',
    'Miro AI': 'Miro',
    'Canva Magic Studio': 'Canva',
    Coda: 'Coda',
    'Monday.com': 'Monday.com',
    'Monday AI': 'Monday.com',
    'Box AI': 'Box',
    'Box AI Agents': 'Box',
    'Dropbox Dash': 'Dropbox',
    'Dropbox AI': 'Dropbox',
    Postman: 'Postman',
    Slack: 'Slack',
    'Slack AI': 'Slack',
    'Zoom AI Companion': 'Zoom',
    Jira: 'Atlassian Jira',
    'Jira AI': 'Atlassian Jira',
    Bitbucket: 'Atlassian Bitbucket',
    'Confluence AI': 'Atlassian Confluence',
    'Atlassian Intelligence': 'Atlassian Cloud',
    'Atlassian Rovo': 'Atlassian Cloud',
    'Atlassian Rovo Dev': 'Atlassian Cloud',
    GitHub: 'GitHub',
    Glean: 'Glean',
    '6sense Revenue AI': '6sense',
    'HashiCorp Vault': 'HashiCorp Cloud Platform',
    'Zoho Zia': 'Zoho',
    'Zoho Zia Voice': 'Zoho',

    /* autodesk / vendor umbrellas with a verified tenant record */
    'Autodesk Assistant': 'Autodesk',
    'Autodesk Neural CAD': 'Autodesk',
    'Autodesk Forma AI': 'Autodesk',
    'Cisco AI Network Analytics': 'Cisco Cloud',
    'Dell AI Factory': 'Dell Technologies Cloud',
    'Dell PowerEdge AI Servers': 'Dell Technologies Cloud',

    /* Microsoft 365 tenancy (MS= TXT record + outlook.com MX) */
    'Microsoft Teams': 'Microsoft 365',
    'Microsoft Power Platform': 'Microsoft 365',
    'Microsoft Copilot Studio': 'Microsoft 365',
    'Microsoft Copilot for Sales': 'Microsoft 365',
    'Power BI': 'Microsoft Power BI',
    'Copilot in Power BI': 'Microsoft Power BI',
    'GitHub Actions': 'GitHub',

    /* Google Workspace tenancy (gws-recovery TXT record + Google MX) */
    NotebookLM: 'Google Workspace',
    'Google Vids': 'Google Workspace',

    /* Adobe enterprise tenancy (adobe-idp TXT record, 94 domains observed) */
    'Adobe Firefly': 'Adobe Identity Management',
    'Adobe Express AI': 'Adobe Identity Management',
    'Adobe GenStudio': 'Adobe Identity Management',
    'Adobe Acrobat AI Assistant': 'Adobe Identity Management',
    'Adobe Sensei GenAI': 'Adobe Identity Management',
    'Adobe Experience Platform AI Assistant': 'Adobe Identity Management',

    /* platforms already detected in the catalog */
    'Kong Gateway': 'Kong',
    'Intercom Fin': 'Intercom',
    'Elastic Stack': 'Elasticsearch',
    'Tableau Pulse': 'Tableau',
    'Salesforce Agentforce': 'Salesforce',
    'Salesloft Rhythm': 'Salesloft',
    'ZoomInfo Copilot': 'Zoominfo',
    'Snowflake Cortex AI': 'Snowflake',
    'Snowflake Cortex Analyst': 'Snowflake',
    'Snowflake Cortex Search': 'Snowflake',
    'Databricks Mosaic AI': 'Databricks',
    'Databricks AI/BI Genie': 'Databricks',
    'IBM watsonx.ai': 'IBM watsonx',
    'IBM watsonx Orchestrate': 'IBM watsonx',
    'IBM watsonx.data': 'IBM watsonx',
    'IBM watsonx.governance': 'IBM watsonx',
    'IBM watsonx BI': 'IBM watsonx',

    /* products of newly added technologies */
    GrammarlyGO: 'Grammarly',
    'Grammarly AI': 'Grammarly',
    'Writer AI Studio': 'Writer',
    'Jasper AI': 'Jasper',
    'Make AI Agents': 'Make',
    'UiPath Autopilot': 'UiPath',
    'Tines AI': 'Tines',
    'Otter AI Chat': 'Otter.ai',
    'Harvey AI': 'Harvey',
    Terraform: 'HashiCorp Cloud Platform',
    'Outreach Kaia': 'Outreach',
    'Clari Copilot': 'Clari',
    'Intuit Assist': 'Intuit QuickBooks',
    'QuickBooks AI': 'Intuit QuickBooks',
    'TurboTax AI': 'Intuit QuickBooks',

    /* self-hosted operator UIs, detected when exposed on a subdomain */
    'Apache Airflow': 'Apache Airflow',
    Superset: 'Apache Superset',
    MLflow: 'MLflow',
    ArgoCD: 'ArgoCD',
    Metabase: 'Metabase',
    Prometheus: 'Prometheus',
    Prefect: 'Prefect',
    Airbyte: 'Airbyte',
    Istio: 'Istio',
    Ray: 'Ray',
    Kubeflow: 'Kubeflow',
    Dagster: 'Dagster',
    dbt: 'dbt',
    Fivetran: 'Fivetran',
    Modal: 'Modal',
    Pulumi: 'Pulumi',
    'Weights & Biases': 'Weights & Biases',
    'Weights & Biases Weave': 'Weights & Biases',
    'DataRobot AI Platform': 'DataRobot',

    /* vendor cloud tenancy */
    'VMware Private AI': 'VMware Cloud',
    'VMware Cloud Foundation AI Services': 'VMware Cloud',
    'IBM Bob': 'IBM Cloud',
    'SAP Joule': 'SAP SuccessFactors',
    'SAP Business AI': 'SAP SuccessFactors',
    'SAP AI Core': 'SAP SuccessFactors',
    'Cisco AI Assistant': 'Cisco Cloud',

    /* hosted control planes and embed surfaces */
    'Sigma Computing': 'Sigma Computing',
    ThoughtSpot: 'ThoughtSpot',
    Chronosphere: 'Chronosphere',
    'Travis CI': 'Travis CI',
    Snyk: 'Snyk',
    'Snyk AI Trust Platform': 'Snyk',
    'Scale Data Engine': 'Scale AI',
    Cerebras: 'Cerebras',
    'Cerebras Inference': 'Cerebras',
    'Lambda Cloud': 'Lambda Cloud',
    ScyllaDB: 'ScyllaDB',
    PlanetScale: 'PlanetScale',
    TiDB: 'TiDB',
    BigQuery: 'Google BigQuery',
    Redshift: 'Amazon Redshift',
    'Amazon SageMaker AI': 'Amazon SageMaker',
    MuleSoft: 'MuleSoft',
    'Workday Illuminate': 'Workday',
    'Workday AI': 'Workday',
    'Oracle Cloud Infrastructure Generative AI': 'Oracle Cloud Infrastructure',
    'Oracle AI Agent Studio': 'Oracle Cloud Infrastructure',
    'Oracle AI Agents': 'Oracle Cloud Infrastructure',
    'Oracle Database 23ai': 'Oracle Cloud Infrastructure',
    'Oracle AI Database 26ai': 'Oracle Cloud Infrastructure',

    /* Kubernetes platforms, detected from an exposed console.
     * Kubernetes maps to itself: it has no pattern of its own, but the Dashboard
     * and OpenShift both imply it, so it is reachable. */
    Kubernetes: 'Kubernetes',
    'Red Hat OpenShift AI': 'Red Hat OpenShift',
    'Red Hat AI Enterprise': 'Red Hat OpenShift',
    'Red Hat Enterprise Linux AI': 'Red Hat OpenShift',

    /* remaining cloud AI planes */
    'Azure AI Foundry': 'Azure AI Foundry',
    'Synapse Analytics': 'Azure Synapse Analytics',
    'Amazon Q Business': 'Amazon Q',
    'Amazon Q Developer': 'Amazon Q',
    'Amazon CodeWhisperer': 'Amazon Q',
    'NVIDIA AI Enterprise': 'NVIDIA AI Enterprise',
    'NVIDIA NeMo': 'NVIDIA AI Enterprise',
    'NVIDIA NIM': 'NVIDIA NIM',
    'Qualcomm AI Hub': 'Qualcomm AI Hub',
    'C3 Generative AI': 'C3 AI',
    'H2O.ai h2oGPTe': 'H2O.ai',

    /* engines detected from an exposed operator UI */
    'Apache Spark': 'Apache Spark',
    'Apache Flink': 'Apache Flink',
    'Apache Kafka': 'Apache Kafka',
    Rancher: 'Rancher',
    Kedro: 'Kedro',
    AutoGPT: 'AutoGPT Platform',
    'PTC ThingWorx Navigate AI': 'PTC ThingWorx',
    'Siemens Industrial Copilot': 'Siemens Xcelerator',
    'Automation Anywhere Autopilot': 'Automation Anywhere',

    /* ML control planes */
    CrewAI: 'CrewAI',
    BentoML: 'BentoML',
    ZenML: 'ZenML',
    DVC: 'DVC',
    Crossplane: 'Crossplane',
    LangGraph: 'LangGraph',
    // LangSmith traces are emitted by LangChain applications, so a LangSmith
    // detection is genuine evidence of LangChain. Seldon, Metaflow, Dataiku and
    // SAS Viya are deliberately NOT mapped onto other vendors' platforms — they
    // are separate products and rolling them up would be a false positive.
    LangChain: 'LangSmith',

    /* generated media: the artefact identifies the generator */
    Midjourney: 'Midjourney',
    'Leonardo AI': 'Leonardo AI',
    'Kling AI': 'Kling AI',
    'Pika 2.0': 'Pika',
    'Suno AI': 'Suno',
    Udio: 'Udio',
    'Stable Diffusion 3': 'Stability AI',
    'Stable Diffusion 3.5': 'Stability AI',
    'Stable Video Diffusion': 'Stability AI',
    'FLUX.1': 'fal.ai',
    'AlphaFold 3': 'AlphaFold',

    /* browser-hosted editors */
    'VS Code': 'VS Code for the Web',

    /* model-provider APIs: the API that serves a model is observable even
     * though the model itself is not */
    Synthesia: 'Synthesia',
    'Grok 3': 'xAI Grok',
    'Grok-2': 'xAI Grok',
    'Meta AI': 'Meta AI',
    'Ideogram 2.0': 'Ideogram',
    'Luma Dream Machine': 'Luma AI',
    'Runway Gen-3 Alpha': 'Runway',
    'Inflection Pi': 'Inflection AI',
    'Reka AI': 'Reka AI',
    'AI21 Jamba': 'AI21 Labs',
    'Aleph Alpha Luminous': 'Aleph Alpha',
    'Qwen 2.5': 'Alibaba Cloud Model Studio',
    'Ernie 4.0': 'Baidu ERNIE',
    Doubao: 'Volcengine Ark',
    'GLM-4': 'Zhipu AI',
    'SAS Viya AI': 'SAS Viya',
    'SAS Visual AI': 'SAS Viya',
    Linkerd: 'Linkerd',

    /* models reported against the platform that serves them, matching how
     * Claude and GPT are already handled */
    'Amazon Nova': 'Amazon Bedrock',
    'Databricks DBRX': 'Databricks',
    'Snowflake Arctic': 'Snowflake',
    'IBM Granite Models': 'IBM watsonx',

    /* add-ons of a suite that is detected */
    'Microsoft Security Copilot': 'Microsoft 365',
    'GitHub Copilot Workspace': 'GitHub',
    'Claude Code': 'Claude Enterprise',

    /* the Llama family is observable only through Meta's hosted API; a
     * self-hosted open-weight deployment leaves nothing to match */
    'Llama 4': 'Llama API',
    'Llama 4 Scout': 'Llama API',
    'Llama 4 Maverick': 'Llama API',
    'Meta Llama 3': 'Llama API',
    'Code Llama': 'Llama API',

    'Seldon Core': 'Seldon Core',
    Metaflow: 'Metaflow',
    'Dataiku LLM Mesh': 'Dataiku',

    /* Taxonomy-only: mapped for completeness, no detection is possible.
     * scripts/coverage-report.js reports these separately from real coverage. */
    'CrowdStrike Falcon': 'CrowdStrike Falcon',
    'CrowdStrike Charlotte AI': 'CrowdStrike Falcon',
    SentinelOne: 'SentinelOne',
    'SentinelOne Purple AI': 'SentinelOne',
    'Zscaler AI': 'Zscaler',
    'Netskope SkopeAI': 'Netskope',
    'Orca Security': 'Orca Security',
    Lacework: 'Lacework',
    'Abnormal Security AI': 'Abnormal Security',
    pgvector: 'pgvector',
    'NVIDIA Jetson Orin': 'NVIDIA Jetson',
    'Anthropic MCP': 'Model Context Protocol',
    Neovim: 'Neovim',
    Zed: 'Zed',
    Phind: 'Phind',
}

/**
 * Rules applied in order to anything not resolved by name or alias.
 * The first matching pattern decides the classification.
 */
const RULES = [
    /* ------------------------------------------------ desktop / CLI tools */
    {
        class: 'desktop',
        reason: 'A desktop or command-line application, not a web technology.',
        patterns: [
            /^(?:vs code|visual studio code|neovim|zed|claude code|github copilot workspace)$/i,
        ],
    },

    /* ------------------------------------------------------------- models */
    {
        class: 'model',
        reason:
            'A model name. Models have no external fingerprint; the API serving ' +
            'them is what gets detected.',
        patterns: [
            /^(?:gpt|claude|gemini|llama|code llama|mistral|mixtral|pixtral|codestral|devstral|command|qwen|ernie|glm|grok|deepseek|nova|titan|imagen|veo|sora|dall-e|whisper|aya|jamba|granite|arctic|dbrx|flux|stable (?:diffusion|video)|kling|pika|luma|ideogram|midjourney|runway|suno|udio|reka|inflection|doubao|phind|leonardo|synthesia)/i,
            /^(?:ai21|aleph alpha|cerebras inference|meta llama|meta ai|amazon nova|snowflake arctic|databricks dbrx|ibm granite models)/i,
            /^alphafold/i,
        ],
    },

    /* -------------------------------------------- back-end infrastructure */
    {
        class: 'backend',
        reason:
            'Server-side data or ML infrastructure. It runs behind the ' +
            'application and emits nothing observable to a visitor.',
        patterns: [
            /^apache (?:spark|kafka|airflow|flink)$/i,
            /^(?:superset|ray|bentoml|mlflow|kubeflow|metaflow|zenml|seldon core|dvc|kedro|dagster|prefect|dbt|fivetran|airbyte|modal|scale data engine)/i,
            /^(?:amazon bedrock|amazon sagemaker|amazon q |amazon codewhisperer|amazon nova|redshift|bigquery|synapse analytics)/i,
            /^(?:azure (?:ai foundry|openai service)|google vertex ai|google dataproc)/i,
            /^(?:nvidia|qualcomm ai hub|red hat (?:ai|openshift ai|enterprise linux ai))/i,
            /^(?:ibm watsonx|ibm bob|sap (?:joule|business ai|ai core)|sas (?:viya|visual) ai|oracle (?:ai|cloud infrastructure|database)|workday (?:illuminate|ai))/i,
            /^(?:dataiku|datarobot|h2o\.ai|c3 generative ai|automation anywhere|siemens industrial copilot|ptc thingworx|mulesoft)/i,
            /^(?:vmware (?:private ai|cloud foundation)|databricks (?:mosaic|ai\/bi))/i,
            /^(?:snowflake cortex|kubernetes|istio|linkerd|prometheus|opentelemetry|argocd|rancher|crossplane|pulumi|helm|buildkite|circleci|travis ci|jenkins)/i,
            /^(?:elastic stack|duckdb|pgvector|tidb|planetscale|scylladb|milvus|lambda cloud|cerebras$)/i,
            /^(?:langchain|langgraph|crewai|autogpt|anthropic mcp|weights & biases)/i,
            /^(?:chronosphere|honeycomb|hex|observable|metabase|sigma computing|thoughtspot|power bi|copilot in power bi|tableau pulse)/i,
        ],
    },

    /* ---------------------------------------- endpoint / network security */
    {
        class: 'endpoint',
        reason:
            'Endpoint, network or cloud-posture security. Runs as an agent or ' +
            'out-of-band scanner with no web-visible footprint.',
        patterns: [
            /^(?:crowdstrike|sentinelone|zscaler|netskope|abnormal security|orca security|lacework|snyk|forcepoint|microsoft security copilot|microsoft insider risk)/i,
        ],
    },

    /* ------------------------------------- AI features inside a platform */
    {
        class: 'platform-level',
        reason:
            'An AI feature inside a platform that is detected. Whether the ' +
            'tenant has the feature enabled is not exposed externally, so it is ' +
            'reported against the parent platform.',
        patterns: [
            /\b(?:ai|copilot|assistant|agents?|brain|intelligence|genai|gpt|joule|zia|ace|einstein|breeze|sidekick|magic|now assist|autopilot|illuminate|pulse|bits ai|charlotte ai|purple ai|skopeai|rovo)\b/i,
        ],
    },
]

/** Normalized form for name comparison. */
const normalize = (value) =>
    String(value).toLowerCase().replace(/[^a-z0-9]/g, '')

// Exact product names that exist in the taxonomy but are not distinguishable
// from their parent platform in a passive web scan.
const PLATFORM_LEVEL_ALIASES = {
    'Samsara Assistant': 'Samsara',
}

/**
 * Classify one requested product against the catalog.
 * @param {{product: string, vendor: string}} item
 * @param {Map<string, string>} byNormalizedName catalog names keyed by normalized form
 * @returns {{product: string, vendor: string, status: string, mapsTo: ?string, reason: string}}
 */
function classify(item, byNormalizedName) {
    const { product, vendor } = item

    const resolve = (name) => byNormalizedName.get(normalize(name))

    if (PLATFORM_LEVEL_ALIASES[product]) {
        const target = resolve(PLATFORM_LEVEL_ALIASES[product])

        return {
            product,
            vendor,
            status: 'platform-level',
            mapsTo: target || null,
            reason:
                'The feature bundle is shipped on Samsara public sign-in pages, ' +
                'so it cannot establish that a customer has Assistant enabled. ' +
                'Reported as Samsara, which is externally observable.',
        }
    }

    // 1. The catalog already has something under this exact name.
    const direct = resolve(product)

    if (direct) {
        return {
            product,
            vendor,
            status: direct in CATALOG_ONLY ? 'catalog-only' : 'detected',
            mapsTo: direct,
            reason:
                direct in CATALOG_ONLY
                    ? `Mapped to ${direct}, which carries taxonomy metadata only: ` +
                      'the product emits nothing observable from outside.'
                    : 'Catalog entry matches the requested name.',
        }
    }

    // 2. An explicit alias resolves it to a catalog entry.
    if (ALIASES[product]) {
        const target = resolve(ALIASES[product])

        if (target) {
            const isSameThing = normalize(ALIASES[product]) === normalize(product)

            if (target in CATALOG_ONLY) {
                return {
                    product,
                    vendor,
                    status: 'catalog-only',
                    mapsTo: target,
                    reason:
                        `Mapped to ${target}, which carries taxonomy metadata ` +
                        'only: the product emits nothing observable from outside.',
                }
            }

            return {
                product,
                vendor,
                status: isSameThing ? 'detected' : 'platform-level',
                mapsTo: target,
                reason: isSameThing
                    ? 'Catalog entry matches the requested name.'
                    : `Reported as ${target}, which is what is externally observable.`,
            }
        }
    }

    // 3. Rule-based classification.
    for (const rule of RULES) {
        if (rule.patterns.some((pattern) => pattern.test(product))) {
            // A platform-level feature is only useful if the parent is detected.
            let mapsTo = null

            if (rule.class === 'platform-level') {
                // Strip the AI-feature words and see whether the base product is
                // in the catalog: "Notion AI" -> "Notion".
                const base = product
                    .replace(
                        /\b(?:ai|copilot|assistant|agents?|brain|intelligence|genai|gpt|studio)\b/gi,
                        ''
                    )
                    .replace(/\s+/g, ' ')
                    .trim()

                mapsTo = resolve(base) || resolve(vendor) || null
            }

            return {
                product,
                vendor,
                status: rule.class,
                mapsTo,
                reason: rule.reason,
            }
        }
    }

    // 4. Nothing matched: a web-deliverable product with no fingerprint yet.
    return {
        product,
        vendor,
        status: 'candidate',
        mapsTo: null,
        reason:
            'Web-deliverable but no fingerprint established yet. Needs a ' +
            'verified signal before it can be added.',
    }
}

module.exports = { ALIASES, RULES, classify, normalize }
