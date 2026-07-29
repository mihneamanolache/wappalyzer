'use strict'

/**
 * Technologies added for emerging-tech taxonomy coverage.
 *
 * Every fingerprint here is catalog-tested. Evidence quality is recorded
 * separately because a syntactically valid regex, an official endpoint, and a
 * marker observed on a real customer domain are not equivalent.
 *
 *   dns-txt   A domain-verification TXT record. Its presence means the domain
 *             owner completed an ownership check with that vendor. This is a
 *             *tenant* signal, not a "the website embeds it" signal, and it
 *             needs `--probe` to be collected.
 *
 *   hostname  A vendor-owned hostname confirmed to resolve, matched on the
 *             scriptSrc or xhr channel. If a page loads or calls that host, the
 *             technology is genuinely present. Hostname anchors are used in
 *             preference to guessed asset filenames, which go stale.
 *
 * The `EVIDENCE` map records whether an entry was observed live, only confirmed
 * in official documentation, inherited from an unreproducible prior sweep, or
 * merely catalog-tested. Products with no externally observable signal are
 * deliberately left without a detection channel.
 */

/* Category ids from scripts/lib/categories-extra.js and categories.json. */
const GEN_AI = 200
const AI_FRAMEWORKS = 201
const VECTOR_DB = 202
const AI_INFRA = 203
const DATA_PLATFORM = 204
const FLEET = 205
const IOT = 206
const CLOUD_SECURITY = 207
const AI_CODING = 208
const AI_AGENTS = 209
const AUTOMATION = 210
const OBSERVABILITY = 211
const ANALYTICS = 10
const SECURITY = 16
const DEVELOPMENT = 47
const DATABASES = 34
const CRM = 53
const LIVE_CHAT = 52
const COLLABORATION = 19
const DMS = 50
const ISSUE_TRACKERS = 13
const BI = 204
const AI = 112

/**
 * TXT-record verification tokens imported from the earlier sweep. The sweep's
 * source domain list and raw results were not retained, so these patterns are
 * treated as unverified until a concrete live domain is recorded below.
 */
const TXT = {
    'OpenAI API': 'openai-domain-verification=',
    'Claude Enterprise': 'anthropic-domain-verification-[a-z0-9]{6}=',
    Cursor: 'cursor-domain-verification-[a-z0-9]{6}=',
    'Perplexity Enterprise': 'perplexity-ai-domain-verification-[a-z0-9]{6}=',
    'Mistral AI': 'mistral-domain-verification=',
    'Anyscale': 'anyscale-domain-verification-[a-z0-9]{6}=',
    'Sourcegraph Amp': 'amp-by-sourcegraph-domain-verification-[a-z0-9]{6}=',
    Windsurf: 'windsurf-verification=',
    Wiz: 'wiz-domain-verification=',
    'Palo Alto Networks': 'paloaltonetworks-site-verification=',
    'Island Enterprise Browser': 'island-verification=',
    Detectify: 'detectify-verification=',
    HackerOne: 'h1-domain-verification=',
    Jamf: 'jamf-site-verification=',
    '1Password': '1password-site-verification=',
    'HashiCorp Cloud Platform': 'hcp-domain-verification=',
    Postman: 'postman-domain-verification=',
    'JetBrains IDEs': 'jetbrains-domain-verification=',
    Figma: 'figma-domain-verification=',
    Miro: 'miro-verification=',
    Canva: 'canva-site-verification=',
    Smartsheet: 'smartsheet-site-validation=',
    Wrike: 'wrike-verification=',
    Loom: 'loom-site-verification=',
    Coda: 'coda-verification=',
    'Monday.com': 'monday-com-verification=',
    'Box': 'box-domain-verification=',
    Dropbox: 'dropbox-domain-verification=',
    Autodesk: 'autodesk-domain-verification=',
    'Cisco Cloud': 'cisco-ci-domain-verification=',
    'HPE GreenLake': 'hpe-greenlake-domain-verification=',
    'Dell Technologies Cloud': 'dell-technologies-domain-verification=',
    'Zoho': 'zoho-verification=',
    TeamViewer: 'teamviewer-sso-verification=',
    Pendo: 'pendo-domain-verification=',
}

/**
 * Existing catalog entries that gain a TXT verification fingerprint. These are
 * merged into the entry rather than replacing it. Evidence quality is recorded
 * separately because the prior sweep is not reproducible.
 */
const TXT_ENRICH = {
    // The standard Microsoft 365 custom-domain verification record. The earlier
    // sweep reported 35 domains but did not retain the underlying records.
    // The entry already detects via outlook.com MX.
    'Microsoft 365': '^MS=ms\\d+',
    // Workspace-specific (GWS = Google Workspace); google-site-verification is
    // deliberately NOT used — Search Console sets it too, so it proves nothing
    // about Workspace tenancy.
    'Google Workspace': 'google-gws-recovery-domain-verification=',
    Notion: 'notion-domain-verification=',
    Zapier: 'zapier-domain-verification-challenge=',
    Airtable: 'airtable-verification=',
    Klaviyo: 'klaviyo-site-verification=',
    ClickUp: 'clickup-verification=',
    Docker: 'docker-verification=',
    Intercom: 'intercom-domain-validation=',
    MongoDB: 'mongodb-site-verification=',
    Dynatrace: 'dynatrace-site-verification=',
    LaunchDarkly: 'launchdarkly-domain-verification=',
    Linear: 'linear-domain-verification=',
    Netlify: 'netlify-domain-verification=',
    'GitLab': 'gitlab-pages-verification-code=',
    Segment: 'segment-site-verification=',
    Mixpanel: 'mixpanel-domain-verify=',
    OneTrust: 'onetrust-domain-verification=',
    DocuSign: 'docusign=',
    Stripe: 'stripe-verification=',
}

/**
 * New technologies. Kept as data so the shape is obvious and every entry goes
 * through the same validation as the rest of the catalog.
 */
const TECHNOLOGIES = {
    /* ------------------------------------------- fleet, IoT, connected ops */

    Samsara: {
        cats: [FLEET, IOT],
        description:
            'Samsara is a connected operations platform for fleet telematics, ' +
            'video-based driver safety, equipment monitoring and site visibility.',
        website: 'https://www.samsara.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        pricing: ['recurring', 'poa', 'enterprise'],
        // The customer-facing app and its asset host. Anchor the hostname so a
        // vendor name in an unrelated script path cannot trigger a detection.
        scriptSrc: '^https?://(?:static\\.)?cloud\\.samsara\\.com/',
        // A web app built on the Samsara API calls these hosts directly.
        xhr: 'api(?:\\.eu)?\\.samsara\\.com',
        // Live Sharing URLs include an organisation id and fleet/viewer path.
        // A generic sign-in or documentation link is not customer usage.
        dom: {
            "iframe[src*='cloud.samsara.com/o/'][src*='/fleet/viewer/']": {
                exists: '',
            },
            "a[href*='cloud.samsara.com/o/'][href*='/fleet/viewer/']": {
                exists: '',
            },
        },
    },

    'Samsara Assistant': {
        cats: [AI_AGENTS, FLEET],
        description:
            'Samsara Assistant is the AI assistant built into the Samsara ' +
            'connected operations platform.',
        website: 'https://www.samsara.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        // No detection channel by design. The ai-assistant bundle is present on
        // Samsara's public sign-in page, so it proves platform capability, not
        // that a customer has the product enabled.
    },

    'Verizon Connect': {
        cats: [FLEET, IOT],
        description:
            'Verizon Connect is a fleet management and telematics platform, ' +
            'covering the Reveal and Fleet (formerly Fleetmatics and Telogis) ' +
            'product lines.',
        website: 'https://www.verizonconnect.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        pricing: ['recurring', 'poa'],
        url: '^https?://(?:(?:login\\.)?[a-z]{2}\\.vzconnect\\.com|reveal(?:\\.[a-z]{2})?\\.fleetmatics\\.com)(?:/|$)',
        scriptSrc: [
            '^https?://(?:[^./]+\\.)*reveal\\.fleetmatics\\.com(?:/|$)',
            '^https?://(?:[^./]+\\.)*telogis\\.com(?:/|$)',
            '^https?://(?:[^./]+\\.)*verizonconnect\\.com/app(?:/|$)',
        ],
        xhr: ['reveal\\.fleetmatics\\.com', 'api\\.telogis\\.com'],
        dom: {
            "iframe[src*='fleetmatics.com']": { exists: '' },
            "iframe[src*='telogis.com']": { exists: '' },
            "a[href*='reveal.fleetmatics.com']": { exists: '' },
        },
    },

    'Verizon Connect Reveal': {
        cats: [FLEET],
        description:
            'Verizon Connect Reveal is the small and mid-sized fleet tracking ' +
            'product line, formerly Fleetmatics Reveal.',
        website: 'https://www.verizonconnect.com/products/reveal/',
        icon: 'default.svg',
        saas: true,
        oss: false,
        url: '^https?://(?:(?:login\\.)?[a-z]{2}\\.vzconnect\\.com|reveal(?:\\.[a-z]{2})?\\.fleetmatics\\.com)(?:/|$)',
        scriptSrc: '^https?://(?:[^./]+\\.)*reveal\\.fleetmatics\\.com(?:/|$)',
        implies: 'Verizon Connect',
    },

    Motive: {
        cats: [FLEET, IOT],
        description:
            'Motive (formerly KeepTruckin) is a fleet management platform for ' +
            'telematics, ELD compliance and AI dashcams.',
        website: 'https://gomotive.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        scriptSrc: 'gomotive\\.com',
        xhr: 'api\\.gomotive\\.com',
        dom: { "iframe[src*='gomotive.com']": { exists: '' } },
    },

    Geotab: {
        cats: [FLEET, IOT],
        description:
            'Geotab is a fleet telematics platform providing GPS tracking, ' +
            'driver safety and vehicle diagnostics.',
        website: 'https://www.geotab.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        scriptSrc: ['my\\.geotab\\.com', 'geotab\\.com/sdk'],
        xhr: 'my\\.geotab\\.com',
        dom: { "iframe[src*='my.geotab.com']": { exists: '' } },
    },

    Lytx: {
        cats: [FLEET],
        description:
            'Lytx provides video telematics and machine-vision driver safety ' +
            'for commercial fleets.',
        website: 'https://www.lytx.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.lytx\\.com',
        scriptSrc: 'lytx\\.com',
    },

    /* -------------------------------------------- generative AI platforms */

    'OpenAI API': {
        cats: [GEN_AI, AI],
        description:
            'The OpenAI API provides access to the GPT, DALL-E, Sora and ' +
            'Whisper model families.',
        website: 'https://platform.openai.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        pricing: ['payg'],
        // A browser calling the API directly, or a tenant verification record.
        xhr: 'api\\.openai\\.com',
        dns: { TXT: TXT['OpenAI API'] },
    },

    'Anthropic API': {
        cats: [GEN_AI, AI],
        description:
            'The Anthropic API provides access to the Claude model family.',
        website: 'https://docs.anthropic.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        pricing: ['payg'],
        xhr: 'api\\.anthropic\\.com',
    },

    'Claude Enterprise': {
        cats: [GEN_AI, AI_AGENTS, AI],
        description:
            'Claude Enterprise is Anthropic’s managed Claude deployment for ' +
            'organisations, with SSO and domain capture.',
        website: 'https://www.anthropic.com/enterprise',
        icon: 'default.svg',
        saas: true,
        oss: false,
        pricing: ['recurring', 'enterprise'],
        dns: { TXT: TXT['Claude Enterprise'] },
    },

    'Google Gemini API': {
        cats: [GEN_AI, AI],
        description:
            'The Google Gemini API provides access to the Gemini model family ' +
            'through Google AI Studio and Vertex AI.',
        website: 'https://ai.google.dev',
        icon: 'default.svg',
        saas: true,
        oss: false,
        pricing: ['payg', 'freemium'],
        xhr: 'generativelanguage\\.googleapis\\.com',
    },

    'Mistral AI': {
        cats: [GEN_AI, AI],
        description:
            'Mistral AI provides open-weight and commercial language models ' +
            'including Mistral Large, Codestral and Pixtral.',
        website: 'https://mistral.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.mistral\\.ai',
        dns: { TXT: TXT['Mistral AI'] },
    },

    Cohere: {
        cats: [GEN_AI, AI],
        description:
            'Cohere provides enterprise language models for generation, ' +
            'embedding and reranking.',
        website: 'https://cohere.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.cohere\\.(?:ai|com)',
    },

    Groq: {
        cats: [AI_INFRA, GEN_AI],
        description:
            'Groq provides low-latency language model inference on its LPU ' +
            'hardware via GroqCloud.',
        website: 'https://groq.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.groq\\.com',
    },

    'Together AI': {
        cats: [AI_INFRA, GEN_AI],
        description:
            'Together AI provides hosted inference and fine-tuning for open ' +
            'language models.',
        website: 'https://www.together.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.together\\.xyz',
    },

    DeepSeek: {
        cats: [GEN_AI, AI],
        description:
            'DeepSeek provides the DeepSeek V3, R1 and Coder language models.',
        website: 'https://www.deepseek.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.deepseek\\.com',
    },

    'Perplexity Enterprise': {
        cats: [GEN_AI, AI],
        description:
            'Perplexity Enterprise Pro is an AI answer engine for organisations.',
        website: 'https://www.perplexity.ai/enterprise',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.perplexity\\.ai',
        dns: { TXT: TXT['Perplexity Enterprise'] },
    },

    ElevenLabs: {
        cats: [GEN_AI, AI],
        description:
            'ElevenLabs provides AI voice synthesis, dubbing and conversational ' +
            'voice agents.',
        website: 'https://elevenlabs.io',
        icon: 'default.svg',
        saas: true,
        oss: false,
        // The conversational widget is a custom element on the host page.
        dom: { 'elevenlabs-convai': { exists: '' } },
        scriptSrc: 'elevenlabs\\.io/.*convai',
        xhr: 'api\\.elevenlabs\\.io',
        // Observed on live company domains as a tenant verification record.
        dns: { TXT: 'elevenlabs=' },
    },

    AssemblyAI: {
        cats: [AI_INFRA, AI],
        description:
            'AssemblyAI provides speech-to-text and audio intelligence APIs.',
        website: 'https://www.assemblyai.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.assemblyai\\.com',
    },

    Replicate: {
        cats: [AI_INFRA],
        description:
            'Replicate runs open-source machine learning models as hosted APIs.',
        website: 'https://replicate.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.replicate\\.com',
    },

    'Hugging Face': {
        cats: [AI_INFRA, AI_FRAMEWORKS],
        description:
            'Hugging Face hosts machine learning models, datasets and inference ' +
            'endpoints.',
        website: 'https://huggingface.co',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:api-inference|huggingface)\\.co',
        scriptSrc: 'huggingface\\.co',
    },

    /* --------------------------------------------------- vector databases */

    Pinecone: {
        cats: [VECTOR_DB, DATABASES],
        description: 'Pinecone is a managed vector database for AI retrieval.',
        website: 'https://www.pinecone.io',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '\\.pinecone\\.io',
    },

    Qdrant: {
        cats: [VECTOR_DB, DATABASES],
        description:
            'Qdrant is an open-source vector database and similarity search ' +
            'engine.',
        website: 'https://qdrant.tech',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '(?:api\\.)?qdrant\\.(?:tech|io)',
    },

    Weaviate: {
        cats: [VECTOR_DB, DATABASES],
        description: 'Weaviate is an open-source vector database.',
        website: 'https://weaviate.io',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '\\.weaviate\\.(?:io|network|cloud)',
    },

    Chroma: {
        cats: [VECTOR_DB, DATABASES],
        description:
            'Chroma is an open-source embedding database for AI applications.',
        website: 'https://www.trychroma.com',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: 'trychroma\\.com',
    },

    /* ------------------------------------------------- AI dev & frameworks */

    LangSmith: {
        cats: [AI_FRAMEWORKS, OBSERVABILITY],
        description:
            'LangSmith is LangChain’s tracing and evaluation platform for LLM ' +
            'applications.',
        website: 'https://www.langchain.com/langsmith',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.smith\\.langchain\\.com',
    },

    Anyscale: {
        cats: [AI_INFRA],
        description:
            'Anyscale is the managed Ray platform for distributed AI workloads.',
        website: 'https://www.anyscale.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Anyscale },
    },

    /* --------------------------------------------- AI coding & developer */

    Cursor: {
        cats: [AI_CODING, DEVELOPMENT],
        description:
            'Cursor is an AI code editor. The verification record indicates an ' +
            'organisation-managed Cursor deployment.',
        website: 'https://cursor.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Cursor },
    },

    Windsurf: {
        cats: [AI_CODING, DEVELOPMENT],
        description:
            'Windsurf (formerly Codeium) is an AI coding assistant and editor.',
        website: 'https://windsurf.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'server\\.codeium\\.com',
        dns: { TXT: TXT.Windsurf },
    },

    'Sourcegraph Amp': {
        cats: [AI_CODING, DEVELOPMENT],
        description:
            'Amp is Sourcegraph’s agentic coding tool for organisations.',
        website: 'https://sourcegraph.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT['Sourcegraph Amp'] },
    },

    Tabnine: {
        cats: [AI_CODING, DEVELOPMENT],
        description: 'Tabnine is an AI code completion assistant.',
        website: 'https://www.tabnine.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.tabnine\\.com',
    },

    'JetBrains IDEs': {
        cats: [DEVELOPMENT],
        description:
            'JetBrains develops IntelliJ IDEA, PyCharm, WebStorm and related ' +
            'developer tools.',
        website: 'https://www.jetbrains.com',
        icon: 'default.svg',
        saas: false,
        oss: false,
        dns: { TXT: TXT['JetBrains IDEs'] },
    },

    Postman: {
        cats: [DEVELOPMENT],
        description: 'Postman is an API development and testing platform.',
        website: 'https://www.postman.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.(?:get)?postman\\.com',
        dns: { TXT: TXT.Postman },
    },

    'HashiCorp Cloud Platform': {
        cats: [AI_INFRA, DEVELOPMENT],
        description:
            'HashiCorp Cloud Platform hosts managed Terraform, Vault, Consul ' +
            'and Boundary.',
        website: 'https://www.hashicorp.com/cloud',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT['HashiCorp Cloud Platform'] },
    },

    /* ---------------------------------------------- emerging cybersecurity */

    Wiz: {
        cats: [CLOUD_SECURITY, SECURITY],
        description:
            'Wiz is a cloud-native application protection platform covering ' +
            'CSPM, vulnerability management and AI-SPM.',
        website: 'https://www.wiz.io',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Wiz },
    },

    'Palo Alto Networks': {
        cats: [CLOUD_SECURITY, SECURITY],
        description:
            'Palo Alto Networks provides network and cloud security including ' +
            'Cortex XSIAM, Prisma and Precision AI.',
        website: 'https://www.paloaltonetworks.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT['Palo Alto Networks'] },
    },

    'Island Enterprise Browser': {
        cats: [CLOUD_SECURITY, SECURITY],
        description:
            'Island is an enterprise browser with built-in data protection and ' +
            'governance controls.',
        website: 'https://www.island.io',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT['Island Enterprise Browser'] },
    },

    HackerOne: {
        cats: [SECURITY],
        description:
            'HackerOne is a vulnerability disclosure and bug bounty platform.',
        website: 'https://www.hackerone.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.HackerOne },
    },

    Detectify: {
        cats: [SECURITY],
        description:
            'Detectify is an external attack surface management and web ' +
            'vulnerability scanning platform.',
        website: 'https://detectify.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Detectify },
    },

    Jamf: {
        cats: [SECURITY],
        description: 'Jamf provides Apple device management and endpoint security.',
        website: 'https://www.jamf.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Jamf },
    },

    '1Password': {
        cats: [SECURITY],
        description: '1Password is a password and secrets management platform.',
        website: 'https://1password.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT['1Password'] },
    },

    /* ------------------------------------------ data platforms & analytics */

    Snowflake: {
        cats: [DATA_PLATFORM, DATABASES],
        description:
            'Snowflake is a cloud data platform for warehousing, engineering ' +
            'and Cortex AI workloads.',
        website: 'https://www.snowflake.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '\\.snowflakecomputing\\.com',
        scriptSrc: 'app\\.snowflake\\.com',
    },

    ClickHouse: {
        cats: [DATA_PLATFORM, DATABASES],
        description:
            'ClickHouse is a column-oriented database for real-time analytics.',
        website: 'https://clickhouse.com',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '\\.clickhouse\\.(?:cloud|com)',
    },

    CockroachDB: {
        cats: [DATABASES],
        description:
            'CockroachDB is a distributed SQL database with horizontal scaling.',
        website: 'https://www.cockroachlabs.com',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '\\.cockroachlabs\\.cloud',
    },

    Neon: {
        cats: [DATABASES, DATA_PLATFORM],
        description: 'Neon is a serverless Postgres platform.',
        website: 'https://neon.tech',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '\\.neon\\.tech',
    },

    Turso: {
        cats: [DATABASES],
        description: 'Turso is an edge-hosted SQLite database platform.',
        website: 'https://turso.tech',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '\\.turso\\.io',
    },

    /* ------------------------------------- AI agents inside existing SaaS */

    Glean: {
        cats: [AI_AGENTS, GEN_AI],
        description:
            'Glean is an enterprise search and AI assistant platform indexing ' +
            'internal company knowledge.',
        website: 'https://www.glean.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        scriptSrc: 'app\\.glean\\.com',
        xhr: '\\.glean\\.com',
        dom: { "iframe[src*='glean.com']": { exists: '' } },
    },

    '6sense': {
        cats: [ANALYTICS, CRM],
        description:
            '6sense Revenue AI is an account-based marketing and predictive ' +
            'intelligence platform.',
        website: 'https://6sense.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        scriptSrc: ['j\\.6sc\\.co', 'epsilon\\.6sense\\.com'],
        xhr: 'epsilon\\.6sense\\.com',
    },

    /* ------------------------------------------- collaboration & workflow */

    Figma: {
        cats: [DEVELOPMENT, COLLABORATION],
        description:
            'Figma is a collaborative interface design platform. Figma AI adds ' +
            'generative design features.',
        website: 'https://www.figma.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Figma },
        dom: { "iframe[src*='figma.com/embed']": { exists: '' } },
        scriptSrc: '(?:www\\.)?figma\\.com/embed',
    },

    Miro: {
        cats: [COLLABORATION],
        description:
            'Miro is a collaborative whiteboard platform. Miro AI adds ' +
            'generative diagramming and summarisation.',
        website: 'https://miro.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Miro },
        dom: { "iframe[src*='miro.com/app/live-embed']": { exists: '' } },
        scriptSrc: 'miro\\.com/app/live-embed',
    },

    Canva: {
        cats: [COLLABORATION, DMS],
        description:
            'Canva is a visual design platform. Canva Magic Studio adds ' +
            'generative design tools.',
        website: 'https://www.canva.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Canva },
        dom: { "iframe[src*='canva.com/design']": { exists: '' } },
    },

    Coda: {
        cats: [COLLABORATION, DMS],
        description:
            'Coda is a collaborative document and application platform.',
        website: 'https://coda.io',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Coda },
        dom: { "iframe[src*='coda.io/embed']": { exists: '' } },
    },

    'Monday.com': {
        cats: [ISSUE_TRACKERS, COLLABORATION],
        description:
            'monday.com is a work management platform. Monday AI adds ' +
            'generative automation and summarisation.',
        website: 'https://monday.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT['Monday.com'] },
        xhr: 'api\\.monday\\.com',
    },

    Box: {
        cats: [DMS],
        description:
            'Box is a content management and collaboration platform. Box AI ' +
            'adds document question answering and agents.',
        website: 'https://www.box.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Box },
        xhr: 'api\\.box\\.com',
        dom: { "iframe[src*='.box.com/embed']": { exists: '' } },
    },

    Dropbox: {
        cats: [DMS],
        description:
            'Dropbox is a file storage and collaboration platform. Dropbox ' +
            'Dash adds AI-powered universal search.',
        website: 'https://www.dropbox.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Dropbox },
        xhr: 'api\\.dropboxapi\\.com',
        scriptSrc: 'www\\.dropbox\\.com/static/api',
    },

    Smartsheet: {
        cats: [COLLABORATION, ISSUE_TRACKERS],
        description: 'Smartsheet is a work and project management platform.',
        website: 'https://www.smartsheet.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Smartsheet },
        dom: { "iframe[src*='smartsheet.com']": { exists: '' } },
    },

    Wrike: {
        cats: [COLLABORATION, ISSUE_TRACKERS],
        description: 'Wrike is a collaborative work management platform.',
        website: 'https://www.wrike.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Wrike },
    },

    Loom: {
        cats: [COLLABORATION],
        description:
            'Loom is an async video messaging platform with AI summaries.',
        website: 'https://www.loom.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Loom },
        dom: { "iframe[src*='loom.com/embed']": { exists: '' } },
    },

    Autodesk: {
        cats: [DEVELOPMENT],
        description:
            'Autodesk provides design and engineering software including AutoCAD, ' +
            'Revit and Fusion, with AI assistants across the portfolio.',
        website: 'https://www.autodesk.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Autodesk },
    },

    TeamViewer: {
        cats: [46],
        description: 'TeamViewer is a remote access and support platform.',
        website: 'https://www.teamviewer.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.TeamViewer },
    },

    Pendo: {
        cats: [ANALYTICS, 58],
        description:
            'Pendo is a product analytics and in-app guidance platform.',
        website: 'https://www.pendo.io',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Pendo },
        scriptSrc: 'cdn\\.pendo\\.io',
    },

    'Cisco Cloud': {
        cats: [AI_INFRA, SECURITY],
        description:
            'Cisco cloud services, covering Intersight, Duo, Umbrella and the ' +
            'Cisco AI Assistant portfolio.',
        website: 'https://www.cisco.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT['Cisco Cloud'] },
    },

    'HPE GreenLake': {
        cats: [AI_INFRA, 63],
        description:
            'HPE GreenLake is Hewlett Packard Enterprise’s hybrid cloud and ' +
            'AI infrastructure platform.',
        website: 'https://www.hpe.com/greenlake',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT['HPE GreenLake'] },
    },

    'Dell Technologies Cloud': {
        cats: [AI_INFRA, 63],
        description:
            'Dell Technologies cloud and AI infrastructure services, including ' +
            'the Dell AI Factory.',
        website: 'https://www.dell.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT['Dell Technologies Cloud'] },
    },

    Zoho: {
        cats: [CRM, COLLABORATION],
        description:
            'Zoho is a business application suite. Zoho Zia is its embedded AI ' +
            'assistant.',
        website: 'https://www.zoho.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: TXT.Zoho },
    },

    Slack: {
        cats: [COLLABORATION, LIVE_CHAT],
        description:
            'Slack is a team messaging platform. Slack AI adds conversation ' +
            'summaries and search.',
        website: 'https://slack.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: 'slack-domain-verification=' },
        scriptSrc: ['a\\.slack-edge\\.com', 'slack\\.com/.*\\.js'],
        dom: {
            "a[href*='slack.com/oauth']": { exists: '' },
            "img[src*='platform.slack-edge.com/img/add_to_slack']": { exists: '' },
        },
    },

    Zoom: {
        cats: [COLLABORATION, 103],
        description:
            'Zoom is a video conferencing platform. Zoom AI Companion adds ' +
            'meeting summaries and generative assistance.',
        website: 'https://zoom.us',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: 'zoom-domain-verification=' },
        scriptSrc: ['source\\.zoom\\.us', 'st1\\.zoom\\.us'],
        dom: { "a[href*='zoom.us/j/']": { exists: '' } },
    },

    'Atlassian Cloud': {
        cats: [ISSUE_TRACKERS, COLLABORATION],
        description:
            'Atlassian Cloud hosts Jira, Confluence, Bitbucket and the ' +
            'Atlassian Intelligence and Rovo AI features.',
        website: 'https://www.atlassian.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: 'atlassian-domain-verification=' },
        xhr: 'api\\.atlassian\\.com',
        scriptSrc: '\\.atlassian\\.net',
    },

    GitHub: {
        cats: [DEVELOPMENT],
        description:
            'GitHub is a code hosting and collaboration platform. GitHub ' +
            'Copilot and Actions are delivered through it.',
        website: 'https://github.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        // Deliberately narrow: a link to a repository says nothing about whether
        // the company runs on GitHub, so only GitHub-served assets and direct API
        // calls count.
        scriptSrc: 'github\\.githubassets\\.com',
        xhr: 'api\\.github\\.com',
    },

    /* -------------------------------- cloud AI services called from browsers */

    'Amazon Bedrock': {
        cats: [GEN_AI, AI_INFRA],
        description:
            'Amazon Bedrock provides managed access to foundation models on ' +
            'AWS. Detected when a page calls the Bedrock runtime directly.',
        website: 'https://aws.amazon.com/bedrock/',
        icon: 'default.svg',
        saas: true,
        oss: false,
        pricing: ['payg'],
        xhr: 'bedrock(?:-runtime|-agent-runtime)?\\.[a-z0-9-]+\\.amazonaws\\.com',
    },

    'Google Vertex AI': {
        cats: [GEN_AI, AI_INFRA],
        description:
            'Google Vertex AI is Google Cloud’s managed machine learning and ' +
            'generative AI platform. Detected when a page calls its endpoints.',
        website: 'https://cloud.google.com/vertex-ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        pricing: ['payg'],
        xhr: '(?:[a-z0-9-]+-)?aiplatform\\.googleapis\\.com',
    },

    'Azure OpenAI Service': {
        cats: [GEN_AI, AI_INFRA],
        description:
            'Azure OpenAI Service hosts OpenAI models inside Microsoft Azure. ' +
            'Detected when a page calls a resource endpoint directly.',
        website: 'https://azure.microsoft.com/products/ai-services/openai-service',
        icon: 'default.svg',
        saas: true,
        oss: false,
        pricing: ['payg'],
        xhr: '\\.openai\\.azure\\.com|\\.cognitiveservices\\.azure\\.com',
    },

    'NVIDIA NIM': {
        cats: [AI_INFRA],
        description:
            'NVIDIA NIM provides hosted inference microservices for NVIDIA ' +
            'accelerated models.',
        website: 'https://www.nvidia.com/en-us/ai/',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'integrate\\.api\\.nvidia\\.com',
    },

    'IBM watsonx': {
        cats: [GEN_AI, AI_INFRA],
        description:
            'IBM watsonx is IBM’s enterprise AI platform covering watsonx.ai, ' +
            'watsonx.data and watsonx.governance.',
        website: 'https://www.ibm.com/watsonx',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '\\.ml\\.cloud\\.ibm\\.com',
    },

    /* --------------------------------------- AI writing, media & assistants */

    Writer: {
        cats: [GEN_AI, AI_AGENTS],
        description:
            'Writer is an enterprise generative AI platform for content and ' +
            'agent workflows.',
        website: 'https://writer.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.writer\\.com',
    },

    'Copy.ai': {
        cats: [GEN_AI],
        description:
            'Copy.ai is a generative AI platform for go-to-market content and ' +
            'workflows.',
        website: 'https://www.copy.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.copy\\.ai',
    },

    Jasper: {
        cats: [GEN_AI],
        description: 'Jasper is a generative AI platform for marketing content.',
        website: 'https://www.jasper.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.jasper\\.ai',
    },

    'Otter.ai': {
        cats: [GEN_AI, COLLABORATION],
        description:
            'Otter.ai provides AI meeting transcription, summaries and chat.',
        website: 'https://otter.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.otter\\.ai',
        dom: { "iframe[src*='otter.ai']": { exists: '' } },
    },

    Descript: {
        cats: [GEN_AI, COLLABORATION],
        description:
            'Descript is an AI audio and video editor. Published projects are ' +
            'embedded from its share host.',
        website: 'https://www.descript.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        scriptSrc: 'share\\.descript\\.com',
        dom: { "iframe[src*='share.descript.com']": { exists: '' } },
    },

    Grammarly: {
        cats: [GEN_AI],
        description:
            'Grammarly is an AI writing assistant. The Text Editor SDK embeds ' +
            'it into web applications.',
        website: 'https://www.grammarly.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        scriptSrc: 'js\\.grammarly\\.com',
        dom: { 'grammarly-editor-plugin': { exists: '' } },
    },

    Harvey: {
        cats: [GEN_AI, AI_AGENTS],
        description: 'Harvey is a generative AI platform for legal work.',
        website: 'https://www.harvey.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.harvey\\.ai',
    },

    'Character.AI': {
        cats: [GEN_AI],
        description:
            'Character.AI is a conversational AI platform for persona-based ' +
            'chat.',
        website: 'https://character.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:^|\\.)character\\.ai',
    },

    Tome: {
        cats: [GEN_AI, COLLABORATION],
        description: 'Tome is an AI-native presentation and storytelling tool.',
        website: 'https://tome.app',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'tome\\.app',
        dom: { "iframe[src*='tome.app']": { exists: '' } },
    },

    'You.com': {
        cats: [GEN_AI],
        description: 'You.com is an AI search and agent platform with an API.',
        website: 'https://you.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.you\\.com',
    },

    Moveworks: {
        cats: [AI_AGENTS],
        description:
            'Moveworks is an agentic AI assistant for employee support.',
        website: 'https://www.moveworks.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.moveworks\\.ai',
    },

    /* --------------------------------------------------- workflow automation */

    Make: {
        cats: [AUTOMATION],
        description:
            'Make (formerly Integromat) is a visual workflow automation ' +
            'platform. Scenario webhooks are called directly from pages.',
        website: 'https://www.make.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'hook\\.[a-z0-9-]+\\.make\\.com',
        dns: { TXT: 'make-domain-verification=' },
    },

    Workato: {
        cats: [AUTOMATION],
        description:
            'Workato is an enterprise integration and workflow automation ' +
            'platform.',
        website: 'https://www.workato.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:webhooks|apim)\\.workato\\.com',
    },

    'Tray.io': {
        cats: [AUTOMATION],
        description:
            'Tray.io is a general automation platform with embedded ' +
            'integration experiences.',
        website: 'https://tray.io',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.tray\\.io',
        scriptSrc: 'embedded\\.tray\\.io',
    },

    Tines: {
        cats: [AUTOMATION, SECURITY],
        description:
            'Tines is a workflow automation platform for security and ' +
            'operations teams.',
        website: 'https://www.tines.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '\\.tines\\.com',
    },

    UiPath: {
        cats: [AUTOMATION, AI_AGENTS],
        description:
            'UiPath is an agentic automation and RPA platform delivered ' +
            'through UiPath Automation Cloud.',
        website: 'https://www.uipath.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:cloud|api)\\.uipath\\.com',
        scriptSrc: 'cloud\\.uipath\\.com',
    },

    /* ----------------------------------------------- low-code & analytics */

    Appsmith: {
        cats: [51, DEVELOPMENT],
        description:
            'Appsmith is an open-source low-code platform for internal tools.',
        website: 'https://www.appsmith.com',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: 'app\\.appsmith\\.com',
        dom: { "iframe[src*='app.appsmith.com']": { exists: '' } },
    },

    Superblocks: {
        cats: [51, DEVELOPMENT],
        description:
            'Superblocks is a programmable low-code platform for internal ' +
            'applications.',
        website: 'https://www.superblocks.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:app|agent)\\.superblocks\\.com',
    },

    Hex: {
        cats: [BI, ANALYTICS],
        description:
            'Hex is a collaborative analytics and data science workspace. ' +
            'Published apps are embedded from app.hex.tech.',
        website: 'https://hex.tech',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'app\\.hex\\.tech',
        dom: { "iframe[src*='app.hex.tech']": { exists: '' } },
    },

    Observable: {
        cats: [BI, ANALYTICS],
        description:
            'Observable is a data visualisation and notebook platform. ' +
            'Notebooks are embedded from observablehq.com.',
        website: 'https://observablehq.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        scriptSrc: 'observablehq\\.com|static\\.observableusercontent\\.com',
        dom: { "iframe[src*='observablehq.com']": { exists: '' } },
    },

    DuckDB: {
        cats: [DATABASES],
        description:
            'DuckDB is an in-process analytical database. DuckDB-Wasm runs it ' +
            'inside the browser.',
        website: 'https://duckdb.org',
        icon: 'default.svg',
        saas: false,
        oss: true,
        scriptSrc: '@duckdb/duckdb-wasm|duckdb-(?:eh|mvp)\\.wasm',
    },

    Unleash: {
        cats: [85],
        description:
            'Unleash is an open-source feature management platform. Frontend ' +
            'SDKs call the Unleash frontend API from the browser.',
        website: 'https://www.getunleash.io',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '\\.getunleash\\.io',
    },

    Honeycomb: {
        cats: [OBSERVABILITY],
        description:
            'Honeycomb is an observability platform. Browser instrumentation ' +
            'sends events to its ingest API.',
        website: 'https://www.honeycomb.io',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.honeycomb\\.io',
    },

    /* ----------------------------------------------------- CI badge evidence */

    CircleCI: {
        cats: [44],
        description:
            'CircleCI is a continuous integration platform. Status badges are ' +
            'served from its badge hosts.',
        website: 'https://circleci.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dom: {
            "img[src*='circleci.com/gh/']": { exists: '' },
            "img[src*='dl.circleci.com/status-badge']": { exists: '' },
        },
    },

    Buildkite: {
        cats: [44],
        description:
            'Buildkite is a CI/CD platform. Status badges are served from ' +
            'badge.buildkite.com.',
        website: 'https://buildkite.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dom: { "img[src*='badge.buildkite.com']": { exists: '' } },
    },

    Outreach: {
        cats: [CRM, 32],
        description:
            'Outreach is a sales engagement platform. Outreach Kaia is its ' +
            'AI meeting assistant.',
        website: 'https://www.outreach.io',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.outreach\\.io',
    },

    Clari: {
        cats: [CRM, ANALYTICS],
        description:
            'Clari is a revenue intelligence platform. Clari Copilot records ' +
            'and analyses customer conversations.',
        website: 'https://www.clari.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:api|app|copilot)\\.clari\\.com',
    },

    'Intuit QuickBooks': {
        cats: [55],
        description:
            'Intuit QuickBooks is an accounting platform. The Connect to ' +
            'QuickBooks flow and API are called from integrating web apps.',
        website: 'https://quickbooks.intuit.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:appcenter|(?:quickbooks\\.)?api)\\.intuit\\.com',
        scriptSrc: 'plugin\\.intuitcdn\\.net',
        dom: { "a[href*='appcenter.intuit.com']": { exists: '' } },
    },

    /* ====================================================================
     * Self-hosted web UIs.
     *
     * These are the "back-end" tools. The engine itself is
     * invisible from outside, but each ships an operator UI that is routinely
     * exposed on a subdomain (airflow.company.com, metabase.company.com), and
     * that UI is detectable.
     *
     * Patterns are taken from each project's shipped index template, not
     * guessed, and are anchored either to a unique DOM id/class or to the
     * <title> element. Anchoring to <title> matters: a bare vendor name in the
     * page body would also match a blog post about the tool, whereas a title tag
     * would not.
     * ================================================================== */

    'Apache Airflow': {
        cats: [AUTOMATION, DATA_PLATFORM],
        description:
            'Apache Airflow is a platform to author, schedule and monitor data ' +
            'workflows. Detected from its exposed web UI.',
        website: 'https://airflow.apache.org',
        icon: 'default.svg',
        saas: false,
        oss: true,
        cpe: 'cpe:2.3:a:apache:airflow:*:*:*:*:*:*:*:*',
        // Shipped in airflow/ui/index.html.
        html: [
            '<title>\\s*Airflow\\s*</title>',
            'href="/static/pin_32\\.png"',
        ],
    },

    'Apache Superset': {
        cats: [BI, ANALYTICS],
        description:
            'Apache Superset is a data exploration and visualisation platform. ' +
            'Detected from its exposed web UI.',
        website: 'https://superset.apache.org',
        icon: 'default.svg',
        saas: false,
        oss: true,
        cpe: 'cpe:2.3:a:apache:superset:*:*:*:*:*:*:*:*',
        // From superset/templates/superset/spa.html: the app root carries a
        // data-bootstrap payload, which no other tool here does.
        html: [
            '<title>[^<]*Superset[^<]*</title>',
            '<div[^>]+id="app"[^>]+data-bootstrap=',
        ],
    },

    MLflow: {
        cats: [AI_INFRA, AI_FRAMEWORKS],
        description:
            'MLflow is a platform for managing the machine learning lifecycle. ' +
            'Detected from its exposed tracking server UI.',
        website: 'https://mlflow.org',
        icon: 'default.svg',
        saas: false,
        oss: true,
        // `mlflow-ui-container` is unique to MLflow's index.html.
        html: [
            'class="mlflow-ui-container"',
            '<title>\\s*MLflow\\s*</title>',
        ],
    },

    ArgoCD: {
        cats: [44, 60],
        description:
            'Argo CD is a declarative GitOps continuous delivery tool for ' +
            'Kubernetes. Detected from its exposed web UI.',
        website: 'https://argo-cd.readthedocs.io',
        icon: 'default.svg',
        saas: false,
        oss: true,
        cpe: 'cpe:2.3:a:argoproj:argo-cd:*:*:*:*:*:*:*:*',
        html: [
            '<title>\\s*Argo CD\\s*</title>',
            "href='assets/favicon/favicon-32x32\\.png'",
        ],
        cookies: { 'argocd.token': '' },
    },

    Metabase: {
        cats: [BI, ANALYTICS],
        description:
            'Metabase is an open-source business intelligence and dashboarding ' +
            'tool. Detected from its exposed web UI.',
        website: 'https://www.metabase.com',
        icon: 'default.svg',
        saas: true,
        oss: true,
        cpe: 'cpe:2.3:a:metabase:metabase:*:*:*:*:*:*:*:*',
        // The bootstrap script id is unique to Metabase's index template.
        html: 'id="_metabaseBootstrap"',
        cookies: { 'metabase.SESSION': '' },
    },

    Prometheus: {
        cats: [OBSERVABILITY, ANALYTICS],
        description:
            'Prometheus is a monitoring system and time series database. ' +
            'Detected from its exposed web UI.',
        website: 'https://prometheus.io',
        icon: 'default.svg',
        saas: false,
        oss: true,
        cpe: 'cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*',
        // Placeholders the Prometheus binary substitutes when serving its UI.
        html: [
            'GLOBAL_LOOKBACKDELTA',
            'GLOBAL_AGENT_MODE',
            '<title>\\s*Prometheus Time Series',
        ],
    },

    Prefect: {
        cats: [AUTOMATION, DATA_PLATFORM],
        description:
            'Prefect is a workflow orchestration platform for data pipelines. ' +
            'Detected from its exposed server UI or Prefect Cloud API.',
        website: 'https://www.prefect.io',
        icon: 'default.svg',
        saas: true,
        oss: true,
        html: [
            '<title>\\s*Prefect Server\\s*</title>',
            'href="/ico/favicon-32x32-dark\\.png"',
        ],
        xhr: 'api\\.prefect\\.cloud',
    },

    Airbyte: {
        cats: [DATA_PLATFORM, AUTOMATION],
        description:
            'Airbyte is an open-source data integration platform. Its web UI ' +
            'publishes the running version as a meta tag.',
        website: 'https://airbyte.com',
        icon: 'default.svg',
        saas: true,
        oss: true,
        // Airbyte is one of the few tools here that exposes a real version
        // number rather than a content hash.
        meta: { 'airbyte:version': '^([\\d.]+[\\w.-]*)$\\;version:\\1' },
        html: [
            'name="airbyte:sec-token"',
            '<title>\\s*Airbyte\\s*</title>',
        ],
        xhr: 'api\\.airbyte\\.com',
    },

    Kiali: {
        cats: [OBSERVABILITY, 60],
        description:
            'Kiali is the observability console for the Istio service mesh. ' +
            'Its presence indicates Istio is in use.',
        website: 'https://kiali.io',
        icon: 'default.svg',
        saas: false,
        oss: true,
        html: [
            '<title>\\s*Kiali\\s*</title>',
            'kiali_icon_lightbkg_16px\\.png',
        ],
        implies: 'Istio',
    },

    Istio: {
        cats: [60, 64],
        description:
            'Istio is a service mesh for Kubernetes. Its ingress gateway ' +
            'identifies itself in the Server response header.',
        website: 'https://istio.io',
        icon: 'default.svg',
        saas: false,
        oss: true,
        cpe: 'cpe:2.3:a:istio:istio:*:*:*:*:*:*:*:*',
        headers: { server: '^istio-envoy$' },
    },

    Ray: {
        cats: [AI_INFRA, AI_FRAMEWORKS],
        description:
            'Ray is a distributed computing framework for AI and Python ' +
            'workloads. Detected from its exposed dashboard.',
        website: 'https://www.ray.io',
        icon: 'default.svg',
        saas: false,
        oss: true,
        html: '<title>\\s*Ray Dashboard\\s*</title>',
    },

    Kubeflow: {
        cats: [AI_INFRA, AI_FRAMEWORKS],
        description:
            'Kubeflow is a machine learning toolkit for Kubernetes. Detected ' +
            'from its exposed central dashboard.',
        website: 'https://www.kubeflow.org',
        icon: 'default.svg',
        saas: false,
        oss: true,
        html: [
            '<title>\\s*Kubeflow Central Dashboard\\s*</title>',
            'content="Kubeflow Central Dashboard"',
        ],
    },

    /* ------------------------------------- managed data & ML control planes */

    'Weights & Biases': {
        cats: [AI_INFRA, OBSERVABILITY],
        description:
            'Weights & Biases is an experiment tracking and model management ' +
            'platform. Reports are embedded from wandb.ai.',
        website: 'https://wandb.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:api\\.)?wandb\\.ai',
        dom: { "iframe[src*='wandb.ai']": { exists: '' } },
    },

    Pulumi: {
        cats: [60, DEVELOPMENT],
        description:
            'Pulumi is an infrastructure-as-code platform. Pulumi Cloud is its ' +
            'managed control plane.',
        website: 'https://www.pulumi.com',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '(?:api|app)\\.pulumi\\.com',
    },

    Dagster: {
        cats: [AUTOMATION, DATA_PLATFORM],
        description:
            'Dagster is a data orchestration platform. Dagster+ is its managed ' +
            'control plane.',
        website: 'https://dagster.io',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '(?:api|app)\\.dagster\\.cloud',
    },

    dbt: {
        cats: [DATA_PLATFORM],
        description:
            'dbt is a data transformation framework. dbt Cloud is its managed ' +
            'platform.',
        website: 'https://www.getdbt.com',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '(?:metadata\\.)?cloud\\.getdbt\\.com',
    },

    Fivetran: {
        cats: [DATA_PLATFORM],
        description:
            'Fivetran is a managed data pipeline and ELT platform.',
        website: 'https://www.fivetran.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.fivetran\\.com',
    },

    Modal: {
        cats: [AI_INFRA],
        description:
            'Modal is a serverless platform for running AI and compute ' +
            'workloads.',
        website: 'https://modal.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.modal\\.com',
    },

    DataRobot: {
        cats: [AI_INFRA, GEN_AI],
        description:
            'DataRobot is an enterprise AI platform for building and operating ' +
            'machine learning models.',
        website: 'https://www.datarobot.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'app\\.datarobot\\.com',
    },

    'Apache Spark': {
        cats: [DATA_PLATFORM, AI_INFRA],
        description:
            'Apache Spark is a distributed data processing engine. Detected ' +
            'from its exposed application or History Server UI.',
        website: 'https://spark.apache.org',
        icon: 'default.svg',
        saas: false,
        oss: true,
        cpe: 'cpe:2.3:a:apache:spark:*:*:*:*:*:*:*:*',
        // Asset paths emitted by org.apache.spark.ui.UIUtils.
        html: [
            '/static/spark-dag-viz\\.js',
            '/static/spark-logo\\.svg',
            'class="spark-logo"',
        ],
    },

    'Apache Flink': {
        cats: [DATA_PLATFORM, AI_INFRA],
        description:
            'Apache Flink is a stream processing framework. Detected from its ' +
            'exposed web dashboard.',
        website: 'https://flink.apache.org',
        icon: 'default.svg',
        saas: false,
        oss: true,
        cpe: 'cpe:2.3:a:apache:flink:*:*:*:*:*:*:*:*',
        html: '<title>\\s*Apache Flink Web Dashboard\\s*</title>',
    },

    'Apache Kafka': {
        cats: [DATA_PLATFORM],
        description:
            'Apache Kafka is a distributed event streaming platform. Confluent ' +
            'Cloud is its managed offering.',
        website: 'https://kafka.apache.org',
        icon: 'default.svg',
        saas: true,
        oss: true,
        cpe: 'cpe:2.3:a:apache:kafka:*:*:*:*:*:*:*:*',
        xhr: '\\.confluent\\.cloud',
    },

    Rancher: {
        cats: [60],
        description:
            'Rancher is a Kubernetes management platform. Detected from its ' +
            'exposed dashboard.',
        website: 'https://www.rancher.com',
        icon: 'default.svg',
        saas: false,
        oss: true,
        html: [
            '<title>\\s*Rancher\\s*</title>',
            '<div[^>]+id="slides"',
        ],
        implies: 'Kubernetes',
    },

    'Kedro-Viz': {
        cats: [AI_FRAMEWORKS, DATA_PLATFORM],
        description:
            'Kedro-Viz visualises Kedro data science pipelines. Its presence ' +
            'indicates Kedro.',
        website: 'https://github.com/kedro-org/kedro-viz',
        icon: 'default.svg',
        saas: false,
        oss: true,
        html: [
            '<title>\\s*Kedro-Viz\\s*</title>',
            'content="Kedro-Viz is an interactive development tool',
        ],
        implies: 'Kedro',
    },

    Kedro: {
        cats: [AI_FRAMEWORKS],
        description:
            'Kedro is a Python framework for reproducible data science ' +
            'pipelines. Reported when Kedro-Viz is detected.',
        website: 'https://kedro.org',
        icon: 'default.svg',
        saas: false,
        oss: true,
    },

    'AutoGPT Platform': {
        cats: [AI_AGENTS, AI_FRAMEWORKS],
        description:
            'AutoGPT is an autonomous AI agent platform. Detected from its ' +
            'exposed web frontend.',
        website: 'https://agpt.co',
        icon: 'default.svg',
        saas: false,
        oss: true,
        html: '<title>\\s*AutoGPT Platform\\s*</title>',
    },

    'PTC ThingWorx': {
        cats: [IOT, 45],
        description:
            'PTC ThingWorx is an industrial IoT platform. Its Composer and ' +
            'runtime are served under a fixed path.',
        website: 'https://www.ptc.com/en/products/thingworx',
        icon: 'default.svg',
        saas: true,
        oss: false,
        url: '/Thingworx(?:/|$)',
        xhr: 'thingworx\\.ptc\\.com',
    },

    // Kubernetes has no fingerprint of its own — the API server is not exposed
    // to visitors. It exists so the consoles below can imply it, which is how it
    // becomes reportable.
    Kubernetes: {
        cats: [60],
        description:
            'Kubernetes is a container orchestration platform. It is not ' +
            'directly observable and is reported when a management console or ' +
            'distribution that runs on it is detected.',
        website: 'https://kubernetes.io',
        icon: 'default.svg',
        saas: false,
        oss: true,
        cpe: 'cpe:2.3:a:kubernetes:kubernetes:*:*:*:*:*:*:*:*',
    },

    'Kubernetes Dashboard': {
        cats: [60],
        description:
            'The Kubernetes Dashboard is the general-purpose web UI for ' +
            'Kubernetes clusters. Its presence indicates Kubernetes.',
        website: 'https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/',
        icon: 'default.svg',
        saas: false,
        oss: true,
        html: '<title>\\s*Kubernetes Dashboard\\s*</title>',
        implies: 'Kubernetes',
    },

    'Red Hat OpenShift': {
        cats: [60, 62],
        description:
            'Red Hat OpenShift is an enterprise Kubernetes platform. Detected ' +
            'from its exposed web console.',
        website: 'https://www.redhat.com/en/technologies/cloud-computing/openshift',
        icon: 'default.svg',
        saas: true,
        oss: true,
        // Titles shipped in openshift/console frontend/public/index.html.
        html: [
            '<title>\\s*Red Hat OpenShift(?:\\s+(?:Online|Dedicated))?\\s*</title>',
            '<title>\\s*OKD\\s*</title>',
        ],
        xhr: 'api\\.openshift\\.com|console\\.redhat\\.com',
        implies: 'Kubernetes',
    },

    /* ------------------------------- hosted control planes & embed surfaces */

    'Azure AI Foundry': {
        cats: [GEN_AI, AI_INFRA],
        description:
            'Azure AI Foundry (formerly Azure Machine Learning studio) is ' +
            'Microsoft’s platform for building and operating AI applications.',
        website: 'https://ai.azure.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:ml|ai)\\.azure\\.com',
    },

    'Azure Synapse Analytics': {
        cats: [DATA_PLATFORM, DATABASES],
        description:
            'Azure Synapse Analytics is Microsoft’s analytics and data ' +
            'warehousing service.',
        website: 'https://azure.microsoft.com/products/synapse-analytics',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '\\.azuresynapse\\.net',
    },

    'Amazon Q': {
        cats: [AI_AGENTS, GEN_AI],
        description:
            'Amazon Q is AWS’s generative AI assistant. Q Business web ' +
            'experiences are hosted on AWS-owned domains.',
        website: 'https://aws.amazon.com/q/',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'qbusiness\\.[a-z0-9-]+\\.on\\.aws|q\\.[a-z0-9-]+\\.amazonaws\\.com',
    },

    'NVIDIA AI Enterprise': {
        cats: [AI_INFRA],
        description:
            'NVIDIA AI Enterprise packages NVIDIA’s AI software, including NIM ' +
            'and NeMo, delivered through its build and cloud-function hosts.',
        website: 'https://www.nvidia.com/en-us/data-center/products/ai-enterprise/',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:build|api\\.nvcf)\\.nvidia\\.com',
    },

    'Qualcomm AI Hub': {
        cats: [AI_INFRA],
        description:
            'Qualcomm AI Hub provides model optimisation and deployment for ' +
            'Qualcomm hardware.',
        website: 'https://aihub.qualcomm.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'aihub\\.qualcomm\\.com',
    },

    'C3 AI': {
        cats: [GEN_AI, AI_INFRA],
        description:
            'C3 AI is an enterprise AI application platform, including C3 ' +
            'Generative AI.',
        website: 'https://c3.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:^|\\.)c3\\.ai',
    },

    'H2O.ai': {
        cats: [AI_INFRA, GEN_AI],
        description:
            'H2O.ai provides machine learning and generative AI platforms ' +
            'including h2oGPTe.',
        website: 'https://h2o.ai',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '\\.h2o\\.ai',
    },


    'Sigma Computing': {
        cats: [BI, ANALYTICS],
        description:
            'Sigma Computing is a cloud analytics and BI platform whose ' +
            'workbooks are embedded into host applications.',
        website: 'https://www.sigmacomputing.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:api|app)\\.sigmacomputing\\.com',
        dom: { "iframe[src*='sigmacomputing.com']": { exists: '' } },
    },

    ThoughtSpot: {
        cats: [BI, ANALYTICS],
        description:
            'ThoughtSpot is a search and AI-driven analytics platform. Its ' +
            'Visual Embed SDK embeds Liveboards into host applications.',
        website: 'https://www.thoughtspot.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '\\.thoughtspot\\.(?:cloud|com)',
        scriptSrc: '@thoughtspot/visual-embed-sdk|thoughtspot\\.com/.*embed',
    },

    Chronosphere: {
        cats: [OBSERVABILITY],
        description:
            'Chronosphere is an observability platform for metrics and traces.',
        website: 'https://chronosphere.io',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '\\.chronosphere\\.io',
    },

    'Travis CI': {
        cats: [44],
        description:
            'Travis CI is a continuous integration service. Build badges are ' +
            'served from its API host.',
        website: 'https://www.travis-ci.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dom: { "img[src*='api.travis-ci.com']": { exists: '' } },
    },

    Snyk: {
        cats: [SECURITY, DEVELOPMENT],
        description:
            'Snyk is a developer security platform. Known-vulnerability badges ' +
            'are served from snyk.io.',
        website: 'https://snyk.io',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.snyk\\.io',
        dom: { "img[src*='snyk.io/test/']": { exists: '' } },
    },

    'Scale AI': {
        cats: [AI_INFRA],
        description:
            'Scale AI provides data labelling and model evaluation for AI ' +
            'development.',
        website: 'https://scale.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.scale\\.com',
    },

    Cerebras: {
        cats: [AI_INFRA, GEN_AI],
        description:
            'Cerebras provides high-throughput language model inference on its ' +
            'wafer-scale hardware.',
        website: 'https://www.cerebras.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.cerebras\\.ai',
    },

    'Lambda Cloud': {
        cats: [AI_INFRA, 63],
        description:
            'Lambda provides GPU cloud infrastructure for AI training and ' +
            'inference.',
        website: 'https://lambdalabs.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'cloud\\.lambdalabs\\.com',
    },

    ScyllaDB: {
        cats: [DATABASES],
        description:
            'ScyllaDB is a high-performance NoSQL database compatible with ' +
            'Cassandra and DynamoDB.',
        website: 'https://www.scylladb.com',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: 'cloud\\.scylladb\\.com',
    },

    PlanetScale: {
        cats: [DATABASES, DATA_PLATFORM],
        description:
            'PlanetScale is a managed MySQL and Postgres platform.',
        website: 'https://planetscale.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.planetscale\\.com|\\.psdb\\.cloud',
    },

    TiDB: {
        cats: [DATABASES, DATA_PLATFORM],
        description:
            'TiDB is a distributed HTAP database. TiDB Cloud is its managed ' +
            'offering.',
        website: 'https://www.pingcap.com',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '\\.tidbcloud\\.com',
    },

    'Google BigQuery': {
        cats: [DATA_PLATFORM, DATABASES],
        description:
            'Google BigQuery is a serverless cloud data warehouse. Detected ' +
            'when a page queries it directly.',
        website: 'https://cloud.google.com/bigquery',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'bigquery(?:datatransfer|reservation)?\\.googleapis\\.com',
    },

    'Amazon Redshift': {
        cats: [DATA_PLATFORM, DATABASES],
        description:
            'Amazon Redshift is a cloud data warehouse. Detected when a page ' +
            'calls the Redshift Data API.',
        website: 'https://aws.amazon.com/redshift/',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'redshift(?:-data|-serverless)?\\.[a-z0-9-]+\\.amazonaws\\.com',
    },

    'Amazon SageMaker': {
        cats: [AI_INFRA],
        description:
            'Amazon SageMaker is AWS’s managed machine learning platform, ' +
            'including hosted notebooks and inference endpoints.',
        website: 'https://aws.amazon.com/sagemaker/',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:runtime\\.)?sagemaker\\.[a-z0-9-]+\\.amazonaws\\.com',
    },

    MuleSoft: {
        cats: [AUTOMATION, DEVELOPMENT],
        description:
            'MuleSoft Anypoint Platform is Salesforce’s integration and API ' +
            'management platform.',
        website: 'https://www.mulesoft.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'anypoint\\.mulesoft\\.com',
    },

    Workday: {
        cats: [101, 55],
        description:
            'Workday is a human capital and financial management platform. ' +
            'Tenant and careers hostnames are linked from company sites.',
        website: 'https://www.workday.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        // Careers links to *.myworkdayjobs.com are a common, unambiguous signal.
        dom: {
            "a[href*='myworkdayjobs.com']": { exists: '' },
            "a[href*='myworkday.com']": { exists: '' },
            "iframe[src*='myworkdayjobs.com']": { exists: '' },
        },
        xhr: '\\.myworkday(?:jobs)?\\.com',
    },

    'Oracle Cloud Infrastructure': {
        cats: [63, AI_INFRA],
        description:
            'Oracle Cloud Infrastructure hosts Oracle’s cloud services, ' +
            'including OCI Generative AI and the 23ai/26ai databases.',
        website: 'https://www.oracle.com/cloud/',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '\\.oraclecloud\\.com',
        scriptSrc: '\\.oraclecloud\\.com',
    },

    /* ------------------------------------------- further tenant signals */

    'VMware Cloud': {
        cats: [AI_INFRA, 63],
        description:
            'VMware (Broadcom) cloud management, including CloudHealth and the ' +
            'VMware Private AI Foundation services.',
        website: 'https://www.vmware.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: 'cloudhealth=' },
    },

    'IBM Cloud': {
        cats: [63, AI_INFRA],
        description:
            'IBM Cloud tenancy, indicated by an IBMid domain claim. IBM ' +
            'watsonx is delivered through it.',
        website: 'https://www.ibm.com/cloud',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: 'ibmid=' },
    },

    'SAP SuccessFactors': {
        cats: [101, 19],
        description:
            'SAP SuccessFactors is SAP’s human capital management suite. The ' +
            'verification record indicates an SAP cloud tenant.',
        website: 'https://www.sap.com/products/hcm.html',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: 'successfactors-site-verification=' },
    },

    'Schneider EcoStruxure': {
        cats: [IOT, 45],
        description:
            'Schneider Electric EcoStruxure is an IoT platform for building, ' +
            'data centre and industrial operations.',
        website: 'https://www.se.com/ww/en/work/campaign/innovation/overview.jsp',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: 'ecostruxure-it-verification=' },
    },

    /* ====================================================================
     * Generated-media CDNs.
     *
     * A model name cannot be fingerprinted, but the artefact it produced can:
     * an image served from cdn.midjourney.com was made with Midjourney. This is
     * evidence of use, and it is what makes the image and video generators on
     * the list reportable at all.
     * ================================================================== */

    Midjourney: {
        cats: [GEN_AI],
        description:
            'Midjourney is a generative image platform. Detected when a page ' +
            'serves imagery from its CDN.',
        website: 'https://www.midjourney.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dom: { "img[src*='cdn.midjourney.com']": { exists: '' } },
        html: 'cdn\\.midjourney\\.com',
    },

    'Leonardo AI': {
        cats: [GEN_AI],
        description:
            'Leonardo AI is a generative image platform. Detected when a page ' +
            'serves imagery from its CDN.',
        website: 'https://leonardo.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dom: { "img[src*='cdn.leonardo.ai']": { exists: '' } },
        html: 'cdn\\.leonardo\\.ai',
    },

    'Kling AI': {
        cats: [GEN_AI],
        description:
            'Kling AI is a generative video platform. Detected from its media ' +
            'CDN or API host.',
        website: 'https://klingai.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        html: 'cdn\\.klingai\\.com',
        xhr: '(?:api|cdn)\\.klingai\\.com',
    },

    Pika: {
        cats: [GEN_AI],
        description:
            'Pika is a generative video platform. Detected when a page serves ' +
            'media from its CDN.',
        website: 'https://pika.art',
        icon: 'default.svg',
        saas: true,
        oss: false,
        html: 'cdn\\.pika\\.art',
        xhr: 'cdn\\.pika\\.art',
    },

    Suno: {
        cats: [GEN_AI],
        description:
            'Suno is a generative music platform. Detected when a page serves ' +
            'audio from its CDN.',
        website: 'https://suno.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        html: 'cdn\\d?\\.suno\\.ai',
        xhr: 'cdn\\d?\\.suno\\.ai',
    },

    Udio: {
        cats: [GEN_AI],
        description:
            'Udio is a generative music platform. Detected when a page embeds ' +
            'or serves Udio media.',
        website: 'https://www.udio.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dom: {
            "audio[src*='udio.com']": { exists: '' },
            "iframe[src*='udio.com']": { exists: '' },
        },
    },

    'Stability AI': {
        cats: [GEN_AI],
        description:
            'Stability AI provides the Stable Diffusion and Stable Video ' +
            'Diffusion model families through its API.',
        website: 'https://stability.ai',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: 'api\\.stability\\.ai',
    },

    'fal.ai': {
        cats: [AI_INFRA, GEN_AI],
        description:
            'fal is an inference platform for generative media models, ' +
            'including the FLUX family. Detected from its run or media hosts.',
        website: 'https://fal.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'fal\\.run|\\.fal\\.media',
        html: '\\.fal\\.media',
    },

    AlphaFold: {
        cats: [AI_INFRA],
        description:
            'AlphaFold is DeepMind’s protein structure prediction system. ' +
            'Detected when a page embeds structures from the AlphaFold database.',
        website: 'https://alphafold.ebi.ac.uk',
        icon: 'default.svg',
        saas: true,
        oss: true,
        html: 'alphafold\\.ebi\\.ac\\.uk',
        xhr: 'alphafold\\.ebi\\.ac\\.uk',
    },

    /* -------------------------------- remaining ML platform control planes */

    CrewAI: {
        cats: [AI_FRAMEWORKS, AI_AGENTS],
        description:
            'CrewAI is a multi-agent orchestration framework. CrewAI ' +
            'Enterprise is its managed control plane.',
        website: 'https://www.crewai.com',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: 'app\\.crewai\\.com',
    },

    BentoML: {
        cats: [AI_INFRA],
        description:
            'BentoML packages and serves machine learning models. BentoCloud ' +
            'is its managed platform.',
        website: 'https://www.bentoml.com',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '(?:cloud|api)\\.bentoml\\.com',
    },

    ZenML: {
        cats: [AI_INFRA, AI_FRAMEWORKS],
        description:
            'ZenML is an MLOps framework for reproducible pipelines. ZenML ' +
            'Cloud is its managed control plane.',
        website: 'https://www.zenml.io',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: 'cloud\\.zenml\\.io',
    },

    DVC: {
        cats: [AI_INFRA, DEVELOPMENT],
        description:
            'DVC is data and model version control for machine learning. DVC ' +
            'Studio is its hosted interface.',
        website: 'https://dvc.org',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: 'studio\\.(?:iterative\\.ai|datachain\\.ai)',
    },

    Crossplane: {
        cats: [60],
        description:
            'Crossplane extends Kubernetes to manage cloud infrastructure. ' +
            'Upbound is its commercial control plane.',
        website: 'https://www.crossplane.io',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '\\.upbound\\.io',
    },

    LangGraph: {
        cats: [AI_FRAMEWORKS, AI_AGENTS],
        description:
            'LangGraph is LangChain’s framework for stateful agent workflows. ' +
            'LangGraph Platform hosts deployed graphs.',
        website: 'https://www.langchain.com/langgraph',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '\\.langgraph\\.app',
    },

    'Siemens Xcelerator': {
        cats: [IOT, 45],
        description:
            'Siemens Xcelerator is Siemens’ industrial software platform, ' +
            'including the Siemens Industrial Copilot.',
        website: 'https://www.siemens.com/xcelerator',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'xcelerator\\.siemens\\.com',
    },

    'Automation Anywhere': {
        cats: [AUTOMATION, AI_AGENTS],
        description:
            'Automation Anywhere is an RPA and agentic automation platform. ' +
            'Control Room is hosted on its own domains.',
        website: 'https://www.automationanywhere.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '\\.automationanywhere\\.(?:digital|com)',
    },

    'VS Code for the Web': {
        cats: [20, DEVELOPMENT],
        description:
            'Visual Studio Code running in the browser, either on vscode.dev ' +
            'or a self-hosted code-server instance.',
        website: 'https://vscode.dev',
        icon: 'default.svg',
        saas: true,
        oss: true,
        html: [
            'id="vscode-workbench-web-configuration"',
            'class="monaco-workbench"',
        ],
        xhr: 'vscode\\.dev',
    },

    /* ================== model-provider APIs and media platforms ========== */

    Synthesia: {
        cats: [GEN_AI, 14],
        description:
            'Synthesia is an AI video generation platform. Generated videos are ' +
            'embedded from its share host.',
        website: 'https://www.synthesia.io',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:share|api)\\.synthesia\\.io',
        html: 'share\\.synthesia\\.io',
        dom: { "iframe[src*='synthesia.io']": { exists: '' } },
    },

    'xAI Grok': {
        cats: [GEN_AI, AI],
        description:
            'xAI provides the Grok model family through its API.',
        website: 'https://x.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.x\\.ai',
    },

    'Meta AI': {
        cats: [GEN_AI, AI],
        description:
            'Meta AI is Meta’s assistant, built on the Llama model family.',
        website: 'https://www.meta.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:www\\.)?meta\\.ai',
        dom: { "a[href*='meta.ai']": { exists: '' } },
    },

    Ideogram: {
        cats: [GEN_AI],
        description:
            'Ideogram is a generative image platform, notable for text ' +
            'rendering in images.',
        website: 'https://ideogram.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: '(?:api\\.)?ideogram\\.ai',
    },

    'Luma AI': {
        cats: [GEN_AI],
        description:
            'Luma AI provides the Dream Machine generative video model.',
        website: 'https://lumalabs.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.lumalabs\\.ai|storage\\.cdn-luma\\.com',
        html: 'storage\\.cdn-luma\\.com',
    },

    Runway: {
        cats: [GEN_AI, 14],
        description:
            'Runway provides generative video models including the Gen-3 ' +
            'family.',
        website: 'https://runwayml.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api(?:\\.dev)?\\.runwayml\\.com',
    },

    'Inflection AI': {
        cats: [GEN_AI, AI],
        description: 'Inflection AI provides the Pi assistant and its API.',
        website: 'https://inflection.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.inflection\\.ai|(?:^|\\.)pi\\.ai',
    },

    'Reka AI': {
        cats: [GEN_AI, AI],
        description: 'Reka AI provides multimodal language models via its API.',
        website: 'https://www.reka.ai',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.reka\\.ai',
    },

    'AI21 Labs': {
        cats: [GEN_AI, AI],
        description:
            'AI21 Labs provides the Jamba and Jurassic model families via its ' +
            'API.',
        website: 'https://www.ai21.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.ai21\\.com',
    },

    'Aleph Alpha': {
        cats: [GEN_AI, AI],
        description:
            'Aleph Alpha provides the Luminous and Pharia model families for ' +
            'European sovereign AI.',
        website: 'https://aleph-alpha.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.aleph-alpha\\.com',
    },

    'Alibaba Cloud Model Studio': {
        cats: [GEN_AI, AI],
        description:
            'Alibaba Cloud Model Studio (DashScope) serves the Qwen model ' +
            'family.',
        website: 'https://www.alibabacloud.com/en/product/modelstudio',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'dashscope(?:-intl)?\\.aliyuncs\\.com',
    },

    'Baidu ERNIE': {
        cats: [GEN_AI, AI],
        description:
            'Baidu ERNIE is served through the Qianfan platform on Baidu Cloud.',
        website: 'https://yiyan.baidu.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'aip\\.baidubce\\.com|qianfan\\.baidubce\\.com',
    },

    'Volcengine Ark': {
        cats: [GEN_AI, AI],
        description:
            'Volcengine Ark is ByteDance’s model platform, serving the Doubao ' +
            'model family.',
        website: 'https://www.volcengine.com/product/ark',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'ark\\.[a-z0-9-]+\\.volces\\.com',
    },

    'Zhipu AI': {
        cats: [GEN_AI, AI],
        description:
            'Zhipu AI provides the GLM model family through its BigModel ' +
            'platform.',
        website: 'https://www.zhipuai.cn',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'open\\.bigmodel\\.cn',
    },

    'SAS Viya': {
        cats: [AI_INFRA, ANALYTICS],
        description:
            'SAS Viya is SAS’s cloud analytics and AI platform.',
        website: 'https://www.sas.com/en_us/software/viya.html',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.sas\\.com',
    },

    'Llama API': {
        cats: [GEN_AI, AI],
        description:
            'The Llama API is Meta’s hosted service for the Llama model ' +
            'family. Open-weight Llama deployments elsewhere are not observable.',
        website: 'https://llama.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        xhr: 'api\\.llama\\.com',
    },

    'Seldon Core': {
        cats: [AI_INFRA],
        description:
            'Seldon Core serves machine learning models on Kubernetes under a ' +
            'fixed inference path.',
        website: 'https://www.seldon.io',
        icon: 'default.svg',
        saas: false,
        oss: true,
        // Documented Seldon Core routing: /seldon/<namespace>/<deployment>/api/...
        url: '/seldon/[^/]+/[^/]+/api/v[\\d.]+/(?:predictions|doc)',
        implies: 'Kubernetes',
    },

    Metaflow: {
        cats: [AI_INFRA, AI_FRAMEWORKS],
        description:
            'Metaflow is a framework for data science workflows. Outerbounds is ' +
            'its managed platform.',
        website: 'https://metaflow.org',
        icon: 'default.svg',
        saas: true,
        oss: true,
        xhr: '(?:api\\.)?outerbounds\\.(?:com|dev)',
    },

    Dataiku: {
        cats: [AI_INFRA, DATA_PLATFORM],
        description:
            'Dataiku is an end-to-end AI and data science platform. Public ' +
            'webapps published from DSS are served under a fixed path.',
        website: 'https://www.dataiku.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
        url: '/public-webapps/',
        xhr: '\\.dataiku\\.com',
    },

    Linkerd: {
        cats: [60, 64],
        description:
            'Linkerd is a service mesh for Kubernetes. Its proxy adds l5d-* ' +
            'headers to meshed traffic.',
        website: 'https://linkerd.io',
        icon: 'default.svg',
        saas: false,
        oss: true,
        headers: {
            'l5d-dst-override': '',
            'l5d-dst-canonical': '',
            'l5d-client-id': '',
        },
        implies: 'Kubernetes',
    },

    /* -------------------------------------------------- Adobe tenant signals */

    'Adobe Identity Management': {
        cats: [69],
        description:
            'Adobe enterprise identity federation. The verification record ' +
            'indicates the organisation runs Adobe enterprise products under ' +
            'a claimed domain.',
        website: 'https://helpx.adobe.com/enterprise/using/identity.html',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: 'adobe-idp-site-verification=' },
    },

    'Adobe Acrobat Sign': {
        cats: [DMS],
        description:
            'Adobe Acrobat Sign is an e-signature platform.',
        website: 'https://www.adobe.com/sign.html',
        icon: 'default.svg',
        saas: true,
        oss: false,
        dns: { TXT: 'adobe-sign-verification=' },
    },
}

/**
 * Taxonomy-only entries.
 *
 * These 15 products have no externally observable signal — see docs/CATALOG.md
 * for why, per product. They are carried so the taxonomy maps 1:1 onto the
 * request and every row has a category, description and vendor, but they
 * deliberately carry **no detection channel** and can never fire.
 *
 * They are listed in CATALOG_ONLY so scripts/coverage-report.js reports them as
 * "mapped, not detectable" rather than counting them as coverage. Do not add a
 * pattern to one of these without real evidence and a passing detection test —
 * an inert pattern is worse than an honest gap.
 */
const CATALOG_ONLY = {
    'CrowdStrike Falcon': {
        cats: [SECURITY, CLOUD_SECURITY],
        description:
            'CrowdStrike Falcon is an endpoint detection and response platform. ' +
            'It runs as a host agent and has no web-visible footprint.',
        website: 'https://www.crowdstrike.com/platform/',
        icon: 'default.svg',
        saas: true,
        oss: false,
    },
    SentinelOne: {
        cats: [SECURITY, CLOUD_SECURITY],
        description:
            'SentinelOne is an autonomous endpoint protection platform. It runs ' +
            'as a host agent and has no web-visible footprint.',
        website: 'https://www.sentinelone.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
    },
    Zscaler: {
        cats: [SECURITY, CLOUD_SECURITY],
        description:
            'Zscaler is a cloud security service edge platform. It operates as ' +
            'a network proxy and is not observable from a public website.',
        website: 'https://www.zscaler.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
    },
    Netskope: {
        cats: [SECURITY, CLOUD_SECURITY],
        description:
            'Netskope is a security service edge and CASB platform. It operates ' +
            'inline on the network and is not observable from a public website.',
        website: 'https://www.netskope.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
    },
    'Orca Security': {
        cats: [CLOUD_SECURITY, SECURITY],
        description:
            'Orca Security is an agentless cloud security platform. It scans ' +
            'cloud accounts out of band and emits nothing to a visitor.',
        website: 'https://orca.security',
        icon: 'default.svg',
        saas: true,
        oss: false,
    },
    Lacework: {
        cats: [CLOUD_SECURITY, SECURITY],
        description:
            'Lacework (Fortinet) is a cloud security posture platform. It scans ' +
            'cloud accounts out of band and emits nothing to a visitor.',
        website: 'https://www.lacework.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
    },
    'Abnormal Security': {
        cats: [SECURITY],
        description:
            'Abnormal Security is an email security platform. It integrates ' +
            'with mail providers over API and has no web-visible footprint.',
        website: 'https://abnormalsecurity.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
    },
    pgvector: {
        cats: [VECTOR_DB, DATABASES],
        description:
            'pgvector is a PostgreSQL extension for vector similarity search. ' +
            'It runs inside the database and emits nothing to a visitor.',
        website: 'https://github.com/pgvector/pgvector',
        icon: 'default.svg',
        saas: false,
        oss: true,
    },
    'NVIDIA Jetson': {
        cats: [IOT, AI_INFRA],
        description:
            'NVIDIA Jetson is an edge AI hardware module family, including ' +
            'Jetson Orin. Hardware is not detectable over the web.',
        website: 'https://www.nvidia.com/en-us/autonomous-machines/embedded-systems/',
        icon: 'default.svg',
        saas: false,
        oss: false,
    },
    'Model Context Protocol': {
        cats: [AI_FRAMEWORKS, AI_AGENTS],
        description:
            'The Model Context Protocol (MCP) is an open standard for ' +
            'connecting AI models to tools. It is a protocol, not a deployed ' +
            'service, so there is no stable endpoint to fingerprint.',
        website: 'https://modelcontextprotocol.io',
        icon: 'default.svg',
        saas: false,
        oss: true,
    },
    Neovim: {
        cats: [20, DEVELOPMENT],
        description:
            'Neovim is a terminal text editor. A local editor has no web ' +
            'surface.',
        website: 'https://neovim.io',
        icon: 'default.svg',
        saas: false,
        oss: true,
    },
    Zed: {
        cats: [20, DEVELOPMENT],
        description:
            'Zed is a native collaborative code editor. A local editor has no ' +
            'web surface.',
        website: 'https://zed.dev',
        icon: 'default.svg',
        saas: false,
        oss: true,
    },
    Phind: {
        cats: [GEN_AI, 29],
        description:
            'Phind is an AI answer engine for developers. It is used directly ' +
            'on its own site and is not embedded elsewhere.',
        website: 'https://www.phind.com',
        icon: 'default.svg',
        saas: true,
        oss: false,
    },
}

/** Evidence quality for every technology authored in this file. */
const EVIDENCE = {}

for (const [name, entry] of Object.entries(TECHNOLOGIES)) {
    const classes = [
        entry.dns && 'dns',
        entry.url && 'url',
        entry.xhr && 'xhr-hostname',
        entry.scriptSrc && 'script-url',
        entry.html && 'shipped-markup',
        entry.dom && 'dom',
        entry.headers && 'headers',
        entry.cookies && 'cookies',
        entry.meta && 'meta',
        entry.js && 'js',
    ].filter(Boolean)

    EVIDENCE[name] = {
        class: classes.join('+') || 'taxonomy-only',
        verification: 'catalog-pattern-only',
        observed:
            'Pattern compiles and is covered by synthetic tests; no retained ' +
            'live target has been reviewed yet.',
        signal: entry.dns ? 'tenant' : 'page/integration',
    }
}

const { isLiteralPattern } = require('./normalize')

/**
 * Tokens deliberately superseded during normalization, and the pattern that
 * replaced each one.
 *
 * Recorded explicitly so the substitution is reviewable rather than inferred, and
 * asserted in test/dns-sweep.test.js. `txtVerification()` additionally verifies
 * literal containment, so this map documents intent while the check enforces it.
 */
const EXPECTED_SUPERSESSIONS = {
    Cursor: null, // regex variant is non-literal, so it survives unchanged
    Detectify: 'detectify-verification',
    DocuSign: 'docusign',
    Dropbox: 'dropbox-domain-verification',
    Mixpanel: 'mixpanel-domain-verify',
    Segment: 'segment-site-verification',
}

/**
 * DNS marker verification is read from the retained sweep rather than asserted.
 *
 * The label used to be hard-coded as `unreproduced-prior-sweep`, which stayed
 * wrong after the sweep became reproducible. It is now derived from
 * `data/dns-sweep-results.json`, so the claim in the report always matches the
 * evidence on disk. If the sweep has never been run, the label degrades to
 * `unverified-no-sweep-retained` rather than overstating.
 *
 * Matching is on the exact (technology, pattern) pair. A technology can hold
 * several TXT patterns, and only some of them may have been seen.
 */
const sweep = (() => {
    try {
        // eslint-disable-next-line global-require
        const results = require('../../data/dns-sweep-results.json')
        const observed = new Map()

        for (const { technology, pattern, domainCount, examples } of results.observed) {
            observed.set(`${technology} ${pattern}`, { domainCount, examples })
        }

        return { results, observed }
    } catch (error) {
        return null
    }
})()

/**
 * Does `candidate` genuinely cover `token`?
 *
 * Three conditions, all required:
 *
 *   1. Both operands are **literal** patterns. Containment only implies a
 *      matching superset for literals; with alternation, anchors or quantifiers
 *      involved, `token.includes(candidate)` says nothing about what each
 *      matches. The function previously claimed to require this but only tested
 *      containment, which left the invariant weaker than documented.
 *   2. `candidate` is a strict substring of `token`, which is the subsumption
 *      relation that removed the token: any record matching `token` also matches
 *      `candidate`, so observing the candidate covers it.
 *   3. The pair appears in `EXPECTED_SUPERSESSIONS`. Even a provable containment
 *      should not silently grant evidence to a marker nobody reviewed, so the
 *      substitution has to be declared.
 *
 * Sharing a technology name is never sufficient on its own.
 *
 * @param {string} token the original, superseded pattern
 * @param {string} candidate an observed pattern for the same technology
 * @param {?string} technology when given, the pair must be declared for it
 */
function supersedes(token, candidate, technology) {
    if (typeof candidate !== 'string' || typeof token !== 'string') {
        return false
    }

    if (!isLiteralPattern(token) || !isLiteralPattern(candidate)) {
        return false
    }

    const contains =
        candidate.length > 0 &&
        candidate.length < token.length &&
        token.includes(candidate)

    if (!contains) {
        return false
    }

    // Declared-substitution gate. Omitting `technology` checks containment alone,
    // which is what the unit tests exercise.
    if (technology !== undefined) {
        return EXPECTED_SUPERSESSIONS[technology] === candidate
    }

    return true
}

/**
 * Verification for one technology's TXT marker, based on retained evidence.
 * @param {string} name
 * @param {string} token
 */
function txtVerification(name, token) {
    if (!sweep) {
        return {
            verification: 'unverified-no-sweep-retained',
            observed:
                `TXT pattern ${token} has no retained sweep. Run ` +
                '`npm run sweep` to produce data/dns-sweep-results.json.',
        }
    }

    const hit = sweep.observed.get(`${name} ${token}`)

    if (hit) {
        return {
            verification: 'corpus-observed',
            observed:
                `TXT pattern ${token} observed on ${hit.domainCount} of ` +
                `${sweep.results.corpusDomains} corpus domains ` +
                `(e.g. ${hit.examples.join(', ')}). Corpus: ` +
                `${sweep.results.corpus}.`,
        }
    }

    // The exact string is absent, which is expected when normalization superseded
    // this token with a broader pattern that survived.
    //
    // Sharing a technology name is NOT enough to call another marker equivalent:
    // a technology can carry several unrelated TXT patterns, and an earlier
    // version of this function would have lent one pattern's evidence to a
    // completely different one. Equivalence is asserted only when the observed
    // pattern is a strict literal substring of this token, which is exactly the
    // subsumption relation that removed it — anything matching the token also
    // matches its substring, so the observation genuinely covers it.
    const superseding = [...sweep.observed.keys()]
        .filter((key) => key.startsWith(`${name} `))
        .map((key) => key.slice(name.length + 1))
        .filter((candidate) => supersedes(token, candidate, name))

    if (superseding.length) {
        return {
            verification: 'corpus-observed-via-equivalent',
            supersededBy: superseding,
            observed:
                `TXT pattern ${token} is not itself in the retained sweep. It was ` +
                'superseded as redundant during normalization by ' +
                `${superseding.join(', ')}, which is observed and which any ` +
                'record matching the original would also match.',
        }
    }

    return {
        verification: 'not-observed-in-corpus',
        observed:
            `TXT pattern ${token} was checked against the retained corpus and ` +
            'not seen. Absence in a bounded corpus is weak evidence, but this ' +
            'marker must not be described as corpus-verified.',
    }
}

for (const [name, token] of Object.entries(TXT)) {
    EVIDENCE[name] = {
        ...EVIDENCE[name],
        class: EVIDENCE[name] && EVIDENCE[name].class !== 'taxonomy-only'
            ? `${EVIDENCE[name].class}+dns-txt`
            : 'dns-txt',
        ...txtVerification(name, token),
        signal: 'tenant',
    }
}

for (const [name, token] of Object.entries(TXT_ENRICH)) {
    EVIDENCE[name] = {
        class: 'dns-txt+existing-catalog',
        ...txtVerification(name, token),
        signal: 'tenant',
    }
}

const REVIEWED_EVIDENCE = {
    Samsara: {
        class: 'customer-live-share+vendor-script-host',
        verification: 'live-observed',
        observed: [
            'https://encompassnashville.org/transportation contains 3 tenant-specific cloud.samsara.com/o/.../fleet/viewer/... links.',
            'https://www.bakerk12.org/departments/transportation/live-bus-routes contains 61 tenant-specific Samsara Live Sharing links.',
            'https://cloud.samsara.com/signin loads its application bundle from cloud.samsara.com.',
        ],
        signal: 'page/integration',
        reviewedAt: '2026-07-28',
    },
    'Samsara Assistant': {
        class: 'rejected-global-bundle',
        verification: 'rejected-marker',
        observed:
            'https://cloud.samsara.com/signin loads ai-assistant-styles.*.js ' +
            'without tenant authentication. The marker cannot prove the feature ' +
            'is enabled and is intentionally not a detection channel.',
        signal: 'platform-capability-only',
        reviewedAt: '2026-07-28',
    },
    'Verizon Connect': {
        class: 'first-party-login',
        verification: 'live-observed',
        observed: [
            'https://reveal.fleetmatics.com redirects to https://login.us.vzconnect.com and renders the Reveal login.',
            'https://login.telogis.com redirects to https://login.platform.telogis.com and loads telogis.com scripts.',
        ],
        signal: 'first-party-application',
        reviewedAt: '2026-07-28',
    },
    'Verizon Connect Reveal': {
        class: 'first-party-login',
        verification: 'live-observed',
        observed:
            'https://login.us.vzconnect.com is the current Reveal login and is ' +
            'documented by Verizon Connect support.',
        signal: 'first-party-application',
        reviewedAt: '2026-07-28',
    },
    'Claude Enterprise': {
        class: 'dns-txt',
        verification: 'live-observed',
        observed: [
            'decagon.ai publishes anthropic-domain-verification-* TXT records.',
            'wikimedia.org publishes an anthropic-domain-verification-* TXT record.',
        ],
        signal: 'tenant',
        reviewedAt: '2026-07-28',
    },
    'OpenAI API': {
        class: 'official-api-host+dns-txt',
        verification: 'official-documented',
        observed:
            'OpenAI documents api.openai.com. API keys are server-side secrets, ' +
            'so a passive browser scan will miss normal back-end integrations.',
        signal: 'browser-visible-api-call-or-tenant',
        reviewedAt: '2026-07-28',
    },
    Jasper: {
        class: 'official-api-host',
        verification: 'official-documented',
        observed:
            'Jasper documents api.jasper.ai and explicitly requires client-side ' +
            'apps to route calls through a back end.',
        signal: 'browser-visible-api-call',
        reviewedAt: '2026-07-28',
    },
    Moveworks: {
        class: 'official-api-host',
        verification: 'official-documented',
        observed: 'Moveworks documents api.moveworks.ai as its REST API base URL.',
        signal: 'browser-visible-api-call',
        reviewedAt: '2026-07-28',
    },
    Harvey: {
        class: 'official-api-host',
        verification: 'official-documented',
        observed: 'Harvey documents api.harvey.ai as its API base URL.',
        signal: 'browser-visible-api-call',
        reviewedAt: '2026-07-28',
    },
    Chroma: {
        class: 'official-api-host',
        verification: 'official-documented',
        observed: 'Chroma documents api.trychroma.com for Chroma Cloud.',
        signal: 'browser-visible-api-call',
        reviewedAt: '2026-07-28',
    },
    Lytx: {
        class: 'official-api-host',
        verification: 'official-documented',
        observed: 'Lytx documents api.lytx.com for its Data Connector API.',
        signal: 'browser-visible-api-call',
        reviewedAt: '2026-07-28',
    },
}

for (const [name, evidence] of Object.entries(REVIEWED_EVIDENCE)) {
    EVIDENCE[name] = {
        ...EVIDENCE[name],
        ...evidence,
    }
}

module.exports = {
    CATALOG_ONLY,
    EVIDENCE,
    EXPECTED_SUPERSESSIONS,
    supersedes,
    TECHNOLOGIES,
    TXT,
    TXT_ENRICH,
}
