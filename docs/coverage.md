# Emerging technology coverage

Source list: `AI technology_products_for_veridion_070226.xlsx` (402 products)

**Mapped onto the catalog: 402 of 402 (100%).**

**Catalog-matchable: 387 of 402 (96%).**

Catalog-matchable means that a detection path exists in the catalog. It is not empirical live-scan coverage, and many API integrations are normally server-side and therefore invisible to a passive browser scan.

**Live-observed evidence retained for 4 of 262 unique mapped technologies:** Claude Enterprise, Samsara, Verizon Connect, Verizon Connect Reveal.

| Status | Count | What it means |
| --- | --- | --- |
| Detected | 150 | A catalog entry exists under this name and has a detection path. This is catalog reachability, not proof that the marker was observed on a real customer site. |
| Detected at platform level | 237 | An AI feature or model inside a platform that is detected. Whether a tenant has the feature enabled is not exposed externally, so it is reported against the parent platform or the API that serves it. |
| Mapped, detection not possible | 15 | Carried in the catalog with full taxonomy metadata so the mapping is complete, but the product emits nothing observable, so the entry has no detection pattern and can never fire. Reachable only through a text-mined hiring signal (see scripts/lib/text-signals.js). |

### Observability caveat

Of the 387 catalog-matchable products, **126 are detectable only through the `xhr` channel** — a browser request to a vendor API host.

Measured by `scripts/xhr-audit.js`: **1 of 85 xhr-only markers appeared in a 29-page corpus under the current request-aborting driver**, while 47 distinct xhr hostnames were collected.

**That is a yield against a convenience corpus, not an observation rate.** Nothing maps each marker to a page where its vendor is in use; the driver aborts non-document/script requests, which suppresses follow-on calls; and only 8 of 29 pages returned a clean 200. Treat it as a lower bound on browser visibility, and the catalog-matchable figure as an upper bound on coverage. See `docs/live-evidence.md`.

## Flagged priorities

| Request | Resolved to | Detection channels |
| --- | --- | --- |
| Samsara  and product versions | Samsara | dom, scriptSrc, xhr |
| ↳ Samsara Assistant | Samsara Assistant | - |
| Verizon Connect - currently track Verizon, but need Connect separately. | Verizon Connect | dom, scriptSrc, url, xhr |
| ↳ Verizon Connect Reveal | Verizon Connect Reveal | scriptSrc, url |

## Detected (150)

| Product | Reported as | Detection channels |
| --- | --- | --- |
| Figma | Figma | dns, dom, scriptSrc |
| Airbyte | Airbyte | html, meta, xhr |
| Airtable | Airtable | dns, dom |
| Amazon Bedrock | Amazon Bedrock | xhr |
| Claude Enterprise | Claude Enterprise | dns |
| Ray | Ray | html |
| Cursor | Cursor | dns |
| Apache Spark | Apache Spark | html |
| Apache Kafka | Apache Kafka | xhr |
| Apache Airflow | Apache Airflow | html |
| Apache Flink | Apache Flink | html |
| Apache Iceberg | Apache Iceberg | dom, probe, url, xhrUrl |
| Apache Hudi | Apache Hudi | dom, probe, url, xhrUrl |
| Appsmith | Appsmith | dom, xhr |
| ArgoCD | ArgoCD | cookies, html |
| Asana | Asana | dom |
| Assembly AI | AssemblyAI | xhr |
| BentoML | BentoML | xhr |
| Bubble | Bubble | headers, js |
| Buildkite | Buildkite | dom |
| Linkerd | Linkerd | headers |
| Cerebras | Cerebras | xhr |
| Character.AI | Character.AI | xhr |
| Chroma | Chroma | xhr |
| Chronosphere | Chronosphere | xhr |
| CircleCI | CircleCI | dom |
| Splunk | Splunk | cookies, headers |
| ClickHouse | ClickHouse | xhr |
| ClickUp | ClickUp | dns, js, scriptSrc |
| Prometheus | Prometheus | html |
| OpenTelemetry | opentelemetry | js, scriptSrc |
| Kubernetes | Kubernetes | implies |
| Helm | Helm | probe |
| CockroachDB | CockroachDB | xhr |
| Coda | Coda | dns, dom |
| Windsurf | Windsurf | dns, xhr |
| Copy.ai | Copy.ai | xhr |
| CrewAI | CrewAI | xhr |
| Dagster | Dagster | xhr |
| MLflow | MLflow | html |
| Delta Lake | Delta Lake | probe, text, url, xhrUrl |
| Databricks | Databricks | dom, headers, meta, scriptSrc, text, url, xhrUrl |
| Datadog | Datadog | js, scriptSrc |
| dbt | dbt | xhr |
| Descript | Descript | dom, scriptSrc |
| Docker | Docker | dns, html |
| DuckDB | DuckDB | scriptSrc |
| Dynatrace | Dynatrace | cookies, dns, js |
| ElevenLabs | ElevenLabs | dns, dom, scriptSrc, xhr |
| Fivetran | Fivetran | xhr |
| Git | git | meta |
| GitLab | GitLab | cookies, dns, html, js, meta |
| GitLab CI/CD | GitLab CI/CD | meta |
| Glean | Glean | dom, scriptSrc, xhr |
| Google Vertex AI | Google Vertex AI | xhr |
| Kubeflow | Kubeflow | html |
| Apigee | Apigee | scriptSrc |
| Looker | Looker | headers |
| Grafana | Grafana | js, scriptSrc, scripts |
| Groq | Groq | xhr |
| Harness | Harness | js, scriptSrc |
| Harvey | Harvey | xhr |
| Hex | Hex | dom, xhr |
| Honeycomb | Honeycomb | xhr |
| Istio | Istio | headers |
| DVC | DVC | xhr |
| Jasper | Jasper | xhr |
| Jenkins | Jenkins | dom, headers, html, js |
| JetBrains IDEs | JetBrains IDEs | dns |
| Kling AI | Kling AI | html, xhr |
| Lambda Cloud | Lambda Cloud | xhr |
| LangSmith | LangSmith | xhr |
| LangGraph | LangGraph | xhr |
| LaunchDarkly | LaunchDarkly | dns, dom, js, scriptSrc, xhr |
| Leonardo AI | Leonardo AI | dom, html |
| Linear | Linear | dns, js |
| Make | Make | dns, xhr |
| Kedro | Kedro | implies |
| Meta AI | Meta AI | dom, xhr |
| Metabase | Metabase | cookies, html |
| Azure AI Foundry | Azure AI Foundry | xhr |
| Azure OpenAI Service | Azure OpenAI Service | xhr |
| Fabric | Fabric | dom, meta |
| GitHub | GitHub | scriptSrc, xhr |
| Midjourney | Midjourney | dom, html |
| Miro | Miro | dns, dom, scriptSrc |
| Modal | Modal | xhr |
| Monday.com | Monday.com | dns, xhr |
| MongoDB | MongoDB | dns |
| Moveworks | Moveworks | xhr |
| n8n | n8n | cookies, meta, scripts |
| Neon | Neon | xhr |
| Metaflow | Metaflow | xhr |
| Notion | Notion | dns, dom |
| NVIDIA NIM | NVIDIA NIM | xhr |
| NVIDIA AI Enterprise | NVIDIA AI Enterprise | xhr |
| Observable | Observable | dom, scriptSrc |
| Okta | Okta | js, scriptSrc |
| Auth0 | Auth0 | dom, headers, scriptSrc |
| OpenAI API | OpenAI API | dns, xhr |
| Optimizely | Optimizely | cookies, js, scriptSrc |
| OutSystems | OutSystems | js, scriptSrc |
| Pinecone | Pinecone | xhr |
| TiDB | TiDB | xhr |
| PlanetScale | PlanetScale | xhr |
| PostgreSQL | PostgreSQL | implies |
| Postman | Postman | dns, xhr |
| Prefect | Prefect | html, xhr |
| Pulumi | Pulumi | xhr |
| Qdrant | Qdrant | xhr |
| Qualcomm AI Hub | Qualcomm AI Hub | xhr |
| Redis | Redis | implies |
| Reka AI | Reka AI | xhr |
| Replicate | Replicate | xhr |
| Retool | Retool | js, scriptSrc, url |
| MuleSoft | MuleSoft | xhr |
| Tableau | Tableau | js, scriptSrc |
| Slack | Slack | dns, dom, scriptSrc |
| ScyllaDB | ScyllaDB | xhr |
| Seldon Core | Seldon Core | url |
| Mendix | Mendix | dom, js |
| Sigma Computing | Sigma Computing | dom, xhr |
| Snowflake | Snowflake | scriptSrc, xhr |
| Snyk | Snyk | dom, xhr |
| Split | Split | js, scriptSrc |
| Statsig | Statsig | headers, js, xhr |
| Supabase | Supabase | dom, js, scriptSrc, scripts |
| Superblocks | Superblocks | xhr |
| Rancher | Rancher | html |
| Synthesia | Synthesia | dom, html, xhr |
| Tabnine | Tabnine | xhr |
| ThoughtSpot | ThoughtSpot | scriptSrc, xhr |
| Tome | Tome | dom, xhr |
| Travis CI | Travis CI | dom |
| Tray.io | Tray.io | scriptSrc, xhr |
| Trino | Trino | dom, headers, probe, text, url, xhrUrl |
| Turso | Turso | xhr |
| Udio | Udio | dom |
| Unleash | Unleash | xhr |
| Crossplane | Crossplane | xhr |
| Weaviate | Weaviate | xhr |
| Webflow | Webflow | dom, js, meta |
| Weights & Biases | Weights & Biases | dom, xhr |
| Wiz | Wiz | dns |
| Workato | Workato | xhr |
| Writer | Writer | xhr |
| You.com | You.com | xhr |
| Zapier | Zapier | dns |
| ZenML | ZenML | xhr |
| Milvus | Milvus | scriptSrc |

## Detected at platform level (237)

| Product | Reported as | Detection channels |
| --- | --- | --- |
| 6sense Revenue AI | 6sense | headers, scriptSrc, xhr |
| Adobe Firefly | Adobe Identity Management | dns |
| Adobe Express AI | Adobe Identity Management | dns |
| Adobe GenStudio | Adobe Identity Management | dns |
| Adobe Acrobat AI Assistant | Adobe Identity Management | dns |
| Adobe Sensei GenAI | Adobe Identity Management | dns |
| Adobe Experience Platform AI Assistant | Adobe Identity Management | dns |
| AI21 Jamba | AI21 Labs | xhr |
| Airtable AI | Airtable | dns, dom |
| Aleph Alpha Luminous | Aleph Alpha | xhr |
| Qwen 2.5 | Alibaba Cloud Model Studio | xhr |
| Amazon CodeWhisperer | Amazon Q | xhr |
| Redshift | Amazon Redshift | xhr |
| Amazon Q Business | Amazon Q | xhr |
| Amazon Q Developer | Amazon Q | xhr |
| Amazon Nova | Amazon Bedrock | xhr |
| Amazon SageMaker AI | Amazon SageMaker | xhr |
| Claude Opus 4 | Anthropic API | xhr |
| Claude Sonnet 4 | Anthropic API | xhr |
| Claude Code | Claude Enterprise | dns |
| Claude Fable 5 | Anthropic API | xhr |
| Claude 3.5 Sonnet | Anthropic API | xhr |
| Claude 3.5 Haiku | Anthropic API | xhr |
| Anyscale Endpoints | Anyscale | dns |
| Superset | Apache Superset | html |
| Apollo AI | Apollo | dom, headers, js |
| Asana AI | Asana | dom |
| Atlassian Intelligence | Atlassian Cloud | dns, scriptSrc, xhr |
| Confluence AI | Atlassian Confluence | dom, headers, meta |
| Jira AI | Atlassian Jira | dom, js, meta |
| Atlassian Rovo | Atlassian Cloud | dns, scriptSrc, xhr |
| Atlassian Rovo Dev | Atlassian Cloud | dns, scriptSrc, xhr |
| Bitbucket | Atlassian Bitbucket | html, js, meta, scripts |
| Jira | Atlassian Jira | dom, js, meta |
| Autodesk Assistant | Autodesk | dns |
| Autodesk Neural CAD | Autodesk | dns |
| Autodesk Forma AI | Autodesk | dns |
| Automation Anywhere Autopilot | Automation Anywhere | xhr |
| Ernie 4.0 | Baidu ERNIE | xhr |
| FLUX.1 | fal.ai | html, xhr |
| Box AI | Box | dns, dom, xhr |
| Box AI Agents | Box | dns, dom, xhr |
| VMware Private AI | VMware Cloud | dns |
| VMware Cloud Foundation AI Services | VMware Cloud | dns |
| Doubao | Volcengine Ark | xhr |
| C3 Generative AI | C3 AI | xhr |
| Canva Magic Studio | Canva | dns, dom, js |
| Cerebras Inference | Cerebras | xhr |
| Cisco AI Assistant | Cisco Cloud | dns |
| Cisco AI Network Analytics | Cisco Cloud | dns |
| Splunk AI Assistant | Splunk | cookies, headers |
| Splunk AI Agents | Splunk | cookies, headers |
| Clari Copilot | Clari | xhr |
| ClickUp Brain | ClickUp | dns, js, scriptSrc |
| Codeium | Windsurf | dns, xhr |
| Cohere Command R | Cohere | xhr |
| Cohere North | Cohere | xhr |
| Command R+ | Cohere | xhr |
| Command A | Cohere | xhr |
| Cohere Embed | Cohere | xhr |
| Cohere Rerank | Cohere | xhr |
| Aya | Cohere | xhr |
| Databricks Mosaic AI | Databricks | dom, headers, meta, scriptSrc, text, url, xhrUrl |
| Databricks DBRX | Databricks | dom, headers, meta, scriptSrc, text, url, xhrUrl |
| Databricks AI/BI Genie | Databricks | dom, headers, meta, scriptSrc, text, url, xhrUrl |
| Datadog Bits AI | Datadog | js, scriptSrc |
| Datadog Bits AI Agents | Datadog | js, scriptSrc |
| Dataiku LLM Mesh | Dataiku | url, xhr |
| DataRobot AI Platform | DataRobot | xhr |
| DeepSeek V3 | DeepSeek | xhr |
| DeepSeek R1 | DeepSeek | xhr |
| DeepSeek Coder | DeepSeek | xhr |
| Dell AI Factory | Dell Technologies Cloud | dns |
| Dell PowerEdge AI Servers | Dell Technologies Cloud | dns |
| Dropbox Dash | Dropbox | dns, scriptSrc, xhr |
| Dropbox AI | Dropbox | dns, scriptSrc, xhr |
| Elastic Stack | Elasticsearch | dom |
| Figma AI | Figma | dns, dom, scriptSrc |
| Geotab Ace | Geotab | dom, scriptSrc, xhr |
| GitHub Copilot | GitHub | scriptSrc, xhr |
| GitHub Copilot Workspace | GitHub | scriptSrc, xhr |
| Gong AI | Gong | headers |
| Gemini 2.5 Pro | Google Gemini API | xhr |
| Gemini Enterprise | Google Gemini API | xhr |
| Google AI Studio | Google Gemini API | xhr |
| Google Vids | Google Workspace | dns |
| NotebookLM | Google Workspace | dns |
| Gemini 2.0 Flash | Google Gemini API | xhr |
| Gemini Ultra | Google Gemini API | xhr |
| Imagen 3 | Google Gemini API | xhr |
| BigQuery | Google BigQuery | xhr |
| AlphaFold 3 | AlphaFold | html, xhr |
| Veo 2 | Google Gemini API | xhr |
| GrammarlyGO | Grammarly | dom, scriptSrc |
| Grammarly AI | Grammarly | dom, scriptSrc |
| GroqCloud | Groq | xhr |
| H2O.ai h2oGPTe | H2O.ai | xhr |
| Harvey AI | Harvey | xhr |
| Terraform | HashiCorp Cloud Platform | dns |
| HashiCorp Vault | HashiCorp Cloud Platform | dns |
| HubSpot Breeze | HubSpot | dns, html, js, scriptSrc |
| HubSpot Breeze AI | HubSpot | dns, html, js, scriptSrc |
| HubSpot Breeze Agents | HubSpot | dns, html, js, scriptSrc |
| HubSpot Breeze Copilot | HubSpot | dns, html, js, scriptSrc |
| Hugging Face Inference Endpoints | Hugging Face | scriptSrc, xhr |
| Hugging Face Enterprise Hub | Hugging Face | scriptSrc, xhr |
| IBM watsonx.ai | IBM watsonx | xhr |
| IBM watsonx Orchestrate | IBM watsonx | xhr |
| IBM Granite Models | IBM watsonx | xhr |
| IBM watsonx.data | IBM watsonx | xhr |
| IBM watsonx.governance | IBM watsonx | xhr |
| IBM watsonx BI | IBM watsonx | xhr |
| IBM Bob | IBM Cloud | dns |
| Ideogram 2.0 | Ideogram | xhr |
| Inflection Pi | Inflection AI | xhr |
| Intercom Fin | Intercom | dns, dom, js, scriptSrc |
| Intuit Assist | Intuit QuickBooks | dom, scriptSrc, xhr |
| QuickBooks AI | Intuit QuickBooks | dom, scriptSrc, xhr |
| TurboTax AI | Intuit QuickBooks | dom, scriptSrc, xhr |
| Island Enterprise Browser AI | Island Enterprise Browser | dns |
| Jasper AI | Jasper | xhr |
| Klaviyo AI | Klaviyo | dns, js, scriptSrc |
| Kong Gateway | Kong | headers |
| LangChain | LangSmith | xhr |
| Luma Dream Machine | Luma AI | html, xhr |
| Lytx Machine Vision + AI | Lytx | scriptSrc, xhr |
| Make AI Agents | Make | dns, xhr |
| Meta Llama 3 | Llama API | xhr |
| Code Llama | Llama API | xhr |
| Llama 4 | Llama API | xhr |
| Llama 4 Scout | Llama API | xhr |
| Llama 4 Maverick | Llama API | xhr |
| Microsoft 365 Copilot | Microsoft 365 | dns |
| Microsoft Copilot Studio | Microsoft 365 | dns |
| Microsoft Security Copilot | Microsoft 365 | dns |
| Microsoft Copilot for Sales | Microsoft 365 | dns |
| Copilot in Power BI | Microsoft Power BI | headers, js, scriptSrc |
| Synapse Analytics | Azure Synapse Analytics | xhr |
| VS Code | VS Code for the Web | html, xhr |
| GitHub Actions | GitHub | scriptSrc, xhr |
| Power BI | Microsoft Power BI | headers, js, scriptSrc |
| Microsoft Teams | Microsoft 365 | dns |
| Microsoft Power Platform | Microsoft 365 | dns |
| Miro AI | Miro | dns, dom, scriptSrc |
| Mistral Large | Mistral AI | dns, xhr |
| Le Chat | Mistral AI | dns, xhr |
| Mistral Medium 3.5 | Mistral AI | dns, xhr |
| Mistral Small 4 | Mistral AI | dns, xhr |
| Codestral | Mistral AI | dns, xhr |
| Devstral 2 | Mistral AI | dns, xhr |
| Mixtral 8x22B | Mistral AI | dns, xhr |
| Pixtral | Mistral AI | dns, xhr |
| Monday AI | Monday.com | dns, xhr |
| Motive AI Dashcam | Motive | dom, scriptSrc, scripts, xhr |
| Notion AI | Notion | dns, dom |
| NVIDIA NeMo | NVIDIA AI Enterprise | xhr |
| GPT-5 | OpenAI API | dns, xhr |
| ChatGPT Enterprise | OpenAI API | dns, xhr |
| Sora | OpenAI API | dns, xhr |
| Codex | OpenAI API | dns, xhr |
| DALL-E 3 | OpenAI API | dns, xhr |
| GPT-4o | OpenAI API | dns, xhr |
| GPT-4 Turbo | OpenAI API | dns, xhr |
| OpenAI o1 | OpenAI API | dns, xhr |
| OpenAI o3 | OpenAI API | dns, xhr |
| Whisper | OpenAI API | dns, xhr |
| Oracle AI Agent Studio | Oracle Cloud Infrastructure | scriptSrc, xhr |
| Oracle Cloud Infrastructure Generative AI | Oracle Cloud Infrastructure | scriptSrc, xhr |
| Oracle Database 23ai | Oracle Cloud Infrastructure | scriptSrc, xhr |
| Oracle AI Database 26ai | Oracle Cloud Infrastructure | scriptSrc, xhr |
| Oracle AI Agents | Oracle Cloud Infrastructure | scriptSrc, xhr |
| Otter AI Chat | Otter.ai | dom, xhr |
| Outreach Kaia | Outreach | xhr |
| Palo Alto Networks Cortex XSIAM | Palo Alto Networks | dns, headers |
| Palo Alto Cortex AgentiX | Palo Alto Networks | dns, headers |
| Palo Alto Prisma AIRS | Palo Alto Networks | dns, headers |
| Palo Alto Precision AI | Palo Alto Networks | dns, headers |
| Perplexity Enterprise Pro | Perplexity Enterprise | dns, xhr |
| Perplexity Pro | Perplexity Enterprise | dns, xhr |
| Pika 2.0 | Pika | html, xhr |
| PTC ThingWorx Navigate AI | PTC ThingWorx | url, xhr |
| Red Hat AI Enterprise | Red Hat OpenShift | html, xhr |
| Red Hat OpenShift AI | Red Hat OpenShift | html, xhr |
| Red Hat Enterprise Linux AI | Red Hat OpenShift | html, xhr |
| Replit Agent | Replit | headers |
| Replit AI | Replit | headers |
| Runway Gen-3 Alpha | Runway | xhr |
| Salesforce Agentforce | Salesforce | cookies, dns, html, js |
| Einstein Copilot | Salesforce | cookies, dns, html, js |
| Einstein GPT | Salesforce | cookies, dns, html, js |
| Slack AI | Slack | dns, dom, scriptSrc |
| Tableau Pulse | Tableau | js, scriptSrc |
| Salesforce Einstein GPT | Salesforce | cookies, dns, html, js |
| Salesforce Data Cloud AI | Salesforce | cookies, dns, html, js |
| Salesloft Rhythm | Salesloft | js |
| Samsara Assistant | Samsara | dom, scriptSrc, xhr |
| SAP Joule | SAP SuccessFactors | dns |
| SAP Business AI | SAP SuccessFactors | dns |
| SAP AI Core | SAP SuccessFactors | dns |
| SAS Viya AI | SAS Viya | xhr |
| SAS Visual AI | SAS Viya | xhr |
| Scale Data Engine | Scale AI | xhr |
| ServiceNow Now Assist | ServiceNow | dom, js, scriptSrc |
| ServiceNow AI Agents | ServiceNow | dom, js, scriptSrc |
| Shopify Sidekick | Shopify | cookies, dom, headers, js, meta, scriptSrc, scripts, url, xhr |
| Shopify Magic | Shopify | cookies, dom, headers, js, meta, scriptSrc, scripts, url, xhr |
| Siemens Industrial Copilot | Siemens Xcelerator | xhr |
| AutoGPT | AutoGPT Platform | html |
| Snowflake Cortex AI | Snowflake | scriptSrc, xhr |
| Snowflake Cortex Analyst | Snowflake | scriptSrc, xhr |
| Snowflake Cortex Search | Snowflake | scriptSrc, xhr |
| Snowflake Arctic | Snowflake | scriptSrc, xhr |
| Snyk AI Trust Platform | Snyk | dom, xhr |
| Cody | Sourcegraph Amp | dns |
| Sourcegraph Cody | Sourcegraph Amp | dns |
| Stable Diffusion 3 | Stability AI | xhr |
| Stable Video Diffusion | Stability AI | xhr |
| Stable Diffusion 3.5 | Stability AI | xhr |
| Suno AI | Suno | html, xhr |
| Tines AI | Tines | xhr |
| Together Inference | Together AI | xhr |
| UiPath Autopilot | UiPath | scriptSrc, xhr |
| Weights & Biases Weave | Weights & Biases | dom, xhr |
| Wiz AI-SPM | Wiz | dns |
| Workday Illuminate | Workday | dom, js, scriptSrc, xhr |
| Workday AI | Workday | dom, js, scriptSrc, xhr |
| Writer AI Studio | Writer | xhr |
| Grok 3 | xAI Grok | xhr |
| Grok-2 | xAI Grok | xhr |
| Zapier AI | Zapier | dns |
| Zapier Agents | Zapier | dns |
| Zendesk AI | Zendesk | cookies, dns, headers, js, scriptSrc |
| GLM-4 | Zhipu AI | xhr |
| Zoho Zia | Zoho | dns |
| Zoho Zia Voice | Zoho | dns |
| Zoom AI Companion | Zoom | dns, dom, scriptSrc |
| ZoomInfo Copilot | Zoominfo | scriptSrc |

## Mapped, detection not possible (15)

| Product | Reported as | Detection channels |
| --- | --- | --- |
| Abnormal Security AI | Abnormal Security | - |
| Anthropic MCP | Model Context Protocol | - |
| CrowdStrike Charlotte AI | CrowdStrike Falcon | - |
| CrowdStrike Falcon | CrowdStrike Falcon | - |
| Lacework | Lacework | - |
| Neovim | Neovim | - |
| Netskope SkopeAI | Netskope | - |
| NVIDIA Jetson Orin | NVIDIA Jetson | - |
| Orca Security | Orca Security | - |
| Phind | Phind | - |
| pgvector | pgvector | - |
| SentinelOne Purple AI | SentinelOne | - |
| SentinelOne | SentinelOne | - |
| Zed | Zed | - |
| Zscaler AI | Zscaler | - |
