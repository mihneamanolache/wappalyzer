# Public domain configuration enrichment

Verified and implemented on 2026-10-22. These additions complement the
[Fabric detection work](microsoft-fabric-detection.md); none of them implies
Microsoft Fabric or Power BI.

## New detections

| Observation | Technology | Interpretation |
| --- | --- | --- |
| Microsoft DKIM CNAME at selector1/2 | Microsoft 365 | Domain has Microsoft mail-signing configuration; extract the initial tenant as metadata |
| enterpriseenrollment CNAME to documented Microsoft management host | Microsoft Intune | Device enrollment discovery configured |
| enterpriseregistration CNAME to enterpriseregistration.windows.net | Microsoft Entra ID | Device registration discovery configured; no Premium inference |
| autodiscover CNAME to autodiscover.outlook.com | Microsoft Exchange Online | Hosted Exchange discovery configured |
| Valid DMARC rua/ruf destination | Cloudflare DMARC Management, dmarcian, Valimail, Agari DMARC Protection, Proofpoint Email Fraud Defense | Reporting destination configured, not proof of delivery or an active subscription |
| _dmarc NS/CNAME to documented Valimail hosts (full mode) | Valimail | Delegated DMARC policy management |
| Bare ZOOM_verify_ TXT token | Zoom | Adds the alternate verification form missing from the existing marker |
| cisco-ci-domain-verification / webexdomainverification TXT | Cisco Webex | Organization domain verification configuration |
| Structured /.well-known/okta-organization response (full mode) | Okta | Organization metadata with an Okta organization URL |

All new DNS patterns have start/end anchors. DMARC provider patterns run only
against individually parsed `mailto:` destinations from exactly one DMARC policy
with a valid `p` tag and no duplicate tags. A provider name in a local part,
unrelated tag, URL query or lookalike hostname cannot trigger detection. We retain
the original record separately. DNS can be stale and any domain owner can publish
a vendor-looking record; this is configuration evidence, not independent vendor
confirmation.

Existing TXT coverage already includes Apple, Stripe, Dropbox, Docker, OneTrust,
Miro and GitLab. We did not duplicate those entries or reinterpret a generic
verification token as use of every product the vendor sells.

## Additional metadata

`domainEvidence` in Wappalyzer results retains named DNS answers with their owner,
type and observation time. It also retains validated Entra publisher association
app IDs, Apple app identifiers, Android package names, OIDC discovery endpoints,
Okta organization metadata, security contacts and MTA-STS policy fields.

The Microsoft DKIM parser covers both the older `tenant.onmicrosoft.com` form
and Microsoft's newer `tenant.<partition>-v1.dkim.mail.microsoft` form. The
initial tenant does **not** establish the current SharePoint address: Microsoft
supports SharePoint domain renaming.

An Entra publisher association file lists applications associated for publisher
domain verification. It is not an inventory of the organization's internal apps.
Its presence does not prove Premium licensing. OIDC metadata requires HTTPS
issuer, authorization and JWKS URLs on the fetched host's origin. This deliberately
misses some valid cross-origin configurations; it avoids attributing an unrelated
issuer copied into a response. We do not infer Keycloak or ADFS from a generic
OIDC document or from the request path alone.

SIP, federation, LDAP, Kerberos, XMPP and CalDAV records remain metadata. Old
Lync/Skype configuration does not prove active Teams use. Public service discovery
does not by itself demonstrate a vulnerability. BIMI, TLS reporting and MTA-STS
records likewise are not a security maturity score. The MTA-STS policy is fetched
from `https://mta-sts.<domain>/.well-known/mta-sts.txt` only after finding its
discovery TXT record. It is not fetched from the homepage host.

## Collection cost and limits

- Disabled probing performs none of these lookups.
- `basic` adds six fixed DNS lookups. The crawler's existing basic setting gets
  Microsoft configuration and DMARC provider detections without enabling full
  HTTP probing.
- `full` adds 16 named DNS lookups and seven fixed HTTPS paths, plus a conditional
  MTA-STS policy request. Work has at most six concurrent operations and a
  four-second scheduling budget (further capped by `maxWait`). Individual DNS or
  HTTP operations have a 1.5-second deadline; work still pending at the scheduling
  deadline may finish within its own deadline. Slow responses can leave some
  optional names unqueried. Absence is not negative evidence of product use.
- DNS results are coalesced in a process cache capped at 2,048 entries and 60
  seconds. Failures are not cached. This is a cache cap, not an authoritative TTL.
- HTTP uses certificate-verified HTTPS, no credentials, no redirects and a
  100 KB body limit. DNS answers are capped at 64 values of at most 4 KB each.
- Queries use the exact crawled hostname, removing only a leading `www.`. They
  do not climb to a parent domain, guess tenants or enumerate users. Consequently,
  crawling a subdomain may miss organization-level records at its apex.

The crawler's existing technology mapping will publish the new technology
detections. Its Kafka technology-array format does not publish the separate
`domainEvidence` metadata field; that field is available through the Wappalyzer
API/CLI. Changing that downstream data contract is a separate integration.

The requested guessed GitHub organization names, guessed SaaS tenant existence
checks and userrealm calls are not included. Robots.txt is already collected.
Sitemaps are not added as a technology signal: their existence does not establish
a specific product or prove that listed paths are internal.

## Sources and reproducible evidence

- [Microsoft DKIM configuration](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure)
  documents both CNAME generations.
- [Microsoft Intune CNAME discovery](https://learn.microsoft.com/en-us/intune/device-enrollment/windows/create-cname-autodiscovery)
  distinguishes enrollment from Entra registration.
- [Microsoft 365 DNS records](https://learn.microsoft.com/en-us/microsoft-365/admin/dns/create-dns-records-using-windows-based-dns?view=o365-worldwide)
  documents autodiscover and SIP discovery targets.
- [SharePoint domain renaming](https://learn.microsoft.com/en-us/sharepoint/change-your-sharepoint-domain-name)
  prevents equating the initial tenant with today's SharePoint URL.
- [Entra publisher domain configuration](https://learn.microsoft.com/en-us/entra/identity-platform/howto-configure-publisher-domain)
  explains the association file's scope.
- [Okta organization metadata API](https://developer.okta.com/docs/api/openapi/okta-management/management/tags/orgsettingmetadata/)
  and the official [SDK metadata model](https://github.com/okta/okta-sdk-nodejs/blob/master/src/types/generated/models/WellKnownOrgMetadata.d.ts)
  and [links model](https://github.com/okta/okta-sdk-nodejs/blob/master/src/types/generated/models/WellKnownOrgMetadataLinks.d.ts)
  establish the fixed path and response fields. This entry has documentation and
  fixture coverage; it is not presented as a measured customer deployment.
- [Cisco Live Webex domain verification](https://www.ciscolive.com/c/dam/r/ciscolive/global-event/docs/2025/pdf/BRKCOL-3017.pdf)
  documents the Cisco Identity token. Direct DNS also confirmed both Webex token
  forms, including bare `webexdomainverification.` with no suffix identifier.
- [Zoom developer support example](https://devforum.zoom.us/t/txt-domain-verification-failing/132516)
  documents Zoom verification; the bare token was directly observed in public DNS.
- [Cloudflare reporting documentation](https://developers.cloudflare.com/dmarc-management/enable/),
  [dmarcian](https://dmarcian.com/dmarc-record-wizard/),
  [Valimail](https://support.valimail.com/en/articles/8466367-pointing-a-dmarc-record-to-valimail),
  and [Fortra Agari](https://static.fortra.com/agari/pdfs/solution-brief/ag-implementing-dmarc-public-sector-emea-sb.pdf)
  describe DMARC configuration. Direct vendor DNS confirms reporting hostnames,
  including Proofpoint's `emaildefense.proofpoint.com`.
- [MTA-STS RFC 8461](https://www.rfc-editor.org/rfc/rfc8461.html),
  [Android Digital Asset Links](https://developers.google.com/digital-asset-links/v1/getting-started),
  [Apple associated domains](https://developer.apple.com/documentation/xcode/supporting-associated-domains),
  [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html), and
  [security.txt RFC 9116](https://www.rfc-editor.org/rfc/rfc9116.html) describe the
  document formats.

Retained direct public DNS observations are in
[`domain-evidence-observations.json`](domain-evidence-observations.json), including
timestamps and queried owners. Tests run those observations through the actual
catalog engine. They also cover lookalike hosts, misplaced provider names,
duplicate DMARC policies, split TXT chunks, malformed discovery JSON, HTML
fallbacks, wrong origins, request limits and partial lookup failures.
