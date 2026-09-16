# The `did:cimd` DID Method Specification (v1.0)

A DID method that treats an **OAuth Client ID Metadata Document** (CIMD) a client already publishes as the identity document. No registry, no ledger, no extra registration step. The URL used as the client identifier is the identifier, and the public keys that document points at are the verification keys.

**Method name:** `cimd`, after the OAuth Client ID Metadata Document this method resolves. The name states the resolution mechanism, not a product, an organization or a network.

**Conformance.** The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD and MAY in this document are to be interpreted as described in [BCP 14](https://www.rfc-editor.org/rfc/rfc2119) when, and only when, they appear in all capitals.

> In this document, CIMD means [OAuth Client ID Metadata Document](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/), the IETF OAuth working group document. It is unrelated to the SMSC protocol of the same acronym (Computer Interface to Message Distribution).

## 0. Motivation

**The document is already there.** AI agents are numerous, short-lived, and cross organizational boundaries. Nobody can hand-register each one with every server it meets. The answer the industry settled on is CIMD: use an HTTPS URL as the client identifier, and have that URL serve the client's own metadata document.

The Model Context Protocol authorization specification puts CIMD first, describing it as the case "when client and server have no prior relationship (most common)", and requires clients and authorization servers to support it (SHOULD). Dynamic Client Registration, long the standard answer, is now optional (MAY) and kept for backwards compatibility. The SCIM agent extension work under way at the IETF likewise leaves OAuth client self-registration to CIMD.

A client following that specification publishes its metadata at a stable URL, publishes its public keys inside it via `jwks` or `jwks_uri`, and authenticates with those keys. A stable identifier, a resolvable document, the keys that document designates, and a rotation path. **Everything a DID does is already happening. Only the name is missing.**

`did:cimd` supplies the name. No new infrastructure and no new registration step: one resolution rule on top of documents that are already deployed.

**Why an agent needs a name.** An agent acts on behalf of a user. To record who delegated what to whom, and to verify that delegation later, the subject of the delegation needs a stable name. A client registration identifier minted anew on each connection cannot be that name. Credentials, policies and audit records all need something to attach to. `did:cimd` puts the URL the agent already has in that place.

The method itself is not agent-specific. Any OAuth client that publishes a CIMD qualifies. It is simply that the agent ecosystem is where this is spreading fastest.

## 1. Scope

What this method establishes is one fact: **control of an HTTPS origin**. Whoever can publish a document at that URL is the DID controller.

It says nothing about whether that origin, or the key it designates, should be *trusted* for any purpose beyond that control. Applications that need an authorization or trust decision (which clients may act on a given task, which keys to rely on) should layer a separate mechanism on top, such as a trust registry or credential-based attestation. This method supplies the *subject identity* such a decision is made about, not the decision.

### 1.1 Maturity of the underlying specification

CIMD is an IETF working group document and not yet an RFC. This specification is designed with that in mind.

- **The dependency is narrow.** This method relies on three things only: the client identifier is an HTTPS URL, the document served there has a `client_id` equal to that URL, and keys are published via `jwks` or `jwks_uri`. These have been stable since the individual draft, and shipping implementations already rely on them.
- **Identifiers are not tied to the draft.** A DID string encodes the URL and nothing else. A revision of CIMD leaves already-issued identifiers valid; only the resolution profile (3.1, 3.2) is affected.
- **The revision is pinned.** This version profiles [draft-ietf-oauth-client-id-metadata-document-02](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/). When the underlying document is revised, this specification is revised too, and continues to state which revision it profiles.
- **The direction of hardening is settled.** Should CIMD adopt a signed-metadata option, this specification is expected to require it (section 7).

## 2. Syntax

```abnf
cimd-did = "did:cimd:" host 1*( ":" segment )
host     = 1*( ALPHA / DIGIT / "-" / "." )      ; a port is encoded as "%3A" port
segment  = 1*( ALPHA / DIGIT / "-" / "_" / "." / pct-encoded )
```

At least one `segment` is REQUIRED, and no `segment` may be `"."` or `".."`. A Client Identifier URL MUST contain a path component and MUST NOT contain dot path components (CIMD, section 3), so a DID without a path segment would map to a URL that cannot be a Client Identifier URL.

The base URL `B` is obtained by replacing each `:` after `host` with `/`, decoding `%3A`, and prefixing `https://`. `B` is the Client Identifier URL and also the URL of the metadata document.

| DID | Base URL `B` |
|---|---|
| `did:cimd:example.com:agents:billing` | `https://example.com/agents/billing` |
| `did:cimd:example.com:client.json` | `https://example.com/client.json` |

`B` itself is the metadata document.

## 3. Operations

### 3.0 Authorization

Authorization for every operation is determined by control of the base URL's HTTPS origin. The DID Document itself is never used to make an authorization decision.

### 3.1 Create

The controller chooses an identity key and publishes a CIMD according to the profile below. There is no third-party registration step.

1. The document MUST be served at `B`, and its `client_id` MUST equal `B`. This is a CIMD requirement.
2. The identity key MUST be declared via `jwks` or `jwks_uri`, both permitted by CIMD. These are the keys the client authenticates itself with, which is exactly the meaning this method gives them.
3. A `jwks_uri` MUST be on the same HTTPS origin as `B`. CIMD itself does not constrain its origin; this is a constraint this method adds.
4. Each key JWK MUST carry a `kid`. It forms the verification method identifier.
5. A CIMD carries no signature of its own. The document and its keys are protected by TLS and same-origin placement only. This reflects the current state of the underlying specification, not a design preference: should CIMD adopt a signed-metadata option, this specification is expected to require it.

### 3.2 Read (Resolve)

1. Parse the DID. On a syntax violation, return `invalidDid`.
2. **Fetch the document.** `GET B` with `Accept: application/json`, over HTTPS only, rejecting any redirect that changes origin. This fetch and the `jwks_uri` fetch in step 3 MUST be treated as fetching an attacker-influenced URL: resolve the host, reject private, loopback and link-local address space, and re-validate the resolved address immediately before connecting to close DNS-rebinding gaps.
   - `200`: validate against the profile (3.1) and extract keys. On a violation, `notFound`.
   - `410`: return `deactivated: true` and stop (see 3.4).
   - `404` or anything else: `notFound`.
3. **Extract keys.** Take `jwks`, or fetch the JWK Set at `jwks_uri`. Discard any secret parameters found. **Retain only keys usable for verifying signatures:** discard a JWK whose `use` is present and is not `"sig"`, and one whose `key_ops` is present and does not include `"verify"`; a JWK carrying neither member is retained. If no key remains, `notFound`.
4. **Assemble the DID Document.**
   - `id` = the requested DID.
   - `verificationMethod` = for each retained key, `{ id: <DID>#<kid>, type: "JsonWebKey2020", controller: <DID>, publicKeyJwk }`.
   - `authentication`, `assertionMethod` = every retained key. The client authenticates as this DID subject with them and signs assertions made on its own behalf with them. This method defines no `keyAgreement`, `capabilityInvocation` or `capabilityDelegation`.
   - `service` = `{ id: <DID>#cimd, type: "OAuthClientMetadata", serviceEndpoint: B }`.
   - `alsoKnownAs` SHOULD contain the CIMD `client_id` (= `B`).

Authenticity of the response rests on the origin verified over TLS. There is no signature beyond that.

### 3.3 Update

Republishing the document at the same URL is an update. Key rotation: publish the new key in `jwks` or at `jwks_uri`, start using it, and remove the old key after an overlap period. Removing the old key immediately would break verification of signatures already in flight, so an overlap period SHOULD be used.

### 3.4 Deactivate

Remove the document and make `B` return `410 Gone`. A DID whose identity document returns `410` is deactivated.

## 4. Security Considerations

Per RFC 3552.

- **Scope of protection.** TLS protects the transport of every document: confidentiality, integrity, server authentication. The CIMD and the JWK Set have no protection beyond TLS. Secret material is out of scope for this method and MUST NOT appear in any of these documents.
- **Origin control is key control.** Whoever takes over a domain, or acquires an expired one, can publish new keys and become the subject of that DID. Signatures that must be verified long after the fact need an additional mechanism, such as recording the key state at signing time.
- **Request forgery.** A resolver is made to fetch a host an attacker chose. Blocking private, loopback and link-local ranges, and re-checking immediately before connecting, is required.
- **Resource limits.** Bound response size, time, and redirect count.
- **Caching.** Keep cache lifetimes short: they determine how fast rotation and deactivation take effect.
- **Key purpose.** Filtering on `use` and `key_ops` keeps an encryption key from being mistaken for an authentication key.

## 5. Privacy Considerations

- The identifier exposes the host and path verbatim. Choose paths that do not leak organizational structure.
- Identifiers on the same origin are correlatable. This method does not aim to prevent correlation.
- Resolution tells the target origin that someone is resolving that identifier. Where resolver privacy matters, use caching or a relay.
- Do not put personal data in a CIMD. Cached copies cannot be recalled.

## 6. Example

CIMD at `https://example.com/agents/billing`:

```json
{
  "client_id": "https://example.com/agents/billing",
  "client_name": "Billing Agent",
  "jwks_uri": "https://example.com/agents/billing/jwks.json",
  "token_endpoint_auth_method": "private_key_jwt"
}
```

Resolved DID Document:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
  "id": "did:cimd:example.com:agents:billing",
  "alsoKnownAs": ["https://example.com/agents/billing"],
  "verificationMethod": [{
    "id": "did:cimd:example.com:agents:billing#key-1",
    "type": "JsonWebKey2020",
    "controller": "did:cimd:example.com:agents:billing",
    "publicKeyJwk": { "kty": "EC", "crv": "P-256", "kid": "key-1", "use": "sig", "x": "...", "y": "..." }
  }],
  "authentication": ["did:cimd:example.com:agents:billing#key-1"],
  "assertionMethod": ["did:cimd:example.com:agents:billing#key-1"],
  "service": [{
    "id": "did:cimd:example.com:agents:billing#cimd",
    "type": "OAuthClientMetadata",
    "serviceEndpoint": "https://example.com/agents/billing"
  }]
}
```

## 7. Future Work

- Require signed metadata once CIMD offers it.
- Other identity document formats are not added to this method; they are defined as separate methods. One method per document format keeps the resolution rule simple.

## 8. Intellectual Property

This specification is published under the [Apache License 2.0](./LICENSE). Implementing this method requires no separate permission from the author, and no fee, registration or membership of any kind.

## References

- [Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
- [Model Context Protocol, Authorization (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [OAuth Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document)](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)
- [RFC 7517 JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 3552 Security Considerations Guidelines](https://www.rfc-editor.org/rfc/rfc3552)
