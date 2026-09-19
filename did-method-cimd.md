# The `did:cimd` DID Method Specification (v1.1)

A DID method that treats an **OAuth Client ID Metadata Document** (CIMD) a client already publishes as the identity document. No registry, no ledger, no extra registration step. The URL used as the client identifier is the identifier, and the public keys that document points at are the verification keys.

**Method name:** `cimd`, after the OAuth Client ID Metadata Document this method resolves. The name states the resolution mechanism, not a product, an organization or a network.

**Conformance.** The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD and MAY in this document are to be interpreted as described in [BCP 14](https://www.rfc-editor.org/rfc/rfc2119) when, and only when, they appear in all capitals.

> In this document, CIMD means [OAuth Client ID Metadata Document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02), the IETF OAuth working group document. It is unrelated to the SMSC protocol of the same acronym (Computer Interface to Message Distribution).

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
- **The revision is pinned.** This version profiles [draft-ietf-oauth-client-id-metadata-document-02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02). When the underlying document is revised, this specification is revised too, and continues to state which revision it profiles.
- **The direction of hardening is settled.** Should CIMD adopt a signed-metadata option, this specification is expected to require it (section 7).

## 2. Syntax

```abnf
cimd-did    = "did:cimd:" authority 1*( ":" segment )
authority   = host [ "%3A" port ]
host        = 1*( ALPHA / DIGIT / "-" / "." )
port        = 1*5DIGIT
segment     = 1*( ALPHA / DIGIT / "-" / "_" / "." / pct-encoded )
pct-encoded = "%" HEXDIG HEXDIG
```

`ALPHA`, `DIGIT` and `HEXDIG` are the core rules of [RFC 5234](https://www.rfc-editor.org/rfc/rfc5234).

At least one `segment` is REQUIRED, and no `segment` may be `"."` or `".."`. A Client Identifier URL MUST contain a path component and MUST NOT contain dot path components (CIMD, section 3), so a DID without a path segment would map to a URL that cannot be a Client Identifier URL.

A port is carried in the `authority` as `%3A` followed by the port number. This is the only percent-encoded sequence permitted in the `authority`; `host` itself is never percent-encoded.

### 2.1 Canonical form

The transformations in 2.2 and 2.3 are inverses only over identifiers in canonical form:

1. `host` is lowercase, and is a DNS name rather than an IP literal.
2. `port`, if present, is not zero-padded, and is neither inserted nor dropped — `443` included.
3. The hexadecimal digits of every `pct-encoded` sequence are uppercase.
4. Within a `segment`, a character the grammar admits literally is written literally, and every other character is percent-encoded.

A resolver given an identifier that satisfies the grammar but not these rules MUST return `invalidDid`. Without them one document would have more than one name.

### 2.2 DID to base URL

The base URL `B` is derived as follows.

1. Verify the identifier against the grammar and 2.1. On failure, return `invalidDid`.
2. Remove the `did:cimd:` prefix and split the remainder on `:`. The first field is the `authority`; the rest, in order, are the path segments.
3. In the `authority` only, replace `%3A` with `:`. Path segments are carried over verbatim; a resolver MUST NOT percent-decode, re-encode or otherwise normalize them.
4. `B` is `"https://"`, the authority, then each path segment preceded by `/`.

`B` is the Client Identifier URL and also the URL of the metadata document.

### 2.3 Base URL to DID

1. The URL MUST be `https`, with a lowercase host, no userinfo, query or fragment, a non-empty path with no empty and no dot segments, no trailing slash, and path segments already in the canonical encoding of §2.1 — drawn only from the characters `segment` admits, with no character percent-encoded that `segment` admits literally. A URL that fails any of these has no `did:cimd` name, because altering it would break the exact `client_id` comparison CIMD requires.
2. The authority is the host, followed by `%3A` and the port if the URL carries one. CIMD compares Client Identifier URLs by simple string comparison, under which `https://example.com/c` and `https://example.com:443/c` are two different clients, so a port is preserved exactly as the URL gives it.
3. Uppercase the hexadecimal digits of every percent-encoded sequence in the path segments, and change nothing else in them.
4. The identifier is `"did:cimd:"` followed by the authority and the path segments, joined with `:`.

### 2.4 Examples

| DID | Base URL `B` |
|---|---|
| `did:cimd:example.com:agents:billing` | `https://example.com/agents/billing` |
| `did:cimd:example.com:client.json` | `https://example.com/client.json` |
| `did:cimd:example.com%3A8443:agents:billing` | `https://example.com:8443/agents/billing` |
| `did:cimd:example.com:a%3Ab` | `https://example.com/a%3Ab` |

`B` itself is the metadata document.

## 3. Operations

### 3.0 Authorization

Authorization for every operation is determined by control of the base URL's HTTPS origin. The DID Document itself is never used to make an authorization decision.

### 3.1 Create

The controller chooses an identity key and publishes a CIMD according to the profile below. There is no third-party registration step.

1. The document MUST be served at `B`, and its `client_id` MUST equal `B`. This is a CIMD requirement.
2. The identity key MUST be declared via **exactly one** of `jwks` or `jwks_uri`, both permitted by CIMD. A document carrying both is invalid under this profile (3.2, step 3).
3. A `jwks_uri` MUST be on the same HTTPS origin as `B`. CIMD itself does not constrain its origin; this is a constraint this method adds.
4. A key JWK MAY carry a `kid`. It is preserved in the DID Document but does not form the verification method identifier (3.2, step 4).
5. A CIMD carries no signature of its own. The document and its keys are protected by TLS and same-origin placement only. This reflects the current state of the underlying specification, not a design preference: should CIMD adopt a signed-metadata option, this specification is expected to require it.

### 3.2 Read (Resolve)

1. Parse the DID. On a syntax or canonical-form violation, return `invalidDid`.
2. **Fetch the document.** `GET B` with `Accept: application/json`, over HTTPS only. **Redirects MUST NOT be followed**; a `3xx` response is `notFound`. This fetch and the `jwks_uri` fetch in step 3 MUST be treated as fetching an attacker-influenced URL: resolve the host, reject private, loopback and link-local address space, and re-validate the resolved address immediately before connecting to close DNS-rebinding gaps.
   - `200`: validate against the profile (3.1) and extract keys. On a violation, `notFound`.
   - `410`: the DID is deactivated (see 3.4).
   - `404` or anything else: `notFound`.

   The redirect rule follows the profiled CIMD revision, which forbids following redirects when fetching the document. It is load-bearing rather than incidental: `client_id` is checked against the requested URL by exact string comparison, so a followed redirect would leave the served document's `client_id` disagreeing with the URL actually fetched, and would let whoever controls DNS or the HTTP front end move an established identity to another origin.
3. **Extract keys.** Take `jwks`, or fetch the JWK Set at `jwks_uri`. If both members are present, `notFound`: RFC 7591 treats the two as mutually exclusive, and guessing which one the publisher meant would let two resolvers disagree about a subject's keys. Discard any secret parameters found. **Retain only keys usable for verifying signatures:** discard a JWK whose `use` is present and is not `"sig"`, and one whose `key_ops` is present and does not include `"verify"`; a JWK carrying neither member is retained. Discard a JWK that lacks the members its `kty` requires, since step 4 cannot be computed for it. If no key remains, `notFound`.
4. **Identify keys.** The verification method identifier of a retained key is `<DID>#<thumbprint>`, where `<thumbprint>` is the base64url-encoded, unpadded SHA-256 JWK Thumbprint of that key ([RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)).

   `kid` is not used for this. [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) leaves the structure of `kid` unspecified and only recommends uniqueness, so a published value may be empty, may contain characters that are invalid in a URI fragment, or may repeat within one key set and collide. A thumbprint is derived from the key material: always present, always fragment-safe, and distinct for distinct keys. `did:jwk`, ACME and the `jkt` confirmation claim of OAuth DPoP identify keys the same way. A `kid`, where published, is preserved inside `publicKeyJwk`, so software that selects keys by `kid` — OAuth client authentication in particular — is unaffected.
5. **Assign verification relationships.** A retained key is referenced from `authentication` and from nothing else. This method defines no `assertionMethod`, `keyAgreement`, `capabilityInvocation` or `capabilityDelegation`.

   A key published in a CIMD is published for OAuth client authentication. It proves that the party presenting it is the client named by `client_id` — that is what a `private_key_jwt` `client_assertion` states, addressed to one token endpoint and replay-protected by `jti`. It carries no authorization to sign arbitrary statements on behalf of the DID subject, and this method MUST NOT infer one.

   A subject may hold keys it uses more broadly; an agent that authenticates with `private_key_jwt` and also signs a Verifiable Presentation for a `cnf`-bound credential holds two capabilities, not one. Expressing that requires the controller to declare a key's purposes, and a declaration mechanism is deferred to a later revision (section 7) rather than assumed here. Until then, a relationship this method does not assign is one the document does not claim.
6. **Assemble the DID Document.**
   - `id` = the requested DID.
   - `verificationMethod` = for each retained key, `{ id: <DID>#<thumbprint>, type: "JsonWebKey2020", controller: <DID>, publicKeyJwk }`.
   - `authentication` = every retained key, per step 5.
   - `service` = `{ id: <DID>#cimd, type: <cimd-service-type>, serviceEndpoint: B }`, where `<cimd-service-type>` is the absolute URI `https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#name-client-id-metadata-document`. An absolute URI is used rather than a short name such as `OAuthClientMetadata`, because a short name is a JSON-LD term and would have to be defined in a context this method does not publish. Registering a short service type is future work (section 7).
   - `alsoKnownAs` SHOULD contain the CIMD `client_id` (= `B`).

Authenticity of the response rests on the origin verified over TLS. There is no signature beyond that.

### 3.3 Update

Republishing the document at the same URL is an update. Key rotation: publish the new key in `jwks` or at `jwks_uri`, start using it, and remove the old key after an overlap period. Removing the old key immediately would break verification of signatures already in flight, so an overlap period SHOULD be used.

### 3.4 Deactivate

Remove the document and make `B` return `410 Gone`. A DID whose identity document returns `410` is deactivated.

On a `410` the resolver MUST report success — `didResolutionMetadata` carries no `error` — and MUST return `didDocument` as `null`, with `didDocumentMetadata` carrying `deactivated` set to `true`. This is the result the DID resolution algorithm specifies for a deactivated DID.

Removing the document without serving `410` produces `404` and therefore `notFound`, which states that no such DID was found rather than that this DID is retired. A controller that means to retire an identifier MUST serve `410`.

## 4. Security Considerations

Per RFC 3552.

- **Scope of protection.** TLS protects the transport of every document: confidentiality, integrity, server authentication. The CIMD and the JWK Set have no protection beyond TLS. Secret material is out of scope for this method and MUST NOT appear in any of these documents.
- **Origin control is key control.** Whoever takes over a domain, or acquires an expired one, can publish new keys and become the subject of that DID. Signatures that must be verified long after the fact need an additional mechanism, such as recording the key state at signing time.
- **Redirects.** They are not followed (3.2). Following them would decouple the document actually fetched from the identifier and weaken the exact `client_id` comparison that client authentication rests on.
- **Request forgery.** A resolver is made to fetch a host an attacker chose. Blocking private, loopback and link-local ranges, and re-checking immediately before connecting, is required.
- **Resource limits.** Bound response size and time.
- **Caching.** Keep cache lifetimes short: they determine how fast rotation and deactivation take effect.
- **Key purpose.** Filtering on `use` and `key_ops` keeps an encryption key from being mistaken for an authentication key. Assigning `authentication` alone (3.2, step 5) keeps a client authentication key from being mistaken for an assertion key. A relying party that needs a key authorized for assertions MUST obtain that authorization elsewhere; this method does not express it.

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
    "id": "did:cimd:example.com:agents:billing#nGqB7kZP2sL9vXcR4tYwE6aZbUj1oXvN6gT0sKiMdQ0",
    "type": "JsonWebKey2020",
    "controller": "did:cimd:example.com:agents:billing",
    "publicKeyJwk": { "kty": "EC", "crv": "P-256", "kid": "key-1", "use": "sig", "x": "...", "y": "..." }
  }],
  "authentication": ["did:cimd:example.com:agents:billing#nGqB7kZP2sL9vXcR4tYwE6aZbUj1oXvN6gT0sKiMdQ0"],
  "service": [{
    "id": "did:cimd:example.com:agents:billing#cimd",
    "type": "https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#name-client-id-metadata-document",
    "serviceEndpoint": "https://example.com/agents/billing"
  }]
}
```

The published `kid` survives inside `publicKeyJwk`; the fragment is the key's thumbprint. The key is referenced from `authentication` only.

## 7. Future Work

- Require signed metadata once CIMD offers it.
- Define a mechanism by which a controller declares the purposes of a key, so that a subject signing on its own behalf — a Verifiable Presentation for a `cnf`-bound credential, for instance — can be expressed without granting every key every relationship. The form this takes is left to a later revision, informed by implementation experience.
- Register a service type for the Client ID Metadata Document in the DID Specification Registries, so that the `service` entry can carry a short name in place of the absolute URI it uses now (3.2, step 6).
- Other identity document formats are not added to this method; they are defined as separate methods. One method per document format keeps the resolution rule simple.

## 8. Intellectual Property

This specification is published under the [Apache License 2.0](./LICENSE). Implementing this method requires no separate permission from the author, and no fee, registration or membership of any kind.

## 9. Changelog

**1.1** — Registry review feedback.

- Section 2: `authority`, `port` and `pct-encoded` added to the ABNF, so that the port syntax the prose already described is expressible; canonical form stated; DID-to-URL and URL-to-DID given as inverse procedures, with a port example. The `%3A` decoding of 1.0 applied to the whole identifier and would have corrupted an encoded path segment; it now applies to the authority alone.
- 3.2 step 2: redirects are no longer followed at all, replacing the same-origin allowance, with the reason recorded. The redirect-count limit in section 4 is dropped as moot.
- 3.2 step 4: verification method identifiers are RFC 7638 thumbprints. `kid` is no longer required by 3.1 and no longer forms the identifier; it is preserved in `publicKeyJwk`.
- 3.2 step 5: a retained key is referenced from `authentication` alone. `assertionMethod`, which 1.0 granted to every key, is no longer assigned by this method at all; a mechanism for declaring key purposes is deferred to a later revision (section 7).
- 3.1 item 2 and 3.2 step 3: a document carrying both `jwks` and `jwks_uri` is invalid.
- The `service` entry keeps its place, but its `type` is now the absolute URI of the CIMD section that defines the document, in place of the short name `OAuthClientMetadata`, which was never defined in any JSON-LD context.
- 3.4: the exact resolution result for `410` is specified — `didDocument` null, `didDocumentMetadata.deactivated` true, no error — and distinguished from `404`.
- The CIMD reference is pinned to the immutable revision 02 URL.

**1.0** — Initial publication.

## References

- [Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
- [Model Context Protocol, Authorization (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [OAuth Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document-02)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02)
- [RFC 5234 ABNF](https://www.rfc-editor.org/rfc/rfc5234)
- [RFC 7517 JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 7591 OAuth 2.0 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)
- [RFC 7638 JSON Web Key Thumbprint](https://www.rfc-editor.org/rfc/rfc7638)
- [RFC 3552 Security Considerations Guidelines](https://www.rfc-editor.org/rfc/rfc3552)
