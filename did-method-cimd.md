# The `did:cimd` DID Method Specification (v0.3)

> `did:cimd` is an independent work. It is not part of, affiliated with, or endorsed by the OAuth Client ID Metadata Document specification, its authors, or the IETF OAuth Working Group. It follows the CIMD specification and respects its authority.

A DID method for DID-based systems that need to resolve an OAuth client. It maps the **OAuth Client ID Metadata Document** (CIMD) a client already publishes to a DID Document. A `did:cimd` and the Client Identifier URL convert to each other without loss, and the keys the document publishes become verification methods, limited to OAuth client authentication. No registry, no ledger, no registration step.

**Status:** Experimental. This specification profiles an Internet-Draft that is still changing, and may itself change incompatibly from one version to the next. It is not a standard, and implementations should expect to follow its revisions.

**Conformance.** The key words MUST, MUST NOT, REQUIRED, SHALL, SHOULD and MAY in this document are to be interpreted as described in [BCP 14](https://www.rfc-editor.org/rfc/rfc2119) when, and only when, they appear in all capitals.

> In this document, CIMD means [OAuth Client ID Metadata Document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03), the IETF OAuth working group document. It is unrelated to the SMSC protocol of the same acronym (Computer Interface to Message Distribution).

## 0. Motivation

CIMD lets an OAuth client use an HTTPS URL as its client identifier and serve its metadata at that URL. It is already deployed: the Model Context Protocol authorization specification names it as the registration mechanism for the case "when client and server have no prior relationship".

Systems that identify parties by DID look keys up through a DID resolver and key their policies and trust registries by DID. An OAuth client that publishes a CIMD already has a URL as its identifier and a document that can be fetched from it, yet such a system cannot resolve it. `did:cimd` closes that gap with one resolution rule and nothing new to publish.

A `did:cimd` and a Client Identifier URL name the same client, and each converts to the other without loss (section 2). They are used in different places: OAuth protocol messages carry the URL, and DID contexts carry the DID (section 4).

## 1. Scope

What this method establishes is one fact: **control of an HTTPS origin**. Whoever can publish a document at that URL is the DID controller.

It says nothing about whether that origin, or a key it publishes, should be *trusted* for any purpose beyond that control. Applications that need an authorization or trust decision (which clients may act on a given task, which keys to rely on) should layer a separate mechanism on top, such as a trust registry or credential-based attestation. This method supplies a name for the client such a decision is about, not the decision.

### 1.1 The DID subject

The DID subject is the OAuth client identified by the Client Identifier URL: a piece of client software, as an authorization server sees it.

It is not a person or an organization, not a particular running instance of the software, and not the party the software acts for. One client may be shared by many users and many instances, a hosted platform's client in particular, and all of them have the same `did:cimd`.

Identifying an instance or a workload is out of scope. That is the subject of other work, including SPIFFE and WIMSE, OAuth Attestation-Based Client Authentication, and the client instance discussion in the IETF OAuth working group.

### 1.2 Limitations

These follow from what the method is, and remain for as long as it exists.

- **Not decentralized.** The identifier is controlled by a single HTTPS origin, and has no control or persistence independent of that origin. It is closer to a controlled identifier in the sense of [Controlled Identifiers v1.0](https://www.w3.org/TR/cid-1.0/) than to an identifier anchored in a decentralized registry.
- **The origin, not the path.** One origin can serve many CIMDs, and every one of them is controlled by whoever operates that origin. A client whose CIMD sits on a shared host, or is provisioned through a CIMD Service (CIMD, section 10.13), has a `did:cimd` that the host operator controls. This method cannot tell the tenant of a path from the operator of the origin.
- **DNS and the Web PKI.** "Control of an HTTPS origin" is only as strong as the DNS and the certificate issuance behind it. Whoever can redirect the name and obtain a certificate for it controls every `did:cimd` on that origin.
- **Two names, one client.** The DID and the Client Identifier URL name the same client. A system that handles both has to keep them equivalent (section 4).
- **A derived document.** The DID Document is computed from the CIMD at resolution time. It is not published, and a cached copy can lag the CIMD it was derived from (3.2.1).
- **Client software only.** See 1.1.
- **No history.** A CIMD carries no record of its earlier contents, and neither does the DID Document derived from it. Neither shows which keys a client used in the past.
- **No revocation.** CIMD defines no signal that a client is gone, and this method adds none (3.4).
- **One client authentication method.** Of the methods a CIMD can declare in `token_endpoint_auth_methods_supported`, this method expresses only `private_key_jwt`. A client that declares only some other method resolves to a document with an empty `authentication`, although an authorization server may be able to authenticate it.
- **`authentication` is narrow.** It means OAuth client authentication to an authorization server and nothing else (3.2, step 5). It does not make the key a general means of authenticating the DID subject, as the relationship does in other DID methods.
- **`authentication` is coarse.** A CIMD does not say which of its signature keys is used for what. A key set may hold a key for signing request objects beside the one used for client authentication, and this method references all of them alike.
- **`authentication` is a capability, not a fact.** A client may declare `none` beside `private_key_jwt` and act as a public client toward an authorization server that does not support the latter. The relationship says the client can authenticate with the key, not that it did in any given interaction.

### 1.3 Relationship to CIMD

- **CIMD publishers are not bound by this specification.** It places requirements on resolvers and relying parties only. A publisher follows CIMD and nothing else. What a CIMD is, and how it is published, fetched and validated, is for CIMD to define.
- **The dependency is stated.** The identifier depends on one thing: the client identifier is an HTTPS URL. Resolution depends on more: the document's `client_id` equals that URL, keys are published via `jwks` or `jwks_uri`, client authentication methods are declared as in CIMD section 5, and fetching and caching follow CIMD section 6.
- **Identifiers are not tied to the draft.** A DID string encodes the URL and nothing else. A revision of CIMD leaves existing identifiers valid; only the resolution profile (3.1, 3.2) is affected.
- **The revision is pinned.** CIMD is an IETF working group document and not yet an RFC. This version profiles [draft-ietf-oauth-client-id-metadata-document-03](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03), and section references to CIMD below are to that revision. When CIMD is revised, this specification is revised too.

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

At least one `segment` is REQUIRED, and no `segment` may be `"."` or `".."`. A Client Identifier URL MUST contain a path component other than `/` and MUST NOT contain dot path components (CIMD, section 3), so a DID without a path segment would map to a URL that cannot be a Client Identifier URL.

A port is carried in the `authority` as `%3A` followed by the port number. This is the only percent-encoded sequence permitted in the `authority`; `host` itself is never percent-encoded.

### 2.1 Canonical form

The transformations in 2.2 and 2.3 are inverses only over identifiers in canonical form:

1. `host` is lowercase, and is a DNS name rather than an IP literal. An internationalized domain name appears in its A-label form (`xn--`), the only form the grammar admits.
2. `port`, if present, is not zero-padded, and is neither inserted nor dropped — `443` included.
3. The hexadecimal digits of every `pct-encoded` sequence are uppercase.
4. Within a `segment`, a character the grammar admits literally is written literally, and every other character is percent-encoded.

A resolver given an identifier that satisfies the grammar but not these rules MUST return `INVALID_DID`. Without them one document would have more than one name.

### 2.2 DID to base URL

The base URL `B` is derived as follows.

1. Verify the identifier against the grammar and 2.1. On failure, return `INVALID_DID`.
2. Remove the `did:cimd:` prefix and split the remainder on `:`. The first field is the `authority`; the rest, in order, are the path segments.
3. In the `authority` only, replace `%3A` with `:`. Path segments are carried over verbatim; a resolver MUST NOT percent-decode, re-encode or otherwise normalize them.
4. `B` is `"https://"`, the authority, then each path segment preceded by `/`.

`B` is the Client Identifier URL and also the URL of the metadata document.

### 2.3 Base URL to DID

1. The URL MUST be `https`, with a lowercase host, no userinfo, query or fragment, a non-empty path with no empty and no dot segments, no trailing slash, and path segments already in the canonical encoding of §2.1 — drawn only from the characters `segment` admits, with no character percent-encoded that `segment` admits literally. A URL that fails any of these has no `did:cimd` name, because altering it would break the exact `client_id` comparison CIMD requires. This is narrower than CIMD (section 3), which discourages a query component without forbidding it, recommends a normalized URL without requiring one, and does not forbid a trailing slash, an empty path segment, or an IP literal as host. Such URLs can be valid Client Identifier URLs and have no `did:cimd`.
2. The authority is the host, followed by `%3A` and the port if the URL carries one. CIMD compares Client Identifier URLs by simple string comparison, under which `https://example.com/c` and `https://example.com:443/c` are two different clients, so a port is preserved exactly as the URL gives it.
3. Uppercase the hexadecimal digits of every percent-encoded sequence in the path segments, and change nothing else in them.
4. The identifier is `"did:cimd:"` followed by the authority and the path segments, joined with `:`.

### 2.4 Examples

| DID | Base URL `B` |
|---|---|
| `did:cimd:example.com:clients:billing` | `https://example.com/clients/billing` |
| `did:cimd:example.com:client.json` | `https://example.com/client.json` |
| `did:cimd:example.com%3A8443:clients:billing` | `https://example.com:8443/clients/billing` |
| `did:cimd:example.com:a%3Ab` | `https://example.com/a%3Ab` |

`B` itself is the metadata document.

## 3. Operations

### 3.0 Authorization

Authorization for every operation is determined by control of the base URL's HTTPS origin. The DID Document itself is never used to make an authorization decision.

### 3.1 Create

There is no create operation apart from publishing a CIMD, and no third-party registration step. This method asks nothing of a publisher (1.3).

A CIMD resolves under this method if it meets the profile below. One that does not is still a valid CIMD; it has no `did:cimd`.

1. Its Client Identifier URL `B` satisfies 2.3.
2. It is served at `B` with `200 OK`, and its `client_id` equals `B`, both of which CIMD requires (sections 4 and 6).
3. It carries at most one of `jwks` and `jwks_uri`, as CIMD requires (section 4.1).
4. A `jwks_uri`, if present, is on the same HTTPS origin as `B`. CIMD does not constrain its origin. This method does, because control of the origin is the only thing it establishes.
5. If it declares `private_key_jwt` (3.2, step 5), it carries `jwks` or `jwks_uri`, as CIMD requires (section 5), and yields at least one signature key, which this method requires.

A CIMD is not itself signed. The document and its keys are protected by TLS and same-origin placement only. A CIMD may carry a signed `software_statement` (CIMD, section 4.3); this method does not use it.

### 3.2 Read (Resolve)

Error names in this specification are the error types defined by [DID Resolution](https://www.w3.org/TR/did-resolution/).

1. Parse the DID. On a syntax or canonical-form violation, return `INVALID_DID`.
2. **Fetch the document.** `GET B` with `Accept: application/json`, over HTTPS only. **Redirects MUST NOT be followed.** This fetch and the `jwks_uri` fetch in step 3 MUST be treated as fetching an attacker-influenced URL. CIMD forbids an authorization server to fetch a URL that resolves to a special-use address (section 10.7, [RFC 6890](https://www.rfc-editor.org/rfc/rfc6890)), which covers private, loopback and link-local space. A resolver MUST follow the same rule. Beyond what CIMD states, it MUST connect only to an address it has checked, so that a later DNS answer cannot substitute another one (DNS rebinding). TLS is still verified against the host name.
   - `200`: validate against the profile (3.1) and continue. On a violation, `NOT_FOUND`.
   - Any other status code, `3xx` included: `NOT_FOUND`. CIMD has an authorization server treat every status code other than `200` as an error (section 6), and this method attaches no further meaning to any of them.
   - No HTTP response (a network error or a timeout): `INTERNAL_ERROR`. This is a transient failure, not a statement about the DID. A resolver SHOULD NOT discard a previously cached valid result because of it, as CIMD says of an authorization server and its cached client metadata (section 6.1).

   The redirect rule is CIMD's rule for an authorization server (section 6), applied here to a resolver. It is load-bearing: `client_id` is checked against the requested URL by exact string comparison, so a followed redirect would leave the served document's `client_id` disagreeing with the URL actually fetched, and would let whoever controls DNS or the HTTP front end move an established identity to another origin.
3. **Extract keys.** If both `jwks` and `jwks_uri` are present, `NOT_FOUND`. If neither is present, the document publishes no key. Otherwise take `jwks`, or fetch the JWK Set at `jwks_uri` under the rules of step 2, sending `Accept: application/jwk-set+json, application/json`. The outcomes are those of step 2: a status code other than `200`, or a body that is not a JWK Set, is `NOT_FOUND`; no HTTP response is `INTERNAL_ERROR`. If any JWK carries private or symmetric key material, `NOT_FOUND`: CIMD permits only public keys (section 4.1), and a resolver does not repair a key set by stripping what should not have been published. **Retain only keys usable for verifying signatures:** discard a JWK whose `use` is present and is not `"sig"`, and one whose `key_ops` is present and does not include `"verify"`; a JWK carrying neither member is retained. Discard a JWK that lacks the members its `kty` requires, since step 4 cannot be computed for it.
4. **Identify keys.** The verification method identifier of a retained key is `<DID>#<thumbprint>`, where `<thumbprint>` is the base64url-encoded, unpadded SHA-256 JWK Thumbprint of that key ([RFC 7638](https://www.rfc-editor.org/rfc/rfc7638)). Retained keys with the same thumbprint are the same key and yield one verification method, taken from the first of them in the key set.

   `kid` is not used for this. [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) leaves the structure of `kid` unspecified and only recommends uniqueness, so a published value may be empty, may contain characters that are invalid in a URI fragment, or may repeat within one key set and collide. A thumbprint is derived from the key material: always present, always fragment-safe, and distinct for distinct keys. A `kid`, where published, is preserved inside `publicKeyJwk`, so software that selects keys by `kid` — OAuth client authentication in particular — is unaffected.
5. **Assign verification relationships.** Determine the client authentication methods the document declares, from the properties CIMD describes (section 5): the value of `token_endpoint_auth_methods_supported` if present; otherwise the single value of `token_endpoint_auth_method` if present; otherwise `none`. CIMD requires the last of these, recommends the first property over the second, and lets an authorization server read the second for backwards compatibility; this method always reads it.

   - If the declared methods include `private_key_jwt`, every retained key is referenced from `authentication`, since a CIMD does not say which of its keys serves which purpose. If no key was retained, `NOT_FOUND`: CIMD requires such a document to carry `jwks` or `jwks_uri` (section 5), and a key set with no signature key cannot serve `private_key_jwt`.
   - Otherwise `authentication` is empty. Retained keys, if any, appear in `verificationMethod` and are referenced from no relationship. A key referenced from no relationship has no defined use under this method.

   This method defines no `assertionMethod`, `keyAgreement`, `capabilityInvocation` or `capabilityDelegation`, and will not.

   `authentication` has one meaning here: the key is one the client uses to authenticate to an authorization server as the client named by `client_id`. That is what a `private_key_jwt` client assertion states, to the authorization server it is addressed to. It does not establish that the key authenticates the DID subject in any other protocol, and it carries no authorization to sign statements on the subject's behalf.

   CIMD has a client publish keys so that it can authenticate to an authorization server (section 5). This method reads them as that and nothing more. In this method's view a client that signs anything else should use separate keys, published and managed apart from its CIMD, and using a CIMD key for another purpose is cross-protocol key reuse. This method does not express such keys.

   A DID Document with an empty `authentication` is a name and nothing more. Presenting such a DID is no evidence that the presenter is the client, and a relying party MUST NOT use it for authentication or holder binding. This is the ordinary case for a public client, not an error.
6. **Assemble the DID Document.**
   - `id` = the requested DID.
   - `alsoKnownAs` = `[ B ]`, the Client Identifier URL.
   - `verificationMethod` = for each retained key, `{ id: <DID>#<thumbprint>, type: "JsonWebKey", controller: <DID>, publicKeyJwk }`; an empty array if none.
   - `authentication` = per step 5.

   The document has no `service` entry. `B` is recoverable from the DID itself (2.2).

Authenticity of the response rests on the origin verified over TLS. There is no signature beyond that.

#### 3.2.1 Caching

A resolver caches a resolution result as an authorization server caches client metadata (CIMD, section 6.2). It SHOULD respect the HTTP cache headers of the CIMD and JWK Set responses, SHOULD enforce a maximum effective cache duration regardless of them, and SHOULD enforce a minimum when none is indicated. It MUST NOT cache an error response or an invalid document.

A DID Document derived under this method SHOULD NOT be stored or republished as a document in its own right. It has no existence apart from the CIMD it was computed from.

### 3.3 Update

Republishing the CIMD at the same URL is an update, and a changed key set is a key rotation. This method adds no rule to either. A resolver sees the document that is current when it fetches, and a change takes effect as caches expire.

### 3.4 Deactivate

Not supported. CIMD defines no signal that a client has been retired, and this method adds none.

A CIMD that is no longer served with `200 OK` no longer resolves, and the result is `NOT_FOUND`, the same as for a DID that never existed. A resolver never sets `deactivated` in `didDocumentMetadata`.

Removing a document is not a revocation mechanism. It takes effect only as caches expire, and it says nothing about signatures made before. A relying party that needs status or revocation obtains it elsewhere.

## 4. Security Considerations

Per RFC 3552.

- **Scope of protection.** TLS protects the transport of every document: confidentiality, integrity, server authentication. The CIMD and the JWK Set have no protection beyond TLS. Secret material MUST NOT appear in a DID Document; a key set that contains any does not resolve (3.2, step 3).
- **Origin control is key control.** Whoever takes over a domain, or acquires an expired one, can publish new keys and become the subject of that DID. CIMD notes the same of the client's identity toward an authorization server (section 10.4).
- **DNS and certificates.** A spoofed DNS answer combined with a mis-issued certificate yields a different document for the same DID. TLS server authentication is the only defence this method has; a resolver MUST validate the certificate chain and host name, and gains from DNSSEC-validated resolution where it is available.
- **Shared origins.** A `did:cimd` is controlled by the operator of its origin, whatever the path (1.2). A relying party that trusts one client on an origin has no basis in this method for distinguishing it from another client there, or from the operator. Look-alike host names are a related risk: an internationalized name is shown in its A-label form (2.1), and a relying party that displays it otherwise takes on the confusable-character problem itself.
- **Two names, one client.** A `did:cimd` and the Client Identifier URL it converts to (2.2) identify the same client. A relying party MUST treat them as one party: before it compares identifiers, stores them, or looks up policy by them, it MUST convert them to a single form (2.2, 2.3). A `did:cimd` MUST NOT be sent to an authorization server as a client identifier: not as a `client_id`, and not as the `iss` or `sub` of a client assertion. Those carry the Client Identifier URL. With these two rules a client has one identity under two spellings, and each spelling has its own place.
- **Key history.** Once a key is removed from a CIMD, the DID no longer resolves to it. A relying party that must verify a signature later MUST NOT rely on resolving again; it records the verification method identifier and the JWK at the time of use. The thumbprint-based identifier (3.2, step 4) lets the recorded JWK be checked against the recorded identifier. It does not show when the key was published; a relying party that needs that keeps its own evidence of time.
- **Key purpose.** Filtering on `use` and `key_ops` keeps an encryption key from being listed as a signature key. Assigning `authentication` only where the document declares `private_key_jwt`, and nothing else ever, keeps a published key from being read as authorized for a purpose the client never gave it (3.2, step 5).
- **Shared clients.** A `did:cimd` may name a client shared by many users and instances (1.1). A relying party MUST NOT take it to identify one of them.
- **Redirects.** They are not followed (3.2).
- **Request forgery.** A resolver is made to fetch a host an attacker chose. Blocking special-use addresses, and connecting only to an address that was checked, is required (3.2, step 2).
- **Resource limits.** Bound the response size, as CIMD recommends to an authorization server (section 10.11), and the response time.
- **Caching.** Cache lifetimes determine how fast a key change or a removal takes effect (3.2.1). CIMD sets no numeric bounds on cache lifetimes, and neither does this method; a relying party for whom staleness is costly sets its own maximum.

## 5. Privacy Considerations

- The identifier exposes the host and path of the Client Identifier URL verbatim.
- Identifiers on the same origin are correlatable. This method does not aim to prevent correlation.
- Resolution tells the target origin, and the DNS provider that answers for it, that someone is resolving that identifier. Where resolver privacy matters, use caching or a relay.
- A DID Document carries nothing from the CIMD except its URL and its public signature keys. Other client metadata is not copied into it.

## 6. Examples

### 6.1 A client that declares `private_key_jwt`

CIMD at `https://example.com/clients/billing`:

```json
{
  "client_id": "https://example.com/clients/billing",
  "client_name": "Billing App",
  "jwks_uri": "https://example.com/clients/billing/jwks.json",
  "token_endpoint_auth_methods_supported": ["private_key_jwt"]
}
```

Resolved DID Document:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/jwk/v1"],
  "id": "did:cimd:example.com:clients:billing",
  "alsoKnownAs": ["https://example.com/clients/billing"],
  "verificationMethod": [{
    "id": "did:cimd:example.com:clients:billing#nGqB7kZP2sL9vXcR4tYwE6aZbUj1oXvN6gT0sKiMdQ0",
    "type": "JsonWebKey",
    "controller": "did:cimd:example.com:clients:billing",
    "publicKeyJwk": { "kty": "EC", "crv": "P-256", "kid": "key-1", "use": "sig", "x": "...", "y": "..." }
  }],
  "authentication": ["did:cimd:example.com:clients:billing#nGqB7kZP2sL9vXcR4tYwE6aZbUj1oXvN6gT0sKiMdQ0"]
}
```

The published `kid` survives inside `publicKeyJwk`; the fragment is the key's thumbprint.

### 6.2 A public client

CIMD at `https://example.com/clients/desktop`, declaring `none` and publishing no key:

```json
{
  "client_id": "https://example.com/clients/desktop",
  "client_name": "Desktop App",
  "redirect_uris": ["http://127.0.0.1/callback"],
  "token_endpoint_auth_methods_supported": ["none"]
}
```

Resolved DID Document:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:cimd:example.com:clients:desktop",
  "alsoKnownAs": ["https://example.com/clients/desktop"],
  "verificationMethod": [],
  "authentication": []
}
```

This document names the client and proves nothing about whoever presents the DID (3.2, step 5).

## 7. Future Work

- Follow CIMD through its revisions to publication as an RFC, re-pinning the profile each time.
- If CIMD defines signed metadata, consider how resolution should use it.

## 8. Intellectual Property

This specification is published under the [Apache License 2.0](./LICENSE). Implementing this method requires no separate permission from the author, and no fee, registration or membership of any kind.

## 9. Changelog

Versions 0.1 and 0.2 were first published as 1.0 and 1.1. The numbering changed; the content of each did not.

**0.3** — Feedback from a CIMD author and the OAuth mailing list.

- A notice of independence from CIMD, its authors and the IETF OAuth Working Group is added at the top.
- The specification is marked experimental.
- Section 0 is rewritten. The method is for DID-based systems that need to resolve an OAuth client; it is no longer presented as identity for AI agents.
- 1.1 is new: the DID subject is the OAuth client software, not an instance, a person, or the party the software acts for. Instance and workload identity are out of scope.
- 1.2 is new: limitations, including that the identifier is controlled by a single origin and names the same client as the Client Identifier URL, that control belongs to the origin rather than the path, that it rests on DNS and the Web PKI, that only `private_key_jwt` is expressed, and what `authentication` does not mean.
- 1.3: this specification places no requirement on CIMD publishers. 3.1 is restated as the conditions under which a CIMD resolves, in place of obligations on a controller.
- The profile moves from CIMD draft-02 to draft-03.
- 3.2 step 2 and 3.4: `410 Gone` no longer means deactivation, and deactivation is not supported. Every status code other than `200` is `NOT_FOUND`. A network error or timeout is `INTERNAL_ERROR`.
- 3.2 step 5: keys are referenced from `authentication` only when the document declares `private_key_jwt`, read from `token_endpoint_auth_methods_supported`, falling back to `token_endpoint_auth_method`, and to `none` when both are absent. The relationship is defined to mean OAuth client authentication to an authorization server and nothing else.
- 3.2 step 3: a key set that yields no signature key is no longer `NOT_FOUND` unless the document declares `private_key_jwt`.
- 3.2 steps 2 to 4: a resolver connects only to an address it has checked. A JWK Set fetch fails as the CIMD fetch does, a network error being `INTERNAL_ERROR`. A key set containing private or symmetric key material does not resolve, where 0.2 stripped it. Keys with the same thumbprint yield one verification method.
- 3.2 step 6: the `service` entry is removed. `alsoKnownAs` is always present.
- 3.2.1 is new: caching follows CIMD section 6.2, and a derived DID Document is not stored or republished.
- 3.3: the overlap-period recommendation, a requirement on publishers, is removed.
- 2.1: an internationalized domain name appears in its A-label form.
- Section 4: key history, shared clients, shared origins, DNS and certificates, and treating the DID and the URL as one party are added. A `did:cimd` is not sent to an authorization server as a client identifier.
- Section 7: the key-purpose declaration mechanism and the service type registration are dropped, as is the statement that other document formats would be defined as separate methods. This method treats keys for purposes other than client authentication as belonging outside the CIMD.
- Error names follow the current DID Resolution specification (`INVALID_DID`, `NOT_FOUND`, `INTERNAL_ERROR`), and verification methods use the `JsonWebKey` type in place of `JsonWebKey2020`.
- The paragraph explaining the method name is removed.
- Examples no longer name the client as an agent.

**0.2** — Registry review feedback.

- Section 2: `authority`, `port` and `pct-encoded` added to the ABNF, so that the port syntax the prose already described is expressible; canonical form stated; DID-to-URL and URL-to-DID given as inverse procedures, with a port example. The `%3A` decoding of 0.1 applied to the whole identifier and would have corrupted an encoded path segment; it now applies to the authority alone.
- 3.2 step 2: redirects are no longer followed at all, replacing the same-origin allowance, with the reason recorded. The redirect-count limit in section 4 is dropped as moot.
- 3.2 step 4: verification method identifiers are RFC 7638 thumbprints. `kid` is no longer required by 3.1 and no longer forms the identifier; it is preserved in `publicKeyJwk`.
- 3.2 step 5: a retained key is referenced from `authentication` alone. `assertionMethod`, which 0.1 granted to every key, is no longer assigned by this method at all; a mechanism for declaring key purposes is deferred to a later revision (section 7).
- 3.1 item 2 and 3.2 step 3: a document carrying both `jwks` and `jwks_uri` is invalid.
- The `service` entry keeps its place, but its `type` is now the absolute URI of the CIMD section that defines the document, in place of the short name `OAuthClientMetadata`, which was never defined in any JSON-LD context.
- 3.4: the exact resolution result for `410` is specified — `didDocument` null, `didDocumentMetadata.deactivated` true, no error — and distinguished from `404`.
- The CIMD reference is pinned to the immutable revision 02 URL.
- 3.1 item 2, 3.2 steps 3, 5 and 6: a CIMD declaring neither `jwks` nor `jwks_uri` now resolves to a keyless identity — a DID Document with an empty `verificationMethod` and `authentication`, usable as a stable subject name but not for authentication or holder binding. A document that carries a key set but yields no valid key still returns `notFound`, so only the deliberate absence of both members is keyless.

**0.1** — Initial publication.

## References

- [Controlled Identifiers v1.0](https://www.w3.org/TR/cid-1.0/)
- [Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
- [DID Resolution](https://www.w3.org/TR/did-resolution/)
- [Model Context Protocol, Authorization: Client Registration (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration)
- [OAuth Client ID Metadata Document (draft-ietf-oauth-client-id-metadata-document-03)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03)
- [RFC 5234 ABNF](https://www.rfc-editor.org/rfc/rfc5234)
- [RFC 6890 Special-Purpose IP Address Registries](https://www.rfc-editor.org/rfc/rfc6890)
- [RFC 7517 JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 7591 OAuth 2.0 Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591)
- [RFC 7638 JSON Web Key Thumbprint](https://www.rfc-editor.org/rfc/rfc7638)
- [RFC 3552 Security Considerations Guidelines](https://www.rfc-editor.org/rfc/rfc3552)
