# did:cimd - a DID method for OAuth clients

`did:cimd` resolves a client's keys from the **OAuth Client ID Metadata Document** (CIMD) it already publishes. No registry, no ledger, no extra registration step. The HTTPS URL a client already uses as its `client_id` becomes the identifier, and the keys that document designates become the verification keys.

- **Specification:** [`did-method-cimd.md`](./did-method-cimd.md)
- **Method name:** `cimd` · **Example:** `did:cimd:example.com:agents:billing`
- **Trust root:** the client's HTTPS origin
- **Status:** v1.1, profiling [draft-ietf-oauth-client-id-metadata-document-02](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02)

## Why

AI agents are numerous, short-lived, and cross organizational boundaries. Nobody can hand-register each one with every server it meets, and the industry's answer is CIMD: use an HTTPS URL as the client identifier, and serve the client's metadata at that URL. The Model Context Protocol authorization specification puts it first, calling it the case "when client and server have no prior relationship (most common)", while Dynamic Client Registration is kept only for backwards compatibility.

Those clients already publish a stable identifier, a resolvable document, the public keys they authenticate with, and a rotation path. Everything a DID does is already happening; only the name is missing. `did:cimd` supplies the name, so the same key can identify the client in DID- and credential-based systems with no second document to publish.

An agent also needs a name for a different reason: delegation. To record who delegated what to whom, and to verify it later, the subject of the delegation needs a stable identifier. A registration id minted anew on each connection cannot serve as one.

The method is not agent-specific. Any OAuth client that publishes a CIMD qualifies.

## How it resolves

```
did:cimd:example.com:agents:billing
  -> https://example.com/agents/billing        (the CIMD; client_id must equal this URL)
  -> jwks / jwks_uri (same origin)             (keys, filtered to signature-verification keys)
  -> DID Document: verificationMethod, authentication
```

`410 Gone` at the document URL means the DID is deactivated.

## Repository layout

```
did-method-cimd.md                          # the specification
registration/w3c-did-extensions/cimd.json   # entry to submit to w3c/did-extensions (methods/cimd.json)
```

## License

Apache-2.0. See [LICENSE](./LICENSE) and section 8 of the specification.
