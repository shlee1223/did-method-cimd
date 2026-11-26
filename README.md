# did:cimd - a DID method for OAuth clients

> `did:cimd` is an independent work. It is not part of, affiliated with, or endorsed by the OAuth Client ID Metadata Document Internet-Draft, its authors, or the IETF OAuth Working Group. It follows the CIMD draft and respects its authority.

`did:cimd` is for DID-based systems that need to resolve an OAuth client. It maps the **OAuth Client ID Metadata Document** (CIMD) a client already publishes to a DID Document. No registry, no ledger, no registration step.

- **Specification:** [`did-method-cimd.md`](./did-method-cimd.md)
- **Method name:** `cimd` · **Example:** `did:cimd:example.com:clients:billing`
- **Trust root:** the HTTPS origin that serves the CIMD
- **Status:** experimental, v0.3, profiling [draft-ietf-oauth-client-id-metadata-document-03](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03)

## Why

Systems that identify parties by DID look keys up through a DID resolver and key their policies and trust registries by DID. An OAuth client that publishes a CIMD already has a URL as its identifier and a document that can be fetched from it, yet such a system cannot resolve it. `did:cimd` closes that gap with one resolution rule and nothing new to publish.

A `did:cimd` and a Client Identifier URL name the same client, and each converts to the other without loss. They are used in different places: OAuth protocol messages carry the URL, and DID contexts carry the DID.

## What it does not do

- It does not identify an agent, an instance, a user, or whoever the software acts for. The subject is the OAuth client software, which many users and instances may share.
- It is not decentralized. The identifier is controlled by a single HTTPS origin.
- It does not place any requirement on CIMD publishers, and adds no lifecycle of its own. There is no deactivation and no revocation.
- It does not give the published keys any purpose beyond OAuth client authentication to an authorization server.

See sections 1.1 and 1.2 of the specification.

## How it resolves

```
did:cimd:example.com:clients:billing
  -> https://example.com/clients/billing       (the CIMD; client_id must equal this URL)
  -> jwks / jwks_uri (same origin)             (keys, filtered to signature-verification keys)
  -> DID Document: alsoKnownAs, verificationMethod,
     authentication (only if the CIMD declares private_key_jwt)
```

Any response other than `200 OK` means the DID does not resolve. A network failure is a transient error and says nothing about the DID. A client that publishes no keys resolves to a document with no verification method: a name, and nothing that can be authenticated.

## Repository layout

```
did-method-cimd.md                          # the specification
registration/w3c-did-extensions/cimd.json   # entry registered in w3c/did-extensions (methods/cimd.json)
```

## License

Apache-2.0. See [LICENSE](./LICENSE) and section 8 of the specification.
