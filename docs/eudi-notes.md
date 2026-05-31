# EUDI Wallet PID Presentation (OpenID4VP Verifier) — Integration Notes

ThunderID acts as an **OpenID4VP Verifier** (German sandbox HAIP profile) so a user can
present their **PID** from the EUDI Wallet and end with a verified-person session. This
note records what is built, the verified integration contracts, the configuration surface,
and the remaining onboarding / wiring work.

> Status: the backend verifier is **functionally complete and unit-tested** offline. The
> live path is gated on RP onboarding (Task 0) and a flow-graph definition; the React
> sample button is specified below but not yet wired (see "Sample app").

---

## Confirmed PID identifiers (HAIP / German sandbox)

- SD-JWT VC type (`vct`): `urn:eudi:pid:de:1`
- Credential format: `dc+sd-jwt`
- SD-JWT claim paths: `given_name`, `family_name`, `birthdate`, `address.{street_address,postal_code,locality,country}`, `nationalities`
- `response_type=vp_token`, `response_mode=direct_post.jwt` (encrypted JWE response mandatory)
- `client_id` scheme: `x509_hash:<base64url-sha256-of-registered-cert>`
- Trust anchor (spike): single German PID provider (Bundesdruckerei)

---

## What is built (file map)

Backend, all under `backend/internal`:

| Area | Package / file | Role |
|---|---|---|
| SD-JWT verification | `system/jose/sdjwt/` | Parse combined SD-JWT, verify issuer sig, resolve disclosures, verify KB-JWT (holder binding). Hand-rolled on existing JWS (no new deps). |
| JWE ephemeral decrypt | `system/jose/jwe/DecryptWithKey` | Decrypt `direct_post.jwt` responses with a per-request ephemeral EC key (reuses existing ECDH-ES/A128GCM). |
| PID policy verifier | `authn/eudi/verifier.go`, `model.go`, `truststore.go` | `vct` check, issuer trust (static store), requested-claims/mandatory-claims policy, claim flattening, stable subject. |
| DCQL + request object | `authn/eudi/dcql.go`, `request.go` | Build the DCQL query and the signed-request (JAR) claims incl. `client_metadata` with the ephemeral encryption JWK. |
| Response parsing | `authn/eudi/response.go` | Parse the OpenID4VP authorization response (`vp_token` DCQL object) and extract the presentation. |
| Service + state | `authn/eudi/service.go`, `statestore.go` | Orchestrates initiate → request-object → submit-response; TTL state store holding `{state → nonce, ephemeral key, status, result}`. |
| Request signer | `authn/eudi/signer.go` | Signs the JAR via the kmprovider key with an `x5c` header. |
| HTTP + wiring | `authn/eudi/handler.go`, `init.go`, `error_constants.go` | `GET /openid4vp/request`, `POST /openid4vp/response`; builds everything from config; registers routes. |
| Flow executor | `flow/executor/eudi_verifier_executor.go` | `EUDIVerifyExecutor`: initiate → QR VIEW → poll → map claims to the authenticated user. Shares the `Service` with the HTTP handler. |
| Config | `system/config/config.go` (`OpenID4VPConfig`, `PIDIssuerConfig`); `cmd/server/repository/conf/deployment.yaml` | Config block (disabled by default). |
| Registration | `cmd/server/servicemanager.go` | `eudi.Initialize` runs before `executor.Initialize`; the `*Service` is threaded into the executor registry. |

---

## Data flow (one happy path)

1. Flow reaches the EUDI step → `EUDIVerifyExecutor.Execute` (first entry) → `Service.Initiate`:
   generates `state` + `nonce` + ephemeral EC P-256 keypair, stores them pending under a
   short TTL, returns `{clientID, requestURI}`. The executor returns a **VIEW** with
   `additionalData`: `eudiClientId`, `eudiRequestUri`, `eudiWalletUri` (the `openid4vp://`
   deep link). The client renders a QR / deep link.
2. Wallet dereferences `request_uri` → `GET /openid4vp/request?state=…` → `Service.RequestObject`
   builds the JAR (DCQL, `client_metadata.jwks` = ephemeral key, `response_uri` carrying the
   state) and signs it (`x5c`).
3. Wallet POSTs the encrypted JWE to `POST /openid4vp/response?state=…` →
   `Service.SubmitResponse`: `jwe.DecryptWithKey` (ephemeral key) → parse → state cross-check →
   `sdjwt.Verify` (signature · selective disclosure · holder binding) → PID policy → marks the
   state `COMPLETED` with the verified claims.
4. The executor (subsequent entries) polls `Service.Result(state)`; on `COMPLETED` it maps the
   disclosed claims into `AuthenticatedUser` and returns `ExecComplete`. The flow continues to
   provisioning / assertion as any other login.

---

## Verified flow-engine contract (important for the flow graph)

`flowexec/engine.go:resolveStepDetailsForPrompt` **rejects a VIEW step that has neither inputs
nor actions**. `common.ExecutorResponse` has **no `Actions` field** — a node's actions come from
the **flow-graph definition**, not the executor.

Consequence for the EUDI graph node:

- The EUDI node MUST define at least one **action** so the pending VIEW is valid and the client
  has something to re-submit while polling.
- That action should **loop back to the same EUDI node** (a self-edge). Re-submitting it
  re-enters `EUDIVerifyExecutor.Execute`, which finds the `state` in `RuntimeData` and polls
  `Service.Result`. The client should poll on an interval (≈2.5 s), not instantly.
- On `COMPLETED` the executor returns `ExecComplete`; the graph then proceeds to the
  `ProvisioningExecutor` (JIT) and `AuthAssertExecutor` (assertion), mirroring social login.

A minimal auth flow graph: `START → EUDIVerifyExecutor (self-loop poll action) → ProvisioningExecutor → AuthAssertExecutor → END`.

---

## Configuration reference (`openid4vp` in deployment.yaml)

Disabled by default. When enabled, every field below is consumed by `eudi.Initialize`:

```yaml
openid4vp:
  enabled: true
  client_id: "x509_hash:<base64url-sha256-of-registered-cert>"
  signing_key_id: "default-key"          # a crypto.keys[] entry whose cert is registered with the RP
  base_url: "https://localhost:8090"     # request_uri/response_uri derived as <base>/openid4vp/{request,response}
  result_redirect_uri: "https://localhost:3000/eudi/result"   # optional; returned to the wallet after POST
  credential_id: "pid-sd-jwt"
  vct: "urn:eudi:pid:de:1"
  ephemeral_key_id: "vp-enc"
  requested_claims: ["given_name", "family_name", "birthdate"]
  mandatory_claims: ["given_name", "family_name"]
  response_enc_values: ["A128GCM"]
  request_validity_seconds: 300
  state_ttl_seconds: 300
  leeway_seconds: 30
  trusted_issuers:
    - issuer: "https://demo.pid-issuer.bundesdruckerei.de/c"
      cert_file: "repository/resources/security/eudi-pid-issuer.cert"   # PEM CERTIFICATE or PUBLIC KEY
```

`client_id` and the KB-JWT audience are the same value (the verifier's identifier).

---

## Task 0 — onboarding checklist (gates the live demo)

These are external dependencies, not code:

- [ ] **RP onboarding + registration certificate.** Obtain the `verifier_info` registration
      certificate and the X.509 cert whose hash becomes the `x509_hash:` `client_id`. Install the
      key under `crypto.keys[]` and set `signing_key_id`. (Longest lead — start first.)
      - `verifier_info` (registration certificate) passthrough is supported by
        `RequestConfig.VerifierInfo` but not yet mapped from config — add when the cert is available.
- [ ] **Trusted PID issuer cert.** Fetch Bundesdruckerei's issuer signing certificate from the
      sandbox mock trust list; save as PEM and reference it in `trusted_issuers[].cert_file`.
- [ ] **Sandbox wallet + test PID.** Install the reference wallet and load a test PID.
- [ ] **Erica debug tool.** Use it to inspect requests/responses while integrating.
- [ ] Flip `openid4vp.enabled: true` and define the auth flow graph (above).

---

## Sample app integration (Task 6 — specification)

Target: `samples/apps/react-vanilla-sample`. The flow API already returns `data.additionalData`;
the EUDI step adds `eudiClientId`, `eudiRequestUri`, `eudiWalletUri`. No QR dependency exists —
render the deep link as a button/link plus the request_uri as text (or add a QR lib if approved).

1. **Types** — extend the `additionalData` type in `src/services/authService.ts` with
   `eudiClientId?`, `eudiRequestUri?`, `eudiWalletUri?`.
2. **Component** — add `src/components/EudiWalletPrompt.tsx` (mirror `PasskeyAuthPrompt.tsx`):
   shows "Open EUDI Wallet" (`<a href={eudiWalletUri}>`), the `eudiRequestUri` as fallback text,
   and a "Waiting for wallet…" spinner.
3. **LoginPage** — in `processAuthResponse`, in the `type === "VIEW"` branch, **before** the
   generic single-action auto-execute, add a guarded branch:
   - if `data.data?.additionalData?.eudiRequestUri` is present → store the eudi data + the step's
     action ref, render `EudiWalletPrompt`, and `setTimeout(≈2500ms)` →
     `submitAuthDecision(executionId, action.ref, undefined, challengeToken)` →
     `processAuthResponse(result.data, action.ref)`. This delayed re-submit is the poll loop; the
     guard ensures existing flows are unaffected (they never set `eudiRequestUri`).
4. On `flowStatus === 'COMPLETE'` the existing path stores the assertion; `ProfilePage` already
   renders `userProfile.attributes`, which will include the disclosed PID claims.

The delayed poll depends on the graph's self-loop action (see the engine contract above).

---

## Open items / later hardening

- **mdoc**: not implemented (SD-JWT VC only). CBOR + ISO 18013-5 deviceAuth is a separate effort.
- **Trust-list client**: the spike pins issuer keys from config (`staticTrustStore`). A full
  trust-list client with freshness/revocation checks is later hardening.
- **Redis state store**: `cacheStateStore` stores the ephemeral private key in-process; a
  Redis-backed deployment needs the key serialised. The spike assumes the in-memory cache.
- **`verifier_info` / registration certificate**: passthrough exists (`RequestConfig.VerifierInfo`)
  but is not yet wired from config — required for the live wallet to accept the verifier.
- **x5c via `x509_hash`**: the signer emits `x5c`; confirm the wallet derives the expected
  `x509_hash` `client_id` from the registered cert during onboarding.
- **Subject linking**: the spike derives a stable issuer-scoped pseudonym (or uses credential
  `sub`). "Link to existing user vs JIT-provision" is a later product decision.

---

## Library choice

SD-JWT and the OpenID4VP request/response plumbing are **hand-rolled** on ThunderID's existing
custom JOSE (`system/jose/{jws,jwt,jwe}`, `system/cryptolib`) — no new dependencies (per
`AGENTS.md`). JWE (ECDH-ES / A128GCM) already existed in-repo and is reused for response
decryption.
