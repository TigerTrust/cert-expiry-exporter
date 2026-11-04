# DESIGN.md — path from exporter to cert-manager External Issuer

This repo ships the smallest valuable Kubernetes thing for 47-day TLS ops: a
Prometheus exporter for Secret expiry. The larger goal is a TigerTrust
external-issuer for cert-manager. This document sketches the staged path so
we don't paint ourselves into a corner.

## Phase 1 (this repo, shipped) — read-only exporter

- Periodically lists Secrets (`type: kubernetes.io/tls` + optionally
  annotated opaque Secrets).
- Parses the leaf, emits:
  - `tigertrust_cert_expiry_timestamp_seconds{...}`
  - `tigertrust_cert_not_after_days{...}`
  - `tigertrust_cert_info{...,algorithm,san_count} = 1`
- Pairs with [`cert-expiry-action`](https://github.com/tigertrust/cert-expiry-action)
  (CI) and [`47-day-readiness-score`](https://github.com/tigertrust/47-day-readiness-score)
  (external surface).

## Phase 2 — cert-manager External Issuer

Follow the official
[`cert-manager/sample-external-issuer`](https://github.com/cert-manager/sample-external-issuer)
scaffold.

**CRDs**

```
apiVersion: tigertrust.io/v1alpha1
kind: TigerTrustIssuer | TigerTrustClusterIssuer
spec:
  acmeDirectory: https://acme-staging-v02.api.letsencrypt.org/directory
  email: ops@example.com
  solver:
    dns01: { provider: route53 | cloudflare | manual }
    http01: { ingress: { class: nginx } }
  # future, feature-flagged:
  tigertrust:
    apiURL: https://api.tigertrust.io
    secretRef: { name: tigertrust-api-key }
```

**Controller** reconciles `CertificateRequest`:

1. Look up the referenced `Issuer`/`ClusterIssuer`.
2. Translate `CertificateRequest.spec.request` (CSR) into an ACME order.
3. Solve challenges via existing cert-manager solvers (DNS-01 preferred).
4. On success, write the chain back to `CertificateRequest.status.certificate`
   and `.ca`.
5. On failure, set `Ready=False` with a stable `reason` for monitoring.

**Reuse from this repo**

- `internal/collector` cert parsing — the Phase-2 reconciler needs the same
  PEM → `*x509.Certificate` plumbing to compute `nextAction` based on ARI.
- `tigertrust_cert_*` metric surface stays — Phase 2 adds
  `tigertrust_ari_window_start_timestamp_seconds{...}` from
  [`acme-ari-demo`](https://github.com/tigertrust/acme-ari-demo).

## Phase 3 — TigerTrust SaaS bridge

Only when the public API is stable. Behind a feature flag in the
`TigerTrustIssuer` CRD:

- `status.provider: tigertrust-api` when `spec.tigertrust.apiURL` is set.
- Empty implementation returns `ErrNotImplemented` today; replace with real
  HTTP client later without changing the CRD surface.

## Non-goals (v0.x)

- Multi-tenant policy evaluation (deferred to `clm-policy-as-code`).
- Full ARI-based renewal controller; today the exporter reads expiry only.
- Windows nodes / Windows containers.
