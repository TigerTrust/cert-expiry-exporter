# cert-expiry-exporter

Prometheus exporter for **TLS certificate expiry in Kubernetes Secrets**. Point Grafana at it and get a dashboard of every cert in your cluster, ranked by days-to-expiry.

> The in-cluster sibling to [`cert-expiry-action`](https://github.com/tigertrust/cert-expiry-action) (CI).
> Built by [TigerTrust](https://tigertrust.io). Apache-2.0.

## What it exposes

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `tigertrust_cert_expiry_timestamp_seconds` | gauge | namespace, secret, common_name, issuer | Unix time the cert expires |
| `tigertrust_cert_not_after_days` | gauge | same | Days until expiry (negative when expired) |
| `tigertrust_cert_info` | gauge (=1) | same + `algorithm`, `san_count` | Static per-cert info |
| `tigertrust_exporter_last_sync_timestamp_seconds` | gauge | — | Last successful sync |
| `tigertrust_exporter_sync_errors_total` | counter | — | Sync iterations that failed |

## Install (Helm)

```sh
helm install cert-expiry-exporter ./deploy/chart \
  --namespace monitoring --create-namespace
```

Scrape with an existing Prometheus:

```sh
helm upgrade cert-expiry-exporter ./deploy/chart \
  --set serviceMonitor.enabled=true
```

Pin it to a few namespaces:

```sh
helm upgrade cert-expiry-exporter ./deploy/chart \
  --set exporter.namespaces=prod-ingress,prod-apps
```

Or opt-in per Secret:

```sh
helm upgrade cert-expiry-exporter ./deploy/chart \
  --set exporter.requireAnnotation=true

kubectl annotate secret my-tls -n prod-apps tigertrust.io/monitor=true
```

## Install (local, for debugging)

```sh
go install github.com/tigertrust/cert-expiry-exporter/cmd/exporter@latest
exporter --kubeconfig ~/.kube/config --interval 30s
```

Then:

```sh
curl -s http://localhost:8080/metrics | grep tigertrust_cert_not_after_days | head
```

## What's observed by default

- Every Secret with `type: kubernetes.io/tls`.
- Any Secret annotated `tigertrust.io/monitor=true` (regardless of type).

With `--require-annotation`, only annotated Secrets are observed — useful on
clusters with a lot of noisy service-mesh certs.

## Grafana dashboard

A starter dashboard lives at `deploy/grafana-dashboard.json`. Import it and
point the Prometheus datasource at your scraping instance.

Key panels:
- **Certs expiring within 14 / 30 days** — big red number
- **Expiring soon** — table of all series sorted by `tigertrust_cert_not_after_days`
- **Days-left per cert over time** — one line per cert

## Alerts

Drop this into your Prometheus rules:

```yaml
groups:
  - name: tigertrust-cert-expiry
    rules:
      - alert: TLSCertExpiringSoon
        expr: tigertrust_cert_not_after_days < 14
        for: 10m
        labels: { severity: critical }
        annotations:
          summary: "TLS cert {{ $labels.namespace }}/{{ $labels.secret }} expires in {{ $value | printf \"%.0f\" }} days"
      - alert: TLSCertExpiryStale
        expr: time() - tigertrust_exporter_last_sync_timestamp_seconds > 600
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "cert-expiry-exporter has not synced for 10m"
```

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--metrics-addr` | `:8080` | Prometheus `/metrics` listener |
| `--probe-addr` | `:8081` | `/healthz` + `/readyz` listener |
| `--namespaces` | `` (all) | Comma-separated list of namespaces |
| `--require-annotation` | `false` | Only observe Secrets with `tigertrust.io/monitor=true` |
| `--interval` | `60s` | Sync period |
| `--kubeconfig` | — | Path override; empty uses in-cluster → `$KUBECONFIG` → `~/.kube/config` |
| `--log-format` | `text` | `text` or `json` |

## RBAC

```
apiGroups: [""]
resources: ["secrets"]
verbs:     ["get", "list", "watch"]
```

The exporter reads `tls.crt` only. It never reads `tls.key`, and no metric
depends on private key material. See [SECURITY.md](./SECURITY.md).

## Where this fits

- **CI gate:** [`cert-expiry-action`](https://github.com/tigertrust/cert-expiry-action) — before deploy
- **Cluster gauge:** this repo — after deploy
- **External surface:** [`47-day-readiness-score`](https://github.com/tigertrust/47-day-readiness-score) — what the internet sees
- **Why renew now:** [`acme-ari-demo`](https://github.com/tigertrust/acme-ari-demo) — ACME Renewal Info

## Roadmap

See [DESIGN.md](./DESIGN.md) for the path to a full cert-manager External
Issuer (Phase 2) and a TigerTrust SaaS bridge (Phase 3).

## License

Apache-2.0. See [LICENSE](./LICENSE) and [SECURITY.md](./SECURITY.md).
