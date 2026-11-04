# Security policy

## Supported versions

The `main` branch and the latest tagged release receive security fixes.

## Reporting a vulnerability

Please email **security@tigertrust.io** with a description of the issue, steps
to reproduce, and any proof-of-concept. We acknowledge reports within 3
business days and aim to ship fixes within 30 days for critical findings.

Do **not** file public GitHub issues for vulnerabilities.

## Permissions

The exporter needs **read-only** access to Secrets cluster-wide. See
`deploy/chart/templates/rbac.yaml`:

```
resources: ["secrets"]
verbs:     ["get", "list", "watch"]
```

Narrow the scope by setting `exporter.namespaces` or by applying the
`tigertrust.io/monitor=true` annotation + `--require-annotation`.

The container runs as non-root with a read-only root filesystem, no
privileged capabilities, and `allowPrivilegeEscalation: false`.

## Private key handling

The exporter parses the **certificate** (`tls.crt`) only. It does not read
`tls.key` or expose any metric that depends on private key material.
