# plugin-aws-acm

A CCF compliance plugin for AWS Certificate Manager (ACM). Fetches certificate data from ACM and evaluates OPA Rego policies to produce Evidence for the CCF API.

## What it checks

| Check | SOC2 Controls | Description |
|-------|--------------|-------------|
| Certificate expiry | CC7.1, CC7.2 | Certificates expiring within threshold days |
| Certificate transparency | CC6.1 | CT logging enabled |
| Key algorithm | CC6.1 | RSA 2048+ or ECDSA P-256+ |
| Wildcard certificates | CC6.1, CC6.7 | Wildcard certs flagged |
| Auto-renewal | A1.2 | Auto-renewal enabled for managed certs |
| Domain validation | CC6.1 | DNS validation preferred over email |
| In-use certificates | CC9.1 | Certificates attached to at least one resource |

## Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `region` | string | required | AWS region |
| `assume_role_arn` | string | "" | IAM role ARN to assume (optional) |
| `policy_labels` | JSON object | {} | Extra labels added to all Evidence entries |

## Required IAM permissions

```json
{
  "Effect": "Allow",
  "Action": [
    "acm:ListCertificates",
    "acm:DescribeCertificate",
    "acm:ListTagsForCertificate"
  ],
  "Resource": "*"
}
```

## Local development

```bash
make build          # produces dist/plugin
make test           # runs unit tests
```

See `examples/agent-config.yaml` for agent configuration examples.
