# plugin-aws-acm

A CCF compliance plugin for AWS Certificate Manager (ACM). Fetches certificate data from ACM and evaluates OPA Rego policies to produce Evidence for the CCF API.

What the plugin checks is determined entirely by the policy bundles configured in the agent. The plugin itself is policy-agnostic — it fetches ACM certificate data and makes it available to whatever policies are loaded.

## Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `regions` | string | required | Comma-separated list of AWS regions, e.g. `us-east-1,eu-west-1` |
| `accounts` | string | "" | Comma-separated list of AWS account IDs to evaluate (optional) |
| `policy_labels` | JSON object | {} | Extra labels added to all Evidence entries |

AWS credentials are resolved from the environment using the standard AWS SDK credential chain (environment variables, shared credentials file, instance profile, etc.).

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

## Prerequisites

- Go 1.22+
- AWS credentials accessible via the standard SDK credential chain

## Local development

```bash
make build          # produces dist/plugin
make test           # runs unit tests
```

See `examples/agent-config.yaml` for agent configuration examples.

## Contributing

The plugin is intentionally policy-agnostic. To add a new compliance check:

1. Add the required ACM API fields to `internal/data.go` (`CertificateContext` struct and `fetchCertificate`).
2. Expose the new field via `ToOPAInput()` (inherited automatically from the struct's JSON tags).
3. Write the new Rego policy in the [`plugin-aws-acm-certificate-policies`](https://github.com/container-solutions/plugin-aws-acm-certificate-policies) repo — see that repo's README for the policy authoring guide.
4. Add unit tests in `internal/data_test.go` covering the new field for empty, populated, and error cases.
