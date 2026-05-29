package internal

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/hashicorp/go-hclog"
)

// ACMClient is the subset of the AWS ACM API used by DataFetcher.
type ACMClient interface {
	ListCertificates(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	DescribeCertificate(ctx context.Context, params *acm.DescribeCertificateInput, optFns ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
	ListTagsForCertificate(ctx context.Context, params *acm.ListTagsForCertificateInput, optFns ...func(*acm.Options)) (*acm.ListTagsForCertificateOutput, error)
}

// DomainValidationOption holds per-domain validation details for a certificate.
type DomainValidationOption struct {
	DomainName       string `json:"domain_name"`
	ValidationMethod string `json:"validation_method"`
}

// CertificateContext holds all fields required by the ACM compliance policies.
type CertificateContext struct {
	Region                        string                   `json:"region"`
	AccountID                     string                   `json:"account_id"`
	CertificateArn                string                   `json:"certificate_arn"`
	DomainName                    string                   `json:"domain_name"`
	Status                        string                   `json:"status"`
	NotAfter                      *time.Time               `json:"not_after,omitempty"`
	KeyAlgorithm                  string                   `json:"key_algorithm"`
	TransparencyLoggingPreference string                   `json:"transparency_logging_preference"`
	DomainValidationOptions       []DomainValidationOption `json:"domain_validation_options"`
	InUseBy                       []string                 `json:"in_use_by"`
	Tags                          map[string]string        `json:"tags"`
}

// DataFetcher retrieves ACM certificate data across configured regions.
type DataFetcher struct {
	logger    hclog.Logger
	config    *PluginConfig
	newClient func(ctx context.Context, region string) (ACMClient, error)
}

// NewDataFetcher returns a DataFetcher using the standard AWS credential chain.
// AWS_ENDPOINT_URL is honoured automatically by the SDK for LocalStack compatibility.
func NewDataFetcher(logger hclog.Logger, cfg *PluginConfig) *DataFetcher {
	return &DataFetcher{
		logger: logger,
		config: cfg,
		newClient: func(ctx context.Context, region string) (ACMClient, error) {
			awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
			if err != nil {
				return nil, err
			}
			return acm.NewFromConfig(awsCfg), nil
		},
	}
}

// FetchData retrieves all ACM certificates across every configured region.
func (df *DataFetcher) FetchData(ctx context.Context) ([]CertificateContext, error) {
	var all []CertificateContext
	for _, region := range df.config.Regions {
		certs, err := df.fetchRegion(ctx, region)
		if err != nil {
			return nil, fmt.Errorf("region %s: %w", region, err)
		}
		all = append(all, certs...)
	}
	return all, nil
}

func (df *DataFetcher) fetchRegion(ctx context.Context, region string) ([]CertificateContext, error) {
	client, err := df.newClient(ctx, region)
	if err != nil {
		return nil, fmt.Errorf("create ACM client: %w", err)
	}

	var certs []CertificateContext
	var nextToken *string
	for {
		out, err := client.ListCertificates(ctx, &acm.ListCertificatesInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("ListCertificates: %w", err)
		}
		for _, summary := range out.CertificateSummaryList {
			arn := aws.ToString(summary.CertificateArn)
			if arn == "" {
				continue
			}
			cert, err := df.fetchCertificate(ctx, client, region, arn)
			if err != nil {
				df.logger.Warn("skipping certificate", "arn", arn, "error", err)
				continue
			}
			certs = append(certs, cert)
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return certs, nil
}

func (df *DataFetcher) fetchCertificate(ctx context.Context, client ACMClient, region, arn string) (CertificateContext, error) {
	descOut, err := client.DescribeCertificate(ctx, &acm.DescribeCertificateInput{
		CertificateArn: aws.String(arn),
	})
	if err != nil {
		return CertificateContext{}, fmt.Errorf("DescribeCertificate: %w", err)
	}

	tagsOut, err := client.ListTagsForCertificate(ctx, &acm.ListTagsForCertificateInput{
		CertificateArn: aws.String(arn),
	})
	if err != nil {
		return CertificateContext{}, fmt.Errorf("ListTagsForCertificate: %w", err)
	}

	detail := descOut.Certificate

	transparencyPref := ""
	if detail.Options != nil {
		transparencyPref = string(detail.Options.CertificateTransparencyLoggingPreference)
	}

	dvos := make([]DomainValidationOption, 0, len(detail.DomainValidationOptions))
	for _, dvo := range detail.DomainValidationOptions {
		dvos = append(dvos, DomainValidationOption{
			DomainName:       aws.ToString(dvo.DomainName),
			ValidationMethod: string(dvo.ValidationMethod),
		})
	}

	tags := make(map[string]string, len(tagsOut.Tags))
	for _, tag := range tagsOut.Tags {
		tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}

	inUseBy := detail.InUseBy
	if inUseBy == nil {
		inUseBy = []string{}
	}

	return CertificateContext{
		Region:                        region,
		AccountID:                     arnAccountID(arn),
		CertificateArn:                arn,
		DomainName:                    aws.ToString(detail.DomainName),
		Status:                        string(detail.Status),
		NotAfter:                      detail.NotAfter,
		KeyAlgorithm:                  string(detail.KeyAlgorithm),
		TransparencyLoggingPreference: transparencyPref,
		DomainValidationOptions:       dvos,
		InUseBy:                       inUseBy,
		Tags:                          tags,
	}, nil
}

// arnAccountID extracts the 12-digit account ID from an ACM ARN.
// ARN format: arn:aws:acm:<region>:<account-id>:certificate/<id>
func arnAccountID(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
