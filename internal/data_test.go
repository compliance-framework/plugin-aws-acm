package internal

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/hashicorp/go-hclog"
)

type mockACMClient struct {
	listCertificates       func(context.Context, *acm.ListCertificatesInput, ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	describeCertificate    func(context.Context, *acm.DescribeCertificateInput, ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
	listTagsForCertificate func(context.Context, *acm.ListTagsForCertificateInput, ...func(*acm.Options)) (*acm.ListTagsForCertificateOutput, error)
}

func (m *mockACMClient) ListCertificates(ctx context.Context, params *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	return m.listCertificates(ctx, params, optFns...)
}

func (m *mockACMClient) DescribeCertificate(ctx context.Context, params *acm.DescribeCertificateInput, optFns ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	return m.describeCertificate(ctx, params, optFns...)
}

func (m *mockACMClient) ListTagsForCertificate(ctx context.Context, params *acm.ListTagsForCertificateInput, optFns ...func(*acm.Options)) (*acm.ListTagsForCertificateOutput, error) {
	return m.listTagsForCertificate(ctx, params, optFns...)
}

func newTestFetcher(regions []string, client ACMClient) *DataFetcher {
	return &DataFetcher{
		logger: hclog.NewNullLogger(),
		config: &PluginConfig{Regions: regions},
		newClient: func(_ context.Context, _ string) (ACMClient, error) {
			return client, nil
		},
	}
}

func TestFetchData_Empty(t *testing.T) {
	mock := &mockACMClient{
		listCertificates: func(_ context.Context, _ *acm.ListCertificatesInput, _ ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
			return &acm.ListCertificatesOutput{}, nil
		},
	}
	f := newTestFetcher([]string{"us-east-1"}, mock)
	certs, err := f.FetchData(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 0 {
		t.Errorf("expected 0 certs, got %d", len(certs))
	}
}

func TestFetchData_SingleCertificate(t *testing.T) {
	arn := "arn:aws:acm:us-east-1:123456789012:certificate/abc-123"
	notAfter := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	mock := &mockACMClient{
		listCertificates: func(_ context.Context, _ *acm.ListCertificatesInput, _ ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
			return &acm.ListCertificatesOutput{
				CertificateSummaryList: []types.CertificateSummary{
					{CertificateArn: aws.String(arn)},
				},
			}, nil
		},
		describeCertificate: func(_ context.Context, _ *acm.DescribeCertificateInput, _ ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
			return &acm.DescribeCertificateOutput{
				Certificate: &types.CertificateDetail{
					CertificateArn: aws.String(arn),
					DomainName:     aws.String("example.com"),
					Status:         types.CertificateStatus("ISSUED"),
					NotAfter:       &notAfter,
					KeyAlgorithm:   types.KeyAlgorithm("RSA_2048"),
					Options: &types.CertificateOptions{
						CertificateTransparencyLoggingPreference: types.CertificateTransparencyLoggingPreference("ENABLED"),
					},
					DomainValidationOptions: []types.DomainValidation{
						{DomainName: aws.String("example.com"), ValidationMethod: types.ValidationMethod("DNS")},
					},
					InUseBy: []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/foo/bar"},
				},
			}, nil
		},
		listTagsForCertificate: func(_ context.Context, _ *acm.ListTagsForCertificateInput, _ ...func(*acm.Options)) (*acm.ListTagsForCertificateOutput, error) {
			return &acm.ListTagsForCertificateOutput{
				Tags: []types.Tag{
					{Key: aws.String("env"), Value: aws.String("prod")},
				},
			}, nil
		},
	}

	f := newTestFetcher([]string{"us-east-1"}, mock)
	certs, err := f.FetchData(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("expected 1 cert, got %d", len(certs))
	}

	c := certs[0]
	if c.CertificateArn != arn {
		t.Errorf("arn: want %q, got %q", arn, c.CertificateArn)
	}
	if c.AccountID != "123456789012" {
		t.Errorf("account_id: want %q, got %q", "123456789012", c.AccountID)
	}
	if c.Region != "us-east-1" {
		t.Errorf("region: want %q, got %q", "us-east-1", c.Region)
	}
	if c.DomainName != "example.com" {
		t.Errorf("domain_name: want %q, got %q", "example.com", c.DomainName)
	}
	if c.Status != "ISSUED" {
		t.Errorf("status: want %q, got %q", "ISSUED", c.Status)
	}
	if c.NotAfter == nil || !c.NotAfter.Equal(notAfter) {
		t.Errorf("not_after: want %v, got %v", notAfter, c.NotAfter)
	}
	if c.KeyAlgorithm != "RSA_2048" {
		t.Errorf("key_algorithm: want %q, got %q", "RSA_2048", c.KeyAlgorithm)
	}
	if c.TransparencyLoggingPreference != "ENABLED" {
		t.Errorf("transparency_logging_preference: want %q, got %q", "ENABLED", c.TransparencyLoggingPreference)
	}
	if len(c.DomainValidationOptions) != 1 || c.DomainValidationOptions[0].ValidationMethod != "DNS" {
		t.Errorf("domain_validation_options: unexpected %v", c.DomainValidationOptions)
	}
	if len(c.InUseBy) != 1 {
		t.Errorf("in_use_by: expected 1 entry, got %v", c.InUseBy)
	}
	if c.Tags["env"] != "prod" {
		t.Errorf("tags: expected env=prod, got %v", c.Tags)
	}
}

func TestFetchData_Pagination(t *testing.T) {
	arns := []string{
		"arn:aws:acm:us-east-1:123456789012:certificate/aaa",
		"arn:aws:acm:us-east-1:123456789012:certificate/bbb",
	}
	callCount := 0

	mock := &mockACMClient{
		listCertificates: func(_ context.Context, _ *acm.ListCertificatesInput, _ ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
			callCount++
			if callCount == 1 {
				return &acm.ListCertificatesOutput{
					CertificateSummaryList: []types.CertificateSummary{{CertificateArn: aws.String(arns[0])}},
					NextToken:              aws.String("page2"),
				}, nil
			}
			return &acm.ListCertificatesOutput{
				CertificateSummaryList: []types.CertificateSummary{{CertificateArn: aws.String(arns[1])}},
			}, nil
		},
		describeCertificate: func(_ context.Context, params *acm.DescribeCertificateInput, _ ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
			return &acm.DescribeCertificateOutput{
				Certificate: &types.CertificateDetail{
					CertificateArn: params.CertificateArn,
					DomainName:     aws.String("example.com"),
					Status:         types.CertificateStatus("ISSUED"),
				},
			}, nil
		},
		listTagsForCertificate: func(_ context.Context, _ *acm.ListTagsForCertificateInput, _ ...func(*acm.Options)) (*acm.ListTagsForCertificateOutput, error) {
			return &acm.ListTagsForCertificateOutput{}, nil
		},
	}

	f := newTestFetcher([]string{"us-east-1"}, mock)
	certs, err := f.FetchData(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("expected 2 certs, got %d", len(certs))
	}
	if callCount != 2 {
		t.Errorf("expected 2 ListCertificates calls, got %d", callCount)
	}
}

func TestFetchData_MultipleRegions(t *testing.T) {
	var clientRegions []string

	f := &DataFetcher{
		logger: hclog.NewNullLogger(),
		config: &PluginConfig{Regions: []string{"us-east-1", "eu-west-1"}},
		newClient: func(_ context.Context, region string) (ACMClient, error) {
			clientRegions = append(clientRegions, region)
			return &mockACMClient{
				listCertificates: func(_ context.Context, _ *acm.ListCertificatesInput, _ ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
					return &acm.ListCertificatesOutput{}, nil
				},
			}, nil
		},
	}

	_, err := f.FetchData(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clientRegions) != 2 || clientRegions[0] != "us-east-1" || clientRegions[1] != "eu-west-1" {
		t.Errorf("expected clients for us-east-1 and eu-west-1, got %v", clientRegions)
	}
}

func TestFetchData_AccountIDFromARN(t *testing.T) {
	cases := []struct {
		arn       string
		accountID string
	}{
		{"arn:aws:acm:us-east-1:123456789012:certificate/abc", "123456789012"},
		{"arn:aws:acm:eu-west-1:999999999999:certificate/xyz", "999999999999"},
		{"invalid", ""},
	}
	for _, tc := range cases {
		got := arnAccountID(tc.arn)
		if got != tc.accountID {
			t.Errorf("arnAccountID(%q): want %q, got %q", tc.arn, tc.accountID, got)
		}
	}
}
