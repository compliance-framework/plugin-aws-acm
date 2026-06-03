package internal

import (
	"context"
	"errors"
	"fmt"
	"strings"

	policyManager "github.com/compliance-framework/agent/policy-manager"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/hashicorp/go-hclog"
)

type PolicyEvaluator struct {
	ctx            context.Context
	logger         hclog.Logger
	stepActivities []*proto.Activity
}

func NewPolicyEvaluator(ctx context.Context, logger hclog.Logger, stepActivities []*proto.Activity) *PolicyEvaluator {
	return &PolicyEvaluator{
		ctx:            ctx,
		logger:         logger,
		stepActivities: stepActivities,
	}
}

// Eval evaluates all policyPaths against cert and returns one Evidence per policy path.
// extraLabels (e.g. PolicyLabels from config) are merged with cert-derived labels;
// SeededUUID derives the evidence UUID from ALL resulting labels, so label keys must
// not change between runs.
func (pe *PolicyEvaluator) Eval(ctx context.Context, cert CertificateContext, policyPaths []string, policyData map[string]interface{}, extraLabels map[string]string) ([]*proto.Evidence, error) {
	var accumulatedErrors error
	evidences := make([]*proto.Evidence, 0)

	input, err := cert.ToOPAInput()
	if err != nil {
		return nil, fmt.Errorf("serialising cert %s: %w", cert.CertificateArn, err)
	}

	componentID := "common-components/aws-acm"
	inventoryID := fmt.Sprintf("aws-acm-certificate/%s", arnCertID(cert.CertificateArn))

	labels := MergeMaps(extraLabels, certificateBaseLabels(), map[string]string{
		"certificate_arn": cert.CertificateArn,
		"resource_arn":    cert.CertificateArn,
		"region":          cert.Region,
		"account_id":      cert.AccountID,
		"domain_name":     cert.DomainName,
	})

	actors := []*proto.OriginActor{
		{
			Title: "The Continuous Compliance Framework",
			Type:  "assessment-platform",
			Links: []*proto.Link{
				{
					Href: "https://compliance-framework.github.io/docs/",
					Rel:  StringAddressed("reference"),
					Text: StringAddressed("The Continuous Compliance Framework"),
				},
			},
		},
		{
			Title: "Continuous Compliance Framework - AWS ACM Plugin",
			Type:  "tool",
			Links: []*proto.Link{
				{
					Href: "https://github.com/compliance-framework/plugin-aws-acm",
					Rel:  StringAddressed("reference"),
					Text: StringAddressed("The Continuous Compliance Framework AWS ACM Plugin"),
				},
			},
		},
	}

	components := []*proto.Component{
		{
			Identifier:  componentID,
			Type:        "service",
			Title:       "AWS Certificate Manager",
			Description: "AWS Certificate Manager (ACM) handles the complexity of creating, storing, and renewing public and private SSL/TLS X.509 certificates and keys that protect AWS websites and applications.",
			Purpose:     "To provision, manage, and deploy public and private SSL/TLS certificates for use with AWS services and connected resources.",
		},
	}

	inventory := []*proto.InventoryItem{
		{
			Identifier: inventoryID,
			Type:       "certificate",
			Title:      fmt.Sprintf("AWS ACM Certificate [%s]", cert.DomainName),
			Props: []*proto.Property{
				{Name: "arn", Value: cert.CertificateArn},
				{Name: "domain_name", Value: cert.DomainName},
				{Name: "region", Value: cert.Region},
				{Name: "status", Value: cert.Status},
				{Name: "key_algorithm", Value: cert.KeyAlgorithm},
			},
			ImplementedComponents: []*proto.InventoryItemImplementedComponent{
				{Identifier: componentID},
			},
		},
	}

	subjects := []*proto.Subject{
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			Identifier: componentID,
		},
		{
			Type:       proto.SubjectType_SUBJECT_TYPE_INVENTORY_ITEM,
			Identifier: inventoryID,
		},
	}

	for _, policyPath := range policyPaths {
		processor := policyManager.NewPolicyProcessor(
			pe.logger,
			labels,
			subjects,
			components,
			inventory,
			actors,
			pe.stepActivities,
			policyData,
		)

		evidence, perr := processor.GenerateResults(ctx, policyPath, input)
		for _, ev := range evidence {
			ev.Title = fmt.Sprintf("%s [%s]", ev.GetTitle(), cert.DomainName)
		}
		evidences = append(evidences, evidence...)
		if perr != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, perr)
		}
	}

	return evidences, accumulatedErrors
}

// certificateBaseLabels returns the stable identity labels applied to every
// ACM certificate evidence entry. SeededUUID (api/sdk/uuid.go) derives the
// evidence UUID from ALL labels including _-prefixed ones — changing any key
// here will change the UUID and break evidence continuity in the UI.
func certificateBaseLabels() map[string]string {
	return map[string]string{
		"provider": "aws",
		"type":     "acm-certificate",
	}
}

// arnCertID extracts the certificate UUID from an ACM ARN.
// ARN format: arn:aws:acm:<region>:<account-id>:certificate/<uuid>
func arnCertID(arn string) string {
	if idx := strings.LastIndex(arn, "/"); idx >= 0 {
		return arn[idx+1:]
	}
	return arn
}
