package main

import (
	"context"
	"fmt"

	"github.com/compliance-framework/agent/runner"
	"github.com/compliance-framework/agent/runner/proto"
	"github.com/container-solutions/plugin-aws-acm/internal"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
)

type CompliancePlugin struct {
	logger     hclog.Logger
	config     *internal.PluginConfig
	policyData map[string]interface{}
}

func (l *CompliancePlugin) Configure(req *proto.ConfigureRequest) (*proto.ConfigureResponse, error) {
	rawConfig := req.GetConfig()
	parsedConfig, err := internal.ParseConfig(rawConfig)
	if err != nil {
		return nil, err
	}
	l.config = parsedConfig

	if req.GetPolicyData() != nil {
		l.policyData = req.GetPolicyData().AsMap()
	} else {
		l.policyData = nil
	}

	return &proto.ConfigureResponse{}, nil
}

func (l *CompliancePlugin) Init(req *proto.InitRequest, apiHelper runner.ApiHelper) (*proto.InitResponse, error) {
	ctx := context.Background()
	subjectTemplates := []*proto.SubjectTemplate{
		{
			Name:                "acm-certificate",
			Type:                proto.SubjectType_SUBJECT_TYPE_COMPONENT,
			TitleTemplate:       "ACM Certificate {{ .certificate_arn }}",
			DescriptionTemplate: "AWS ACM Certificate {{ .certificate_arn }} in {{ .account_id }}/{{ .region }}.",
			PurposeTemplate:     "Represents an AWS ACM certificate evaluated for compliance posture.",
			IdentityLabelKeys:   []string{"account_id", "region", "certificate_arn"},
			LabelSchema: []*proto.SubjectLabelSchema{
				{Key: "account_id", Description: "AWS account ID"},
				{Key: "region", Description: "AWS region"},
				{Key: "certificate_arn", Description: "ACM Certificate ARN"},
				{Key: "domain_name", Description: "Primary domain name on the certificate"},
			},
		},
	}
	return runner.InitWithSubjectsAndRisksFromPolicies(ctx, l.logger, req, apiHelper, subjectTemplates)
}

func (l *CompliancePlugin) Eval(request *proto.EvalRequest, apiHelper runner.ApiHelper) (*proto.EvalResponse, error) {
	ctx := context.Background()
	activities := make([]*proto.Activity, 0)

	if request == nil {
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, fmt.Errorf("eval request is nil")
	}

	dataFetcher := internal.NewDataFetcher(l.logger, l.config)
	certs, err := dataFetcher.FetchData(ctx)
	if err != nil {
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, fmt.Errorf("failed to fetch data: %w", err)
	}

	policyEvaluator := internal.NewPolicyEvaluator(ctx, l.logger, activities)
	data := map[string]interface{}{"certificates": certs}

	evidences, err := policyEvaluator.Eval(ctx, data, request.PolicyPaths, l.policyData, l.config.PolicyLabels)
	if err != nil {
		return &proto.EvalResponse{
			Status: proto.ExecutionStatus_FAILURE,
		}, fmt.Errorf("failed to evaluate policies: %w", err)
	}

	if err := apiHelper.CreateEvidence(ctx, evidences); err != nil {
		l.logger.Error("Error creating evidence", "error", err)
		return &proto.EvalResponse{Status: proto.ExecutionStatus_FAILURE}, err
	}

	return &proto.EvalResponse{Status: proto.ExecutionStatus_SUCCESS}, nil
}

func main() {
	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Debug,
		JSONFormat: true,
	})

	compliancePluginObj := &CompliancePlugin{
		logger: logger,
	}
	logger.Debug("initiating plugin")

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: runner.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			"runner": &runner.RunnerV2GRPCPlugin{
				Impl: compliancePluginObj,
			},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}
