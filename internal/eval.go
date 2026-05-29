package internal

import (
	"context"
	"errors"

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

func (pe *PolicyEvaluator) Eval(ctx context.Context, input map[string]interface{}, policyPaths []string, policyData map[string]interface{}, labels map[string]string) ([]*proto.Evidence, error) {
	var accumulatedErrors error

	evidences := make([]*proto.Evidence, 0)
	activities := pe.stepActivities

	for _, policyPath := range policyPaths {
		processor := policyManager.NewPolicyProcessor(
			pe.logger,
			MergeMaps(labels, map[string]string{
				"provider": "aws",
				"type":     "acm-certificate",
				// _-prefixed labels are internal context visible to the policy
				// engine but hidden from the UI and excluded from stream UUID
				// generation.
			}),
			[]*proto.Subject{},
			[]*proto.Component{},
			[]*proto.InventoryItem{},
			[]*proto.OriginActor{},
			activities,
			policyData,
		)

		evidence, perr := processor.GenerateResults(ctx, policyPath, input)
		evidences = append(evidences, evidence...)
		if perr != nil {
			accumulatedErrors = errors.Join(accumulatedErrors, perr)
		}
	}

	return evidences, accumulatedErrors
}
