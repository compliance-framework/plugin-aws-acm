package internal

import (
	"encoding/json"
	"fmt"
	"strings"
)

type PluginConfig struct {
	Region        string
	AssumeRoleARN string
	PolicyLabels  map[string]string
}

func ParseConfig(raw map[string]string) (*PluginConfig, error) {
	config := &PluginConfig{}

	config.Region = strings.TrimSpace(raw["region"])
	if config.Region == "" {
		return nil, fmt.Errorf("config key 'region' is required")
	}
	config.AssumeRoleARN = strings.TrimSpace(raw["assume_role_arn"])

	if v := strings.TrimSpace(raw["policy_labels"]); v != "" {
		if err := json.Unmarshal([]byte(v), &config.PolicyLabels); err != nil {
			return nil, fmt.Errorf("could not parse policy_labels: %w", err)
		}
	}

	return config, nil
}
