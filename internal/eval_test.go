package internal

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBundleRootData_OverridesWinOverBundleDefaults(t *testing.T) {
	dir := t.TempDir()
	bundleJSON := `{"expiry_warning_days":30,"required_certificate_tags":["Environment"]}`
	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte(bundleJSON), 0644); err != nil {
		t.Fatal(err)
	}

	overrides := map[string]interface{}{
		"expiry_warning_days": float64(90),
	}

	result, err := LoadBundleRootData(dir, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Operator override (90) must win over bundle default (30).
	if got := result["expiry_warning_days"]; got != float64(90) {
		t.Errorf("expiry_warning_days: got %v, want 90", got)
	}

	// Bundle key absent from overrides must still be present.
	if _, ok := result["required_certificate_tags"]; !ok {
		t.Error("required_certificate_tags from bundle missing from merged result")
	}
}

func TestLoadBundleRootData_NoBundleDataJsonReturnsOverrides(t *testing.T) {
	dir := t.TempDir() // no data.json written

	overrides := map[string]interface{}{
		"expiry_warning_days": float64(60),
	}

	result, err := LoadBundleRootData(dir, overrides)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := result["expiry_warning_days"]; got != float64(60) {
		t.Errorf("expiry_warning_days: got %v, want 60", got)
	}
}

func TestLoadBundleRootData_FindsDataJsonOneDirectoryUp(t *testing.T) {
	root := t.TempDir()
	bundleJSON := `{"expiry_warning_days":30}`
	if err := os.WriteFile(filepath.Join(root, "data.json"), []byte(bundleJSON), 0644); err != nil {
		t.Fatal(err)
	}
	policiesDir := filepath.Join(root, "policies")
	if err := os.Mkdir(policiesDir, 0755); err != nil {
		t.Fatal(err)
	}

	// policyPath is the policies/ subdirectory; data.json is one level up.
	result, err := LoadBundleRootData(policiesDir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := result["expiry_warning_days"]; got != float64(30) {
		t.Errorf("expiry_warning_days: got %v, want 30", got)
	}
}
