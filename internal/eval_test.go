package internal

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// writeTarGz creates a tar.gz archive at dest containing a single file at
// the given internal path with the given content.
func writeTarGz(t *testing.T, dest, internalPath, content string) {
	t.Helper()
	f, err := os.Create(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()
	body := []byte(content)
	if err := tw.WriteHeader(&tar.Header{Name: internalPath, Mode: 0644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
}

// TestLoadBundleRootData_TarGzBundle documents the known gap: when the agent
// supplies a bundle as a tar.gz file path, LoadBundleRootData receives that
// file path as policyPath. Path-joining into a file returns ENOTDIR (treated
// as not-found and skipped), and data.json inside the archive is never read.
// Bundle defaults are silently lost; policies relying on data.* will fail.
// Fix: detect tar.gz paths in LoadBundleRootData and extract data.json from
// the archive before falling back to the filesystem candidates.
func TestLoadBundleRootData_TarGzBundle(t *testing.T) {
	root := t.TempDir()
	bundlePath := filepath.Join(root, "bundle.tar.gz")
	writeTarGz(t, bundlePath, "data.json", `{"expiry_warning_days":30}`)

	result, err := LoadBundleRootData(bundlePath, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// data.json is not extracted from the archive; bundle defaults are silently lost.
	// Update this assertion once tar.gz support is implemented.
	if _, loaded := result["expiry_warning_days"]; loaded {
		t.Fatal("tar.gz bundle support appears to be implemented — update this test to assert correct loading behaviour")
	}
}

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

func TestLoadBundleRootData_PolicyPathDataJsonWinsOverParent(t *testing.T) {
	root := t.TempDir()
	parentJSON := `{"expiry_warning_days":30,"source":"parent"}`
	if err := os.WriteFile(filepath.Join(root, "data.json"), []byte(parentJSON), 0644); err != nil {
		t.Fatal(err)
	}
	policiesDir := filepath.Join(root, "policies")
	if err := os.Mkdir(policiesDir, 0755); err != nil {
		t.Fatal(err)
	}
	policiesJSON := `{"expiry_warning_days":60,"source":"policyPath"}`
	if err := os.WriteFile(filepath.Join(policiesDir, "data.json"), []byte(policiesJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// When both data.json locations exist, policyPath/data.json must win.
	result, err := LoadBundleRootData(policiesDir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := result["source"]; got != "policyPath" {
		t.Errorf("source: got %v, want policyPath", got)
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
