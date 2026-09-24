package main

import (
	"context"
	"strings"
	"testing"

	"github.com/elcanotek/auth/internal/config"
	"github.com/elcanotek/auth/internal/store"
)

func TestMagicAllowlistStartCheckUsesPersistentDomains(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	cfg := &config.Config{LoginMode: "magic"}
	if err := magicAllowlistStartCheck(cfg, st); err == nil || !strings.Contains(err.Error(), "domain allowlist") {
		t.Fatalf("empty production allowlist: %v", err)
	}
	if err := st.AddDomain(context.Background(), "example.com"); err != nil {
		t.Fatal(err)
	}
	if err := magicAllowlistStartCheck(cfg, st); err != nil {
		t.Fatalf("persistent allowlist was rejected: %v", err)
	}
}
