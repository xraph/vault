package source_test

import (
	"context"
	"errors"
	"testing"

	"github.com/xraph/vault/source"
)

func bg() context.Context { return context.Background() }

func TestChainFirstHitWins(t *testing.T) {
	m1 := source.NewMemory()
	m2 := source.NewMemory()

	m1.Set(bg(), "key1", "from-m1")
	m2.Set(bg(), "key1", "from-m2")

	chain := source.NewChain(m1, m2)

	val, err := chain.Get(bg(), "key1")
	if err != nil {
		t.Fatal(err)
	}
	if val.Raw != "from-m1" {
		t.Errorf("Raw = %q, want %q (first source wins)", val.Raw, "from-m1")
	}
}

func TestChainFallthrough(t *testing.T) {
	m1 := source.NewMemory()
	m2 := source.NewMemory()

	// Only m2 has the key.
	m2.Set(bg(), "key2", "from-m2")

	chain := source.NewChain(m1, m2)

	val, err := chain.Get(bg(), "key2")
	if err != nil {
		t.Fatal(err)
	}
	if val.Raw != "from-m2" {
		t.Errorf("Raw = %q, want %q (fallthrough to m2)", val.Raw, "from-m2")
	}
}

func TestChainAllMiss(t *testing.T) {
	m1 := source.NewMemory()
	m2 := source.NewMemory()

	chain := source.NewChain(m1, m2)

	_, err := chain.Get(bg(), "missing-key")
	if !errors.Is(err, source.ErrKeyNotFound) {
		t.Errorf("got %v, want ErrKeyNotFound", err)
	}
}

func TestChainListMerges(t *testing.T) {
	m1 := source.NewMemory()
	m2 := source.NewMemory()

	m1.Set(bg(), "a", "1")
	m1.Set(bg(), "b", "2")
	m2.Set(bg(), "b", "overridden") // b also in m2 — m1 wins
	m2.Set(bg(), "c", "3")

	chain := source.NewChain(m1, m2)

	vals, err := chain.List(bg(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 3 {
		t.Fatalf("len = %d, want 3", len(vals))
	}

	byKey := make(map[string]string)
	for _, v := range vals {
		byKey[v.Key] = v.Raw
	}
	if byKey["b"] != "2" {
		t.Errorf("b = %q, want %q (m1 wins)", byKey["b"], "2")
	}
}

func TestChainClose(t *testing.T) {
	chain := source.NewChain(source.NewMemory(), source.NewMemory())
	if err := chain.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
