package memory

import (
	"testing"

	"github.com/xraph/vault/internal/storetest"
	"github.com/xraph/vault/secret"
)

func TestVersionEncryption(t *testing.T) {
	storetest.RunVersionEncryption(t, func(*testing.T) (secret.Store, func(key, appID string, version int64)) {
		s := New()
		legacy := func(key, appID string, version int64) {
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, v := range s.secretVersions[sKey(key, appID)] {
				if v.Version == version {
					v.EncryptionAlg = nil
				}
			}
		}
		return s, legacy
	})
}
