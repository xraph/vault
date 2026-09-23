// Package core holds the types every Vault subsystem needs and that none of
// them may reach the root package for.
//
// The subsystem packages (secret, flag, config, override, rotation) embed
// Entity and compare against the sentinel errors. If those lived in the root
// package, the root could not import the subsystems, and the composed Vault
// in vault.go could not exist. This package is a leaf: it imports nothing
// from Vault.
//
// The root package re-exports everything here, so vault.Entity and
// vault.ErrSecretNotFound continue to work unchanged.
package core
