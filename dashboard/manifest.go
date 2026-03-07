package dashboard

import (
	"github.com/xraph/forge/extensions/dashboard/contributor"
)

// NewManifest builds a contributor.Manifest for the vault dashboard.
func NewManifest() *contributor.Manifest {
	return &contributor.Manifest{
		Name:        "vault",
		DisplayName: "Vault",
		Icon:        "shield",
		Version:     "1.0.0",
		Layout:      "extension",
		ShowSidebar: boolPtr(true),
		TopbarConfig: &contributor.TopbarConfig{
			Title:       "Vault",
			LogoIcon:    "shield",
			AccentColor: "#8b5cf6",
			ShowSearch:  true,
			Actions: []contributor.TopbarAction{
				{Label: "API Docs", Icon: "file-text", Href: "/docs", Variant: "ghost"},
			},
		},
		Nav:      baseNav(),
		Widgets:  baseWidgets(),
		Settings: baseSettings(),
		Capabilities: []string{
			"searchable",
		},
	}
}

// baseNav returns the core navigation items for the vault dashboard.
func baseNav() []contributor.NavItem {
	return []contributor.NavItem{
		// Overview
		{Label: "Overview", Path: "/", Icon: "layout-dashboard", Group: "Overview", Priority: 0},

		// Secrets
		{Label: "Secrets", Path: "/secrets", Icon: "lock", Group: "Secrets", Priority: 0},

		// Feature Flags
		{Label: "Feature Flags", Path: "/flags", Icon: "flag", Group: "Feature Flags", Priority: 0},

		// Configuration
		{Label: "Config Entries", Path: "/config", Icon: "settings-2", Group: "Configuration", Priority: 0},
		{Label: "Overrides", Path: "/overrides", Icon: "layers", Group: "Configuration", Priority: 1},

		// Operations
		{Label: "Rotation", Path: "/rotation", Icon: "refresh-cw", Group: "Operations", Priority: 0},
		{Label: "Audit Log", Path: "/audit", Icon: "file-text", Group: "Operations", Priority: 1},

		// System
		{Label: "Settings", Path: "/settings", Icon: "settings", Group: "System", Priority: 0},
	}
}

// baseWidgets returns the core widget descriptors for the vault dashboard.
func baseWidgets() []contributor.WidgetDescriptor {
	return []contributor.WidgetDescriptor{
		{
			ID:          "vault-stats",
			Title:       "Vault Stats",
			Description: "Secrets, flags, and config metrics",
			Size:        "md",
			RefreshSec:  30,
			Group:       "Vault",
		},
		{
			ID:          "vault-recent-audit",
			Title:       "Recent Audit",
			Description: "Latest vault audit log entries",
			Size:        "lg",
			RefreshSec:  15,
			Group:       "Vault",
		},
	}
}

// baseSettings returns the core settings descriptors for the vault dashboard.
func baseSettings() []contributor.SettingsDescriptor {
	return []contributor.SettingsDescriptor{
		{
			ID:          "vault-config",
			Title:       "Vault Configuration",
			Description: "Secrets engine settings",
			Group:       "Vault",
			Icon:        "shield",
		},
	}
}

func boolPtr(b bool) *bool { return &b }
