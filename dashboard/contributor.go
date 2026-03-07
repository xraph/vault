package dashboard

import (
	"context"
	"fmt"
	"strings"

	"github.com/a-h/templ"

	"github.com/xraph/forge/extensions/dashboard/contributor"

	"github.com/xraph/vault"
	"github.com/xraph/vault/audit"
	vaultconfig "github.com/xraph/vault/config"
	"github.com/xraph/vault/dashboard/pages"
	"github.com/xraph/vault/dashboard/widgets"
	"github.com/xraph/vault/flag"
	"github.com/xraph/vault/override"
	"github.com/xraph/vault/rotation"
	"github.com/xraph/vault/secret"
	"github.com/xraph/vault/store"
)

// Ensure Contributor implements the required interface at compile time.
var _ contributor.LocalContributor = (*Contributor)(nil)

// Contributor implements the dashboard LocalContributor interface for the
// vault extension. It renders pages, widgets, and settings using templ
// components and ForgeUI.
type Contributor struct {
	manifest *contributor.Manifest
	store    store.Store
	appID    string
}

// New creates a new vault dashboard contributor.
func New(manifest *contributor.Manifest, s store.Store, appID string) *Contributor {
	return &Contributor{
		manifest: manifest,
		store:    s,
		appID:    appID,
	}
}

// Manifest returns the contributor manifest.
func (c *Contributor) Manifest() *contributor.Manifest { return c.manifest }

// RenderPage renders a page for the given route.
func (c *Contributor) RenderPage(ctx context.Context, route string, params contributor.Params) (templ.Component, error) {
	switch route {
	case "/", "":
		return c.renderOverview(ctx)
	case "/secrets":
		return c.renderSecrets(ctx, params)
	case "/secrets/detail":
		return c.renderSecretDetail(ctx, params)
	case "/secrets/create":
		return c.renderSecretCreate(ctx, params)
	case "/flags":
		return c.renderFlags(ctx, params)
	case "/flags/detail":
		return c.renderFlagDetail(ctx, params)
	case "/flags/create":
		return c.renderFlagCreate(ctx, params)
	case "/config":
		return c.renderConfig(ctx, params)
	case "/config/detail":
		return c.renderConfigDetail(ctx, params)
	case "/config/create":
		return c.renderConfigCreate(ctx, params)
	case "/overrides":
		return c.renderOverrides(ctx, params)
	case "/overrides/detail":
		return c.renderOverrideDetail(ctx, params)
	case "/rotation":
		return c.renderRotation(ctx)
	case "/rotation/detail":
		return c.renderRotationDetail(ctx, params)
	case "/audit":
		return c.renderAudit(ctx, params)
	case "/settings":
		return c.renderSettings(ctx)
	default:
		return nil, contributor.ErrPageNotFound
	}
}

// RenderWidget renders a widget by ID.
func (c *Contributor) RenderWidget(ctx context.Context, widgetID string) (templ.Component, error) {
	switch widgetID {
	case "vault-stats":
		return c.renderStatsWidget(ctx)
	case "vault-recent-audit":
		return c.renderRecentAuditWidget(ctx)
	default:
		return nil, contributor.ErrWidgetNotFound
	}
}

// RenderSettings renders a settings panel by ID.
func (c *Contributor) RenderSettings(ctx context.Context, settingID string) (templ.Component, error) {
	switch settingID {
	case "vault-config":
		return c.renderSettings(ctx)
	default:
		return nil, contributor.ErrSettingNotFound
	}
}

// ─── Page Renderers ──────────────────────────────────────────────────────────

func (c *Contributor) renderOverview(ctx context.Context) (templ.Component, error) {
	appID := c.appID

	stats := pages.OverviewStats{
		SecretCount:         fetchSecretCount(ctx, c.store, appID),
		FlagCount:           fetchFlagCount(ctx, c.store, appID),
		ConfigCount:         fetchConfigCount(ctx, c.store, appID),
		RotationPolicyCount: fetchRotationPolicyCount(ctx, c.store, appID),
		AuditEntryCount:     fetchAuditCount(ctx, c.store, appID),
	}

	recentAudit, err := fetchAuditEntries(ctx, c.store, appID, audit.ListOpts{Limit: 10})
	if err != nil {
		recentAudit = nil
	}

	return pages.OverviewPage(stats, recentAudit), nil
}

func (c *Contributor) renderSecrets(ctx context.Context, params contributor.Params) (templ.Component, error) {
	appID := c.appID

	secrets, err := fetchSecrets(ctx, c.store, appID, secret.ListOpts{Limit: 100})
	if err != nil {
		secrets = nil
	}

	keyFilter := params.QueryParams["key"]
	if keyFilter != "" && secrets != nil {
		filtered := make([]*secret.Meta, 0)
		for _, s := range secrets {
			if strings.Contains(strings.ToLower(s.Key), strings.ToLower(keyFilter)) {
				filtered = append(filtered, s)
			}
		}
		secrets = filtered
	}

	return pages.SecretsPage(pages.SecretsPageData{
		Secrets:   secrets,
		KeyFilter: keyFilter,
	}), nil
}

func (c *Contributor) renderSecretDetail(ctx context.Context, params contributor.Params) (templ.Component, error) {
	key := params.QueryParams["key"]
	appID := params.QueryParams["app_id"]
	if appID == "" {
		appID = c.appID
	}
	if key == "" {
		return nil, contributor.ErrPageNotFound
	}

	// Fetch secret metadata
	secrets, err := fetchSecrets(ctx, c.store, appID, secret.ListOpts{Limit: 10000})
	if err != nil {
		return nil, fmt.Errorf("dashboard: list secrets: %w", err)
	}

	var meta *secret.Meta
	for _, s := range secrets {
		if s.Key == key {
			meta = s
			break
		}
	}
	if meta == nil {
		return nil, contributor.ErrPageNotFound
	}

	// Fetch versions
	versions, verErr := fetchSecretVersions(ctx, c.store, key, appID)
	if verErr != nil {
		versions = nil
	}

	// Fetch rotation policy (may not exist)
	policy, polErr := c.store.GetRotationPolicy(ctx, key, appID)
	if polErr != nil {
		policy = nil
	}

	// Fetch audit entries for this key
	auditEntries, audErr := fetchAuditByKey(ctx, c.store, key, appID, audit.ListOpts{Limit: 20})
	if audErr != nil {
		auditEntries = nil
	}

	return pages.SecretDetailPage(pages.SecretDetailData{
		Secret:         meta,
		Versions:       versions,
		RotationPolicy: policy,
		AuditEntries:   auditEntries,
	}), nil
}

func (c *Contributor) renderSecretCreate(ctx context.Context, params contributor.Params) (templ.Component, error) {
	appID := c.appID

	// Handle form POST.
	if params.FormData["action"] == "create_secret" {
		key := strings.TrimSpace(params.FormData["key"])
		value := params.FormData["value"]
		formAppID := strings.TrimSpace(params.FormData["app_id"])
		if formAppID == "" {
			formAppID = appID
		}

		s := &secret.Secret{
			Entity: vault.NewEntity(),
			Key:    key,
			Value:  []byte(value),
			AppID:  formAppID,
		}

		if err := c.store.SetSecret(ctx, s); err != nil {
			return pages.SecretCreatePage(pages.SecretCreateData{
				Error: err.Error(),
				AppID: appID,
			}), nil
		}

		return c.renderSecrets(ctx, params)
	}

	return pages.SecretCreatePage(pages.SecretCreateData{
		AppID: appID,
	}), nil
}

func (c *Contributor) renderFlags(ctx context.Context, params contributor.Params) (templ.Component, error) {
	appID := c.appID
	typeFilter := params.QueryParams["type"]

	flags, err := fetchFlags(ctx, c.store, appID, flag.ListOpts{Limit: 100})
	if err != nil {
		flags = nil
	}

	// Apply type filter
	if typeFilter != "" && flags != nil {
		filtered := make([]*flag.Definition, 0)
		for _, f := range flags {
			if strings.EqualFold(string(f.Type), typeFilter) {
				filtered = append(filtered, f)
			}
		}
		flags = filtered
	}

	return pages.FlagsPage(pages.FlagsPageData{
		Flags:      flags,
		TypeFilter: typeFilter,
	}), nil
}

func (c *Contributor) renderFlagDetail(ctx context.Context, params contributor.Params) (templ.Component, error) {
	key := params.QueryParams["key"]
	appID := params.QueryParams["app_id"]
	if appID == "" {
		appID = c.appID
	}
	if key == "" {
		return nil, contributor.ErrPageNotFound
	}

	// Handle actions
	if action := params.QueryParams["action"]; action != "" {
		switch action {
		case "enable":
			if flagDef, getErr := c.store.GetFlagDefinition(ctx, key, appID); getErr == nil && flagDef != nil {
				flagDef.Enabled = true
				if defErr := c.store.DefineFlag(ctx, flagDef); defErr != nil {
					return nil, fmt.Errorf("dashboard: enable flag: %w", defErr)
				}
			}
		case "disable":
			if flagDef, getErr := c.store.GetFlagDefinition(ctx, key, appID); getErr == nil && flagDef != nil {
				flagDef.Enabled = false
				if defErr := c.store.DefineFlag(ctx, flagDef); defErr != nil {
					return nil, fmt.Errorf("dashboard: disable flag: %w", defErr)
				}
			}
		}
	}

	def, err := c.store.GetFlagDefinition(ctx, key, appID)
	if err != nil {
		return nil, fmt.Errorf("dashboard: resolve flag: %w", err)
	}

	rules, rulesErr := fetchFlagRules(ctx, c.store, key, appID)
	if rulesErr != nil {
		rules = nil
	}
	overrides, ovErr := fetchFlagOverrides(ctx, c.store, key, appID)
	if ovErr != nil {
		overrides = nil
	}

	return pages.FlagDetailPage(pages.FlagDetailData{
		Flag:      def,
		Rules:     rules,
		Overrides: overrides,
	}), nil
}

func (c *Contributor) renderFlagCreate(ctx context.Context, params contributor.Params) (templ.Component, error) {
	appID := c.appID

	// Handle form POST.
	if params.FormData["action"] == "create_flag" {
		key := strings.TrimSpace(params.FormData["key"])
		flagType := flag.Type(strings.TrimSpace(params.FormData["flag_type"]))
		defaultValue := strings.TrimSpace(params.FormData["default_value"])
		description := strings.TrimSpace(params.FormData["description"])
		tagsStr := strings.TrimSpace(params.FormData["tags"])
		enabled := params.FormData["enabled"] == "true"
		formAppID := strings.TrimSpace(params.FormData["app_id"])
		if formAppID == "" {
			formAppID = appID
		}

		var tags []string
		if tagsStr != "" {
			for _, t := range strings.Split(tagsStr, ",") {
				t = strings.TrimSpace(t)
				if t != "" {
					tags = append(tags, t)
				}
			}
		}

		def := &flag.Definition{
			Entity:       vault.NewEntity(),
			Key:          key,
			Type:         flagType,
			DefaultValue: defaultValue,
			Description:  description,
			Tags:         tags,
			Enabled:      enabled,
			AppID:        formAppID,
		}

		if err := c.store.DefineFlag(ctx, def); err != nil {
			return pages.FlagCreatePage(pages.FlagCreateData{
				Error: err.Error(),
				AppID: appID,
			}), nil
		}

		return c.renderFlags(ctx, params)
	}

	return pages.FlagCreatePage(pages.FlagCreateData{
		AppID: appID,
	}), nil
}

func (c *Contributor) renderConfig(ctx context.Context, params contributor.Params) (templ.Component, error) {
	appID := c.appID
	keyFilter := params.QueryParams["key"]

	entries, err := fetchConfigs(ctx, c.store, appID, vaultconfig.ListOpts{Limit: 100})
	if err != nil {
		entries = nil
	}

	// Apply key filter
	if keyFilter != "" && entries != nil {
		filtered := make([]*vaultconfig.Entry, 0)
		for _, e := range entries {
			if strings.Contains(strings.ToLower(e.Key), strings.ToLower(keyFilter)) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	return pages.ConfigPage(pages.ConfigPageData{
		Entries:   entries,
		KeyFilter: keyFilter,
	}), nil
}

func (c *Contributor) renderConfigDetail(ctx context.Context, params contributor.Params) (templ.Component, error) {
	key := params.QueryParams["key"]
	appID := params.QueryParams["app_id"]
	if appID == "" {
		appID = c.appID
	}
	if key == "" {
		return nil, contributor.ErrPageNotFound
	}

	entry, err := c.store.GetConfig(ctx, key, appID)
	if err != nil {
		return nil, fmt.Errorf("dashboard: resolve config: %w", err)
	}

	versions, verErr := fetchConfigVersions(ctx, c.store, key, appID)
	if verErr != nil {
		versions = nil
	}
	overrides, ovErr := fetchOverridesByKey(ctx, c.store, key, appID)
	if ovErr != nil {
		overrides = nil
	}

	return pages.ConfigDetailPage(pages.ConfigDetailData{
		Entry:     entry,
		Versions:  versions,
		Overrides: overrides,
	}), nil
}

func (c *Contributor) renderConfigCreate(ctx context.Context, params contributor.Params) (templ.Component, error) {
	appID := c.appID

	// Handle form POST.
	if params.FormData["action"] == "create_config" {
		key := strings.TrimSpace(params.FormData["key"])
		value := strings.TrimSpace(params.FormData["value"])
		valueType := strings.TrimSpace(params.FormData["value_type"])
		description := strings.TrimSpace(params.FormData["description"])
		formAppID := strings.TrimSpace(params.FormData["app_id"])
		if formAppID == "" {
			formAppID = appID
		}

		entry := &vaultconfig.Entry{
			Entity:      vault.NewEntity(),
			Key:         key,
			Value:       value,
			ValueType:   valueType,
			Description: description,
			AppID:       formAppID,
		}

		if err := c.store.SetConfig(ctx, entry); err != nil {
			return pages.ConfigCreatePage(pages.ConfigCreateData{
				Error: err.Error(),
				AppID: appID,
			}), nil
		}

		return c.renderConfig(ctx, params)
	}

	return pages.ConfigCreatePage(pages.ConfigCreateData{
		AppID: appID,
	}), nil
}

func (c *Contributor) renderOverrides(ctx context.Context, params contributor.Params) (templ.Component, error) {
	appID := c.appID
	tenantFilter := params.QueryParams["tenant_id"]

	var overrides []*override.Override

	if tenantFilter != "" {
		var fetchErr error
		overrides, fetchErr = fetchOverridesByTenant(ctx, c.store, appID, tenantFilter)
		if fetchErr != nil {
			overrides = nil
		}
	} else {
		// List overrides from known config keys — get all config entries first,
		// then gather overrides for each key.
		entries, entriesErr := fetchConfigs(ctx, c.store, appID, vaultconfig.ListOpts{Limit: 100})
		if entriesErr != nil {
			entries = nil
		}
		for _, e := range entries {
			keyOverrides, koErr := fetchOverridesByKey(ctx, c.store, e.Key, appID)
			if koErr != nil {
				continue
			}
			overrides = append(overrides, keyOverrides...)
			if len(overrides) >= 100 {
				break
			}
		}
		if len(overrides) > 100 {
			overrides = overrides[:100]
		}
	}

	return pages.OverridesPage(pages.OverridesPageData{
		Overrides:    overrides,
		TenantFilter: tenantFilter,
	}), nil
}

func (c *Contributor) renderOverrideDetail(ctx context.Context, params contributor.Params) (templ.Component, error) {
	key := params.QueryParams["key"]
	appID := params.QueryParams["app_id"]
	tenantID := params.QueryParams["tenant_id"]
	if appID == "" {
		appID = c.appID
	}
	if key == "" || tenantID == "" {
		return nil, contributor.ErrPageNotFound
	}

	o, err := c.store.GetOverride(ctx, key, appID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("dashboard: resolve override: %w", err)
	}

	return pages.OverrideDetailPage(pages.OverrideDetailData{
		Override: o,
	}), nil
}

func (c *Contributor) renderRotation(ctx context.Context) (templ.Component, error) {
	policies, err := fetchRotationPolicies(ctx, c.store, c.appID)
	if err != nil {
		policies = nil
	}

	return pages.RotationPage(pages.RotationPageData{
		Policies: policies,
	}), nil
}

func (c *Contributor) renderRotationDetail(ctx context.Context, params contributor.Params) (templ.Component, error) {
	key := params.QueryParams["key"]
	appID := params.QueryParams["app_id"]
	if appID == "" {
		appID = c.appID
	}
	if key == "" {
		return nil, contributor.ErrPageNotFound
	}

	policy, err := c.store.GetRotationPolicy(ctx, key, appID)
	if err != nil {
		return nil, fmt.Errorf("dashboard: resolve rotation policy: %w", err)
	}

	records, recErr := fetchRotationRecords(ctx, c.store, key, appID, rotation.ListOpts{Limit: 50})
	if recErr != nil {
		records = nil
	}

	return pages.RotationDetailPage(pages.RotationDetailData{
		Policy:  policy,
		Records: records,
	}), nil
}

func (c *Contributor) renderAudit(ctx context.Context, params contributor.Params) (templ.Component, error) {
	appID := c.appID
	resourceFilter := params.QueryParams["resource"]

	entries, err := fetchAuditEntries(ctx, c.store, appID, audit.ListOpts{Limit: 100})
	if err != nil {
		entries = nil
	}

	// Apply resource filter
	if resourceFilter != "" && entries != nil {
		filtered := make([]*audit.Entry, 0)
		for _, e := range entries {
			if strings.EqualFold(e.Resource, resourceFilter) {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	return pages.AuditPage(pages.AuditPageData{
		Entries:        entries,
		ResourceFilter: resourceFilter,
	}), nil
}

func (c *Contributor) renderSettings(_ context.Context) (templ.Component, error) {
	return pages.SettingsPage(pages.SettingsData{
		AppID: c.appID,
	}), nil
}

// ─── Widget Renderers ────────────────────────────────────────────────────────

func (c *Contributor) renderStatsWidget(ctx context.Context) (templ.Component, error) {
	appID := c.appID
	data := widgets.StatsData{
		Secrets: fetchSecretCount(ctx, c.store, appID),
		Flags:   fetchFlagCount(ctx, c.store, appID),
		Config:  fetchConfigCount(ctx, c.store, appID),
		Audit:   fetchAuditCount(ctx, c.store, appID),
	}
	return widgets.StatsWidget(data), nil
}

func (c *Contributor) renderRecentAuditWidget(ctx context.Context) (templ.Component, error) {
	entries, auditErr := fetchAuditEntries(ctx, c.store, c.appID, audit.ListOpts{Limit: 5})
	if auditErr != nil {
		entries = nil
	}
	return widgets.RecentAuditWidget(entries), nil
}
