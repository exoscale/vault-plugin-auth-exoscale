package exoscale

import (
	"context"
	"errors"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	defaultAPIEndpoint = "https://api.exoscale.com/v1"

	configStoragePath    = "config"
	configKeyAPIEndpoint = "api_endpoint"
	configKeyAPIKey      = "api_key"
	configKeyAPISecret   = "api_secret"
	configKeyAppRoleMode = "approle_mode"
	configKeyZone        = "zone"
)

var (
	pathConfigHelpSyn  = "Configure the Exoscale auth backend plugin"
	pathConfigHelpDesc = `
This endpoint manages the configuration of the root Exoscale auth backend
plugin, including the Exoscale API credentials enabling it to authenticate
Vault clients using this authentication method.
`
)

var (
	errMissingAPICredentials = errors.New("missing API credentials")
	errMissingZone           = errors.New("missing zone")
)

func pathConfig(b *exoscaleBackend) *framework.Path {
	p := &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			configKeyAPIEndpoint: {
				Type:        framework.TypeString,
				Description: "Exoscale API endpoint",
			},
			configKeyAPIKey: {
				Type:         framework.TypeString,
				Description:  "Exoscale API key",
				DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
			},
			configKeyAPISecret: {
				Type:         framework.TypeString,
				Description:  "Exoscale API secret",
				DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
			},
			configKeyAppRoleMode: {
				Type:        framework.TypeBool,
				Description: "Run in AppRole-compatible mode",
			},
			configKeyZone: {
				Type:        framework.TypeString,
				Description: "Exoscale zone to look Compute instances into",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
		},

		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}

	return p
}

func (b *exoscaleBackend) pathConfigRead(ctx context.Context,
	req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if config == nil {
		return nil, nil
	}

	d := map[string]interface{}{
		configKeyAPIEndpoint: config.APIEndpoint,
		configKeyAPIKey:      config.APIKey,
		configKeyAPISecret:   config.APISecret,
		configKeyAppRoleMode: config.AppRoleMode,
		configKeyZone:        config.Zone,
	}

	return &logical.Response{
		Data: d,
	}, nil
}

func (b *exoscaleBackend) pathConfigWrite(ctx context.Context,
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config := &backendConfig{APIEndpoint: defaultAPIEndpoint}

	if v, ok := data.GetOk(configKeyAPIEndpoint); ok {
		config.APIEndpoint = v.(string)
	}
	if v, ok := data.GetOk(configKeyAPIKey); ok {
		config.APIKey = v.(string)
	}
	if v, ok := data.GetOk(configKeyAPISecret); ok {
		config.APISecret = v.(string)
	}

	if config.APIKey == "" || config.APISecret == "" {
		return nil, errMissingAPICredentials
	}

	if v, ok := data.GetOk(configKeyZone); ok {
		config.Zone = v.(string)
	} else {
		return nil, errMissingZone
	}

	if v, ok := data.GetOk(configKeyAppRoleMode); ok {
		config.AppRoleMode = v.(bool)
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.exo = egoscale.NewClient(config.APIEndpoint, config.APIKey, config.APISecret)

	res := &logical.Response{}
	res.AddWarning("Read access to this endpoint should be controlled via ACLs as " +
		"it will return sensitive information as-is, including the backend plugin API credentials")

	return res, nil
}

type backendConfig struct {
	APIEndpoint string `json:"api_endpoint"`
	APIKey      string `json:"api_key"`
	APISecret   string `json:"api_secret"`
	AppRoleMode bool   `json:"approle_mode"`
	Zone        string `json:"zone"`
}
