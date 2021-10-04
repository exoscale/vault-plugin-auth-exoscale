package exoscale

import (
	"context"
	"fmt"

	egoscale "github.com/exoscale/egoscale/v2"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath       = "config"
	configKeyAPIEnvironment = "api_environment"
	configKeyAPIKey         = "api_key"
	configKeyAPISecret      = "api_secret"
	configKeyAppRoleMode    = "approle_mode"
	configKeyZone           = "zone"

	defaultAPIEnvironment = "api"
)

var (
	pathConfigHelpSyn  = "Configure the Exoscale auth backend plugin"
	pathConfigHelpDesc = `
This endpoint manages the configuration of the root Exoscale auth backend
plugin, including the Exoscale API credentials enabling it to authenticate
Vault clients using this authentication method.
`
)

func pathConfig(b *exoscaleBackend) *framework.Path {
	p := &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			configKeyAPIEnvironment: {
				Type:        framework.TypeString,
				Description: "Exoscale API environment",
				Default:     defaultAPIEnvironment,
			},
			configKeyAPIKey: {
				Type:         framework.TypeString,
				Description:  "Exoscale API key",
				Required:     true,
				DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
			},
			configKeyAPISecret: {
				Type:         framework.TypeString,
				Description:  "Exoscale API secret",
				Required:     true,
				DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
			},
			configKeyAppRoleMode: {
				Type:        framework.TypeBool,
				Default:     false,
				Description: "Run in AppRole-compatible mode",
			},
			configKeyZone: {
				Type:        framework.TypeString,
				Description: "Exoscale zone",
				Required:    true,
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

func (b *exoscaleBackend) pathConfigRead(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	} else if config == nil {
		return nil, nil
	}

	d := map[string]interface{}{
		configKeyAPIEnvironment: config.APIEnvironment,
		configKeyAPIKey:         config.APIKey,
		configKeyAPISecret:      config.APISecret,
		configKeyAppRoleMode:    config.AppRoleMode,
		configKeyZone:           config.Zone,
	}

	return &logical.Response{
		Data: d,
	}, nil
}

func (b *exoscaleBackend) pathConfigWrite(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	config := backendConfig{
		APIEnvironment: data.Get(configKeyAPIEnvironment).(string),
		APIKey:         data.Get(configKeyAPIKey).(string),
		APISecret:      data.Get(configKeyAPISecret).(string),
		AppRoleMode:    data.Get(configKeyAppRoleMode).(bool),
		Zone:           data.Get(configKeyZone).(string),
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	exo, err := egoscale.NewClient(config.APIKey, config.APISecret)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize Exoscale client: %w", err)
	}
	b.exo = exo

	res := &logical.Response{}
	res.AddWarning("Read access to this endpoint should be controlled via ACLs as " +
		"it will return sensitive information as-is, including the backend plugin API credentials")

	return res, nil
}

type backendConfig struct {
	APIEnvironment string `json:"api_environment"`
	APIKey         string `json:"api_key"`
	APISecret      string `json:"api_secret"`
	AppRoleMode    bool   `json:"approle_mode"`
	Zone           string `json:"zone"`
}
