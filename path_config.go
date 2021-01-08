package authExoscale

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

var pathConfigHelp = map[string][2]string{
	"config": {
		"Configure the Exoscale Authentication backend.",
		"Set the Exoscale IAM key/secret to access the Exoscale API.",
	},
	"api-key": {
		"Exoscale IAM/API key (EXO...).",
		`
Exoscale IAM/API key. It requires READ-ONLY access to the following API endpoints:
 - TODO: to retrieve the Compute Instance attributed IP address
 - TODO: to retrieve the Compute Instance creation timestamp
 - TODO: to retrieve the Compute Instance Tags
 - TODO: to retrieve the Compute Instance parent Instance Pool
`,
	},
	"api-secret": {
		"Exoscale IAM/API secret.",
		"Exoscale IAM/API secret (corresponding to the 'api_key').",
	},
}

type configStorageEntry struct {
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
}

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config$",
		HelpSynopsis:    strings.TrimSpace(pathConfigHelp["config"][0]),
		HelpDescription: strings.TrimSpace(pathConfigHelp["config"][1]),
		Fields: map[string]*framework.FieldSchema{
			"api_key": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: strings.TrimSpace(pathConfigHelp["api-key"][0]),
			},
			"api_secret": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: strings.TrimSpace(pathConfigHelp["api-secret"][0]),
			},
		},
		ExistenceCheck: b.pathConfigExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathConfigCreateUpdate,
			logical.ReadOperation:   b.pathConfigRead,
			logical.DeleteOperation: b.pathConfigDelete,
		},
	}
}


////////////////////////////////////////////////////////////////////////////////
// config
//

// Persist the configuration.
func (b *backend) storeConfig(ctx context.Context, s logical.Storage, config *configStorageEntry) error {
	if config == nil {
		return fmt.Errorf("nil config")
	}

	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("failed to create storage entry for the configuration")
	}

	if err = s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// Read the configuration from storage
func (b *backend) Config(ctx context.Context, s logical.Storage) (*configStorageEntry, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var config configStorageEntry
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, err
	}
	return &config, nil
}

func (b *backend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return config != nil, nil
}

func (b *backend) pathConfigCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = new(configStorageEntry)
	}

	if apiKeyRaw, ok := data.GetOk("api_key"); ok {
		config.APIKey = apiKeyRaw.(string)
	}
	else {
		return logical.ErrorResponse("missing api_key"), nil
	}

	if apiSecretRaw, ok := data.GetOk("api_secret"); ok {
		config.APISecret = apiSecretRaw.(string)
	}
	else {
		return logical.ErrorResponse("missing api_secret"), nil
	}

	if err := b.storeConfig(ctx, req.Storage, config); err != nil {
		return nil, err
	}

	b.reset()

	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.Config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"api_key":    config.APIKey,
			//"api_secret": config.APISecret,  // NOPE! Do not disclose API secret!
		},
	}
	return resp, nil
}

func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "config")

	if err == nil {
		b.reset()
	}

	return nil, err
}
