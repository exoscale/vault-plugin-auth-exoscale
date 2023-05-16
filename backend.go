package exoscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	vaultsdkver "github.com/hashicorp/vault/sdk/version"

	egoscale "github.com/exoscale/egoscale/v2"
	exoapi "github.com/exoscale/egoscale/v2/api"

	"github.com/exoscale/vault-plugin-auth-exoscale/version"
)

var backendHelp = `
The Exoscale auth backend for Vault allows Exoscale Compute Instance Pool
members to authenticate to a Vault server.
`

type exoscaleClient interface {
	GetInstance(context.Context, string, string) (*egoscale.Instance, error)
	GetInstancePool(context.Context, string, string) (*egoscale.InstancePool, error)
	GetSecurityGroup(context.Context, string, string) (*egoscale.SecurityGroup, error)
}

type exoscaleBackend struct {
	exo exoscaleClient
	*framework.Backend
}

func (b *exoscaleBackend) config(ctx context.Context, storage logical.Storage) (*backendConfig, error) {
	var config backendConfig

	raw, err := storage.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, nil
	}

	if err := json.Unmarshal(raw.Value, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func (b *exoscaleBackend) authRenew(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	if b.exo == nil {
		return nil, errors.New("backend is not configured")
	}

	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	var roleName string
	if v, ok := req.Auth.InternalData["role"]; ok {
		roleName = v.(string)
	} else {
		b.Logger().Error(
			"role information missing from token internal data",
			"client_remote_addr", req.Connection.RemoteAddr,
		)
		return nil, errInternalError
	}

	role, err := b.roleConfig(ctx, req.Storage, roleName)
	if err != nil {
		b.Logger().Error(
			fmt.Sprintf("unable to retrieve role %q: %s", roleName, err),
			"client_remote_addr", req.Connection.RemoteAddr,
		)
		return nil, errInternalError
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", roleName), nil
	}

	if _, err = b.auth(ctx, role, req, nil); err != nil {
		b.Logger().Error(
			err.Error(),
			"client_remote_addr", req.Connection.RemoteAddr,
		)

		switch {
		case errors.Is(err, errMissingField), errors.Is(err, errInvalidFieldValue):
			return logical.ErrorResponse(err.Error()), nil

		case errors.Is(err, errAuthFailed):
			return nil, logical.ErrPermissionDenied

		default:
			return nil, err
		}
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = role.TokenTTL
	resp.Auth.MaxTTL = role.TokenMaxTTL
	resp.Auth.Period = role.TokenPeriod

	return resp, nil
}

func (b *exoscaleBackend) auth(
	ctx context.Context,
	role *backendRole,
	req *logical.Request,
	data *framework.FieldData,
) (*egoscale.Instance, error) {
	var instanceID string

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, errors.New("backend is not configured")
	}

	if data != nil {
		// Initial login mode

		param := authLoginParamInstance
		// In AppRole-compatible mode, we expect `role`/`instance` parameters to be passed using
		// the same name as in the AppRole authentication method (`role_id`/`secret_id`).
		if config.AppRoleMode {
			param = authLoginParamSecretID
		}

		instanceID = data.Get(param).(string)
	} else {
		// Token renewal mode

		if v, ok := req.Auth.InternalData["instance_id"]; ok {
			instanceID = v.(string)
		} else {
			return nil, fmt.Errorf(
				"%w: instance_id information missing from token internal data",
				errInternalError,
			)
		}
	}

	if instanceID == "" {
		return nil, fmt.Errorf("%w: %s", errMissingField, authLoginParamInstance)
	}

	ctx = exoapi.WithEndpoint(ctx, exoapi.NewReqEndpoint(config.APIEnvironment, config.Zone))

	instance, err := b.exo.GetInstance(ctx, config.Zone, instanceID)
	if err != nil {
		if errors.Is(err, exoapi.ErrNotFound) {
			return nil, fmt.Errorf(
				"%w: instance %s does not exist in zone %s",
				errAuthFailed,
				instanceID,
				config.Zone,
			)
		}
		return nil, fmt.Errorf("%w: unable to retrieve Compute instance information: %v",
			errInternalError,
			err) // nolint:errorlint
	}

	if err := b.checkInstanceRole(ctx, req, instance, role); err != nil {
		return instance, err
	}

	return instance, nil
}

func init() {
	egoscale.UserAgent = fmt.Sprintf("Exoscale-Vault-Plugin-Auth/%s (%s) Vault-SDK/%s %s",
		version.Version,
		version.Commit,
		vaultsdkver.Version,
		egoscale.UserAgent)
}

func Factory(ctx context.Context, backendConfig *logical.BackendConfig) (logical.Backend, error) {
	var backend exoscaleBackend

	backend.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   backend.authRenew,
		Help:        backendHelp,

		Paths: []*framework.Path{
			pathInfo(&backend),
			pathConfig(&backend),
			pathLogin(&backend),
			pathListRoles(&backend),
			pathRole(&backend),
		},

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
		},
	}

	config, err := backend.config(ctx, backendConfig.StorageView)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve backend config from storage: %w", err)
	}

	if config != nil {
		exo, err := egoscale.NewClient(config.APIKey, config.APISecret)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize Exoscale client: %w", err)
		}
		backend.exo = exo
	}

	if err := backend.Setup(ctx, backendConfig); err != nil {
		return nil, fmt.Errorf("unable to create factory: %w", err)
	}

	return &backend, nil
}
