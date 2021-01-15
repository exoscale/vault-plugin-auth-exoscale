package exoscale

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	vaultsdkver "github.com/hashicorp/vault/sdk/version"
	"github.com/pkg/errors"

	"github.com/exoscale/vault-plugin-auth-exoscale/version"
)

var backendHelp = `
The Exoscale auth backend for Vault allows Exoscale Compute Instance Pool
members to authenticate to a Vault server.
`

type exoscaleBackend struct {
	exo *egoscale.Client
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

func (b *exoscaleBackend) authRenew(ctx context.Context,
	req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if b.exo == nil {
		return nil, errors.New("backend is not configured")
	}

	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	var roleName string
	if v, ok := req.Auth.InternalData["role"]; !ok {
		b.Logger().Error("role information missing from token internal data",
			"client_remote_addr", req.Connection.RemoteAddr)
		return nil, errInternalError
	} else {
		roleName = v.(string)
	}

	role, err := b.roleConfig(ctx, req.Storage, roleName)
	if err != nil {
		b.Logger().Error(fmt.Sprintf("unable to retrieve role %q: %s", roleName, err),
			"client_remote_addr", req.Connection.RemoteAddr)
		return nil, errInternalError
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role %q not found", roleName)), nil
	}

	if _, err = b.auth(ctx, role, req, nil); err != nil {
		b.Logger().Error(err.Error(),
			"client_remote_addr", req.Connection.RemoteAddr)

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

func (b *exoscaleBackend) auth(ctx context.Context, role *backendRole,
	req *logical.Request, data *framework.FieldData) (*egoscale.VirtualMachine, error) {
	var (
		zoneName   string
		instanceID *egoscale.UUID
	)

	if data != nil {
		// Initial login mode

		if v, ok := data.GetOk("zone"); ok {
			zoneName = v.(string)
		}
		if zoneName == "" {
			return nil, fmt.Errorf("%w: %s", errMissingField, "zone")
		}

		if v, ok := data.GetOk("instance"); ok {
			uuid, err := egoscale.ParseUUID(v.(string))
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %s", errInvalidFieldValue, "instance", err) // nolint:errorlint
			}
			instanceID = uuid
		}
	} else {
		// Token renewal mode

		if v, ok := req.Auth.InternalData["zone"]; !ok {
			return nil, fmt.Errorf("%w: zone information missing from token internal data", errInternalError)
		} else {
			zoneName = v.(string)
		}

		if v, ok := req.Auth.InternalData["instance_id"]; !ok {
			return nil, fmt.Errorf("%w: instance_id information missing from token internal data",
				errInternalError)
		} else {
			instanceID = egoscale.MustParseUUID(v.(string))
		}
	}

	z, err := b.exo.GetWithContext(ctx, &egoscale.Zone{Name: zoneName})
	if err != nil {
		return nil, fmt.Errorf("%w: unable to retrieve zone information: %s",
			errInternalError,
			err) // nolint:errorlint
	}
	zone := z.(*egoscale.Zone)

	if instanceID == nil {
		return nil, fmt.Errorf("%w: %s", errMissingField, "instance")
	}
	i, err := b.exo.GetWithContext(ctx, &egoscale.VirtualMachine{
		ID:     instanceID,
		ZoneID: zone.ID,
	})
	if err != nil {
		if errors.Is(err, egoscale.ErrNotFound) {
			return nil, fmt.Errorf("%w: instance %s does not exist in zone %s",
				errAuthFailed,
				instanceID,
				zoneName)
		}
		return nil, fmt.Errorf("%w: unable to retrieve Compute instance information: %s",
			errInternalError,
			err) // nolint:errorlint
	}
	instance := i.(*egoscale.VirtualMachine)

	if err := role.checkInstance(req, instance); err != nil {
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

func Factory(ctx context.Context, config *logical.BackendConfig) (logical.Backend, error) {
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

	if err := backend.Setup(ctx, config); err != nil {
		return nil, errors.Wrap(err, "failed to create factory")
	}

	return &backend, nil
}
