package exoscale

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	authLoginParamInstance = "instance"
	authLoginParamRole     = "role"
	authLoginParamRoleID   = "role_id"
	authLoginParamSecretID = "secret_id"
)

var (
	pathLoginHelpSyn  = "Log in via an Exoscale Compute Instance"
	pathLoginHelpDesc = `
This endpoint authenticates using the properties of an Exoscale Compute
Instance. When authenticating, the Vault auth backend verifies the Instance
ID provided by the client, and grants a Vault token if they match actual
resources.

By default, the exoscale auth method only checks that the Compute instance
corresponding to the ID specified by the client actually exists; depending on
the specified role, additional checks can be performed to further authenticate
clients (see role-related path for more information).
`

	errAuthFailed        = errors.New("authentication failed")
	errInternalError     = errors.New("internal error")
	errInvalidFieldValue = errors.New("invalid field value")
	errMissingField      = errors.New("missing field")
)

func pathLogin(b *exoscaleBackend) *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			authLoginParamInstance: {
				Type:        framework.TypeString,
				Description: "Instance ID",
			},
			authLoginParamRole: {
				Type:        framework.TypeString,
				Description: "Role name",
			},
			authLoginParamRoleID: {
				Type:        framework.TypeString,
				Description: "AppRole RoleID (role name)",
			},
			authLoginParamSecretID: {
				Type:        framework.TypeString,
				Description: "AppRole SecretID (instance ID)",
			},
			"zone": {
				Type:        framework.TypeString,
				Description: "Instance zone",
				Deprecated:  true,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.pathLoginWrite},
		},

		HelpSynopsis:    pathLoginHelpSyn,
		HelpDescription: pathLoginHelpDesc,
	}
}

func (b *exoscaleBackend) pathLoginWrite(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	if b.exo == nil {
		return nil, errors.New("backend is not configured")
	}

	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, errors.New("backend is not configured")
	}

	roleParamName := authLoginParamRole
	instanceParamName := authLoginParamInstance
	// In AppRole-compatible mode, we expect `role`/`instance` parameters to be passed using
	// the same name as in the AppRole authentication method (`role_id`/`secret_id`).
	if config.AppRoleMode {
		roleParamName = authLoginParamRoleID
		instanceParamName = authLoginParamSecretID
	}

	if _, ok := data.GetOk(roleParamName); !ok {
		return logical.ErrorResponse("%v: %s", errMissingField, roleParamName), nil
	}
	roleName := data.Get(roleParamName).(string)

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

	if _, ok := data.GetOk(instanceParamName); !ok {
		return logical.ErrorResponse("%v: %s", errMissingField, instanceParamName), nil
	}

	instance, err := b.auth(ctx, role, req, data)
	if err != nil {
		b.Logger().Error(err.Error(), "client_remote_addr", req.Connection.RemoteAddr)

		switch {
		case errors.Is(err, errMissingField), errors.Is(err, errInvalidFieldValue):
			return logical.ErrorResponse(err.Error()), nil

		case errors.Is(err, errAuthFailed):
			return nil, logical.ErrPermissionDenied

		default:
			return nil, err
		}
	}

	b.Logger().Debug(
		"successfully authenticated instance",
		"instance_id", *instance.ID,
		"instance_name", instance.Name,
		"zone", instance.Zone,
	)

	auth := &logical.Auth{
		InternalData: map[string]interface{}{
			"instance_id": *instance.ID,
			"zone":        *instance.Zone,
			"role":        roleName,
		},
	}

	role.PopulateTokenAuth(auth)

	return &logical.Response{
		Auth: auth,
	}, nil
}
