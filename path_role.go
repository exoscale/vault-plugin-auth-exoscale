package exoscale

import (
	"context"
	"fmt"
	"time"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

const (
	roleStoragePathPrefix = "role/"

	roleKeyName                         = "name"
	roleKeyAllowedInstancePools         = "allowed_instance_pools"
	roleKeyMatchClientInstanceIPAddress = "match_client_instance_ip_address"
	roleKeyMaxClientInstanceAge         = "max_client_instance_age"
)

var (
	pathListRolesHelpSyn  = "List the configured backend roles"
	pathListRolesHelpDesc = `
This endpoint returns a list of the configured backend roles.
`

	pathRoleHelpSyn  = "Manage backend roles"
	pathRoleHelpDesc = `
This endpoint manages backend roles, which are used to determine how Vault
clients running on Exoscale Compute instances must be authenticated by the
exoscale auth method.

When creating a role, the following checks (disabled by default) can be
performed:

  * The specified Compute instance must be member of a specific Instance Pool.
  * The client (requester) IP address must match the specified Compute
    instance's IP address.
  * The specified Compute instance must not have been created too long ago.
`
)

type backendRole struct {
	AllowedInstancePools         []string      `json:"allowed_instance_pools"`
	MaxClientInstanceAge         time.Duration `json:"max_client_instance_age"`
	MatchClientInstanceIPAddress bool          `json:"match_client_instance_ip_address"`

	tokenutil.TokenParams
}

func (r *backendRole) checkInstance(req *logical.Request, instance *egoscale.VirtualMachine) error {
	// Check Instance <> Instance Pool relationship
	if r.AllowedInstancePools != nil {
		var isMember bool
		for _, instancePoolID := range r.AllowedInstancePools {
			if instance.ManagerID == nil {
				break
			}

			if instance.ManagerID.String() == instancePoolID {
				isMember = true
				break
			}
		}
		if !isMember {
			return fmt.Errorf("%w: instance %s is not member of any Instance Pools allowed by role",
				errAuthFailed,
				instance.ID)
		}
	}

	// Check client Instance age limit
	if r.MaxClientInstanceAge > 0 {
		instanceCreationTime, err := time.Parse("2006-01-02T15:04:05-0700", instance.Created)
		if err != nil {
			return fmt.Errorf("%w: unable to parse Compute instance creation timestamp: %s",
				errInternalError,
				err) // nolint:errorlint
		}

		instanceLifetime := time.Now().Sub(instanceCreationTime)
		if instanceLifetime > r.MaxClientInstanceAge {
			return fmt.Errorf("%w: instance %s is older than maximum allowed age (%s > %s)",
				errAuthFailed,
				instance.ID,
				instanceLifetime,
				r.MaxClientInstanceAge)
		}
	}

	// Check client IP address matches client Instance IP address
	if r.MatchClientInstanceIPAddress {
		if req.Connection.RemoteAddr != instance.DefaultNic().IPAddress.String() {
			return fmt.Errorf("%w: client IP address does not match instance IP address (%s != %s)",
				errAuthFailed,
				req.Connection.RemoteAddr,
				instance.DefaultNic().IPAddress.String())
		}
	}

	return nil
}

func pathListRoles(b *exoscaleBackend) *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{Callback: b.listRoles},
		},

		HelpSynopsis:    pathListRolesHelpSyn,
		HelpDescription: pathListRolesHelpDesc,
	}
}

func pathRole(b *exoscaleBackend) *framework.Path {
	p := &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			roleKeyName: {
				Type:        framework.TypeString,
				Description: "Name of the role",
				Required:    true,
			},
			roleKeyAllowedInstancePools: {
				Type: framework.TypeStringSlice,
				Description: "List of Instance Pools (ID) the client Compute " +
					"instance must be member of during authentication",
			},
			roleKeyMatchClientInstanceIPAddress: {
				Type: framework.TypeBool,
				Description: "Match clients remote IP address against advertised " +
					"Compute instance's during authentication (disabled by default)",
			},
			roleKeyMaxClientInstanceAge: {
				Type: framework.TypeDurationSecond,
				Description: "Maximum client Compute instance age to allow during " +
					"authentication (0 = disabled)",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: b.writeRole},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.writeRole},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.readRole},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.deleteRole},
		},

		HelpSynopsis:    pathRoleHelpSyn,
		HelpDescription: pathRoleHelpDesc,
	}

	tokenutil.AddTokenFields(p.Fields)

	return p
}

func (b *exoscaleBackend) roleConfig(ctx context.Context, storage logical.Storage, name string) (*backendRole, error) {
	var role backendRole

	entry, err := storage.Get(ctx, roleStoragePathPrefix+name)
	if err != nil {
		return nil, errors.Wrapf(err, "error retrieving role %q", name)
	}
	if entry == nil {
		return nil, nil
	}

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	return &role, nil
}

func (b *exoscaleBackend) listRoles(ctx context.Context, req *logical.Request,
	_ *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, roleStoragePathPrefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(roles), nil
}

func (b *exoscaleBackend) readRole(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	role, err := b.roleConfig(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	d := map[string]interface{}{
		roleKeyAllowedInstancePools:         fmt.Sprint(role.AllowedInstancePools),
		roleKeyMatchClientInstanceIPAddress: role.MatchClientInstanceIPAddress,
		roleKeyMaxClientInstanceAge:         fmt.Sprint(role.MaxClientInstanceAge),
	}

	role.PopulateTokenData(d)

	return &logical.Response{Data: d}, nil
}

func (b *exoscaleBackend) writeRole(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	role, err := b.roleConfig(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &backendRole{}
	}

	if v, ok := data.GetOk(roleKeyAllowedInstancePools); ok {
		role.AllowedInstancePools = v.([]string)
	}
	if v, ok := data.GetOk(roleKeyMatchClientInstanceIPAddress); ok {
		role.MatchClientInstanceIPAddress = v.(bool)
	}
	if v, ok := data.GetOk(roleKeyMaxClientInstanceAge); ok {
		role.MaxClientInstanceAge = time.Second * time.Duration(v.(int))
	}

	if err := role.ParseTokenFields(req, data); err != nil {
		return nil, err
	}

	entry, err := logical.StorageEntryJSON(roleStoragePathPrefix+name, role)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *exoscaleBackend) deleteRole(ctx context.Context, req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if err := req.Storage.Delete(ctx, roleStoragePathPrefix+name); err != nil {
		return nil, err
	}

	return nil, nil
}
