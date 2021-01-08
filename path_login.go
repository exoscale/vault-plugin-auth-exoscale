package authExoscale

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/hashicorp/vault/sdk/logical"
)

var pathLoginHelp = [2]string{
	"Issue a token based on the credentials supplied.",
	`The credentials 'role_id' and 'instance_id' are required at all times.

'role_id' is the Role ID (UUID), which may be fetched using the 'role/<role_name>/role_id' endpoint.

'instance_id' is the Exoscale Compute Instance ID (UUID), which may be fetched within the Instance
from the http://metadata.exoscale.com/latest/meta-data/instance-id endpoint.

Temporarily, 'secret_id' may be used in place of 'instance_id' such as to allow the Vault Agent
to use the AppRole auth-method against this backend.`,
	},
}

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login$",
		HelpSynopsis:    pathLoginHelp[0],
		HelpDescription: pathLoginHelp[1],
		Fields: map[string]*framework.FieldSchema{
			"role_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Role ID (UUID).",
			},
			"instance_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Exoscale Compute Instance ID (UUID)",
			},
			"secret_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Deprecated. For use with Vault Agent AppRole auth-method only. Prefer 'instance_id' where possible.",
				Deprecated:  true
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.AliasLookaheadOperation: b.pathLoginUpdateAliasLookahead,
			logical.UpdateOperation:         b.pathLoginUpdate,
		},
	}
}

func (b *backend) pathLoginUpdateAliasLookahead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleID := strings.TrimSpace(data.Get("role_id").(string))
	if roleID == "" {
		return nil, fmt.Errorf("missing role_id")
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: roleID,
			},
		},
	}, nil
}

// Returns the Auth object indicating the authentication and authorization information
// if the credentials provided are validated by the backend.
func (b *backend) pathLoginUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	// RoleID must be supplied during every login
	roleID := strings.TrimSpace(data.Get("role_id").(string))
	if roleID == "" {
		return logical.ErrorResponse("missing role_id"), nil
	}

	// InstanceID must be supplied during every login
	instanceID := strings.TrimSpace(data.GetFirst("instance_id", "secret_id").(string))
	if instanceID == "" {
		return logical.ErrorResponse("missing instance_id"), nil
	}

	// Look for the storage entry that maps the roleID to role
	roleIDIndex, err := b.RoleID(ctx, req.Storage, roleID)
	if err != nil {
		return nil, err
	}
	if roleIDIndex == nil {
		return logical.ErrorResponse("invalid role_id"), nil
	}

	roleName := roleIDIndex.Name

	roleLock := b.roleLock(roleName)
	roleLock.RLock()

	role, err := b.Role(ctx, req.Storage, roleName)
	roleLock.RUnlock()
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("invalid role_id"), nil
	}


	//
	// Provider (Exoscale API)
	//

	config, err := b.Config(ctx, req.Storage)
	if err != nil || config == nil {
		return nil, errwrap.Wrapf("unable to retrieve backend configuration: {{err}}", err)
	}

	provider, err := b.Provider(config)
	if err != nil {
		return nil, err
	}

	// TODO: Retrieve the Compute Instance meta-data (orchestrator-attributed IP, age, tags, parent Pool, etc.)
	//InstanceMetadata := ...


	//
	// Authentication
	//

	// instance_match_ip
	if role.InstanceMatchIP {
		if req.Connection == nil || req.Connection.RemoteAddr == "" {
			return nil, fmt.Errorf("failed to get connection information")
		}
		if InstanceMetadata.IP != req.Connection.RemoteAddr {  // TODO
			return logical.ErrorResponse("Instance IP address mismatch (instance_match_ip)"), nil
		}
	}

	// instance_bound_cidrs
	if len(role.InstanceBoundCIDRs) != 0 {
		if req.Connection == nil || req.Connection.RemoteAddr == "" {
			return nil, fmt.Errorf("failed to get connection information")
		}
		belongs, err := cidrutil.IPBelongsToCIDRBlocksSlice(req.Connection.RemoteAddr, role.InstanceBoundCIDRs)
		if !belongs || err != nil {
			return logical.ErrorResponse(errwrap.Wrapf(fmt.Sprintf("source address %q unauthorized through CIDR restrictions (instance_bound_cidrs); {{err}}", req.Connection.RemoteAddr), err).Error()), nil
		}
	}

	// instance_max_age
	if role.InstanceMaxAge > 0 {
		if InstanceMetadata.Age > role.InstanceMaxAge {  // TODO
			return logical.ErrorResponse("Instance is too old (instance_max_age)"), nil
		}
	}

	// instance_allowed_tags
	if len(role.InstanceAllowedTags) != 0 {
		belongs := false
		// TODO: InstanceMetadata.Tags in role.InstanceAllowedTags -> belongs := true
		if !belongs {
			return logical.ErrorResponse("Instance Tags mismatch (instance_allowed_tags)"), nil
		}
	}

	// instance_allowed_pool_ids
	if len(role.InstanceAllowedPoolIDs) != 0 {
		belongs := false
		// TODO: InstanceMetadata.PoolID in role.InstanceAllowedPoolIDs -> belongs := true
		if !belongs {
			return logical.ErrorResponse("Instance Pool mismatch (instance_allowed_pool_ids)"), nil
		}
	}


	//
	// Token issuance
	//

	metadata = make(map[string]string)
	metadata["role_name"] = role.name

	auth := &logical.Auth{
		InternalData: map[string]interface{}{
			"role_name": role.name,
		},
		Metadata: metadata,
		Alias: &logical.Alias{
			Name:     role.RoleID,
			Metadata: metadata,
		},
	}
	role.PopulateTokenAuth(auth)

	return &logical.Response{
		Auth: auth,
	}, nil
}

// Invoked when the token issued by this backend is attempting a renewal.
func (b *backend) pathLoginRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := req.Auth.InternalData["role_name"].(string)
	if roleName == "" {
		return nil, fmt.Errorf("failed to fetch role_name during renewal")
	}

	lock := b.roleLock(roleName)
	lock.RLock()
	defer lock.RUnlock()

	// Ensure that the Role still exists.
	role, err := b.Role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("failed to validate role %q during renewal: {{err}}", roleName), err)
	}
	if role == nil {
		return nil, fmt.Errorf("role %q does not exist during renewal", roleName)
	}

	resp := &logical.Response{Auth: req.Auth}
	resp.Auth.TTL = role.TokenTTL
	resp.Auth.MaxTTL = role.TokenMaxTTL
	resp.Auth.Period = role.TokenPeriod
	return resp, nil
}
