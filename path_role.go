package authExoscale

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	uuid "github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/helper/parseutil"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/helper/strutil"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

var pathRoleHelp = map[string][2]string{
	"role": {
		"Register a role with the backend.",
		"The set of 'instance_*' constraints on the role defines access to the role.",
	},
	"role-list": {
		"Lists all the roles registered with the backend.",
		"The list will contain the names of the roles.",
	},
	"role-id": {
		"UUID. The 'role_id' of the role.",
		`
The 'role_id' must be presented as a credential during the login. This 'role_id' can be
retrieved using this endpoint.
`,
	},
	"instance-match-ip": {
		"Boolean. Check the Instance IP address matches the orchestrator's.",
		`
If set, requires the Instance/client IP address (as seen from the Vault server)
matches the orchestrator-assigned Instance IP address. Default: false.
`,
	},
	"instance-bound-cidrs": {
		"Comma-separated list of CIDR blocks which the Instance IP address must belong to.",
		`
If set, requires the Instance/client IP address (as seen from the Vault server)
is included in one of the given CIDR blocks. Default: empty (ignored).
`,
	},
	"instance-max-age": {
		"Duration. Instance maximum age.",
		`
If set, requires the Instance age - duration after its creation - is lower
(or equal) than the specified maximum age. Default: 0 (ignored).
`,
	},
	"instance-allowed-tags": {
		"Comma-separated list of tags which the Instance must match.",
		`
If set, requires at least of on the Instance's tags is included in the given tags
("key=value"). Default: empty (ignored).
`,
	},
	"instance-allowed-pool-ids": {
		"Comma-separated list of Instance Pool IDs which the Instance must belong to.",
		`
If set, requires the Instance belongs to one of the given Instance Pool IDs (UUID).
Default: empty (ignored).
`,
	},
	"token-ttl": {
		"Duration. The lifetime of the issued Vault Token.",
		`
The lifetime of the Vault Token - aka. Time-to-Live - defines the duration before which the
token must be renewed to remain valid.
`,
	},
	"token-max-ttl": {
		"Duration. The maximum lifetime of the issued Vault Token.",
		`
The maximum lifetime of the Vault Token - aka. Time-to-Live - defines the maximum overall
lifetime of the token after which it may no longer be renewed.
`,
	},
	"token-num-uses": {
		"Integer. Number of times the issued Vault Token may be used.",
		"This indicates how many times the Vault Token may be used (for authentication).",
	},
	"token-period": {
		"Duration. The lifetime of the issued Periodic Vault Token.",
		`
The lifetime of the Vault Token - aka. Time-to-Live - defines the duration before which the
token must be renewed to remain valid. A Periodic Vault Token implicitly has an infinite
maximum lifetime and unrestricted times of use, allowing it to remain valid indefinitly, as long
as it's being renewed within its lifetime (and extended for another lifetime).
`,
	},
	"token-bound-cidrs": {
		"Comma-separated string or list of CIDR blocks which the bearer must belong to.",
		`
If set, requires the bearer IP address (as seen from the Vault server) is included in one
of the given CIDR blocks. Default: empty (ignored).
`,
	},
	"token-policies": {
		"Comma-separated list of Policies to grant on the issued Vault Token.",
		"Policies define the permissions (<-> ACLs) granted to the client bearing the Vault Token.",
	},
}

// roleStorageEntry stores all the options that are set on an role
type roleStorageEntry struct {
	// Name of the role. This field is not persisted on disk. After the role is
	// read out of disk, the sanitized version of name is set in this field for
	// subsequent use of role name elsewhere.
	name string

	// UUID that uniquely represents this role. This serves as a credential
	// to perform login using this role.
	RoleID string `json:"role_id" mapstructure:"role_id"`

	// If set, requires the Instance/client IP address (as seen from the Vault server)
	// matches the orchestrator-assigned Instance IP address
	InstanceMatchIP bool `json:"instance_match_ip" mapstructure:"instance_match_ip"`

	// If set, requires the Instance/client IP address (as seen from the Vault server)
	// is included in one of the given CIDR blocks
	InstanceBoundCIDRs []string `json:"instance_bound_cidrs" mapstructure:"instance_bound_cidrs"`

	// If set, requires the Instance age - duration after its creation - is lower
	// (or equal) than the specified maximum age
	InstanceMaxAge time.Duration `json:"instance_max_age" mapstructure:"instance_max_age"`

	// If set, requires at least of on the Instance's tags is included in the given tags ("key=value")
	InstanceAllowedTags []string `json:"instance_allowed_tags" mapstructure:"instance_allowed_tags"`

	// If set, requires the Instance belongs to one of the given Instance Pool IDs (UUID)
	InstanceAllowedPoolIDs []string `json:"instance_allowed_pool_ids" mapstructure:"instance_allowed_pool_ids"`

	// Token issuance parameters
	tokenutil.TokenParams
}

// roleIDStorageEntry represents the reverse mapping from RoleID to Role
type roleIDStorageEntry struct {
	Name string `json:"name" mapstructure:"name"`
}

// rolePaths creates all the paths that are used to register and manage an role.
//
// Paths returned:
// role/ - For listing all the registered roles
// role/<role_name> - For registering an role
// role/<role_name>/role-id - For fetching the role_id of an role
// role/<role_name>/instance-match-ip - For updating the param
// role/<role_name>/instance-bound-cidrs - For updating the param
// role/<role_name>/instance-max-age - For updating the param
// role/<role_name>/instance-allowed-tags - For updating the param
// role/<role_name>/instance-allowed-pool-ids - For updating the param
// role/<role_name>/token-ttl - For updating the param
// role/<role_name>/token-max-ttl - For updating the param
// role/<role_name>/token-max-uses - For updating the param
// role/<role_name>/token-period - For updating the param
// role/<role_name>/token-bound-cidrs - For updating the param
// role/<role_name>/token-policies - For updating the param
func pathRole(b *backend) []*framework.Path {
	defTokenFields := tokenutil.TokenFields()

	p := &framework.Path{
		Pattern: "role/" + framework.GenericNameRegex("role_name"),
		HelpSynopsis:    strings.TrimSpace(pathRoleHelp["role"][0]),
		HelpDescription: strings.TrimSpace(pathRoleHelp["role"][1]),
		Fields: map[string]*framework.FieldSchema{
			"role_name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Name of the role.",
			},

			"role_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: strings.TrimSpace(pathRoleHelp["role-id"][0]),
			},

			"instance_match_ip": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Default:     false,
				Description: strings.TrimSpace(pathRoleHelp["instance-match-ip"][0]),
			},

			"instance_bound_cidrs": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: strings.TrimSpace(pathRoleHelp["instance-bound-cidrs"][0]),
			},

			"instance_max_age": &framework.FieldSchema{
				Type:        framework.TypeDurationSecond,
				Default:     0,
				Description: strings.TrimSpace(pathRoleHelp["instance-max-age"][0]),
			},

			"instance_allowed_tags": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: strings.TrimSpace(pathRoleHelp["instance-allowed-tags"][0]),
			},

			"instance_allowed_pool_ids": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: strings.TrimSpace(pathRoleHelp["instance-allowed-pool-ids"][0]),
			},
		},
		ExistenceCheck: b.pathRoleExistenceCheck,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathRoleCreateUpdate,
			logical.UpdateOperation: b.pathRoleCreateUpdate,
			logical.ReadOperation:   b.pathRoleRead,
			logical.DeleteOperation: b.pathRoleDelete,
		},
	}

	tokenutil.AddTokenFields(p.Fields)

	return []*framework.Path{
		p,

		&framework.Path{
			Pattern: "role/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathRoleList,
			},
			HelpSynopsis:    strings.TrimSpace(pathRoleHelp["role-list"][0]),
			HelpDescription: strings.TrimSpace(pathRoleHelp["role-list"][1]),
		},

		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/role-id$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"role_id": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: strings.TrimSpace(pathRoleHelp["role-id"][0]),
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathRoleRoleIDRead,
				logical.UpdateOperation: b.pathRoleRoleIDUpdate,
			},
			HelpSynopsis:    strings.TrimSpace(pathRoleHelp["role-id"][0]),
			HelpDescription: strings.TrimSpace(pathRoleHelp["role-id"][1]),
		},

		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/instance-match-ip$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"instance_match_ip": &framework.FieldSchema{
					Type:        framework.TypeBool,
					Default:     false,
					Description: strings.TrimSpace(pathRoleHelp["instance-match-ip"][1]),
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleInstanceMatchIPUpdate,
				logical.ReadOperation:   b.pathRoleInstanceMatchIPRead,
				logical.DeleteOperation: b.pathRoleInstanceMatchIPDelete,
			},
			HelpSynopsis:    strings.TrimSpace(pathRoleHelp["instance-match-ip"][0]),
			HelpDescription: strings.TrimSpace(pathRoleHelp["instance-match-ip"][1]),
		},

		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/instance-bound-cidrs$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"instance_bound_cidrs": &framework.FieldSchema{
					Type: framework.TypeCommaStringSlice,
					Description: strings.TrimSpace(pathRoleHelp["instance-bound-cidrs"][1]),
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleInstanceBoundCIDRUpdate,
				logical.ReadOperation:   b.pathRoleInstanceBoundCIDRRead,
				logical.DeleteOperation: b.pathRoleInstanceBoundCIDRDelete,
			},
			HelpSynopsis:    strings.TrimSpace(pathRoleHelp["instance-bound-cidrs"][0]),
			HelpDescription: strings.TrimSpace(pathRoleHelp["instance-bound-cidrs"][1]),
		},

		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/instance-max-age$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"instance_max_age": &framework.FieldSchema{
					Type: framework.TypeDurationSecond,
					Description: strings.TrimSpace(pathRoleHelp["instance-max-age"][1]),
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleInstanceMaxAgeUpdate,
				logical.ReadOperation:   b.pathRoleInstanceMaxAgeRead,
				logical.DeleteOperation: b.pathRoleInstanceMaxAgeDelete,
			},
			HelpSynopsis:    strings.TrimSpace(pathRoleHelp["instance-max-age"][0]),
			HelpDescription: strings.TrimSpace(pathRoleHelp["instance-max-age"][1]),
		},

		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/instance-allowed-tags$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"instance_allowed_tags": &framework.FieldSchema{
					Type: framework.TypeCommaStringSlice,
					Description: strings.TrimSpace(pathRoleHelp["instance-allowed-tags"][1]),
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleInstanceAllowedTagsUpdate,
				logical.ReadOperation:   b.pathRoleInstanceAllowedTagsRead,
				logical.DeleteOperation: b.pathRoleInstanceAllowedTagsDelete,
			},
			HelpSynopsis:    strings.TrimSpace(pathRoleHelp["instance-allowed-tags"][0]),
			HelpDescription: strings.TrimSpace(pathRoleHelp["instance-allowed-tags"][1]),
		},

		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/instance-allowed-pool-ids",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"instance_allowed_pool_ids": &framework.FieldSchema{
					Type: framework.TypeCommaStringSlice,
					Description: strings.TrimSpace(pathRoleHelp["instance-allowed-pool-ids"][1]),
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleInstanceAllowedPoolIDsUpdate,
				logical.ReadOperation:   b.pathRoleInstanceAllowedPoolIDsRead,
				logical.DeleteOperation: b.pathRoleInstanceAllowedPoolIDsDelete,
			},
			HelpSynopsis:    strings.TrimSpace(pathRoleHelp["instance-allowed-pool-ids"][0]),
			HelpDescription: strings.TrimSpace(pathRoleHelp["instance-allowed-pool-ids"][1]),
		},

		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/token-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"token_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: defTokenFields["token_ttl"].Description,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleTokenTTLUpdate,
				logical.ReadOperation:   b.pathRoleTokenTTLRead,
				logical.DeleteOperation: b.pathRoleTokenTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(pathRoleHelp["token-ttl"][0]),
			HelpDescription: strings.TrimSpace(pathRoleHelp["token-ttl"][1]),
		},

		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/token-max-ttl$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"token_max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: defTokenFields["token_max_ttl"].Description,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleTokenMaxTTLUpdate,
				logical.ReadOperation:   b.pathRoleTokenMaxTTLRead,
				logical.DeleteOperation: b.pathRoleTokenMaxTTLDelete,
			},
			HelpSynopsis:    strings.TrimSpace(pathRoleHelp["token-max-ttl"][0]),
			HelpDescription: strings.TrimSpace(pathRoleHelp["token-max-ttl"][1]),
		},

		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/token-num-uses$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"token_num_uses": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: defTokenFields["token_num_uses"].Description,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleTokenNumUsesUpdate,
				logical.ReadOperation:   b.pathRoleTokenNumUsesRead,
				logical.DeleteOperation: b.pathRoleTokenNumUsesDelete,
			},
			HelpSynopsis:    strings.TrimSpace(pathRoleHelp["token-num-uses"][0]),
			HelpDescription: strings.TrimSpace(pathRoleHelp["token-num-uses"][1]),
		},

		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/token-bound-cidrs$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"token_bound_cidrs": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: defTokenFields["token_bound_cidrs"].Description,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleTokenBoundCIDRUpdate,
				logical.ReadOperation:   b.pathRoleTokenBoundCIDRRead,
				logical.DeleteOperation: b.pathRoleTokenBoundCIDRDelete,
			},
			HelpSynopsis:    strings.TrimSpace(pathRoleHelp["token-bound-cidrs"][0]),
			HelpDescription: strings.TrimSpace(pathRoleHelp["token-bound-cidrs"][1]),
		},

		&framework.Path{
			Pattern: "role/" + framework.GenericNameRegex("role_name") + "/token-policies$",
			Fields: map[string]*framework.FieldSchema{
				"role_name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"token_policies": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: defTokenFields["token_policies"].Description,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathRoleTokenPoliciesUpdate,
				logical.ReadOperation:   b.pathRoleTokenPoliciesRead,
				logical.DeleteOperation: b.pathRoleTokenPoliciesDelete,
			},
			HelpSynopsis:    strings.TrimSpace(pathRoleHelp["token-policies"][0]),
			HelpDescription: strings.TrimSpace(pathRoleHelp["token-policies"][1]),
		},
	}
}


////////////////////////////////////////////////////////////////////////////////
// role(_name)
//

func (b *backend) roleLock(roleName string) *locksutil.LockEntry {
	return locksutil.LockForKey(b.roleLocks, strings.ToLower(roleName))
}

// Persist the role and creates an index from roleID to role name
func (b *backend) storeRole(ctx context.Context, s logical.Storage, roleName string, role *roleStorageEntry, previousRoleID string) error {
	if roleName == "" {
		return fmt.Errorf("missing role_name")
	}
	roleName := strings.ToLower(roleName)

	if role == nil {
		return fmt.Errorf("nil role")
	}

	// Check if role constraints are properly set
	if err := validateRoleConstraints(role); err != nil {
		return err
	}

	// Create a storage entry for the role
	entry, err := logical.StorageEntryJSON("role/"+roleName, role)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role %q", roleName)
	}

	// Check if the index from the role_id to role already exists
	roleIDIndex, err := b.RoleID(ctx, s, role.RoleID)
	if err != nil {
		return errwrap.Wrapf("failed to read role_id index: {{err}}", err)
	}

	// If the entry exists, make sure that it belongs to the current role
	if roleIDIndex != nil && roleIDIndex.Name != roleName {
		return fmt.Errorf("role_id already in use")
	}

	// When role_id is getting updated, delete the old index before
	// a new one is created
	if previousRoleID != "" && previousRoleID != role.RoleID {
		if err = b.deleteRoleID(ctx, s, previousRoleID); err != nil {
			return errwrap.Wrapf("failed to delete previous role ID index: {{err}}", err)
		}
	}

	// Save the role entry only after all the validations
	if err = s.Put(ctx, entry); err != nil {
		return err
	}

	// If previousRoleID is still intact, don't create another one
	if previousRoleID != "" && previousRoleID == role.RoleID {
		return nil
	}

	// Create a storage entry for reverse mapping of RoleID to role.
	// Note that secondary index is created when the roleLock is held.
	return b.storeRoleID(ctx, s, role.RoleID, &roleIDStorageEntry{
		Name: roleName,
	})
}

// Read the role from storage
func (b *backend) Role(ctx context.Context, s logical.Storage, roleName string) (*roleStorageEntry, error) {
	if roleName == "" {
		return nil, fmt.Errorf("missing role_name")
	}
	roleName := strings.ToLower(roleName)

	if entry, err := s.Get(ctx, "role/"+roleName); err != nil {
		return nil, err
	}
	else if entry == nil {
		return nil, nil
	}

	var role roleStorageEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}
	return &role, nil
}

// pathRoleExistenceCheck returns whether the role with the given name exists or not.
func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return false, fmt.Errorf("missing role_name")
	}
	roleName := strings.ToLower(roleName)

	lock := b.roleLock(roleName)
	lock.RLock()
	defer lock.RUnlock()

	role, err := b.Role(ctx, req.Storage, roleName)
	if err != nil {
		return false, err
	}

	return role != nil, nil
}

// pathRoleList is used to list all the Roles registered with the backend.
func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

// validateRoleConstraints checks if the role has at least one constraint
// enabled.
func validateRoleConstraints(role *roleStorageEntry) error {
	if role == nil {
		return fmt.Errorf("nil role")
	}

	// At least one constraint should be enabled on the role
	switch {
	case role.InstanceMatchIP:
	case len(role.InstanceBoundCIDRs) != 0:
	case len(role.InstanceAllowedTags) != 0:
	case len(role.InstanceAllowedPoolIDs) != 0:
	default:
		return fmt.Errorf("at least one Instance IP, Tag or Pool constraint should be enabled on the role")
	}

	return nil
}

// pathRoleCreateUpdate registers a new role with the backend or updates the options
// of an existing role
func (b *backend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}
	roleName := strings.ToLower(roleName)

	lock := b.roleLock(roleName)
	lock.Lock()
	defer lock.Unlock()

	// Check if the role already exists
	role, err := b.Role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}

	// Create a new entry object if this is a CreateOperation
	switch {
	case role == nil && req.Operation == logical.CreateOperation:
		role = &roleStorageEntry{
			name: roleName,
		}
	case role == nil:
		return logical.ErrorResponse(fmt.Sprintf("role name %q doesn't exist", roleName)), logical.ErrUnsupportedPath
	}

	var resp *logical.Response

	if err := role.ParseTokenFields(req, data); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	previousRoleID := role.RoleID
	if roleIDRaw, ok := data.GetOk("role_id"); ok {
		role.RoleID = roleIDRaw.(string)
	}
	else if req.Operation == logical.CreateOperation {
		roleID, err := uuid.GenerateUUID()
		if err != nil {
			return nil, errwrap.Wrapf("failed to generate role_id: {{err}}", err)
		}
		role.RoleID = roleID
	}
	if role.RoleID == "" {
		return logical.ErrorResponse("invalid role_id supplied, or failed to generate a role_id"), nil
	}

	if instanceMatchIPRaw, ok := data.GetOk("instance_match_ip"); ok {
		role.InstanceMatchIP = instanceMatchIPRaw.(bool)
	}
	else if req.Operation == logical.CreateOperation {
		role.InstanceMatchIP = data.Get("instance_match_ip").(bool)
	}

	if instanceBoundCIDRsRaw, ok := data.GetOk("instance_bound_cidrs"); ok {
		role.InstanceBoundCIDRs = instanceBoundCIDRsRaw.([]string)
	}
	if len(role.InstanceBoundCIDRs) != 0 {
		valid, err := cidrutil.ValidateCIDRListSlice(role.InstanceBoundCIDRs)
		if err != nil {
			return nil, errwrap.Wrapf("failed to validate CIDR blocks: {{err}}", err)
		}
		if !valid {
			return logical.ErrorResponse("invalid CIDR blocks"), nil
		}
	}

	if instanceMaxAgeRaw, ok := data.GetOk("instance_max_age"); ok {
		role.InstanceMaxAge = time.Second * time.Duration(instanceMaxAgeRaw.(int))
	}
	else if req.Operation == logical.CreateOperation {
		role.InstanceMaxAge = time.Second * time.Duration(data.Get("instance_max_age").(int))
	}

	if instanceAllowedTagsRaw, ok := data.GetOk("instance_allowed_tags"); ok {
		role.InstanceAllowedTags = instanceAllowedTagsRaw.([]string)
	}

	if instanceAllowedPoolIDsRaw, ok := data.GetOk("instance_allowed_tags"); ok {
		role.InstanceAllowedPoolIDs = instanceAllowedPoolIDsRaw.([]string)
	}

	if role.TokenMaxTTL > b.System().MaxLeaseTTL() {
		resp = &logical.Response{}
		resp.AddWarning("token_max_ttl is greater than the backend mount's maximum TTL value; issued tokens' max TTL value will be truncated")
	}

	if role.TokenPeriod > b.System().MaxLeaseTTL() {
		return logical.ErrorResponse(fmt.Sprintf("period of %q is greater than the backend's maximum lease TTL of %q", role.Period.String(), b.System().MaxLeaseTTL().String())), nil
	}

	// Store the entry.
	return resp, b.storeRole(ctx, req.Storage, role.name, role, previousRoleID)
}

// pathRoleRead grabs a read lock and reads the options set on the role from the storage
func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}
	roleName := strings.ToLower(roleName)

	lock := b.roleLock(roleName)
	lock.RLock()
	lockRelease := lock.RUnlock

	role, err := b.Role(ctx, req.Storage, roleName)
	if err != nil {
		lockRelease()
		return nil, err
	}

	if role == nil {
		lockRelease()
		return nil, nil
	}

	respData := map[string]interface{}{
		"instance_match_ip":         role.InstanceMatchIP,
		"instance_bound_cidrs":      role.InstanceBoundCIDRs,
		"instance_max_age":          role.InstanceMaxAge / time.Second,
		"instance_allowed_tags":     role.InstanceAllowedTags,
		"instance_allowed_pool_ids": role.InstanceAllowedPoolIDs,
	}
	role.PopulateTokenData(respData)

	resp := &logical.Response{
		Data: respData,
	}

	if err := validateRoleConstraints(role); err != nil {
		resp.AddWarning("Role does not have any constraints set on it. Updates to this role will require a constraint to be set")
	}

	// For sanity, verify that the index still exists. If the index is missing,
	// add one and return a warning so it can be reported.
	roleIDIndex, err := b.RoleID(ctx, req.Storage, role.RoleID)
	if err != nil {
		lockRelease()
		return nil, err
	}

	if roleIDIndex == nil {
		// Switch to a write lock
		lock.RUnlock()
		lock.Lock()
		lockRelease = lock.Unlock

		// Check again if the index is missing
		roleIDIndex, err = b.RoleID(ctx, req.Storage, role.RoleID)
		if err != nil {
			lockRelease()
			return nil, err
		}

		if roleIDIndex == nil {
			// Create a new index
			err = b.storeRoleID(ctx, req.Storage, role.RoleID, &roleIDStorageEntry{
				Name: role.name,
			})
			if err != nil {
				lockRelease()
				return nil, errwrap.Wrapf(fmt.Sprintf("failed to create secondary index for role_id %q: {{err}}", role.RoleID), err)
			}
			resp.AddWarning("Role identifier was missing an index back to role name. A new index has been added. Please report this observation.")
		}
	}

	lockRelease()

	return resp, nil
}

// pathRoleDelete removes the role from the storage
func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}
	roleName := strings.ToLower(roleName)

	lock := b.roleLock(roleName)
	lock.Lock()
	defer lock.Unlock()

	role, err := b.Role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	// Delete the reverse mapping from RoleID to the role
	if err = b.deleteRoleID(ctx, req.Storage, role.RoleID); err != nil {
		return nil, errwrap.Wrapf(fmt.Sprintf("failed to delete the mapping from RoleID to role %q: {{err}}", role.name), err)
	}

	// After deleting the RoleID, delete the role itself
	if err = req.Storage.Delete(ctx, "role/"+role.name); err != nil {
		return nil, err
	}

	return nil, nil
}


////////////////////////////////////////////////////////////////////////////////
// role_id
//

func (b *backend) roleIDLock(roleID string) *locksutil.LockEntry {
	return locksutil.LockForKey(b.roleIDLocks, roleID)
}

// Creates a storage entry that maps RoleID to Role
func (b *backend) storeRoleID(ctx context.Context, s logical.Storage, roleID string, roleIDEntry *roleIDStorageEntry) error {
	lock := b.roleIDLock(roleID)
	lock.Lock()
	defer lock.Unlock()

	salt, err := b.Salt(ctx)
	if err != nil {
		return err
	}
	entryIndex := "role_id/" + salt.SaltID(roleID)

	entry, err := logical.StorageEntryJSON(entryIndex, roleIDEntry)
	if err != nil {
		return err
	}
	if err = s.Put(ctx, entry); err != nil {
		return err
	}
	return nil
}

// Read the storage entry that maps RoleID to Role
func (b *backend) RoleID(ctx context.Context, s logical.Storage, roleID string) (*roleIDStorageEntry, error) {
	if roleID == "" {
		return nil, fmt.Errorf("missing role_id")
	}

	lock := b.roleIDLock(roleID)
	lock.RLock()
	defer lock.RUnlock()

	var result roleIDStorageEntry

	salt, err := b.Salt(ctx)
	if err != nil {
		return nil, err
	}
	entryIndex := "role_id/" + salt.SaltID(roleID)

	if entry, err := s.Get(ctx, entryIndex); err != nil {
		return nil, err
	}
	else if entry == nil {
		return nil, nil
	}
	else if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Remove the secondary index that maps the RoleID to the Role
func (b *backend) deleteRoleID(ctx context.Context, s logical.Storage, roleID string) error {
	if roleID == "" {
		return fmt.Errorf("missing role_id")
	}

	lock := b.roleIDLock(roleID)
	lock.Lock()
	defer lock.Unlock()

	salt, err := b.Salt(ctx)
	if err != nil {
		return err
	}
	entryIndex := "role_id/" + salt.SaltID(roleID)

	return s.Delete(ctx, entryIndex)
}

func (b *backend) pathRoleRoleIDUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}
	roleName := strings.ToLower(roleName)

	lock := b.roleLock(roleName)
	lock.Lock()
	defer lock.Unlock()

	role, err := b.Role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, logical.ErrUnsupportedPath
	}

	previousRoleID := role.RoleID
	role.RoleID = data.Get("role_id").(string)
	if role.RoleID == "" {
		return logical.ErrorResponse("missing role_id"), nil
	}

	return nil, b.storeRole(ctx, req.Storage, role.name, role, previousRoleID)
}

func (b *backend) pathRoleRoleIDRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldRead(ctx, req, data, "role_id")
}


////////////////////////////////////////////////////////////////////////////////
// instance_match_ip
//

func (b *backend) pathRoleInstanceMatchIPUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldUpdate(ctx, req, data, "instance_match_ip")
}

func (b *backend) pathRoleInstanceMatchIPRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldRead(ctx, req, data, "instance_match_ip")
}

func (b *backend) pathRoleInstanceMatchIPDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldDelete(ctx, req, data, "instance_match_ip")
}


////////////////////////////////////////////////////////////////////////////////
// instance_bound_cidrs
//

func (b *backend) pathRoleInstanceBoundCIDRsUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldUpdate(ctx, req, data, "instance_bound_cidrs")
}

func (b *backend) pathRoleInstanceBoundCIDRsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldRead(ctx, req, data, "instance_bound_cidrs")
}

func (b *backend) pathRoleInstanceBoundCIDRsDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldDelete(ctx, req, data, "instance_bound_cidrs")
}


////////////////////////////////////////////////////////////////////////////////
// instance_max_age
//

func (b *backend) pathRoleInstanceMaxAgeUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldUpdate(ctx, req, data, "instance_max_age")
}

func (b *backend) pathRoleInstanceMaxAgeRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldRead(ctx, req, data, "instance_max_age")
}

func (b *backend) pathRoleInstanceMaxAgeDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldDelete(ctx, req, data, "instance_max_age")
}


////////////////////////////////////////////////////////////////////////////////
// instance_allowed_tags
//

func (b *backend) pathRoleInstanceAllowedTagsUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldUpdate(ctx, req, data, "instance_allowed_tags")
}

func (b *backend) pathRoleInstanceAllowedTagsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldRead(ctx, req, data, "instance_allowed_tags")
}

func (b *backend) pathRoleInstanceAllowedTagsDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldDelete(ctx, req, data, "instance_allowed_tags")
}


////////////////////////////////////////////////////////////////////////////////
// instance_allowed_pool_ids
//

func (b *backend) pathRoleInstanceAllowedPoolIDsUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldUpdate(ctx, req, data, "instance_allowed_pool_ids")
}

func (b *backend) pathRoleInstanceAllowedPoolIDsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldRead(ctx, req, data, "instance_allowed_pool_ids")
}

func (b *backend) pathRoleInstanceAllowedPoolIDsDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldDelete(ctx, req, data, "instance_allowed_pool_ids")
}


////////////////////////////////////////////////////////////////////////////////
// token_ttl
//

func (b *backend) pathRoleTokenTTLUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldUpdate(ctx, req, data, "token_ttl")
}

func (b *backend) pathRoleTokenTTLRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldRead(ctx, req, data, "token_ttl")
}

func (b *backend) pathRoleTokenTTLDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldDelete(ctx, req, data, "token_ttl")
}


////////////////////////////////////////////////////////////////////////////////
// token_max_ttl
//

func (b *backend) pathRoleTokenMaxTTLUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldUpdate(ctx, req, data, "token_max_ttl")
}

func (b *backend) pathRoleTokenMaxTTLRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldRead(ctx, req, data, "token_max_ttl")
}

func (b *backend) pathRoleTokenMaxTTLDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldDelete(ctx, req, data, "token_max_ttl")
}


////////////////////////////////////////////////////////////////////////////////
// token_num_uses
//

func (b *backend) pathRoleTokenNumUsesUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldUpdate(ctx, req, data, "token_num_uses")
}

func (b *backend) pathRoleTokenNumUsesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldRead(ctx, req, data, "token_num_uses")
}

func (b *backend) pathRoleTokenNumUsesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldDelete(ctx, req, data, "token_num_uses")
}


////////////////////////////////////////////////////////////////////////////////
// token_period
//

func (b *backend) pathRoleTokenPeriodUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldUpdate(ctx, req, data, "token_period")
}

func (b *backend) pathRoleTokenPeriodRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldRead(ctx, req, data, "token_period")
}

func (b *backend) pathRoleTokenPeriodDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldDelete(ctx, req, data, "token_period")
}


////////////////////////////////////////////////////////////////////////////////
// token_bound_cidrs
//

func (b *backend) pathRoleTokenBoundCIDRsUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldUpdate(ctx, req, data, "token_bound_cidrs")
}

func (b *backend) pathRoleTokenBoundCIDRsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldRead(ctx, req, data, "token_bound_cidrs")
}

func (b *backend) pathRoleTokenBoundCIDRsDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldDelete(ctx, req, data, "token_bound_cidrs")
}


////////////////////////////////////////////////////////////////////////////////
// token_policies
//

func (b *backend) pathRoleTokenPoliciesUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldUpdate(ctx, req, data, "token_policies")
}

func (b *backend) pathRoleTokenPoliciesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldRead(ctx, req, data, "token_policies")
}

func (b *backend) pathRoleTokenPoliciesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathRoleFieldDelete(ctx, req, data, "token_policies")
}


////////////////////////////////////////////////////////////////////////////////
// *
//

func (b *backend) pathRoleFieldUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData, fieldName string) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}
	roleName := strings.ToLower(roleName)

	lock := b.roleLock(roleName)
	lock.Lock()
	defer lock.Unlock()

	role, err := b.Role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, logical.ErrUnsupportedPath
	}

	switch fieldName {
	case "instance_match_ip":
		if instanceMatchIPRaw, ok := data.GetOk("instance_match_ip"); ok {
			role.InstanceMatchIP = instanceMatchIPRaw.(bool)
		}
		else {
			return logical.ErrorResponse("missing instance_match_ip"), nil
		}
	case "instance_bound_cidrs":
		if instanceBoundCIDRsRaw, ok := data.GetOk("instance_bound_cidrs"); ok {
			cidrs, err := parseutil.ParseAddrs(instanceBoundCIDRsRaw.([]string))
			if err != nil {
				return logical.ErrorResponse(errwrap.Wrapf("failed to parse instance_bound_cidrs: {{err}}", err).Error()), nil
			}
			valid, err := cidrutil.ValidateCIDRListSlice(cidrs)
			if err != nil {
				return logical.ErrorResponse(errwrap.Wrapf("failed to validate CIDR blocks: {{err}}", err).Error()), nil
			}
			if !valid {
				return logical.ErrorResponse("failed to validate CIDR blocks"), nil
			}
			role.InstanceBoundCIDRs = cidrs
		}
		else {
			return logical.ErrorResponse("missing instance_bound_cidrs"), nil
		}
	case "instance_max_age":
		if instanceMaxAgeRaw, ok := data.GetOk("instance_max_age"); ok {
			role.InstanceMaxAge = time.Second * time.Duration(instanceMaxAgeRaw.(int))
		}
		else {
			return logical.ErrorResponse("missing instance_max_age"), nil
		}
	case "instance_allowed_tags":
		if instanceAllowedTagsRaw, ok := data.GetOk("instance_allowed_tags"); ok {
			keyValues, err := parseutil.ParseCommaStringSlice(instanceAllowedTagsRaw.([]string))
			if err != nil {
				return logical.ErrorResponse(errwrap.Wrapf("failed to parse instance_allowed_tags: {{err}}", err).Error()), nil
			}
			role.InstanceAllowedTags = keyValues
		}
		else {
			return logical.ErrorResponse("missing instance_allowed_tags"), nil
		}
	case "instance_allowed_pool_ids":
		// TODO
		if instanceAllowedPoolIDsRaw, ok := data.GetOk("instance_allowed_pool_ids"); ok {
			uuids, err := parseutil.ParseCommaStringSlice(instanceAllowedPoolIDsRaw.([]string))
			if err != nil {
				return logical.ErrorResponse(errwrap.Wrapf("failed to parse instance_allowed_pool_ids: {{err}}", err).Error()), nil
			}
			for _, uuid := range uuids {
				if _, err != uuid.ParseUUID(uuid); err != nil {
					return logical.ErrorResponse(errwrap.Wrapf("failed to validate UUID: {{err}}", err).Error()), nil
				}
			}
		}
		else {
			return logical.ErrorResponse("missing instance_allowed_pool_ids"), nil
		}
	case "token_ttl":
		if tokenTTLRaw, ok := data.GetOk("token_ttl"); ok {
			role.TokenTTL = time.Second * time.Duration(tokenTTLRaw.(int))
			if role.TokenMaxTTL > time.Duration(0) && role.TokenTTL > role.TokenMaxTTL {
				return logical.ErrorResponse("token_ttl should not be greater than token_max_ttl"), nil
			}
		}
		else {
			return logical.ErrorResponse("missing token_ttl"), nil
		}
	case "token_max_ttl":
		if tokenMaxTTLRaw, ok := data.GetOk("token_max_ttl"); ok {
			role.TokenMaxTTL = time.Second * time.Duration(tokenMaxTTLRaw.(int))
			if role.TokenMaxTTL > time.Duration(0) && role.TokenTTL > role.TokenMaxTTL {
				return logical.ErrorResponse("token_max_ttl should be greater than or equal to token_ttl"), nil
			}
		}
		else {
			return logical.ErrorResponse("missing token_max_ttl"), nil
		}
	case "token_num_uses":
		if tokenNumUsesRaw, ok := data.GetOk("token_num_uses"); ok {
			role.TokenNumUses = tokenNumUsesRaw.(int)
		}
		else {
			return logical.ErrorResponse("missing token_num_uses"), nil
		}
	case "token_period":
		if tokenPeriodRaw, ok := data.GetOk("token_period"); ok {
			role.TokenPeriod = time.Second * time.Duration(tokenPeriodRaw.(int))
			if role.TokenPeriod > b.System().MaxLeaseTTL() {
				return logical.ErrorResponse(fmt.Sprintf("period of %q is greater than the backend's maximum lease TTL of %q", role.Period.String(), b.System().MaxLeaseTTL().String())), nil
			}
		}
		else {
			return logical.ErrorResponse("missing period"), nil
		}
	case "token_bound_cidrs":
		if cidrsRaw, ok := data.GetOk("token_bound_cidrs"); ok {
			cidrs, err := parseutil.ParseAddrs(cidrsRaw.([]string))
			if err != nil {
				return logical.ErrorResponse(errwrap.Wrapf("failed to parse token_bound_cidrs: {{err}}", err).Error()), nil
			}
			valid, err := cidrutil.ValidateCIDRListSlice(cidrs)
			if err != nil {
				return logical.ErrorResponse(errwrap.Wrapf("failed to validate CIDR blocks: {{err}}", err).Error()), nil
			}
			if !valid {
				return logical.ErrorResponse("failed to validate CIDR blocks"), nil
			}
			role.TokenBoundCIDRs = cidrs
		}
		else {
			return logical.ErrorResponse("missing token_bound_cidrs"), nil
		}
	case "token_policies":
		if tokenPoliciesRaw, ok := data.GetOk("token_policies"); ok {
			role.TokenPolicies = policyutil.ParsePolicies(tokenPoliciesRaw)
		}
		else {
			return logical.ErrorResponse("missing token_policies"), nil
		}
	default:
		// shouldn't occur IRL
		return nil, errors.New("unrecognized field provided: " + fieldName)
	}

	return nil, b.storeRole(ctx, req.Storage, role.name, role, "")
}

func (b *backend) pathRoleFieldRead(ctx context.Context, req *logical.Request, data *framework.FieldData, fieldName string) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}
	roleName := strings.ToLower(roleName)

	lock := b.roleLock(roleName)
	lock.RLock()
	defer lock.RUnlock()

	role, err := b.Role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	switch fieldName {
	case "role_id":
		return &logical.Response{
			Data: map[string]interface{}{
				"role_id": role.RoleID,
			},
		}, nil
	case "instance_match_ip":
		return &logical.Response{
			Data: map[string]interface{}{
				"instance_match_ip": role.InstanceMatchIP,
			},
		}, nil
	case "instance_bound_cidrs":
		return &logical.Response{
			Data: map[string]interface{}{
				"instance_bound_cidrs": role.InstanceBoundCIDRs,
			},
		}, nil
	case "instance_max_age":
		return &logical.Response{
			Data: map[string]interface{}{
				"instance_max_age": role.InstanceMaxAge / time.Second,
			},
		}, nil
	case "instance_allowed_tags":
		return &logical.Response{
			Data: map[string]interface{}{
				"instance_allowed_tags": role.InstanceAllowedTags,
			},
		}, nil
	case "instance_allowed_pool_ids":
		return &logical.Response{
			Data: map[string]interface{}{
				"instance_allowed_pool_ids": role.InstanceAllowedPoolIDs,
			},
		}, nil
	case "token_ttl":
		return &logical.Response{
			Data: map[string]interface{}{
				"token_ttl": role.TokenTTL / time.Second,
			},
		}, nil
	case "token_max_ttl":
		return &logical.Response{
			Data: map[string]interface{}{
				"token_max_ttl": role.TokenMaxTTL / time.Second,
			},
		}, nil
	case "token_num_uses":
		return &logical.Response{
			Data: map[string]interface{}{
				"token_num_uses": role.TokenNumUses,
			},
		}, nil
	case "token_period":
		return &logical.Response{
			Data: map[string]interface{}{
				"token_period": role.TokenPeriod / time.Second,
			},
		}, nil
	case "token_bound_cidrs":
		return &logical.Response{
			Data: map[string]interface{}{
				"token_bound_cidrs": role.TokenBoundCIDRs,
			},
		}, nil
	case "token_policies":
		return &logical.Response{
			Data: map[string]interface{}{
				"token_period": role.TokenPolicies,
			},
		}, nil
	default:
		// shouldn't occur IRL
		return nil, errors.New("unrecognized field provided: " + fieldName)
	}
}

func (b *backend) pathRoleFieldDelete(ctx context.Context, req *logical.Request, data *framework.FieldData, fieldName string) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)
	if roleName == "" {
		return logical.ErrorResponse("missing role_name"), nil
	}
	roleName := strings.ToLower(roleName)

	lock := b.roleLock(roleName)
	lock.Lock()
	defer lock.Unlock()

	role, err := b.Role(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	switch fieldName {
	case "instance_match_ip":
		role.InstanceMatchIP = data.GetDefaultOrZero("instance_match_ip").(bool)
	case "instance_max_age":
		role.InstanceMaxAge = time.Second * time.Duration(data.GetDefaultOrZero("instance_max_age").(int))
	case "instance_bound_cidrs":
		role.InstanceBoundCIDRs = nil
	case "instance_allowed_tags":
		role.InstanceAllowedTags = nil
	case "instance_allowed_pool_ids":
		role.InstanceAllowedPoolIDs = nil
	case "token_ttl":
		role.TokenTTL = time.Second * time.Duration(data.GetDefaultOrZero("token_ttl").(int))
	case "token_max_ttl":
		role.TokenMaxTTL = time.Second * time.Duration(data.GetDefaultOrZero("token_max_ttl").(int))
	case "token_num_uses":
		role.TokenNumUses = data.GetDefaultOrZero("token_num_uses").(int)
	case "token_period":
		role.TokenPeriod = data.GetDefaultOrZero("token_period").(int)
	case "token_bound_cidrs":
		role.TokenBoundCIDRs = nil
	case "token_policies":
		role.TokenPolicies = nil
	default:
		// shouldn't occur IRL
		return nil, errors.New("unrecognized field provided: " + fieldName)
	}

	return nil, b.storeRole(ctx, req.Storage, role.name, role, "")
}
