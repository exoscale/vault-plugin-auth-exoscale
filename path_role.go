package exoscale

import (
	"context"
	"fmt"
	"time"

	"github.com/exoscale/egoscale"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

const (
	roleStoragePathPrefix = "role/"

	roleKeyName      = "name"
	roleKeyValidator = "validator"
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
	Validator string `json:"validator"`

	tokenutil.TokenParams
}

func buildProgram(expression string) (cel.Program, error) {
	env, err := cel.NewEnv(cel.Declarations(
		decls.NewVar("client_ip", decls.String),
		decls.NewVar("created", decls.Timestamp),
		decls.NewVar("id", decls.String),
		decls.NewVar("manager", decls.String),
		decls.NewVar("manager_id", decls.String),
		decls.NewVar("name", decls.String),
		decls.NewVar("now", decls.Timestamp),
		decls.NewVar("public_ip", decls.String),
		decls.NewVar("security_group_names", decls.NewListType(decls.String)),
		decls.NewVar("security_group_ids", decls.NewListType(decls.String)),
		decls.NewVar("tags", decls.NewMapType(decls.String, decls.String)),
		decls.NewVar("zone", decls.String),
		decls.NewVar("zone_id", decls.String),
	))
	if err != nil {
		return nil, err
	}

	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("type-check error: %w", issues.Err())
	}
	if ast.ResultType().String() != "primitive:BOOL" {
		return nil, fmt.Errorf("bad expression: result type should be boolean")
	}
	p, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (r *backendRole) checkInstance(req *logical.Request, instance *egoscale.VirtualMachine) error {
	p, err := buildProgram(r.Validator)
	if err != nil {
		return err
	}

	tags := make(map[string]string)
	for _, t := range instance.Tags {
		tags[t.Key] = t.Value
	}

	created, _ := time.Parse("2006-01-02T15:04:05-0700", instance.Created)
	var ipaddress string
	for _, n := range instance.Nic {
		if n.IsDefault {
			ipaddress = n.IPAddress.String()
			break
		}
	}
	sgNames := make([]string, 0)
	sgIDs := make([]string, 0)
	for _, sg := range instance.SecurityGroup {
		sgNames = append(sgNames, sg.Name)
		sgIDs = append(sgIDs, sg.ID.String())
	}
	var managerid string
	if instance.ManagerID != nil {
		managerid = instance.ManagerID.String()
	}
	evalContext := map[string]interface{}{
		"client_ip":            req.Connection.RemoteAddr,
		"created":              created,
		"id":                   instance.ID.String(),
		"manager":              instance.Manager,
		"manager_id":           managerid,
		"name":                 instance.Name,
		"now":                  time.Now(),
		"public_ip":            ipaddress,
		"security_group_names": sgNames,
		"security_group_ids":   sgIDs,
		"tags":                 tags,
		"zone":                 instance.ZoneName,
		"zone_id":              instance.ZoneID,
	}
	result, _, err := p.Eval(evalContext)
	if err != nil {
		return err
	}

	success := result.Value().(bool)
	if !success {
		return fmt.Errorf("failed validation")
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
			roleKeyValidator: {
				Type:        framework.TypeString,
				Description: "Validation expression in CEL",
				Default:     "client_ip == public_ip",
				Required:    true,
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
		roleKeyValidator: role.Validator,
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

	if v, ok := data.GetOk(roleKeyValidator); ok {
		role.Validator = v.(string)
		_, err := buildProgram(role.Validator)
		if err != nil {
			return nil, err
		}
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
