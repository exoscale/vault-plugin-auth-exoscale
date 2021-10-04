package exoscale

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	egoscale "github.com/exoscale/egoscale/v2"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	roleStoragePathPrefix = "role/"

	roleKeyName      = "name"
	roleKeyValidator = "validator"

	roleValidatorVarClientIP                   = "client_ip"
	roleValidatorVarInstanceCreated            = "instance_created"
	roleValidatorVarInstanceID                 = "instance_id"
	roleValidatorVarInstanceManager            = "instance_manager"
	roleValidatorVarInstanceManagerID          = "instance_manager_id"
	roleValidatorVarInstanceManagerName        = "instance_manager_name"
	roleValidatorVarInstanceName               = "instance_name"
	roleValidatorVarInstancePublicIP           = "instance_public_ip"
	roleValidatorVarInstanceSecurityGroupIDs   = "instance_security_group_ids"
	roleValidatorVarInstanceSecurityGroupNames = "instance_security_group_names"
	roleValidatorVarInstanceLabels             = "instance_labels"
	roleValidatorVarInstanceZone               = "instance_zone"
	roleValidatorVarNow                        = "now"

	defaultRoleValidator = roleValidatorVarClientIP + " == " + roleValidatorVarInstancePublicIP
)

var (
	roleValidatorsVars = map[string]string{
		roleValidatorVarClientIP:                   "IP address of the Vault client (string)",
		roleValidatorVarInstanceCreated:            "creation date of the instance (timestamp)",
		roleValidatorVarInstanceID:                 "ID of the instance (string)",
		roleValidatorVarInstanceManager:            "type of the instance manager, if any (string)",
		roleValidatorVarInstanceManagerID:          "ID of the instance manager, if any (string)",
		roleValidatorVarInstanceManagerName:        "name of the instance manager, if any (string)",
		roleValidatorVarInstanceName:               "name of the instance (string)",
		roleValidatorVarInstancePublicIP:           "public IPv4 address of the instance (string)",
		roleValidatorVarInstanceSecurityGroupIDs:   "list of Security Group IDs the instance belongs to (list of strings)",
		roleValidatorVarInstanceSecurityGroupNames: "list of Security Group names the instance belongs to (list of strings)",
		roleValidatorVarInstanceLabels:             "map of instance labels (map[string]string)",
		roleValidatorVarInstanceZone:               "name of the instance's zone (string)",
		roleValidatorVarNow:                        "current timestamp (timestamp)",
	}

	pathListRolesHelpSyn  = "List the configured backend roles"
	pathListRolesHelpDesc = `
This endpoint returns a list of configured backend roles.
`

	pathRoleHelpSyn  = "Manage backend roles"
	pathRoleHelpDesc = fmt.Sprintf(`
This endpoint manages backend roles, which are used to determine how Vault
clients running on Exoscale Compute instances must be authenticated by the
exoscale auth method.

When creating a role, the validator CEL[0] expression can contain the following
variables:

%s

If no validation expression is provided during the creation of a role, the
following expression is set by default:

  %s

[0]: https://github.com/google/cel-spec
`, func() string {
		var (
			vars = make([]string, 0)
			out  strings.Builder
		)

		for k := range roleValidatorsVars {
			vars = append(vars, k)
		}
		sort.Strings(vars)
		for _, v := range vars {
			_, _ = fmt.Fprintf(&out, "  * %s: %s\n", v, roleValidatorsVars[v])
		}

		return out.String()
	}(),
		defaultRoleValidator,
	)
)

type backendRole struct {
	Validator string `json:"validator"`

	tokenutil.TokenParams
}

func (b *exoscaleBackend) checkInstanceRole(
	ctx context.Context,
	req *logical.Request,
	instance *egoscale.Instance,
	role *backendRole,
) error {
	p, err := buildCELProgram(role.Validator)
	if err != nil {
		return err
	}

	labels := make(map[string]string)
	if instance.Labels != nil {
		for k, v := range *instance.Labels {
			labels[k] = v
		}
	}

	var managerType, managerID, managerName string
	if instance.Manager != nil {
		managerType = instance.Manager.Type
		managerID = instance.Manager.ID
		switch instance.Manager.Type {
		case "instance-pool":
			instancePool, err := b.exo.GetInstancePool(ctx, *instance.Zone, managerID)
			if err != nil {
				return fmt.Errorf("unable to retrieve Instance Pool %q: %w", managerID, err)
			}
			managerName = *instancePool.Name

		default:
		}
	}

	sgNames := make([]string, 0)
	sgIDs := make([]string, 0)
	if instance.SecurityGroupIDs != nil {
		for _, id := range *instance.SecurityGroupIDs {
			sg, err := b.exo.GetSecurityGroup(ctx, *instance.Zone, id)
			if err != nil {
				return fmt.Errorf("unable to retrieve Security Group %q: %w", id, err)
			}
			sgIDs = append(sgIDs, *sg.ID)
			sgNames = append(sgNames, *sg.Name)
		}
	}

	evalContext := map[string]interface{}{
		roleValidatorVarClientIP:                   req.Connection.RemoteAddr,
		roleValidatorVarInstanceCreated:            *instance.CreatedAt,
		roleValidatorVarInstanceID:                 *instance.ID,
		roleValidatorVarInstanceManager:            managerType,
		roleValidatorVarInstanceManagerID:          managerID,
		roleValidatorVarInstanceManagerName:        managerName,
		roleValidatorVarInstanceName:               instance.Name,
		roleValidatorVarInstancePublicIP:           instance.PublicIPAddress.String(),
		roleValidatorVarInstanceSecurityGroupIDs:   sgIDs,
		roleValidatorVarInstanceSecurityGroupNames: sgNames,
		roleValidatorVarInstanceLabels:             labels,
		roleValidatorVarInstanceZone:               instance.Zone,
		roleValidatorVarNow:                        time.Now(),
	}

	result, _, err := p.Eval(evalContext)
	if err != nil {
		return err
	}

	if success := result.Value().(bool); !success {
		return fmt.Errorf("%w: role validation failed", errAuthFailed)
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
				Default:     defaultRoleValidator,
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
		return nil, fmt.Errorf("unable to retrieve role %q: %w", name, err)
	}
	if entry == nil {
		return nil, nil
	}

	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	return &role, nil
}

func (b *exoscaleBackend) listRoles(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, roleStoragePathPrefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(roles), nil
}

func (b *exoscaleBackend) readRole(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
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

func (b *exoscaleBackend) writeRole(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name := data.Get("name").(string)

	role, err := b.roleConfig(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &backendRole{}
	}

	role.Validator = data.Get(roleKeyValidator).(string)
	if _, err = buildCELProgram(role.Validator); err != nil {
		if errors.Is(err, errInvalidFieldValue) {
			return logical.ErrorResponse(err.Error()), nil
		}
		return nil, err
	}

	b.Logger().Debug(
		fmt.Sprintf("creating role %q", name),
		"validator", role.Validator,
	)

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

func (b *exoscaleBackend) deleteRole(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData,
) (*logical.Response, error) {
	name := data.Get("name").(string)
	if err := req.Storage.Delete(ctx, roleStoragePathPrefix+name); err != nil {
		return nil, err
	}

	return nil, nil
}

func buildCELProgram(expression string) (cel.Program, error) {
	env, err := cel.NewEnv(cel.Declarations(
		decls.NewVar(roleValidatorVarClientIP, decls.String),
		decls.NewVar(roleValidatorVarInstanceCreated, decls.Timestamp),
		decls.NewVar(roleValidatorVarInstanceID, decls.String),
		decls.NewVar(roleValidatorVarInstanceManager, decls.String),
		decls.NewVar(roleValidatorVarInstanceManagerID, decls.String),
		decls.NewVar(roleValidatorVarInstanceManagerName, decls.String),
		decls.NewVar(roleValidatorVarInstanceName, decls.String),
		decls.NewVar(roleValidatorVarInstancePublicIP, decls.String),
		decls.NewVar(roleValidatorVarInstanceSecurityGroupIDs, decls.NewListType(decls.String)),
		decls.NewVar(roleValidatorVarInstanceSecurityGroupNames, decls.NewListType(decls.String)),
		decls.NewVar(roleValidatorVarInstanceLabels, decls.NewMapType(decls.String, decls.String)),
		decls.NewVar(roleValidatorVarInstanceZone, decls.String),
		decls.NewVar(roleValidatorVarNow, decls.Timestamp),
	))
	if err != nil {
		return nil, err
	}

	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("%w: %s: %s", errInvalidFieldValue, "validator", issues.Err()) // nolint:errorlint
	}
	if ast.ResultType().String() != "primitive:BOOL" {
		return nil, fmt.Errorf("bad expression: result type should be boolean")
	}

	p, err := env.Program(ast,
		cel.EvalOptions(cel.OptExhaustiveEval, cel.OptPartialEval))
	if err != nil {
		return nil, err
	}

	return p, nil
}
