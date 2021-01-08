package authExoscale

import (
	"context"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/helper/salt"
	"github.com/hashicorp/vault/sdk/logical"
)

const backendHelp = `
The Exoscale Authentication backend plugin allows authentication of
Exoscale Compute Instances.

Required credentials are the 'role_id' and 'instance_id'.
Refer to the Login documentation for further help.

Authorization is further controlled by 'instance_*' constraints.
Refer to the Role documentation for further help.
`

type backend struct {
	*framework.Backend

	// The provider - Exoscale API endpoint - for retrieving Compute Instances meta-data.
	provider      provider
	providerMutex sync.RWMutex

	// The salt value to be used by the information to be accessed only/ by this backend.
	salt      *salt.Salt
	saltMutex sync.RWMutex

	// The view to use when creating the salt
	view logical.Storage

	// Locks to make changes to role entries. These will be initialized to a
	// predefined number of locks when the backend is created, and will be
	// indexed based on salted role names.
	roleLocks []*locksutil.LockEntry

	// Locks to make changes to the storage entries of RoleIDs generated. These
	// will be initialized to a predefined number of locks when the backend is
	// created, and will be indexed based on the salted RoleIDs.
	roleIDLocks []*locksutil.LockEntry
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(conf)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend(conf *logical.BackendConfig) (*backend, error) {
	// Create a backend object
	b := &backend{
		view: conf.StorageView,

		// Create locks to modify the registered roles
		roleLocks: locksutil.CreateLocks(),

		// Create locks to modify the generated RoleIDs
		roleIDLocks: locksutil.CreateLocks(),
	}

	// Attach the paths and secrets that are to be handled by the backend
	b.Backend = &framework.Backend{
		BackendType:  logical.TypeCredential,
		Help:         backendHelp,
		Invalidate:   b.invalidate,
		AuthRenew:    b.pathLoginRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
			SealWrapStorage: []string{
				"config",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathLogin(b),
				pathConfig(b),
			},
			pathRole(b),
		),
	}
	return b, nil
}

// Return the salt used to hash the role IDs within the backend storage
func (b *backend) Salt(ctx context.Context) (*salt.Salt, error) {
	b.saltMutex.RLock()
	if b.salt != nil {
		defer b.saltMutex.RUnlock()
		return b.salt, nil
	}
	b.saltMutex.RUnlock()
	b.saltMutex.Lock()
	defer b.saltMutex.Unlock()
	if b.salt != nil {
		return b.salt, nil
	}
	salt, err := salt.NewSalt(ctx, b.view, &salt.Config{
		HashFunc: salt.SHA256Hash,
		Location: salt.DefaultLocation,
	})
	if err != nil {
		return nil, err
	}
	b.salt = salt
	return b.salt, nil
}

// Return the authentication provider
func (b *backend) Provider(config *configStorageEntry) (provider, error) {
	b.provider.RLock()
	unlockFunc := b.provider.RUnlock
	defer func() { unlockFunc() }()

	if b.provider != nil {
		return b.provider, nil
	}

	// Upgrade lock
	b.provider.RUnlock()
	b.provider.Lock()
	unlockFunc = b.provider.Unlock

	if b.provider != nil {
		return b.provider, nil
	}

	provider, err := newExoscaleProvider(config)  // TODO
	if err != nil {
		return nil, err
	}

	b.provider = provider
	return b.provider, nil
}

func (b *backend) invalidate(_ context.Context, key string) {
	switch key {
	case salt.DefaultLocation:
		b.saltMutex.Lock()
		defer b.saltMutex.Unlock()
		b.salt = nil
	case "config":
		b.reset()
	}
}

func (b *backend) reset() {
	b.provider.Lock()
	defer b.provider.Unlock()

	b.provider = nil
}
