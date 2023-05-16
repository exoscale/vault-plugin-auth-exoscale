package exoscale

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	egoscale "github.com/exoscale/egoscale/v2"
	exoapi "github.com/exoscale/egoscale/v2/api"
)

type backendTestSuite struct {
	backend logical.Backend
	storage logical.Storage

	suite.Suite
}

var testSeededRand = rand.New(rand.NewSource(time.Now().UnixNano()))

func (ts *backendTestSuite) storeEntry(k string, v interface{}) {
	entry, err := logical.StorageEntryJSON(k, v)
	if err != nil {
		ts.FailNow("unable to JSON-encode entry", err)
	}

	if err := ts.storage.Put(context.Background(), entry); err != nil {
		ts.FailNow("unable to store entry", err)
	}
}

func (ts *backendTestSuite) SetupTest() {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	config.Logger = hclog.NewNullLogger()

	backend, err := Factory(context.Background(), config)
	if err != nil {
		ts.T().Fatal(err)
	}
	backend.(*exoscaleBackend).exo = new(exoscaleClientMock)

	ts.backend = backend
	ts.storage = config.StorageView
}

func (ts *backendTestSuite) TearDownTest() {
	ts.backend = nil
	ts.storage = nil
}

func (ts *backendTestSuite) TestBackendAuthRenew() {
	tests := []struct {
		name         string
		setupFunc    func(*backendTestSuite)
		resCheckFunc func(*backendTestSuite, *logical.Response, error)
		internalData map[string]interface{}
		wantErr      bool
	}{
		{
			name: "fail_permission_denied",
			setupFunc: func(ts *backendTestSuite) {
				ts.backend.(*exoscaleBackend).exo.(*exoscaleClientMock).
					On("GetInstance", mock.Anything, testZone, testInstanceID).
					Return(new(egoscale.Instance), exoapi.ErrNotFound)
			},
			resCheckFunc: func(ts *backendTestSuite, res *logical.Response, err error) {
				ts.Require().EqualError(err, logical.ErrPermissionDenied.Error())
			},
			internalData: map[string]interface{}{
				"instance_id": testInstanceID,
				"role":        testRoleName,
				"zone":        testZone,
			},
			wantErr: true,
		},
		{
			name: "ok",
			setupFunc: func(ts *backendTestSuite) {
				ts.backend.(*exoscaleBackend).exo.(*exoscaleClientMock).
					On("GetInstance", mock.Anything, testZone, testInstanceID).
					Return(&egoscale.Instance{
						CreatedAt:      &testInstanceCreated,
						ID:             &testInstanceID,
						InstanceTypeID: &testInstanceTypeID,
						Labels:         &testInstanceLabels,
						Manager: &egoscale.InstanceManager{
							ID:   testInstancePoolID,
							Type: "instance-pool",
						},
						Name:             &testInstanceName,
						PublicIPAddress:  &testInstanceIPAddress,
						SecurityGroupIDs: &[]string{testInstanceSecurityGroupID},
						State:            &testInstanceState,
						TemplateID:       &testInstanceTemplateID,
						Zone:             &testZone,
					}, nil)

				ts.backend.(*exoscaleBackend).exo.(*exoscaleClientMock).
					On("GetInstancePool", mock.Anything, testZone, testInstancePoolID).
					Return(&egoscale.InstancePool{
						ElasticIPIDs:   nil,
						ID:             &testInstancePoolID,
						InstanceIDs:    &[]string{testInstanceID},
						InstanceTypeID: &testInstanceTypeID,
						Name:           &testInstancePoolName,
						State:          &testInstanceState,
						TemplateID:     &testInstanceTemplateID,
						Zone:           &testZone,
					}, nil)

				ts.backend.(*exoscaleBackend).exo.(*exoscaleClientMock).
					On("GetSecurityGroup", mock.Anything, testZone, testInstanceSecurityGroupID).
					Return(&egoscale.SecurityGroup{
						ID:   &testInstanceSecurityGroupID,
						Name: &testInstanceSecurityGroupName,
					}, nil)
			},
			resCheckFunc: func(ts *backendTestSuite, res *logical.Response, _ error) {
				ts.Require().Equal(
					map[string]interface{}{
						"instance_id": testInstanceID,
						"role":        testRoleName,
						"zone":        testZone,
					},
					res.Auth.InternalData)
			},
			internalData: map[string]interface{}{
				"instance_id": testInstanceID,
				"role":        testRoleName,
				"zone":        testZone,
			},
		},
	}

	for _, tt := range tests {
		ts.T().Run(tt.name, func(t *testing.T) {
			// Reset the Exoscale client mock calls stack between test cases
			ts.backend.(*exoscaleBackend).exo.(*exoscaleClientMock).ExpectedCalls = nil

			ts.storeEntry(configStoragePath, &backendConfig{Zone: testZone})
			ts.storeEntry(roleStoragePathPrefix+testRoleName, testRole)

			if setup := tt.setupFunc; setup != nil {
				setup(ts)
			}

			res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
				Storage:    ts.storage,
				Operation:  logical.RenewOperation,
				Connection: &logical.Connection{RemoteAddr: testInstanceIPAddress.String()},
				Auth: &logical.Auth{
					InternalData: tt.internalData,
				},
			})
			if err != nil != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			tt.resCheckFunc(ts, res, err)
		})
	}
}

func (ts *backendTestSuite) randomID() string {
	id, err := uuid.NewV4()
	if err != nil {
		ts.T().Fatalf("unable to generate a new UUID: %s", err)
	}
	return id.String()
}

func (ts *backendTestSuite) randomStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[testSeededRand.Intn(len(charset))]
	}
	return string(b)
}

func (ts *backendTestSuite) randomString(length int) string {
	const defaultCharset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	return ts.randomStringWithCharset(length, defaultCharset)
}

func TestSuiteAccBackendTestSuite(t *testing.T) {
	suite.Run(t, new(backendTestSuite))
}
