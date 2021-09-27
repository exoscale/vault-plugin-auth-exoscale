package exoscale

import (
	"context"
	"net/http"
	"testing"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/suite"
)

type backendTestSuite struct {
	backend logical.Backend
	storage logical.Storage

	suite.Suite
}

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

	backendConfigEntry, err := logical.StorageEntryJSON(configStoragePath, backendConfig{
		APIEndpoint: testConfigAPIEndpoint,
		APIKey:      testConfigAPIKey,
		APISecret:   testConfigAPISecret,
	})
	if err != nil {
		ts.FailNow("unable to JSON-encode backend config entry", err)
	}
	if err := config.StorageView.Put(context.Background(), backendConfigEntry); err != nil {
		ts.FailNow("unable to store backend config entry", err)
	}

	backend, err := Factory(context.Background(), config)
	if err != nil {
		ts.T().Fatal(err)
	}

	exo := egoscale.NewClient(
		testConfigAPIEndpoint,
		testConfigAPIKey,
		testConfigAPISecret)

	httpmock.ActivateNonDefault(exo.HTTPClient)

	ts.mockListZonesAPI([]egoscale.Zone{{
		Name: testZoneName,
		ID:   egoscale.MustParseUUID(testZoneID),
	}})

	backend.(*exoscaleBackend).exo = exo

	ts.backend = backend
	ts.storage = config.StorageView
}

func (ts *backendTestSuite) TearDownTest() {
	ts.backend = nil
	ts.storage = nil

	httpmock.DeactivateAndReset()
}

func (ts *backendTestSuite) mockListZonesAPI(res []egoscale.Zone) {
	httpmock.RegisterResponder("GET",
		"=~/v1.*command=listZones.*",
		func(req *http.Request) (*http.Response, error) {
			resp, err := httpmock.NewJsonResponse(http.StatusOK, struct {
				ListZoneResponse egoscale.ListZonesResponse `json:"listzonesresponse"`
			}{
				egoscale.ListZonesResponse{
					Count: len(res),
					Zone:  res,
				},
			})

			ts.Require().NoError(err)
			return resp, nil
		})
}

func (ts *backendTestSuite) mockListVirtualMachinesAPI(res []egoscale.VirtualMachine) {
	httpmock.RegisterResponder("GET",
		"=~/v1.*command=listVirtualMachines.*",
		func(req *http.Request) (*http.Response, error) {
			resp, err := httpmock.NewJsonResponse(http.StatusOK, struct {
				ListVirtualMachinesResponse egoscale.ListVirtualMachinesResponse `json:"listvirtualmachinesresponse"`
			}{
				egoscale.ListVirtualMachinesResponse{
					Count:          len(res),
					VirtualMachine: res,
				},
			})

			ts.Require().NoError(err)
			return resp, nil
		})
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
				ts.storeEntry(roleStoragePathPrefix+testRoleName, testRole)
				ts.mockListVirtualMachinesAPI([]egoscale.VirtualMachine{})
			},
			resCheckFunc: func(ts *backendTestSuite, res *logical.Response, err error) {
				ts.Require().EqualError(err, logical.ErrPermissionDenied.Error())
			},
			internalData: map[string]interface{}{
				"instance_id": testInstanceID,
				"role":        testRoleName,
				"zone":        testZoneName,
			},
			wantErr: true,
		},
		{
			name: "ok",
			setupFunc: func(ts *backendTestSuite) {
				ts.storeEntry(roleStoragePathPrefix+testRoleName, testRole)
				ts.mockListVirtualMachinesAPI([]egoscale.VirtualMachine{{
					Name:      testInstanceName,
					Created:   testInstanceCreated,
					ID:        egoscale.MustParseUUID(testInstanceID),
					ZoneName:  testZoneName,
					ZoneID:    egoscale.MustParseUUID(testZoneID),
					Manager:   "instancepool",
					ManagerID: egoscale.MustParseUUID(testInstancePoolID),
					Nic:       []egoscale.Nic{{IPAddress: testInstanceIPAddress, IsDefault: true}},
				}})
			},
			resCheckFunc: func(ts *backendTestSuite, res *logical.Response, _ error) {
				ts.Require().Equal(
					map[string]interface{}{
						"instance_id": testInstanceID,
						"role":        testRoleName,
						"zone":        testZoneName,
					},
					res.Auth.InternalData)
			},
			internalData: map[string]interface{}{
				"instance_id": testInstanceID,
				"role":        testRoleName,
				"zone":        testZoneName,
			},
		},
	}

	for _, tt := range tests {
		httpmock.Reset()

		ts.T().Run(tt.name, func(t *testing.T) {
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

func TestSuiteAccBackendTestSuite(t *testing.T) {
	suite.Run(t, new(backendTestSuite))
}
