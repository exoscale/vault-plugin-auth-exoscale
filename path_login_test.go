package exoscale

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	egoscale "github.com/exoscale/egoscale/v2"
	exoapi "github.com/exoscale/egoscale/v2/api"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/mock"
)

var (
	testInstanceCreated           = time.Now().Add(-time.Minute)
	testInstanceID                = new(backendTestSuite).randomID()
	testInstanceIPAddress         = net.ParseIP("1.2.3.4")
	testInstanceLabels            = map[string]string{"k1": "v1", "k2": "v2"}
	testInstanceName              = new(backendTestSuite).randomString(10)
	testInstancePoolID            = new(backendTestSuite).randomID()
	testInstancePoolName          = new(backendTestSuite).randomString(10)
	testInstanceSecurityGroupID   = new(backendTestSuite).randomID()
	testInstanceSecurityGroupName = new(backendTestSuite).randomString(10)
	testInstanceState             = "running"
	testInstanceTemplateID        = new(backendTestSuite).randomID()
	testInstanceTypeID            = new(backendTestSuite).randomID()
	testZone                      = "ch-gva-2"
)

func (ts *backendTestSuite) TestPathLogin() {
	tests := []struct {
		name         string
		setupFunc    func(*backendTestSuite)
		resCheckFunc func(*backendTestSuite, *logical.Response, error)
		reqData      map[string]interface{}
		wantErr      bool
	}{
		{
			name:    "fail_missing_field",
			reqData: map[string]interface{}{},
			setupFunc: func(ts *backendTestSuite) {
				ts.storeEntry(configStoragePath, &backendConfig{Zone: testZone})
			},
			resCheckFunc: func(ts *backendTestSuite, res *logical.Response, _ error) {
				ts.Require().True(strings.Contains(res.Error().Error(), errMissingField.Error()))
			},
		},
		{
			name: "fail_permission_denied",
			setupFunc: func(ts *backendTestSuite) {
				ts.storeEntry(configStoragePath, backendConfig{Zone: testZone})

				ts.backend.(*exoscaleBackend).exo.(*exoscaleClientMock).
					On("GetInstance", mock.Anything, testZone, testInstanceID).
					Return(new(egoscale.Instance), exoapi.ErrNotFound)
			},
			resCheckFunc: func(ts *backendTestSuite, response *logical.Response, err error) {
				ts.Require().EqualError(err, logical.ErrPermissionDenied.Error())
			},
			reqData: map[string]interface{}{
				authLoginParamInstance: testInstanceID,
				authLoginParamRole:     testRoleName,
			},
			wantErr: true,
		},
		{
			name: "ok",
			setupFunc: func(ts *backendTestSuite) {
				ts.storeEntry(configStoragePath, &backendConfig{Zone: testZone})

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
			resCheckFunc: func(ts *backendTestSuite, res *logical.Response, err error) {
				ts.Require().NoError(err)
				ts.Require().Equal(map[string]interface{}{
					"instance_id": testInstanceID,
					"role":        testRoleName,
					"zone":        testZone,
				}, res.Auth.InternalData)
			},
			reqData: map[string]interface{}{
				authLoginParamInstance: testInstanceID,
				authLoginParamRole:     testRoleName,
			},
		},
		{
			name: "ok_approle_mode",
			setupFunc: func(ts *backendTestSuite) {
				ts.storeEntry(configStoragePath, backendConfig{
					AppRoleMode: true,
					Zone:        testZone,
				})

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
				ts.Require().Equal(map[string]interface{}{
					"instance_id": testInstanceID,
					"role":        testRoleName,
					"zone":        testZone,
				}, res.Auth.InternalData)
			},
			reqData: map[string]interface{}{
				authLoginParamRoleID:   testRoleName,
				authLoginParamSecretID: testInstanceID,
			},
		},
	}

	ts.storeEntry(roleStoragePathPrefix+testRoleName, backendRole{
		Validator: fmt.Sprintf(
			`client_ip == instance_public_ip && `+
				`instance_created > now - duration("10m") && `+
				`instance_id == "%s" && `+
				`instance_manager_id == "%s" && `+
				`instance_manager_name == "%s" && `+
				`"%s" in instance_security_group_ids && `+
				`"%s" in instance_security_group_names && `+
				`instance_labels == {%s} && `+
				`instance_zone == "%s"`,
			testInstanceID,
			testInstancePoolID,
			testInstancePoolName,
			testInstanceSecurityGroupID,
			testInstanceSecurityGroupName,
			func() string {
				tags := make([]string, 0)
				for k, v := range testInstanceLabels {
					tags = append(tags, fmt.Sprintf("%q:%q", k, v))
				}
				return strings.Join(tags, ",")
			}(),
			testZone,
		),
	})

	for _, tt := range tests {
		// Reset the Exoscale client mock calls stack between test cases
		ts.backend.(*exoscaleBackend).exo.(*exoscaleClientMock).ExpectedCalls = nil

		ts.T().Run(tt.name, func(t *testing.T) {
			if setup := tt.setupFunc; setup != nil {
				setup(ts)
			}

			res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
				Storage:    ts.storage,
				Operation:  logical.UpdateOperation,
				Path:       "login",
				Connection: &logical.Connection{RemoteAddr: testInstanceIPAddress.String()},
				Data:       tt.reqData,
			})
			if err != nil != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			tt.resCheckFunc(ts, res, err)
		})
	}
}
