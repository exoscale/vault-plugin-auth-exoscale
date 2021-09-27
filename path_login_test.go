package exoscale

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/jarcoal/httpmock"
)

var (
	testZoneName                       = "ch-gva-2"
	testZoneID                         = "1128bd56-b4d9-4ac6-a7b9-c715b187ce11"
	testInstanceName                   = "test-instance"
	testInstanceID                     = "288e37eb-1d66-4634-88aa-8dc87a9e484d"
	testInstanceCreated                = time.Now().Add(-time.Minute).Format("2006-01-02T15:04:05-0700")
	testInstancePoolID                 = "74bb6f3d-f43a-4038-a1b9-5a6779aa37f3"
	testInstanceSecurityGroupName      = "test-sg"
	testInstanceSecurityGroupID        = "2ded49f6-1221-4d70-bc23-aafad5404fe9"
	testInstanceDefaultSecurityGroupID = "80fe7557-9100-4875-964c-a7c3db93a1e2"
	testInstanceIPAddress              = net.ParseIP("1.2.3.4")
	testInstanceTags                   = map[string]string{
		"k1": "v1",
		"k2": "v2",
	}
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
			resCheckFunc: func(ts *backendTestSuite, res *logical.Response, _ error) {
				ts.Require().True(strings.Contains(res.Error().Error(), errMissingField.Error()))
			},
		},
		{
			name: "fail_permission_denied",
			setupFunc: func(ts *backendTestSuite) {
				ts.storeEntry(configStoragePath, backendConfig{
					Zone: testZoneName,
				})

				ts.mockListVirtualMachinesAPI([]egoscale.VirtualMachine{})
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
				ts.storeEntry(roleStoragePathPrefix+testRoleName, backendRole{
					Validator: fmt.Sprintf(
						`client_ip == instance_public_ip && `+
							`instance_manager_id == "%s" && `+
							`instance_created > now - duration("10m") && `+
							`"%s" in instance_security_group_ids && `+
							`"default" in instance_security_group_names && `+
							`instance_tags == {%s} && `+
							`instance_zone_id == "%s" && `+
							`instance_zone_name == "%s"`,
						testInstancePoolID,
						testInstanceSecurityGroupID,
						func() string {
							tags := make([]string, 0)
							for k, v := range testInstanceTags {
								tags = append(tags, fmt.Sprintf("%q:%q", k, v))
							}
							return strings.Join(tags, ",")
						}(),
						testZoneID,
						testZoneName,
					),
				})

				ts.mockListVirtualMachinesAPI([]egoscale.VirtualMachine{{
					Name:      testInstanceName,
					Created:   testInstanceCreated,
					ID:        egoscale.MustParseUUID(testInstanceID),
					ZoneName:  testZoneName,
					ZoneID:    egoscale.MustParseUUID(testZoneID),
					ManagerID: egoscale.MustParseUUID(testInstancePoolID),
					Nic:       []egoscale.Nic{{IPAddress: testInstanceIPAddress, IsDefault: true}},
					SecurityGroup: []egoscale.SecurityGroup{
						{
							ID:   egoscale.MustParseUUID(testInstanceDefaultSecurityGroupID),
							Name: "default",
						},
						{
							ID:   egoscale.MustParseUUID(testInstanceSecurityGroupID),
							Name: testInstanceSecurityGroupName,
						},
					},
					Tags: func() []egoscale.ResourceTag {
						tags := make([]egoscale.ResourceTag, 0)
						for k, v := range testInstanceTags {
							tags = append(tags, egoscale.ResourceTag{Key: k, Value: v})
						}
						return tags
					}(),
				}})
			},
			resCheckFunc: func(ts *backendTestSuite, res *logical.Response, _ error) {
				ts.Require().Equal(map[string]interface{}{
					"instance_id": testInstanceID,
					"role":        testRoleName,
					"zone":        testZoneName,
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
				})

				ts.storeEntry(roleStoragePathPrefix+testRoleName, backendRole{
					Validator: fmt.Sprintf(
						`client_ip == instance_public_ip && `+
							`instance_manager_id == "%s" && `+
							`instance_created > now - duration("10m") && `+
							`"%s" in instance_security_group_ids && `+
							`"default" in instance_security_group_names && `+
							`instance_tags == {%s} && `+
							`instance_zone_id == "%s" && `+
							`instance_zone_name == "%s"`,
						testInstancePoolID,
						testInstanceSecurityGroupID,
						func() string {
							tags := make([]string, 0)
							for k, v := range testInstanceTags {
								tags = append(tags, fmt.Sprintf("%q:%q", k, v))
							}
							return strings.Join(tags, ",")
						}(),
						testZoneID,
						testZoneName,
					),
				})

				ts.mockListVirtualMachinesAPI([]egoscale.VirtualMachine{{
					Name:      testInstanceName,
					Created:   testInstanceCreated,
					ID:        egoscale.MustParseUUID(testInstanceID),
					ZoneName:  testZoneName,
					ZoneID:    egoscale.MustParseUUID(testZoneID),
					ManagerID: egoscale.MustParseUUID(testInstancePoolID),
					Nic:       []egoscale.Nic{{IPAddress: testInstanceIPAddress, IsDefault: true}},
					SecurityGroup: []egoscale.SecurityGroup{
						{
							ID:   egoscale.MustParseUUID(testInstanceDefaultSecurityGroupID),
							Name: "default",
						},
						{
							ID:   egoscale.MustParseUUID(testInstanceSecurityGroupID),
							Name: testInstanceSecurityGroupName,
						},
					},
					Tags: func() []egoscale.ResourceTag {
						tags := make([]egoscale.ResourceTag, 0)
						for k, v := range testInstanceTags {
							tags = append(tags, egoscale.ResourceTag{Key: k, Value: v})
						}
						return tags
					}(),
				}})
			},
			resCheckFunc: func(ts *backendTestSuite, res *logical.Response, _ error) {
				ts.Require().Equal(map[string]interface{}{
					"instance_id": testInstanceID,
					"role":        testRoleName,
					"zone":        testZoneName,
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
				`instance_manager_id == "%s" && `+
				`instance_created > now - duration("10m") && `+
				`"%s" in instance_security_group_ids && `+
				`"default" in instance_security_group_names && `+
				`instance_tags == {%s} && `+
				`instance_zone_id == "%s" && `+
				`instance_zone_name == "%s"`,
			testInstancePoolID,
			testInstanceSecurityGroupID,
			func() string {
				tags := make([]string, 0)
				for k, v := range testInstanceTags {
					tags = append(tags, fmt.Sprintf("%q:%q", k, v))
				}
				return strings.Join(tags, ",")
			}(),
			testZoneID,
			testZoneName,
		),
	})

	for _, tt := range tests {
		httpmock.Reset()

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
