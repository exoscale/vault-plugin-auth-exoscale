package exoscale

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/exoscale/egoscale"
	"github.com/hashicorp/vault/sdk/logical"
)

var (
	testZoneName          = "ch-gva-2"
	testZoneID            = "1128bd56-b4d9-4ac6-a7b9-c715b187ce11"
	testInstanceName      = "test-instance"
	testInstanceID        = "288e37eb-1d66-4634-88aa-8dc87a9e484d"
	testInstancePoolID    = "74bb6f3d-f43a-4038-a1b9-5a6779aa37f3"
	testInstanceIPAddress = net.ParseIP("1.2.3.4")
	testInstanceCreated   = time.Now().Add(-time.Minute).Format("2006-01-02T15:04:05-0700")
)

func (ts *backendTestSuite) TestPathLogin_ErrorMissingField() {
	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:    ts.storage,
		Operation:  logical.UpdateOperation,
		Path:       "login",
		Connection: &logical.Connection{RemoteAddr: testInstanceIPAddress.String()},
		Data:       map[string]interface{}{},
	})
	ts.Require().NoError(err, "request failed")
	ts.Require().True(strings.Contains(res.Error().Error(), errMissingField.Error()))
}

func (ts *backendTestSuite) TestPathLogin_ErrorInvalidFieldValue() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, testRole)
	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:    ts.storage,
		Operation:  logical.UpdateOperation,
		Path:       "login",
		Connection: &logical.Connection{RemoteAddr: testInstanceIPAddress.String()},
		Data: map[string]interface{}{
			"instance": "lolnope",
			"role":     testRoleName,
			"zone":     testZoneName,
		},
	})
	ts.Require().NoError(err, "request failed")
	ts.Require().True(strings.Contains(res.Error().Error(), errInvalidFieldValue.Error()))
}

func (ts *backendTestSuite) TestPathLogin_DenyClientNotInstancePoolMember() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, testRole)
	ts.mockListVirtualMachinesAPI([]egoscale.VirtualMachine{{
		Name:      testInstanceName,
		ID:        egoscale.MustParseUUID(testInstanceID),
		ZoneName:  testZoneName,
		ZoneID:    egoscale.MustParseUUID(testZoneID),
		ManagerID: nil,
		Nic:       []egoscale.Nic{{IPAddress: testInstanceIPAddress, IsDefault: true}},
	}})

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:    ts.storage,
		Operation:  logical.UpdateOperation,
		Path:       "login",
		Connection: &logical.Connection{RemoteAddr: testInstanceIPAddress.String()},
		Data: map[string]interface{}{
			"instance": testInstanceID,
			"role":     testRoleName,
			"zone":     testZoneName,
		},
	})
	ts.Require().Error(err, "request should have failed")
	ts.Require().True(strings.Contains(err.Error(), "failed validation"))
}

func (ts *backendTestSuite) TestPathLogin_DenyNonBooleanExpressions() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, testBadRole)
	ts.mockListVirtualMachinesAPI([]egoscale.VirtualMachine{{
		Name:      testInstanceName,
		ID:        egoscale.MustParseUUID(testInstanceID),
		ZoneName:  testZoneName,
		ZoneID:    egoscale.MustParseUUID(testZoneID),
		ManagerID: nil,
		Nic:       []egoscale.Nic{{IPAddress: testInstanceIPAddress, IsDefault: true}},
	}})

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:    ts.storage,
		Operation:  logical.UpdateOperation,
		Path:       "login",
		Connection: &logical.Connection{RemoteAddr: testInstanceIPAddress.String()},
		Data: map[string]interface{}{
			"instance": testInstanceID,
			"role":     testRoleName,
			"zone":     testZoneName,
		},
	})
	ts.Require().Error(err, "request should have failed")
	ts.Require().True(strings.Contains(err.Error(), "bad expression: result type should be boolean"))
}

func (ts *backendTestSuite) TestPathLogin_DenyClientWrongInstancePool() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, testRole)
	ts.mockListVirtualMachinesAPI([]egoscale.VirtualMachine{{
		Name:      testInstanceName,
		ID:        egoscale.MustParseUUID(testInstanceID),
		ZoneName:  testZoneName,
		ZoneID:    egoscale.MustParseUUID(testZoneID),
		ManagerID: egoscale.MustParseUUID("8dcbacef-f285-4d45-b49c-3c7a5c183899"),
		Nic:       []egoscale.Nic{{IPAddress: testInstanceIPAddress, IsDefault: true}},
	}})

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:    ts.storage,
		Operation:  logical.UpdateOperation,
		Path:       "login",
		Connection: &logical.Connection{RemoteAddr: testInstanceIPAddress.String()},
		Data: map[string]interface{}{
			"instance": testInstanceID,
			"role":     testRoleName,
			"zone":     testZoneName,
		},
	})
	ts.Require().Error(err, "request should have failed")
	ts.Require().True(strings.Contains(err.Error(), "failed validation"))
}

func (ts *backendTestSuite) TestPathLogin_DenyClientInstanceTooOld() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, testRole)
	ts.mockListVirtualMachinesAPI([]egoscale.VirtualMachine{{
		Name:      testInstanceName,
		Created:   time.Now().Add(-time.Hour).Format("2006-01-02T15:04:05-0700"),
		ID:        egoscale.MustParseUUID(testInstanceID),
		ZoneName:  testZoneName,
		ZoneID:    egoscale.MustParseUUID(testZoneID),
		ManagerID: egoscale.MustParseUUID(testInstancePoolID),
		Nic:       []egoscale.Nic{{IPAddress: testInstanceIPAddress, IsDefault: true}},
	}})

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:    ts.storage,
		Operation:  logical.UpdateOperation,
		Path:       "login",
		Connection: &logical.Connection{RemoteAddr: testInstanceIPAddress.String()},
		Data: map[string]interface{}{
			"instance": testInstanceID,
			"role":     testRoleName,
			"zone":     testZoneName,
		},
	})
	ts.Require().Error(err, "request should have failed")
	ts.Require().True(strings.Contains(err.Error(), "failed validation"))
}

func (ts *backendTestSuite) TestPathLogin_DenyClientWrongIPAddress() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, testRole)
	ts.mockListVirtualMachinesAPI([]egoscale.VirtualMachine{{
		Name:      testInstanceName,
		Created:   testInstanceCreated,
		ID:        egoscale.MustParseUUID(testInstanceID),
		ZoneName:  testZoneName,
		ZoneID:    egoscale.MustParseUUID(testZoneID),
		ManagerID: egoscale.MustParseUUID(testInstancePoolID),
		Nic:       []egoscale.Nic{{IPAddress: testInstanceIPAddress, IsDefault: true}},
	}})

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:    ts.storage,
		Operation:  logical.UpdateOperation,
		Path:       "login",
		Connection: &logical.Connection{RemoteAddr: "5.6.7.8"},
		Data: map[string]interface{}{
			"instance": testInstanceID,
			"role":     testRoleName,
			"zone":     testZoneName,
		},
	})
	ts.Require().Error(err, "request should have failed")
	ts.Require().True(strings.Contains(err.Error(), "failed validation"))
}

func (ts *backendTestSuite) TestPathLogin_Successful() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, testRole)
	ts.mockListVirtualMachinesAPI([]egoscale.VirtualMachine{{
		Name:      testInstanceName,
		Created:   testInstanceCreated,
		ID:        egoscale.MustParseUUID(testInstanceID),
		ZoneName:  testZoneName,
		ZoneID:    egoscale.MustParseUUID(testZoneID),
		ManagerID: egoscale.MustParseUUID(testInstancePoolID),
		Nic:       []egoscale.Nic{{IPAddress: testInstanceIPAddress, IsDefault: true}},
	}})

	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:    ts.storage,
		Operation:  logical.UpdateOperation,
		Path:       "login",
		Connection: &logical.Connection{RemoteAddr: testInstanceIPAddress.String()},
		Data: map[string]interface{}{
			"instance": testInstanceID,
			"role":     testRoleName,
			"zone":     testZoneName,
		},
	})
	ts.Require().NoError(err)
	ts.Require().Equal(map[string]interface{}{
		"instance_id": testInstanceID,
		"role":        testRoleName,
		"zone":        testZoneName,
	}, res.Auth.InternalData)
}
