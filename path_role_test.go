package exoscale

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/logical"
)

var (
	testRoleName          = "read-only"
	testRoleTokenPolicies = []string{"read-only"}
	testRoleValidator     = fmt.Sprintf(
		"zone == \"%s\" && client_ip == public_ip && manager_id == \"%s\" && created > now - duration(\"10m\")",
		testZoneName,
		testInstancePoolID)
	testBadRoleValidator = "zone"
	testBadRole          = backendRole{Validator: testBadRoleValidator}
	testRole             = backendRole{Validator: testRoleValidator}
)

func (ts *backendTestSuite) TestPathRoleWrite() {
	var actualRoleConfig backendRole

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      roleStoragePathPrefix + testRoleName,
		Data: map[string]interface{}{
			roleKeyValidator: testRoleValidator,
		},
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	entry, err := ts.storage.Get(context.Background(), roleStoragePathPrefix+testRoleName)
	ts.Require().NoError(err)
	ts.Require().NoError(entry.DecodeJSON(&actualRoleConfig))
	ts.Require().Equal(testRole, actualRoleConfig)
}

func (ts *backendTestSuite) TestPathRoleWriteBadValidator() {
	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      roleStoragePathPrefix + testRoleName,
		Data: map[string]interface{}{
			roleKeyValidator: testBadRoleValidator,
		},
	})
	ts.Require().Error(err, "request should have failed")
	ts.Require().True(strings.Contains(err.Error(), "bad expression: result type should be boolean"))
}

func (ts *backendTestSuite) TestPathRoleRead() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, testRole)

	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.ReadOperation,
		Path:      roleStoragePathPrefix + testRoleName,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	ts.Require().Equal(testRoleValidator, res.Data[roleKeyValidator].(string))
}

func (ts *backendTestSuite) TestPathRoleList() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, testRole)

	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.ListOperation,
		Path:      roleStoragePathPrefix,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	ts.Require().Equal(logical.ListResponse([]string{testRoleName}), res)
}

func (ts *backendTestSuite) TestPathRoleDelete() {
	ts.storeEntry(roleStoragePathPrefix+testRoleName, testRole)

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.DeleteOperation,
		Path:      roleStoragePathPrefix + testRoleName,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	res, err := ts.storage.Get(context.Background(), roleStoragePathPrefix+testRoleName)
	ts.Require().NoError(err)
	ts.Require().Nil(res)
}
