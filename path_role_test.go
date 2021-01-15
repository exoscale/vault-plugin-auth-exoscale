package exoscale

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

var (
	testRoleName                 = "read-only"
	testRoleTokenPolicies        = []string{"read-only"}
	testRoleAllowedInstancePools = []string{testInstancePoolID}
	testRoleMaxClientInstanceAge = 10 * time.Minute
	testRole                     = backendRole{
		AllowedInstancePools:         testRoleAllowedInstancePools,
		MatchClientInstanceIPAddress: true,
		MaxClientInstanceAge:         testRoleMaxClientInstanceAge,
	}
)

func (ts *backendTestSuite) TestPathRoleWrite() {
	var actualRoleConfig backendRole

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      roleStoragePathPrefix + testRoleName,
		Data: map[string]interface{}{
			roleKeyAllowedInstancePools:         testRoleAllowedInstancePools,
			roleKeyMatchClientInstanceIPAddress: true,
			roleKeyMaxClientInstanceAge:         testRoleMaxClientInstanceAge,
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

	ts.Require().Equal(fmt.Sprint(testRoleAllowedInstancePools), res.Data[roleKeyAllowedInstancePools].(string))
	ts.Require().Equal(true, res.Data[roleKeyMatchClientInstanceIPAddress].(bool))
	ts.Require().Equal(fmt.Sprint(testRoleMaxClientInstanceAge), res.Data[roleKeyMaxClientInstanceAge].(string))
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
