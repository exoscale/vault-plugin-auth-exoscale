package exoscale

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/logical"
)

var (
	testRoleName         = "read-only"
	testBadRoleValidator = "zone"
	testRole             = backendRole{Validator: defaultRoleValidator}
)

func (ts *backendTestSuite) TestPathRoleWrite() {
	var actual backendRole

	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      roleStoragePathPrefix + testRoleName,
		Data: map[string]interface{}{
			roleKeyValidator: testRole.Validator,
		},
	})
	ts.Require().NoError(err, "request failed")
	ts.Require().NoError(res.Error())

	entry, err := ts.storage.Get(context.Background(), roleStoragePathPrefix+testRoleName)
	ts.Require().NoError(err)
	ts.Require().NoError(entry.DecodeJSON(&actual))
	ts.Require().Equal(testRole, actual)
}

func (ts *backendTestSuite) TestPathRoleWriteBadValidator() {
	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      roleStoragePathPrefix + testRoleName,
		Data: map[string]interface{}{
			roleKeyValidator: testBadRoleValidator,
		},
	})
	ts.Require().NoError(err)
	ts.Require().True(strings.Contains(res.Error().Error(), "invalid field value: validator"))
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

	ts.Require().Equal(testRole.Validator, res.Data[roleKeyValidator].(string))
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
