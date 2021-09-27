package exoscale

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

var (
	testRoleName = "read-only"

	testRole = backendRole{Validator: defaultRoleValidator}
)

func (ts *backendTestSuite) TestPathRoleWrite() {
	tests := []struct {
		name         string
		resCheckFunc func(*backendTestSuite, *logical.Response, error)
		reqData      map[string]interface{}
		wantErr      bool
	}{
		{
			name: "fail_bad_validator",
			resCheckFunc: func(ts *backendTestSuite, res *logical.Response, err error) {
				ts.Require().True(strings.Contains(res.Error().Error(), "invalid field value: validator"))
			},
			reqData: map[string]interface{}{
				roleKeyValidator: "lolnope",
			},
		},
		{
			name: "ok",
			resCheckFunc: func(ts *backendTestSuite, res *logical.Response, _ error) {
				var actual backendRole
				entry, err := ts.storage.Get(context.Background(), roleStoragePathPrefix+testRoleName)
				ts.Require().NoError(err)
				ts.Require().NoError(entry.DecodeJSON(&actual))
				ts.Require().Equal(testRole, actual)
			},
			reqData: map[string]interface{}{
				roleKeyValidator: testRole.Validator,
			},
		},
	}

	for _, tt := range tests {
		ts.T().Run(tt.name, func(t *testing.T) {
			res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
				Storage:   ts.storage,
				Operation: logical.CreateOperation,
				Path:      roleStoragePathPrefix + testRoleName,
				Data:      tt.reqData,
			})
			if err != nil != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			tt.resCheckFunc(ts, res, err)
		})
	}
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
