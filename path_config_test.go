package exoscale

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

var (
	testConfigAPIEndpoint = defaultAPIEndpoint
	testConfigAPIKey      = "EXOabcdef0123456789abcdef01"
	testConfigAPISecret   = "ABCDEFGHIJKLMNOPRQSTUVWXYZ0123456789abcdefg"
)

func (ts *backendTestSuite) TestPathConfigWrite() {
	tests := []struct {
		name         string
		resCheckFunc func(*backendTestSuite, *logical.Response, error)
		reqData      map[string]interface{}
		wantErr      bool
	}{
		{
			name: "fail_missing_credentials",
			resCheckFunc: func(ts *backendTestSuite, res *logical.Response, err error) {
				require.EqualError(ts.T(), err, errMissingAPICredentials.Error())
			},
			reqData: map[string]interface{}{
				configKeyZone: testZoneName,
			},
			wantErr: true,
		},
		{
			name: "fail_missing_zone",
			resCheckFunc: func(ts *backendTestSuite, res *logical.Response, err error) {
				require.EqualError(ts.T(), err, errMissingZone.Error())
			},
			reqData: map[string]interface{}{
				configKeyAPIKey:    testConfigAPIKey,
				configKeyAPISecret: testConfigAPISecret,
			},
			wantErr: true,
		},
		{
			name: "ok",
			resCheckFunc: func(ts *backendTestSuite, res *logical.Response, _ error) {
				var actual backendConfig
				entry, err := ts.storage.Get(context.Background(), configStoragePath)
				ts.Require().NoError(err)
				ts.Require().NoError(entry.DecodeJSON(&actual))
				require.Equal(ts.T(), backendConfig{
					APIEndpoint: testConfigAPIEndpoint,
					APIKey:      testConfigAPIKey,
					APISecret:   testConfigAPISecret,
					AppRoleMode: true,
					Zone:        testZoneName,
				}, actual)
			},
			reqData: map[string]interface{}{
				configKeyAPIEndpoint: testConfigAPIEndpoint,
				configKeyAPIKey:      testConfigAPIKey,
				configKeyAPISecret:   testConfigAPISecret,
				configKeyAppRoleMode: true,
				configKeyZone:        testZoneName,
			},
		},
	}

	for _, tt := range tests {
		ts.T().Run(tt.name, func(t *testing.T) {
			res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
				Storage:   ts.storage,
				Operation: logical.CreateOperation,
				Path:      configStoragePath,
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

func (ts *backendTestSuite) TestPathConfigRead() {
	ts.storeEntry(configStoragePath, backendConfig{
		APIEndpoint: testConfigAPIEndpoint,
		APIKey:      testConfigAPIKey,
		APISecret:   testConfigAPISecret,
		AppRoleMode: true,
		Zone:        testZoneName,
	})

	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.ReadOperation,
		Path:      configStoragePath,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	require.Equal(ts.T(), testConfigAPIEndpoint, res.Data[configKeyAPIEndpoint].(string))
	require.Equal(ts.T(), testConfigAPIKey, res.Data[configKeyAPIKey].(string))
	require.Equal(ts.T(), testConfigAPISecret, res.Data[configKeyAPISecret].(string))
	require.True(ts.T(), res.Data[configKeyAppRoleMode].(bool))
	require.Equal(ts.T(), testZoneName, res.Data[configKeyZone].(string))
}
