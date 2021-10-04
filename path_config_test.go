package exoscale

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

var (
	testConfigAPIEnvironment = "test"
	testConfigAPIKey         = "EXOabcdef0123456789abcdef01"
	testConfigAPISecret      = "ABCDEFGHIJKLMNOPRQSTUVWXYZ0123456789abcdefg"
)

func (ts *backendTestSuite) TestPathConfigWrite() {
	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      configStoragePath,
		Data: map[string]interface{}{
			configKeyAPIEnvironment: testConfigAPIEnvironment,
			configKeyAPIKey:         testConfigAPIKey,
			configKeyAPISecret:      testConfigAPISecret,
			configKeyAppRoleMode:    true,
			configKeyZone:           testZone,
		},
	})

	ts.Require().NoError(err)
	var actual backendConfig
	entry, err := ts.storage.Get(context.Background(), configStoragePath)
	ts.Require().NoError(err)
	ts.Require().NoError(entry.DecodeJSON(&actual))
	require.Equal(ts.T(), backendConfig{
		APIEnvironment: testConfigAPIEnvironment,
		APIKey:         testConfigAPIKey,
		APISecret:      testConfigAPISecret,
		AppRoleMode:    true,
		Zone:           testZone,
	}, actual)
}

func (ts *backendTestSuite) TestPathConfigRead() {
	ts.storeEntry(configStoragePath, backendConfig{
		APIEnvironment: testConfigAPIEnvironment,
		APIKey:         testConfigAPIKey,
		APISecret:      testConfigAPISecret,
		AppRoleMode:    true,
		Zone:           testZone,
	})

	res, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.ReadOperation,
		Path:      configStoragePath,
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	require.Equal(ts.T(), testConfigAPIEnvironment, res.Data[configKeyAPIEnvironment].(string))
	require.Equal(ts.T(), testConfigAPIKey, res.Data[configKeyAPIKey].(string))
	require.Equal(ts.T(), testConfigAPISecret, res.Data[configKeyAPISecret].(string))
	require.True(ts.T(), res.Data[configKeyAppRoleMode].(bool))
	require.Equal(ts.T(), testZone, res.Data[configKeyZone].(string))
}
