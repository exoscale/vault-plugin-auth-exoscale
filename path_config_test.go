package exoscale

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

var (
	testConfigAPIEndpoint = defaultAPIEndpoint
	testConfigAPIKey      = "EXOabcdef0123456789abcdef01"
	testConfigAPISecret   = "ABCDEFGHIJKLMNOPRQSTUVWXYZ0123456789abcdefg"
)

func (ts *backendTestSuite) TestPathConfigWriteWithMissingAPICredentials() {
	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      configStoragePath,
	})

	require.EqualError(ts.T(), err, errMissingAPICredentials.Error())
}

func (ts *backendTestSuite) TestPathConfigWrite() {
	var actualBackendConfig backendConfig

	_, err := ts.backend.HandleRequest(context.Background(), &logical.Request{
		Storage:   ts.storage,
		Operation: logical.CreateOperation,
		Path:      configStoragePath,
		Data: map[string]interface{}{
			configKeyAPIEndpoint: testConfigAPIEndpoint,
			configKeyAPIKey:      testConfigAPIKey,
			configKeyAPISecret:   testConfigAPISecret,
		},
	})
	if err != nil {
		ts.FailNow("request failed", err)
	}

	entry, err := ts.storage.Get(context.Background(), configStoragePath)
	if err != nil {
		ts.FailNow("unable to retrieve entry from storage", err)
	}
	if err := entry.DecodeJSON(&actualBackendConfig); err != nil {
		ts.FailNow("unable to JSON-decode entry", err)
	}

	require.Equal(ts.T(), backendConfig{
		APIEndpoint: testConfigAPIEndpoint,
		APIKey:      testConfigAPIKey,
		APISecret:   testConfigAPISecret,
	}, actualBackendConfig)
}

func (ts *backendTestSuite) TestPathConfigRead() {
	entry, err := logical.StorageEntryJSON(configStoragePath, backendConfig{
		APIEndpoint: testConfigAPIEndpoint,
		APIKey:      testConfigAPIKey,
		APISecret:   testConfigAPISecret,
	})
	if err != nil {
		ts.FailNow("unable to JSON-encode entry", err)
	}

	if err := ts.storage.Put(context.Background(), entry); err != nil {
		ts.FailNow("unable to store entry", err)
	}

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
}
