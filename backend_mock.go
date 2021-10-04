package exoscale

import (
	"context"

	egoscale "github.com/exoscale/egoscale/v2"
	"github.com/stretchr/testify/mock"
)

type exoscaleClientMock struct {
	mock.Mock
}

func (m *exoscaleClientMock) GetInstance(ctx context.Context, zone, id string) (*egoscale.Instance, error) {
	args := m.Called(ctx, zone, id)
	return args.Get(0).(*egoscale.Instance), args.Error(1)
}

func (m *exoscaleClientMock) GetInstancePool(ctx context.Context, zone, id string) (*egoscale.InstancePool, error) {
	args := m.Called(ctx, zone, id)
	return args.Get(0).(*egoscale.InstancePool), args.Error(1)
}

func (m *exoscaleClientMock) GetSecurityGroup(ctx context.Context, zone, id string) (*egoscale.SecurityGroup, error) {
	args := m.Called(ctx, zone, id)
	return args.Get(0).(*egoscale.SecurityGroup), args.Error(1)
}
