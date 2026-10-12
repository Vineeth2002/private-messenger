package authorization

import (
	"context"

	"github.com/sovereign-messenger/private-messenger/services/gateway/internal/kt"
)

var _ interface {
	ValidateLeaf(context.Context, kt.TransparencyLeafV1) error
} = (*PostgresAuthorizer)(nil)
