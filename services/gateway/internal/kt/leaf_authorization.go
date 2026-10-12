package kt

import "context"

// LeafAuthorizationValidator is implemented by the account/device
// authorization layer. The KT package depends only on this narrow contract
// so the authorization package can continue to depend on kt without creating
// an import cycle.
type LeafAuthorizationValidator interface {
	ValidateLeaf(context.Context, TransparencyLeafV1) error
}
