package kt

import (
	"context"
	"errors"
)

// DeviceBoundTransparencyPublicationService is the production bridge between
// persisted device state, account/device authorization state, and the
// existing atomic KT publication service.
//
// It does not define enrollment, revocation, recovery, or HTTP semantics.
// It only ensures that an authenticated TransparencyLeafV1 matches both the
// persisted device state and the persisted authorization state before the
// existing KT publisher runs.
type DeviceBoundTransparencyPublicationService struct {
	deviceReader DeviceStateReader
	authorizer   LeafAuthorizationValidator
	publisher    *TransparencyPublicationService
}

func NewDeviceBoundTransparencyPublicationService(
	deviceReader DeviceStateReader,
	authorizer LeafAuthorizationValidator,
	publisher *TransparencyPublicationService,
) (*DeviceBoundTransparencyPublicationService, error) {
	if deviceReader == nil {
		return nil, errors.New("nil device state reader")
	}
	if authorizer == nil {
		return nil, errors.New("nil leaf authorization validator")
	}
	if publisher == nil {
		return nil, errors.New("nil transparency publication service")
	}
	return &DeviceBoundTransparencyPublicationService{
		deviceReader: deviceReader,
		authorizer:   authorizer,
		publisher:    publisher,
	}, nil
}

// PublishStateAndSTH validates the authenticated leaf against the existing
// devices table and authorization state, then delegates to the existing
// atomic KT publication service.
func (p *DeviceBoundTransparencyPublicationService) PublishStateAndSTH(
	ctx context.Context,
	leaf SMTLeaf,
	leafRaw []byte,
	historyRaw []byte,
) (PublishedTransparencySnapshot, error) {
	if p == nil || p.deviceReader == nil || p.authorizer == nil || p.publisher == nil {
		return PublishedTransparencySnapshot{}, errors.New("nil authorized transparency publisher")
	}

	if err := validatePublishedTransparencyLeaf(leaf, leafRaw); err != nil {
		return PublishedTransparencySnapshot{}, err
	}

	parsedLeaf, err := ParseTransparencyLeafV1(leafRaw)
	if err != nil {
		return PublishedTransparencySnapshot{}, err
	}

	if err := ValidateTransparencyLeafAgainstDevice(ctx, p.deviceReader, parsedLeaf); err != nil {
		return PublishedTransparencySnapshot{}, err
	}

	if err := p.authorizer.ValidateLeaf(ctx, parsedLeaf); err != nil {
		return PublishedTransparencySnapshot{}, err
	}

	return p.publisher.PublishStateAndSTH(ctx, leaf, leafRaw, historyRaw)
}
