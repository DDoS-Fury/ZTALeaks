package db

import (
	"context"

	"ztaleaks/business-logic/internal/models"
)

// PersonnelRepository defines the interface for interacting with personnel data
type PersonnelRepository interface {
	GetByID(ctx context.Context, id string) (*models.Personnel, error)
	GetAll(ctx context.Context) ([]*models.Personnel, error)
	Create(ctx context.Context, personnel *models.Personnel) error
	Update(ctx context.Context, personnel *models.Personnel) error
	Delete(ctx context.Context, id string) error
}

// ZoneRepository defines the interface for interacting with zone data
type ZoneRepository interface {
	GetByID(ctx context.Context, id string) (*models.Zone, error)
	GetAll(ctx context.Context) ([]*models.Zone, error)
	Create(ctx context.Context, zone *models.Zone) error
	Update(ctx context.Context, zone *models.Zone) error
	Delete(ctx context.Context, id string) error
}

// BadgeRepository defines the interface for interacting with access badge data
type BadgeRepository interface {
	GetByID(ctx context.Context, id string) (*models.AccessBadge, error)
	GetAll(ctx context.Context) ([]*models.AccessBadge, error)
	Create(ctx context.Context, badge *models.AccessBadge) error
	Update(ctx context.Context, badge *models.AccessBadge) error
	Delete(ctx context.Context, id string) error
}

// ReactorRepository defines the interface for interacting with reactor parameter data
type ReactorRepository interface {
	GetByID(ctx context.Context, id string) (*models.ReactorParameters, error)
	GetAll(ctx context.Context) ([]*models.ReactorParameters, error)
	Create(ctx context.Context, rp *models.ReactorParameters) error
	Update(ctx context.Context, rp *models.ReactorParameters) error
	Delete(ctx context.Context, id string) error
}
