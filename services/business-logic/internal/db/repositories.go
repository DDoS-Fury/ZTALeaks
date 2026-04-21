package db

import (
	"context"

	"ztaleaks/business-logic/internal/models"

	"go.mongodb.org/mongo-driver/mongo"
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

// MaintenanceOrderRepository defines the interface for interacting with maintenance order data
type MaintenanceOrderRepository interface {
	GetByID(ctx context.Context, id string) (*models.MaintenanceOrder, error)
	GetAll(ctx context.Context) ([]*models.MaintenanceOrder, error)
	Create(ctx context.Context, order *models.MaintenanceOrder) error
	Update(ctx context.Context, order *models.MaintenanceOrder) error
	Delete(ctx context.Context, id string) error
}

// DocumentRepository defines the interface for interacting with document data
type DocumentRepository interface {
	GetByID(ctx context.Context, id string) (*models.Document, error)
	GetAll(ctx context.Context) ([]*models.Document, error)
	Create(ctx context.Context, doc *models.Document) error
	Update(ctx context.Context, doc *models.Document) error
	Delete(ctx context.Context, id string) error
}

// NuclearMaterialRepository defines the interface for interacting with nuclear material data
type NuclearMaterialRepository interface {
	GetByID(ctx context.Context, id string) (*models.NuclearMaterial, error)
	GetAll(ctx context.Context) ([]*models.NuclearMaterial, error)
	Create(ctx context.Context, material *models.NuclearMaterial) error
	Update(ctx context.Context, material *models.NuclearMaterial) error
	Delete(ctx context.Context, id string) error
}

// Repositories groups all data repositories for easy injection
type Repositories struct {
	Personnel        PersonnelRepository
	Zone             ZoneRepository
	Badge            BadgeRepository
	Reactor          ReactorRepository
	MaintenanceOrder MaintenanceOrderRepository
	Document         DocumentRepository
	NuclearMaterial  NuclearMaterialRepository
}

// InitRepositories creates and returns a struct containing all initialized Mongo repositories
func InitRepositories(database *mongo.Database) *Repositories {
	return &Repositories{
		Personnel:        NewMongoPersonnelRepository(database),
		Zone:             NewMongoZoneRepository(database),
		Badge:            NewMongoBadgeRepository(database),
		Reactor:          NewMongoReactorRepository(database),
		MaintenanceOrder: NewMongoMaintenanceOrderRepository(database),
		Document:         NewMongoDocumentRepository(database),
		NuclearMaterial:  NewMongoNuclearMaterialRepository(database),
	}
}
