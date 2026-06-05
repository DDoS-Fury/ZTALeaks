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

// ReactorRepository defines the interface for interacting with reactor parameter data
type ReactorRepository interface {
	GetByID(ctx context.Context, id string) (*models.ReactorParameters, error)
	GetAll(ctx context.Context) ([]*models.ReactorParameters, error)
	Create(ctx context.Context, rp *models.ReactorParameters) error
	Update(ctx context.Context, rp *models.ReactorParameters) error
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
	Personnel       PersonnelRepository
	Reactor         ReactorRepository
	Document        DocumentRepository
	NuclearMaterial NuclearMaterialRepository
}

// InitRepositories creates and returns a struct containing all initialized Mongo repositories
func InitRepositories(databases *AppConfig) *Repositories {
	return &Repositories{
		Personnel:       NewMongoPersonnelRepository(databases.OperatorDB),
		Reactor:         NewMongoReactorRepository(databases.AdminDB),
		Document:        NewMongoDocumentRepository(databases.managerDB),
		NuclearMaterial: NewMongoNuclearMaterialRepository(databases.managerDB),
	}
}
