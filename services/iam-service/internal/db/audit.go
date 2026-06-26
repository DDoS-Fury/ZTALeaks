package db

import (
	"go.mongodb.org/mongo-driver/mongo/options"
)

// auditServiceName identifica iam-service nel log di accesso prodotto dal
// container security-db (campo `service`).
const auditServiceName = "iam-service"

// comment costruisce "<service>|<identita>" da propagare a un'operazione Mongo.
// MongoDB lo registra nel profiler (system.profile.command.comment) e il tailer
// interno al container DB lo usa per i campi `service`/`utente_connesso` di
// db_access.jsonl. L'identita' qui e' lo username/ID utente noto al repository.
func comment(identity string) string {
	if identity == "" {
		identity = "-"
	}
	return auditServiceName + "|" + identity
}

// Costruttori di opzioni con comment, uno per tipo di operazione.
func cFindOne(identity string) *options.FindOneOptions {
	return options.FindOne().SetComment(comment(identity))
}
func cInsert(identity string) *options.InsertOneOptions {
	return options.InsertOne().SetComment(comment(identity))
}
func cUpdate(identity string) *options.UpdateOptions {
	return options.Update().SetComment(comment(identity))
}
func cCount(identity string) *options.CountOptions {
	return options.Count().SetComment(comment(identity))
}
