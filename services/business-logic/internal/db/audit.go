package db

import (
	"context"

	"go.mongodb.org/mongo-driver/mongo/options"
)

// serviceName identifica questo servizio nel log di accesso prodotto dal
// container DB (campo `service`).
const serviceName = "business-logic"

// commentFor costruisce il commento "<service>|<impiegato>" da propagare a ogni
// operazione Mongo. MongoDB lo registra nel profiler
// (system.profile.command.comment) e il tailer interno al container DB lo usa
// per popolare i campi `service` e `utente_connesso` di db_access.jsonl.
// L'impiegato e' iniettato nel context dal LoggingMiddleware (X-Current-User);
// se assente si usa "-".
func commentFor(ctx context.Context) string {
	user := "-"
	if v, ok := ctx.Value("user_id").(string); ok && v != "" {
		user = v
	}
	requestID := "-"
	if v, ok := ctx.Value("req_id").(string); ok && v != "" {
		requestID = v
	}
	return serviceName + "|" + user + "|" + requestID
}

// Costruttori di opzioni con il comment gia' impostato, uno per tipo di
// operazione. Centralizzano la propagazione dell'identita' senza obbligare ogni
// repository a importare il package options.
func cInsert(ctx context.Context) *options.InsertOneOptions {
	return options.InsertOne().SetComment(commentFor(ctx))
}
func cFindOne(ctx context.Context) *options.FindOneOptions {
	return options.FindOne().SetComment(commentFor(ctx))
}
func cFind(ctx context.Context) *options.FindOptions {
	return options.Find().SetComment(commentFor(ctx))
}
func cUpdate(ctx context.Context) *options.UpdateOptions {
	return options.Update().SetComment(commentFor(ctx))
}
func cDelete(ctx context.Context) *options.DeleteOptions {
	return options.Delete().SetComment(commentFor(ctx))
}
