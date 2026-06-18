# Task Management

## [x] Integrate 5-node AI Model and Remove HMAC Cookie

Goal: Apportare le modifiche necessarie per integrare la nuova versione del modello nella ZTA (5 nodi, no cookie HMAC, JA3 come config node).

### Steps
1. [x] Plan
2. [x] Remove `devicecookie.go` (crypto and handler logic in `iam-service`).
3. [x] Remove `device_cookie.go` in `security-orchestrator`.
4. [x] Update `iam-service` routes (`login.go`, `ui.go`, `verify_otp.go`) to remove `ensureDeviceCookie()`.
5. [x] Modify `aiscorer/client.go` to include `KeyConfig` and `omitempty` on `KeyDevice`.
6. [x] Update `buildAIEvent` in `handler.go` to extract JA3, pass it to `KeyConfig`, and omit `KeyDevice` for non-TPM devices.
7. [x] Verify compilation and test suite (Run `go test ./...` in both services).
8. [x] Update `lessons.md`.
