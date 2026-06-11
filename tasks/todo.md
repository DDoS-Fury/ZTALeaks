# TGN Optional Device Edge

## Plan
- [x] Update `src/serve_api.py` to make `key_device` optional in `EventIn`.
- [x] Update `src/serve_tgn.py` `score_event` and `commit_event` to bypass device node logic and connect source directly to user when device is missing.
- [x] Update `tests/generator.py` to support `omit_device` flag.
- [x] Update `tests/test_client.py` to support `--no-device` and configurable `--host`/`--port`.
- [x] Add `test-ablation` service to `docker-compose.yml` under `ablation-no-device` profile.

## Verification
- [x] Run `docker compose --profile serve-tgn --profile ablation-no-device up --build` and check logs.

## Review
- (To be filled after implementation)
