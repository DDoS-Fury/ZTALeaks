# Self-Improvement Lessons

## Docker Command Documentation
**Mistake**: I attempted to guess the standard `docker compose` command (`docker compose --profile training-tgn up --build train-tgn`) instead of reading the provided documentation.
**Correction**: The user pointed out the existence of `docs/docker.md` which specified the exact command (`docker compose --profile training-tgn up`).
**Rule**: Always check for specific documentation (e.g. `docs/docker.md`, `README.md`) in the component folder before attempting to run services or scripts. Do not assume standard commands apply directly without checking documentation.
