# Getting Started with ZTALeaks

Welcome to the ZTALeaks Zero Trust Architecture simulation. This guide will help you set up, start, and test the microservices-based environment.

## Prerequisites

Before starting, ensure you have the following installed on your machine:
- **Docker**
- **Docker Compose**
- **CUDA runtime** (to train the model)

Once downloaded this repository, since it has a submodule you must launch the following command.
```bash
git submodule update --init --recursive
```

### Configuration (`.env`)
You must configure the required environment variables before starting the cluster. 
Create an `.env` file in the root directory and ensure the following variables are set:
- Splunk HTTP Event Collector (HEC) tokens
- Database passwords and credentials for both Security DB (device fingerprints) and Business DB (application data)

### AI Model Initialization
In order to make the solution functionable, you MUST train Graphadata (to obtain the weights). That operation require only 2 minutes on a RTX 5070TI Blackwell, you must have (at least) 7GB of free VRAM; althought you must change some settings. If you have problem, let us know, so we can give you the weights. Below the commands.

- enter the `infra/ai-inference/` .
- launch the following compose command.
```bash
   docker compose --profile training-tgn up --build
```
- once finished, return to the repo's root and enjoy your AI-based ZTA!



## Starting the Environment

The system is deployed using Docker Compose, which sets up the necessary services and container networks (`Front-Net`, `Auth-Net`, `Back-Net`).

To build and start all the services in detached mode, run:
```bash
docker compose -f deployments/docker/docker-compose.yaml up -d --build
```

### Seeding the Database
The database structure is created automatically on the first start, but it remains empty. The `seeder` service populates both the Business DB (personnel, documents, nuclear materials, reactor parameters) and the Security DB (default users `admin`/`manager1`/`operator1`, password `admin123`). It starts together with the stack, but you can (re-)run it explicitly at any time:
```bash
docker compose -f deployments/docker/docker-compose.yaml up --build seeder
```
Re-running it is required after changing the default users (e.g., the role migration to `operator`/`manager`/`admin`): the seeder upserts roles and clearances onto existing users.

To stop the environment:
```bash
docker compose -f deployments/docker/docker-compose.yaml down
```


## Testing the Solution

The project involves validating adaptive, risk-based access control and network intrusion detection (e.g., via SnoRT and Splunk integration). 

### Simulating Traffic & Attacks
To thoroughly test the architecture, you need to simulate both legitimate traffic baselines and attack scenarios. 

1. **Test Environment Spin-Up**:
   There is a dedicated testing docker-compose file available for isolated test runs or specific mock setups:
   
   ```bash
   docker compose -f deployments/docker/docker-compose.test.yaml up -d --build
   ```

2. **Attack Scenarios**:
   - **Port Scanning**: This is the simplest attack pattern to test your Intrusion Detection System (e.g., snoRT). Ensure firewalls permit the initial scan to allow the NIDS to detect and alert on it.
   - **Credential Stuffing & Impossible Travel**: Generate edge-case user workflows to trigger Splunk alerts based on ZTNA metadata and JA3 fingerprints.

3. **Log Verification**:
   - Verify that all microservices correctly propagate the `X-Request-ID` header.
   - Check your centralized Splunk dashboard to ensure logs are correlated end-to-end and alerts are firing accurately for the simulated attacks.

## Security Constraints Reminder
- **Database Reachability**: The Business DB must NEVER be directly reachable from the outside world or the Security Orchestrator (it communicates exclusively via `Back-Net`). Validate this network isolation during your testing phase.
