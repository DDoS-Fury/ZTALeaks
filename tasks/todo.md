# ZTALeaks Kubernetes Migration Plan

- [x] Extract Configs & Secrets (ConfigMaps, Secrets for .env, rego, envoy.yaml, nginx.conf)
- [x] Deploy Databases (StatefulSets + Services for Business DB and Security DB)
- [x] Deploy PEP components (A single Deployment containing Firewall, Envoy, Snort, Snort-internal sharing the network namespace)
- [x] Deploy PDP components (Security Orchestrator, OPA)
- [x] Deploy Business Logic & Frontend (Deployments + Services)
- [x] Implement NetworkPolicies (Strict zero-trust segmentation for Front-Net, Auth-Net, Back-Net)
- [x] Create a Kustomization/apply script or documentation.
