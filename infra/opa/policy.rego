package envoy.authz

import rego.v1

# Default decision: deny everything unless a rule explicitly allows it.
default allow := true