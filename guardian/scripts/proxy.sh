#!/usr/bin/env bash
# Copyright (c) Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Run a local Envoy in front of the fleet on :8080 — the same routing the
# production proxy stack deploys: /process_request only, round robin, retry-on-422
# (previous_hosts), instances gated on GET /registered. Requires an `envoy` binary
# (`brew install envoy` or func-e).
set -euo pipefail

STATE_DIR="${STATE_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.fleet}"
command -v envoy >/dev/null || { echo "error: envoy not found (brew install envoy)" >&2; exit 1; }
ports=$(for f in "$STATE_DIR"/*.env; do
    port=$(basename "$f" .env)
    if [[ $port =~ ^[0-9]+$ ]]; then echo "$port"; fi
done)
[ -n "$ports" ] || { echo "error: no fleet instances in $STATE_DIR" >&2; exit 1; }

endpoints=""
for p in $ports; do
    endpoints+="              - endpoint: { address: { socket_address: { address: 127.0.0.1, port_value: $p } } }"$'\n'
done

CONFIG=$(mktemp -t envoy).yaml && touch "$CONFIG"
cat > "$CONFIG" <<YAML
static_resources:
  listeners:
    - name: public
      address: { socket_address: { address: 127.0.0.1, port_value: 8080 } }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: guardian
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  virtual_hosts:
                    - name: guardian
                      domains: ["*"]
                      routes:
                        - match: { path: "/process_request" }
                          route:
                            cluster: enclaves
                            retry_policy:
                              retry_on: retriable-status-codes
                              retriable_status_codes: [422]
                              num_retries: 9
                              retry_host_predicate:
                                - name: envoy.retry_host_predicates.previous_hosts
                                  typed_config:
                                    "@type": type.googleapis.com/envoy.extensions.retry.host.previous_hosts.v3.PreviousHostsPredicate
                              host_selection_retry_max_attempts: 9
  clusters:
    - name: enclaves
      type: STATIC
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: enclaves
        endpoints:
          - lb_endpoints:
$endpoints
      health_checks:
        - timeout: 2s
          interval: 5s
          unhealthy_threshold: 2
          healthy_threshold: 1
          http_health_check: { path: /registered }
YAML
echo "==> envoy on http://127.0.0.1:8080/process_request -> fleet ports: $(echo "$ports" | tr '\n' ' ')"
exec envoy -c "$CONFIG" --log-level warn
