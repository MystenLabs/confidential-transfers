# Guardian enclave service

The Guardian runs as a fleet of Nitro Enclaves behind a single Envoy proxy. Each
enclave generates its own encryption and signing keys at boot and becomes
eligible for traffic only after those keys are attested and registered on chain.
The proxy exposes the request-processing endpoint, load-balances across the
registered fleet, and retries another enclave when the selected instance cannot
open a request.
