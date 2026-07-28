# API versioning policy

Kitsos uses a major version in every public API path, starting with `/v1`.
OpenAPI `info.version` follows semantic versioning for documentation releases;
the URL changes only when the API contract needs a new major version.

## Changes that stay in `/v1`

Backward-compatible additions do not require `/v2`, including:

- adding a new endpoint;
- adding an optional request field;
- adding an optional response field;
- adding a new resource type or capability that existing calls do not use;
- performance, reliability, validation, observability, and security fixes;
- changing implementation details without changing the documented contract;
- deprecating an endpoint while it remains functional.

Clients must ignore unknown response fields. New enum values are introduced
carefully because exhaustive client implementations may treat them as a
breaking change.

## Changes that require `/v2`

Create `/v2` when a useful change cannot be delivered compatibly, for example:

- removing or renaming an endpoint, field, or query parameter;
- changing a field's type, meaning, or response envelope;
- making an optional request field required;
- changing authentication in a way that invalidates existing clients;
- changing established status-code or idempotency behavior;
- replacing pagination, filtering, or ordering semantics incompatibly.

`/v1` and `/v2` should run in parallel during a documented migration window.
Deprecated `/v1` endpoints receive documentation notices and, where practical,
`Deprecation` and `Sunset` response headers before removal.

Security fixes and hard abuse limits apply to every supported version
immediately. They are not delayed for a new major version. Product quota
changes are account policy, not API-version changes, and should be announced
when they materially affect normal use.
