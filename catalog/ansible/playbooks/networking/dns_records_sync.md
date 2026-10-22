# Synchronize Cloudflare A records

## Inputs

`dns_records_sync.yml` runs locally in the Runner. Required inputs are
`provider=cloudflare`, `provider_zone_id`, `zone_name` and the protected
`CLOUDFLARE_API_TOKEN` environment variable. `dns_changes` defaults to an empty
ordered list. Each change supplies `change_id`, `action=create|update|delete|adopt`,
`hostname`, `record_type=A`, `value`, boolean `proxied` and `ttl`; proxied records
require automatic TTL 1.
Changes carry their existing provider/tracked/deployment identities. Adoption
requires an existing provider record, deployment and null tracked-record ID.
`compare_before_apply` defaults to false; its confirmed external deletion requires
an unproxied A record, explicit provider ID and no tracked ID. `simulate` defaults
to false.

## Behavior

Validate the change set, then call the adjacent
[change procedure](../../tasks/dns_records_sync_change.yml) sequentially. It owns Cloudflare
requests and comparison before application. This is not a generic DNS provider
or other-record-type procedure. Simulation ends before validation/API changes.
Earlier applied changes are not rolled back after a later failure.

## Results

`TEMPLATE_OUTPUT_JSON` contains ordered `applied_changes`; each row retains
`change_id`, `action`, `hostname`, `record_type`, `value`, `ttl`, `proxied`,
`provider_record_id`, nullable `deployment_id` and nullable `tracked_record_id`.
The helper emits cumulative rows as changes complete. On failure, publish
the changes already accumulated, with `authorization_denied:true` when observed,
then fail. An incomplete list does not claim remaining changes happened; no token
or raw credential is part of the result.

## Progress

Existing steps are `dns_sync:start`, `dns_sync:complete` and `dns_sync:failure`,
including requested/applied counts and provider/zone metadata.
