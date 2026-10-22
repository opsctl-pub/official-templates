# Configure the managed Traefik proxy

## Inputs

`traefik_proxy.yml` uses the selected Server, `server_id`, `org_id`, `operation_id`
and existing managed runtime settings. `traefik_dashboard_enabled` defaults to false.
Enabled dashboards require normalized `traefik_dashboard_host`, protected
`traefik_dashboard_auth` (username plus supported password hash), and automatic
certificate subject/issuance inputs. DNS-01 additionally requires protected broker
credentials. Disabled-dashboard retirement uses explicit
`certificate_dashboard_retirement`. Full certificate inputs are in the
[dashboard setup below](#server-dashboard-setup).
`simulate` defaults to false.

## Behavior

Build native gateway arguments, configure the authenticated dashboard and
converge the managed runtime. Enabled setup observes selection before changes
and admits only known absent/automatic Server selection; it then issues/enrolls
the dashboard certificate. Explicit disabled retirement observes and retires
only the relevant automatic subject. Later setup failure may attempt runtime
restoration and unreferenced broker-token cleanup, but does not promise rollback
of certificate/enrollment changes. Simulation ends before effects.

## Results

The gateway uses completion progress; included certificate procedures emit their
actual `certificate_observation` and safe failures. Pre-effect selection refusal
emits unknown full observation, never fake absence. Completion is historical
execution evidence, not ongoing proxy/application readiness. Private dashboard
authentication and broker values are not public results.

## Progress

Existing steps are `traefik:start`, `traefik:ready`, `traefik:complete` and
`traefik:failure`. Included certificate results keep their separate meanings.

## Server Dashboard Setup

Dashboard setup admits automatic issue for an exact Server subject without a
backend-invented preimage. Before dashboard, runtime, broker or renewal mutation,
it reads the native five-field snapshot in explicit selection-only mode, with
host probes disabled and no running-gateway or enrollment prerequisite. Absolute
template-owned selection paths and ancestors must be root-owned, unlinked and
of the expected type. Actual missing selection/ancestors may establish absence;
unreadable, foreign, malformed or changed state remains unknown. Only a successful
absent or automatic selection is admitted; custom/native/unknown refuses setup.
The captured snapshot becomes local expected_certificate. After runtime converge,
unchanged generic issuance reobserves/compares it before mutation, preserving final
serving, enrollment and restoration. Existing automatic material may change to
the admitted hostname for that same Server. The helper's explicit --selection-only
returns exactly the five snapshot fields and skips probes/enrollment; its default
observation and --snapshot behavior remain unchanged.

Pre-effect setup refusal emits a valid UNKNOWN full certificate_observation and a
fixed procedure_error before failing. The five-field snapshot stays local; it
cannot supply full validity, binding count or enrollment facts. Unknown selection
is never rewritten as absent.
Dedicated Server dashboard retirement supplies certificate_dashboard_retirement=true
with authenticated subject/organization/hosts, not a historical renewable leaf or
backend expected_certificate. The procedure observes current selection, requires
the exact Server dashboard route absent, pauses its timer and waits for its service,
then reobserves and freezes the local five-field snapshot for existing strict
selection removal CAS. Nonautomatic material remains selected and unchanged;
certificate_observation plus automatic_retired reports actual final facts.
Final absence retains renewal={enabled:false,active:false,next_due_at:null} only
after the timer was observed absent or disabled/inactive; native/custom selections
retain renewal=null. Failed or unknown final observation cannot inherit success.
Generic retirement defaults certificate_dashboard_retirement=false and retains
the caller's strict expected snapshot. These sequences do not claim atomic CAS
across independent native tasks; publication still checks the frozen selection.
