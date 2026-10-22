# Exclude a gateway backend

## Inputs

`exclude_gateway_backend.yml` requires `phase=converge|gateway`, `retiring_backend`,
nonempty unique `remaining_backends` (maximum 64), `expected_route` and the route
subject. `converge` also takes the complete
[route-convergence inputs](traefik_route_converge.md); its expected route must
contain the retiring endpoint and its desired endpoints must equal the remaining
set. `gateway` observes the already-switched route. `simulate` defaults to false.

## Behavior

In `converge`, run the existing route procedure before observing exclusion.
Require a present route with the exact serving counterpart set and no retiring
endpoint. In `gateway`, also compare the complete observed route with the supplied
snapshot. This excludes a configured backend; it does not itself drain runtime
connections, wait for clients or stop/remove a container.

## Results

`TEMPLATE_OUTPUT_JSON` contains `deployment_route_observation` and
`connection_drain={outcome,observed_at,phase:gateway,state,remaining_backends,
container_id,active_inbound_connections}`. Successful exclusion uses `clear` and
null runtime fields. Failure reports `incomplete`/`unknown`, null unavailable
facts and `procedure_error={phase:observe,code:route_observation_incomplete}`,
then fails. Simulation emits no consumed result. See the existing
[runtime drain result contract](../../containers/container_remove.md#runtime-drain-observations).

## Progress

The imported convergence path retains `traefik-route:*` progress. Exclusion
observation itself emits named facts, not a separate progress sequence.

## Gateway exclusion and runtime drain

Gateway `exclude_gateway_backend` takes `phase=gateway`, `retiring_backend`,
nonempty `remaining_backends`, `expected_route` and the route subject. Observe
the already-switched route and exact exclusion; no sleep-as-drained result.
Ordinary detach uses explicit `phase=converge`: complete `RouteConvergeInput`
plus `retiring_backend` and `remaining_backends`. Its frozen pre-withdrawal CAS
must contain the retiring endpoint; desired endpoints equal the remaining set.
The same child withdraws then observes exclusion. Missing phase refuses.

Runtime count/failure semantics and combined image results are defined by
[container removal](../../containers/container_remove.md#runtime-drain-observations).
