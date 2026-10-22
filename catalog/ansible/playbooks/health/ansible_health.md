# Check Runner Ansible

## Inputs

`ansible_health.yml` runs on `localhost` with fact gathering disabled. It has no
procedure-specific inputs. The catalog currently registers it as `ansible_health`.

## Behavior

Run a local shell progress message, an Ansible debug task and a completion message.
This checks Ansible execution inside the Runner, not SSH, a Server, Docker or an
application. It does not prepare or change a customer Server.

## Results

Successful execution reports that Ansible ran inside the Runner. There is no
`TEMPLATE_OUTPUT_JSON` result. A failed task fails execution; missing completion
does not establish health. The marker's fixed duration is not a measured runtime.

## Progress

Existing steps are `ansible:health:start` (running) and `ansible:health:done`
(completed).
