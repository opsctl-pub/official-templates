# The public request and DO policy projection live with the provider procedure.
def require($ok): if $ok then . else error("unqualified") end;
def exact($fields): type == "object" and keys == ($fields | sort);
def bounded_text: type == "string" and length > 0 and length <= 255 and (explode | all(.[]; . >= 32 and . != 127));
def port: type == "number" and floor == . and . >= 1 and . <= 65535;
def unique_rows: length == (unique | length);
def public_rule:
  exact(["protocol", "port"]) and (.protocol == "tcp" or .protocol == "udp") and (.port | port);
def octets:
  require(type == "string" and test("^(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}$"))
  | split(".") | map(tonumber) | require(all(.[]; . <= 255));
def host32:
  try (split("/") | require(length == 2 and .[1] == "32") | .[0] | octets | length == 4) catch false;
def private_rule:
  exact(["protocol", "port", "source_addresses"]) and .protocol == "tcp" and (.port | port)
  and (.source_addresses | type == "array" and length == 1 and (.[0] | host32));
def public_key: [.protocol, .port];
def private_key: [.protocol, .port, .source_addresses[0]];
def state:
  {public: (.managed_rules | map(public_key) | sort),
   private: (.managed_private_rules | map(private_key) | sort)};
def neutral_rule:
  exact(["protocol", "port_start", "port_end", "peers"])
  and (.protocol == "tcp" or .protocol == "udp" or .protocol == "icmp")
  and (if .protocol == "icmp" then .port_start == null and .port_end == null
       else (.port_start | port) and (.port_end | port) and .port_start <= .port_end end)
  and (.peers | type == "array" and length > 0 and length <= 100 and unique_rows
      and all(.[]; exact(["kind", "identity"]) and (.identity | bounded_text)
          and (.kind == "address" or .kind == "instance" or .kind == "tag"
               or .kind == "load_balancer" or .kind == "kubernetes")));
def preserved_policy:
  exact(["name", "unrelated_ingress", "outbound", "attached_firewall_ids", "attached_instance_ids", "fingerprint"])
  and (.name | bounded_text)
  and (.unrelated_ingress | type == "array" and length <= 100 and all(.[]; neutral_rule))
  and (.outbound | type == "array" and length <= 100 and all(.[]; neutral_rule))
  and (.fingerprint | type == "string" and test("^[0-9a-f]{64}$"));
def valid_state($request):
  exact(["managed_rules", "managed_private_rules"])
  and (.managed_rules | type == "array" and length <= 35 and all(.[]; public_rule) and unique_rows)
  and (.managed_private_rules | type == "array" and length <= 64 and all(.[]; private_rule) and unique_rows)
  and all(.managed_rules[]; . as $r | any($request.managed_rules[]; . == $r))
  and all(.managed_private_rules[]; . as $r | any($request.managed_private_rules[]; . == $r));
def request:
  . as $r
  | require(exact(["format_version", "action", "provider_instance_id", "firewall_id", "region",
      "ssh_port", "managed_rules", "managed_private_rules"]
      + (if .action == "change" then ["step", "expected_before", "expected_after", "preserved_policy"] else [] end)))
  | require(.format_version == 1 and (.action == "creation" or .action == "observe" or .action == "change"))
  | require(.provider_instance_id | type == "string" and test("^[1-9][0-9]{0,15}$")
      and (tonumber <= 9007199254740991) and (tonumber | tostring) == .)
  | require(.firewall_id | type == "string" and test("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$"))
  | require(.region | type == "string" and test("^[a-z][a-z0-9-]{1,31}$"))
  | require(.ssh_port | port)
  | require(.managed_rules | type == "array" and length <= (if $r.action == "creation" then 35 else 67 end) and all(.[]; public_rule) and unique_rows)
  | require(.managed_private_rules | type == "array" and length <= 64 and all(.[]; private_rule) and unique_rows)
  | require(any(.managed_rules[]; .protocol == "tcp" and .port == $r.ssh_port))
  | require(all(.managed_private_rules[]; . as $p
      | .port != $r.ssh_port and .port != 80 and .port != 443
      and all($r.managed_rules[]; .protocol != $p.protocol or .port != $p.port)))
  | if .action != "change" then . else
      require(.step | exact(["action", "rule"]) and (.action == "add" or .action == "remove"))
      | require(.step.rule | public_rule or private_rule)
      | require(.step.rule as $step
          | (if $step | has("source_addresses") then
                $step.port != $r.ssh_port and $step.port != 80 and $step.port != 443
                and any($r.managed_private_rules[]; . == $step)
             else ($step.protocol != "tcp" or $step.port != $r.ssh_port)
                and any($r.managed_rules[]; . == $step) and
                ($r.step.action != "remove" or ($step.protocol != "tcp" or ($step.port != 80 and $step.port != 443))) end))
      | require(.expected_before | valid_state($r))
      | require(.expected_after | valid_state($r))
      | (.step.rule | has("source_addresses")) as $private
      | (if $private then "managed_private_rules" else "managed_rules" end) as $field
      | (if $private then "managed_rules" else "managed_private_rules" end) as $other
      | .step.rule as $rule
      | require((.expected_before[$other] | sort) == (.expected_after[$other] | sort))
      | require(if .step.action == "add" then
          (.expected_before[$field] | index($rule)) == null and
          ((.expected_before[$field] + [$rule]) | sort) == (.expected_after[$field] | sort)
        else (.expected_before[$field] | index($rule)) != null and
          (.expected_before[$field] - [$rule] | sort) == (.expected_after[$field] | sort) end)
      | require(any(.expected_before.managed_rules[]; .protocol == "tcp" and .port == $r.ssh_port)
          and any(.expected_after.managed_rules[]; .protocol == "tcp" and .port == $r.ssh_port))
      | require(.preserved_policy | preserved_policy)
      | require(.preserved_policy.attached_firewall_ids == [.firewall_id]
          and .preserved_policy.attached_instance_ids == [.provider_instance_id]
          and (.preserved_policy.fingerprint | type == "string" and test("^[0-9a-f]{64}$")))
    end;

# Python's historical compact/sorted ASCII JSON defines the existing fingerprints.
def hex_digit: "0123456789abcdef"[.:.+1];
def hex4: . as $n | [4096,256,16,1] | map((($n / . | floor) % 16) | hex_digit) | join("");
def ascii_json:
  tojson | explode | map(if . < 127 then [.] | implode else
    if . < 65536 then "\\u" + hex4 else
      (. - 65536) as $n | "\\u" + ((55296 + ($n / 1024 | floor)) | hex4)
        + "\\u" + ((56320 + ($n % 1024)) | hex4) end end) | join("");
def sorted_object:
  if type == "object" then to_entries | sort_by(.key) | map(.value |= sorted_object) | from_entries
  elif type == "array" then map(sorted_object) else . end;
def canonical: sorted_object | ascii_json;
def canonical_sort: sort_by(canonical);
def hex_number:
  require(test("^[0-9a-fA-F]{1,4}$")) | ascii_downcase | explode
  | reduce .[] as $n (0; . * 16 + (if $n <= 57 then $n-48 else $n-87 end));
def short_hex: hex4 | sub("^0+(?=.)"; "");
def ipv6_groups:
  ascii_downcase
  | if contains(".") then
      split(":") as $parts | ($parts[-1] | octets) as $v4
      | (($parts[0:-1] + [($v4[0]*256+$v4[1] | short_hex), ($v4[2]*256+$v4[3] | short_hex)]) | join(":"))
    else . end
  | split("::") | require(length <= 2)
  | if length == 1 then .[0] | split(":") | map(hex_number) | require(length == 8)
    else (if .[0] == "" then [] else .[0] | split(":") | map(hex_number) end) as $left
      | (if .[1] == "" then [] else .[1] | split(":") | map(hex_number) end) as $right
      | require(($left | length) + ($right | length) < 8)
      | $left + [range(8-($left|length)-($right|length)) | 0] + $right end;
def ipv6_text:
  . as $groups
  | [range(8) as $i | select($groups[$i] == 0 and ($i == 0 or $groups[$i-1] != 0))
      | {start:$i, count: ([range($i;8) | select($groups[.] != 0)][0] // 8) - $i}]
  | sort_by(-.count, .start) | (.[0] // {start:0,count:0}) as $run
  | if $run.count < 2 then $groups | map(short_hex) | join(":")
    else ($groups[:$run.start] | map(short_hex) | join(":")) + "::"
      + ($groups[$run.start+$run.count:] | map(short_hex) | join(":")) end;
def ipv4_prefix:
  if contains(".") then
    octets | reduce .[] as $v (0; . * 256 + $v)
    | . as $mask
    | if $mask == 0 then 0 else
        [range(33) | . as $prefix
          | select($mask == pow(2;32)-pow(2;32-$prefix)
            or ($mask < pow(2;24) and $mask == pow(2;32-$prefix)-1))]
        | require(length == 1) | .[0] end
  else require(test("^[0-9]+$")) | tonumber | require(. <= 32) end;
def network:
  split("/") | require(length <= 2) | . as $parts
  | if $parts[0] | contains(":") then
      ($parts[1] // "128" | require(test("^[0-9]+$")) | tonumber | require(. <= 128)) as $prefix
      | ($parts[0] | ipv6_groups) as $groups
      | require(all(range(8); . as $i | ([(16-$prefix+16*$i),0] | max | [.,16] | min) as $bits
          | $groups[$i] % pow(2;$bits) == 0))
      | ($groups | ipv6_text) + "/" + ($prefix | tostring)
    else ($parts[1] // "32" | ipv4_prefix) as $prefix
      | ($parts[0] | octets) as $groups
      | (reduce $groups[] as $v (0; . * 256 + $v)) as $value
      | require($value % pow(2;32-$prefix) == 0)
      | ($groups | map(tostring) | join(".")) + "/" + ($prefix | tostring) end;
def peer($kind):
  if $kind == "instance" then require(type == "number" and floor == . and . > 0 and . <= 9007199254740991) | tostring
  else require(bounded_text) | if $kind == "address" then network else . end end
  | {kind:$kind, identity:.};
def policy_rule($direction):
  . as $raw
  | require(type == "object" and (keys - ["protocol", "ports", $direction, "action"] | length) == 0)
  | require((if has("action") then .action == "allow" else true end) and (.protocol == "tcp" or .protocol == "udp" or .protocol == "icmp"))
  | require(.ports | type == "string")
  | (if .protocol == "icmp" then require(.ports == "0") | [null,null]
     elif .ports == "0" then [1,65535]
     else .ports | require(test("^[0-9]+(-[0-9]+)?$")) | split("-") | map(tonumber)
       | if length == 1 then [.[0],.[0]] else . end
       | require(all(.[]; port) and .[0] <= .[1]) end) as $range
  | .[$direction] as $peers
  | require($peers | type == "object" and (keys - ["addresses", "droplet_ids", "tags", "load_balancer_uids", "kubernetes_ids"] | length) == 0)
  | [ [["addresses","address"],["droplet_ids","instance"],["tags","tag"],
        ["load_balancer_uids","load_balancer"],["kubernetes_ids","kubernetes"]][] as $pair
      | (if $peers | has($pair[0]) then $peers[$pair[0]] else [] end | require(type == "array" and length <= 100))[] | peer($pair[1]) ]
  | sort_by(.kind,.identity) | require(length > 0 and length <= 100 and unique_rows)
  | {protocol:$raw.protocol, port_start:$range[0], port_end:$range[1], peers:.};
def overlaps($rule; $candidate):
  $rule.protocol == $candidate.protocol and $rule.port_start != null
  and $rule.port_start <= $candidate.port and $rule.port_end >= $candidate.port;
def managed_source($raw; $source):
  $raw.sources.addresses == [$source]
  and all(["droplet_ids", "tags", "load_balancer_uids", "kubernetes_ids"][];
      . as $key | ($raw.sources[$key] // []) == []);
def projection($r; $firewall; $page):
  $firewall | require(type == "object" and .id == $r.firewall_id
    and .droplet_ids == [($r.provider_instance_id | tonumber)] and .tags == []
    and (.status == "waiting" or .status == "succeeded" or .status == "failed"))
  | require(.pending_changes | type == "array" and length <= 1
      and all(.[]; exact(["droplet_id", "removing", "status"])
        and .droplet_id == ($r.provider_instance_id | tonumber) and .removing == false
        and (.status == "waiting" or .status == "succeeded" or .status == "failed")))
  | require($page | type == "object" and (.firewalls | type == "array" and length == 1)
      and .firewalls[0].id == $r.firewall_id and (.meta | type == "object") and .meta.total == 1
      and (.links | type == "object") and ((if .links | has("pages") then .links.pages else {} end) | type == "object")
      and ((.links.pages // {}).next | not))
  | require(.name | bounded_text)
  | require(.inbound_rules | type == "array" and length <= 100)
  | require(.outbound_rules | type == "array" and length <= 100)
  | reduce .inbound_rules[] as $raw ({public:[], private:[], unrelated:[], raw:[]};
      ($raw | policy_rule("sources")) as $rule
      | [$r.managed_private_rules[] | select(overlaps($rule;.))] as $private
      | [$r.managed_rules[] | select(overlaps($rule;.))] as $public
      | if ($private | length) > 0 then
          require($rule.port_start == $rule.port_end and $raw.ports == ($rule.port_start | tostring))
          | [$private[] | select(managed_source($raw;.source_addresses[0]))] as $matches
          | require(($matches | length) == 1) | .private += [$matches[0] | private_key]
        elif ($public | length) > 0 and $rule.port_start == $rule.port_end
             and $raw.ports == ($rule.port_start | tostring) and managed_source($raw;"0.0.0.0/0") then
          .public += [[$rule.protocol,$rule.port_start]]
        else .unrelated += [$rule] | .raw += [$raw] end)
  | require((.public | unique_rows) and (.private | unique_rows))
  | . as $classified
  | ($firewall.outbound_rules | map(policy_rule("destinations")) | canonical_sort) as $outbound
  | {id:$r.firewall_id, instance:$r.provider_instance_id, name:$firewall.name,
      unrelated_ingress:($classified.unrelated | canonical_sort), outbound:$outbound,
      tags:[], attachments:[$r.firewall_id], raw_unrelated_ingress:($classified.raw | canonical_sort),
      raw_outbound:($firewall.outbound_rules | canonical_sort)} as $policy
  | {policy:$policy, public:($classified.public | sort), private:($classified.private | sort),
      settled:($firewall.status == "succeeded" and $firewall.pending_changes == [])};
def observation($r; $p; $digest; $fingerprint; $observed):
  {provider_instance_id:$r.provider_instance_id, firewall_id:$r.firewall_id,
   rules:$p.public, private_rules:$p.private, attached_firewall_ids:[$r.firewall_id],
   attached_instance_ids:[$r.provider_instance_id], settled:$p.settled,
   policy_fingerprint:$digest, fingerprint:$fingerprint,
   preserved_policy:{name:$p.policy.name, unrelated_ingress:$p.policy.unrelated_ingress,
      outbound:$p.policy.outbound, attached_firewall_ids:[$r.firewall_id],
      attached_instance_ids:[$r.provider_instance_id], fingerprint:$digest},
   observed_at:$observed, observation_complete:true};

# Native policy runs without HTTP or credentials. Generic address/action and
# identity bounds are enforced by Runner; attribute meaning stays in this module.
def native_inbound:
  require((.action // "allow") == "allow") |
  {protocol, ports:(if .protocol == "icmp" and (.port_range // "") == "" then "0" else .port_range end), sources:{
    addresses:(.source_addresses // []), droplet_ids:(.source_droplet_ids // [] | map(tonumber)),
    tags:(.source_tags // []), load_balancer_uids:(.source_load_balancer_uids // []),
    kubernetes_ids:(.source_kubernetes_ids // [])}} | policy_rule("sources");
def native_outbound:
  require((.action // "allow") == "allow") |
  {protocol, ports:(if .protocol == "icmp" and (.port_range // "") == "" then "0" else .port_range end), destinations:{
    addresses:(.destination_addresses // []), droplet_ids:(.destination_droplet_ids // [] | map(tonumber)),
    tags:(.destination_tags // []), load_balancer_uids:(.destination_load_balancer_uids // []),
    kubernetes_ids:(.destination_kubernetes_ids // [])}} | policy_rule("destinations");
def expected_inbound:
  [.managed_rules[] | {protocol, ports:(.port | tostring), sources:{addresses:["0.0.0.0/0"]}}]
  + [.managed_private_rules[] | {protocol, ports:(.port | tostring), sources:{addresses:.source_addresses}}]
  | map(policy_rule("sources")) | canonical_sort;
def native_plan:
  require(exact(["action", "scope", "variables", "plan"]))
  | . as $input | .scope as $scope | .variables.opsctl_server as $server
  | .plan.resource_changes as $changes
  | require($changes | type == "array")
  | require(.plan.variables.opsctl_server.value == $server)
  | [$changes[] | select(.mode == "managed")] as $managed
  | [$managed[] | select(.address == "digitalocean_droplet.server[0]")] as $compute
  | [$managed[] | select(.address == "digitalocean_firewall.server[0]")] as $protection
  | require(all($managed[]; .address == "digitalocean_droplet.server[0]"
      or .address == "digitalocean_firewall.server[0]"))
  | if $scope.purpose == "create" then
      require(($input.variables.compute_present // true) == true
          and .plan.variables.protection_present.value == true
          and $server.simulate == false and ($compute | length) == 1 and ($protection | length) == 1)
      | require(all($managed[]; .change.actions == ["create"]))
      | $compute[0].change.after as $host | $protection[0].change.after as $firewall
      | require($host.name == $server.name and $host.region == $server.region
          and $host.size == $server.size and $host.image == $server.image
          and ($host.tags | sort) == ($server.tags | sort)
          and $host.monitoring == ($server.provider_config.do.enable_monitoring // false)
          and $host.backups == ($server.provider_config.do.enable_backups // false)
          and $host.ipv6 == ($server.provider_config.do.enable_ipv6 // false))
      | require($server.ssh_key.registered_id != ""
          and ($host.ssh_keys | map(tostring)) == [$server.ssh_key.registered_id])
      | require(($server.networks | length) == 0 or
          all($server.networks[]; .network_id == $host.vpc_uuid))
      | require($firewall.name == ($server.name + "-fw") and ($firewall.tags // []) == [])
      | require(($firewall.outbound_rule | map(native_outbound) | canonical_sort) ==
          ([{protocol:"tcp",ports:"1-65535"}, {protocol:"udp",ports:"1-65535"}, {protocol:"icmp",ports:"0"}]
            | map(. + {destinations:{addresses:["0.0.0.0/0", "::/0"]}} | policy_rule("destinations")) | canonical_sort))
      | {managed_rules:$server.public_ingress_rules, managed_private_rules:
          [$server.private_ingress_bindings[] | {protocol:.requested.protocol, port:.requested.port,
            source_addresses:[(.endpoint.host + "/32")]}]} as $desired
      | require(($firewall.inbound_rule | map(native_inbound) | canonical_sort) == ($desired | expected_inbound))
    elif $scope.purpose == "retire_compute" then
      require($input.variables.compute_present == false and ($compute | length) == 1
          and $compute[0].change.actions == ["delete"]
          and all($protection[]; .change.actions == ["no-op"]))
    elif $scope.purpose == "retire_remaining" then
      require(($compute | length) == 0 and ($protection | length) <= 1
          and all($protection[]; .change.actions == ["delete"]
            and (.change.before.droplet_ids // [] | length) == 0
            and (.change.before.tags // [] | length) == 0))
    else error("native purpose") end
  | true;

if $mode == "native_prepare" then
  $request[0] | require(exact(["action", "scope", "variables"]))
  | require(.action == "prepare_native_plan"
      and (.scope.purpose == "retire_compute" or .scope.purpose == "retire_remaining")
      and (.variables | has("protection_present") | not)
      and .variables.compute_present == false)
  | [.scope.resources[] | select(.address == "digitalocean_firewall.server[0]")]
  | require(length == 1) | .[0].provider_id
  | require(type == "string" and test("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$"))
elif $mode == "native_plan" then $request[0] | native_plan
elif $mode == "request" then $request[0] | request
elif $mode == "projection" then projection($request[0]; $firewall[0].firewall; $page[0])
elif $mode == "policy" then $projection[0].policy | canonical
elif $mode == "fingerprint" then
  ([$digest, $projection[0].public]
    + (if ($request[0].managed_private_rules | length) > 0 then [$projection[0].private] else [] end)
    + [$projection[0].settled]) | canonical
elif $mode == "observation" then observation($request[0]; $projection[0]; $digest; $fingerprint; $observed)
elif $mode == "creation" then
  $projection[0].settled and $projection[0].public == ($request[0] | state | .public)
  and $projection[0].private == ($request[0] | state | .private)
elif $mode == "change_state" then
  $request[0] as $r | $projection[0] as $p
  | if ($p.settled | not) then "pending"
    elif {public:$p.public,private:$p.private} == ($r.expected_after | state) then "after"
    elif {public:$p.public,private:$p.private} == ($r.expected_before | state) then "before"
    else "conflict" end
elif $mode == "payload" then
  $request[0].step.rule | {inbound_rules:[{protocol,ports:(.port | tostring),
      sources:{addresses:(.source_addresses // ["0.0.0.0/0"])}}]}
else error("mode") end
