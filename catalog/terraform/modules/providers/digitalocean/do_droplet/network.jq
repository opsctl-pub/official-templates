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
def native_id: type == "string" and test("^[1-9][0-9]{0,15}$") and tonumber <= 9007199254740991;
def uuid: type == "string" and test("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$");
def ipv4_number: octets | reduce .[] as $n (0; . * 256 + $n);
def cidr:
  . as $raw | split("/") | require(length == 2 and (.[1] | test("^[0-9]+$")))
  | (.[0] | ipv4_number) as $base | .[1] as $text | (.[1] | tonumber) as $prefix
  | require($prefix <= 32 and ($prefix | tostring) == $text and $base % pow(2;32-$prefix) == 0)
  | {base:$base, size:pow(2;32-$prefix), text:$raw};
def request:
  . as $r | require(exact(["format_version","action","network_id","region","ipv4_cidr","members","listeners"]))
  | require(.format_version == 1 and (.action == "domain" or .action == "targets" or .action == "creation"))
  | require(.network_id | uuid)
  | require(.members | type == "array" and length <= 32 and unique_rows and all(.[]; native_id))
  | require(.listeners | type == "array" and length <= 128 and all(.[];
      exact(["from_id","to_id","protocol","port"]) and .protocol == "tcp" and (.port | port)
      and .from_id != .to_id and (.from_id as $id | $r.members | index($id)) != null
      and (.to_id as $id | $r.members | index($id)) != null))
  | require(if .action == "domain" then .members == [] and .listeners == [] and .region == null and .ipv4_cidr == null
      else (.region | bounded_text) and (.ipv4_cidr | cidr | true) and (.members | length) > 0 end)
  | require(.action != "creation" or ((.members | length) == 1 and .listeners == []));
def domain($r):
  .vpc | require(type == "object" and .id == $r.network_id and (.region | bounded_text))
  | (.ip_range | cidr) as $domain
  | require(any(["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"][] | cidr;
       . as $private | $domain.base >= $private.base and $domain.base + $domain.size <= $private.base + $private.size))
  | require($r.region == null or .region == $r.region)
  | require($r.ipv4_cidr == null or .ip_range == $r.ipv4_cidr)
  | {network_id:.id, region:.region, ipv4_cidr:.ip_range};
def member($r; $domain; $id):
  .droplet | require(type == "object" and (.id | type == "number") and (.id | tostring) == $id
      and .vpc_uuid == $r.network_id and .region.slug == $domain.region)
  | require(.networks.v4 | type == "array" and length <= 64 and all(.[]; .type == "public" or .type == "private"))
  | [.networks.v4[] | select(.type == "private") | .ip_address] | require(length == 1) | .[0] as $host
  | ($domain.ipv4_cidr | cidr) as $net | ($host | ipv4_number) as $ip
  | require($ip > $net.base and $ip < $net.base + $net.size - 1)
  | {id:$id, host:$host};
def policy($id):
  require(type == "object" and (.firewalls | type == "array" and length <= 100)
      and (.meta.total | type == "number") and .meta.total == (.firewalls | length)
      and (.links // {} | type == "object") and (.links.pages // {} | type == "object") and (.links.pages.next | not))
  | .firewalls | require((map(.id) | unique | length) == length)
  | map(require((.id | uuid) and .status == "succeeded" and .pending_changes == [] and .tags == [])
      | require(.droplet_ids | type == "array" and length > 0 and length <= 1000 and unique_rows
          and all(.[]; type == "number" and floor == . and . > 0 and . <= 9007199254740991)
          and index($id | tonumber) != null)
      | require(.inbound_rules | type == "array" and length <= 100)
      | require(.outbound_rules | type == "array" and length <= 100)
      | {id:.id, droplet_ids:(.droplet_ids | sort), tags:[],
          inbound:(.inbound_rules | map(policy_rule("sources")) | canonical_sort),
          outbound:(.outbound_rules | map(policy_rule("destinations")) | canonical_sort)}) | canonical_sort;
def covers($port): .protocol == "tcp" and .port_start <= $port and .port_end >= $port;
def permits($peer): any(.peers[];
  .kind == "instance" and .identity == $peer.id or .kind == "address" and
    (try ((.identity | cidr) as $net | ($peer.host | ipv4_number) as $ip | $ip >= $net.base and $ip < $net.base + $net.size) catch false));
def listener($members; $listeners):
  . as $l | ($members[] | select(.id == $l.from_id)) as $consumer
  | ($members[] | select(.id == $l.to_id)) as $producer
  | [$producer.policy[].inbound[] | select(covers($l.port))] as $rules
  | [$listeners[] | select(.to_id == $l.to_id and .port == $l.port) | .from_id] as $ids
  | [$members[] | select(.id as $id | $ids | index($id))] as $approved
  | require(all($rules[].peers[]; . as $peer | any($approved[];
      $peer.kind == "address" and $peer.identity == (.host + "/32")
      or $peer.kind == "instance" and $peer.identity == .id)))
  | require(($producer.policy | length) > 0)
  | require(($consumer.policy | length) == 0 or any($consumer.policy[].outbound[]; covers($l.port) and permits($producer)))
  | any($rules[]; permits($consumer));
if $mode == "request" then $request[0] | request
elif $mode == "domain" then $payload[0] | domain($request[0])
elif $mode == "member" then $payload[0] | member($request[0]; $domain[0]; $id)
elif $mode == "policy" then $payload[0] | policy($id) | canonical
elif $mode == "listeners" then
  $members | require((map(.host) | unique | length) == length)
  | [$request[0].listeners[] | select((listener($members; $request[0].listeners)) | not)]
else error("mode") end
