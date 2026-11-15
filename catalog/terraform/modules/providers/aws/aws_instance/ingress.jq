def require($ok): if $ok then . else error("unqualified") end;
def exact($fields): type == "object" and keys == ($fields | sort);
def port: type == "number" and floor == . and . >= 1 and . <= 65535;
def rule: exact(["protocol","port"]) and (.protocol == "tcp" or .protocol == "udp") and (.port | port);
def request:
  . as $r
  | require(exact(["format_version","action","provider_instance_id","firewall_id","region",
      "ssh_port","managed_rules","managed_private_rules"]))
  | require(.format_version == 1 and .action == "creation")
  | require(.provider_instance_id | type == "string" and test("^i-([0-9a-f]{8}|[0-9a-f]{17})$"))
  | require(.firewall_id | type == "string" and test("^sg-([0-9a-f]{8}|[0-9a-f]{17})$"))
  | require(.region | type == "string" and test("^[a-z]{2}(-[a-z]+)+-[0-9]+$"))
  | require(.ssh_port | port)
  | require(.managed_rules | type == "array" and length <= 35 and all(.[]; rule) and length == (unique | length))
  | require(any(.managed_rules[]; .protocol == "tcp" and .port == $r.ssh_port))
  | require(.managed_private_rules == []);
def observed:
  $request[0] as $r
  | $group[0] | require(type == "object" and (.SecurityGroups | type == "array" and length == 1))
  | .SecurityGroups[0] | require(.GroupId == $r.firewall_id)
  | require(.IpPermissions | type == "array" and length <= 100)
  | require(.IpPermissionsEgress | type == "array" and length <= 100)
  | [.IpPermissions[]
      | require((.IpProtocol == "tcp" or .IpProtocol == "udp") and (.FromPort | port)
          and .FromPort == .ToPort)
      | require((.Ipv6Ranges // []) == [] and (.UserIdGroupPairs // []) == [] and (.PrefixListIds // []) == [])
      | require(.IpRanges | type == "array" and length == 1 and .[0].CidrIp == "0.0.0.0/0"
          and (.[0] | type == "object" and (keys - ["CidrIp", "Description"] | length) == 0))
      | [.IpProtocol,.FromPort]] as $rules
  | require(($rules | unique | length) == ($rules | length))
  | $instance[0] | require(type == "object" and (.Reservations | type == "array"))
  | require(all(.Reservations[]; type == "object" and (.Instances | type == "array")))
  | [.Reservations[].Instances[]] | require(length == 1 and .[0].InstanceId == $r.provider_instance_id)
  | .[0] | require(.SecurityGroups | type == "array" and length == 1 and .[0].GroupId == $r.firewall_id)
  | ($rules | sort) == ($r.managed_rules | map([.protocol,.port]) | sort);
if $mode == "request" then $request[0] | request
elif $mode == "observed" then observed
else error("mode") end
