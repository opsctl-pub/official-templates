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

def volume_id: type == "string" and test("^vol-([0-9a-f]{8}|[0-9a-f]{17})$");
def instance_id: type == "string" and test("^i-([0-9a-f]{8}|[0-9a-f]{17})$");
def group_id: type == "string" and test("^sg-([0-9a-f]{8}|[0-9a-f]{17})$");
def device_name: type == "string" and test("^/dev/[A-Za-z0-9_-]{1,64}$");
def unique_devices($device; $volume):
  (map(getpath($device)) | unique | length) == length and
  (map(getpath($volume)) | unique | length) == length;
def creation_rules:
  map(require(.cidr_blocks == ["0.0.0.0/0"] and .from_port == .to_port
      and (.ipv6_cidr_blocks // []) == [] and (.prefix_list_ids // []) == []
      and (.security_groups // []) == [] and .self == false)
      | [.protocol, .from_port]) | sort;
def native_policy:
  require(exact(["action", "scope", "variables", "plan"]))
  | . as $r | .scope.purpose as $purpose | .variables.opsctl_server as $server
  | require(.plan.variables.opsctl_server.value == $server and (.plan.resource_changes | type == "array"))
  | [.plan.resource_changes[] | select(.mode == "managed")] as $managed
  | [$managed[] | select(.address == "aws_instance.server[0]")] as $compute
  | [$managed[] | select(.address == "aws_security_group.this[0]")] as $protection
  | require(($managed | length) == (($compute + $protection) | length))
  | if $purpose == "create" then
      require(.plan.variables.compute_present.value == true and $server.simulate == false
              and ($compute | length) == 1 and ($protection | length) == 1
              and all($managed[]; .change.actions == ["create"]))
      | $compute[0].change.after as $host | $protection[0].change.after as $group
      | (reduce $server.tags[] as $tag ({}; .[$tag] = "true") | .Name = $server.name) as $tags
      | require($host.instance_type == $server.size and $host.key_name == $server.ssh_key.registered_name
              and ($host.key_name | type == "string" and length > 0)
              and $host.volume_tags == $tags
              and ($host.root_block_device | type == "array" and length == 1 and .[0].delete_on_termination == true))
      | require(($group.ingress | creation_rules) == ($server.public_ingress_rules | map([.protocol, .port]) | sort)
                and ($group.egress | creation_rules) == [["-1", 0]])
      | {purpose:$purpose}
    elif $purpose == "retire_compute" then
      require($r.variables.compute_present == false and ($compute | length) == 1
              and $compute[0].change.actions == ["delete"]
              and all($protection[]; .change.actions == ["no-op"] and .change.before == .change.after))
      | $compute[0].change.before as $before
      | $r.scope.intent.observation_only.volume as $volume
      | require($volume | volume_id)
      | require($before.id | instance_id)
      | require($server.region | type == "string" and test("^[a-z]{2}(-[a-z]+)+-[0-9]+$"))
      | require($before.root_block_device | type == "array" and length == 1
                and .[0].volume_id == $volume and .[0].delete_on_termination == true and (.[0].device_name | device_name))
      | require($before.ebs_block_device | type == "array" and length <= 127
                and all(.[]; (.volume_id | volume_id) and (.device_name | device_name)
                             and .delete_on_termination == false))
      | require(($before.root_block_device + $before.ebs_block_device) | unique_devices(["device_name"]; ["volume_id"]))
      | {purpose:$purpose, instance:$before.id, region:$server.region,
         root_device:$before.root_block_device[0].device_name, volume:$volume}
    elif $purpose == "retire_remaining" then
      require($r.variables.compute_present == false and .plan.variables.compute_present.value == false
              and ($compute | length) == 0 and $server.simulate == false)
      | require($r.scope.resources | type == "array" and length == 1
                and .[0].address == "aws_security_group.this[0]" and .[0].actions == ["delete"]
                and (.[0].provider_id | group_id))
      | $r.scope.resources[0].provider_id as $group_id
      | require($server.region | type == "string" and test("^[a-z]{2}(-[a-z]+)+-[0-9]+$"))
      | require(($protection | length) <= 1 and all($protection[];
                .change.actions == ["delete"] and .change.before.id == $group_id and .change.after == null))
      | {purpose:$purpose, group:$group_id, region:$server.region, planned:($protection | length == 1)}
    else error("native purpose") end;

def current_devices:
  $policy[0] as $expected
  | $instance[0] | require(type == "object" and .NextToken == null and (.Reservations | type == "array"))
  | require(all(.Reservations[]; type == "object" and (.Instances | type == "array")))
  | [.Reservations[].Instances[]]
  | require(length == 1 and .[0].InstanceId == $expected.instance
            and .[0].RootDeviceType == "ebs" and .[0].RootDeviceName == $expected.root_device)
  | .[0].BlockDeviceMappings
  | require(type == "array" and length >= 1 and length <= 128
            and all(.[]; (.DeviceName | device_name) and (.Ebs | type == "object" and (.VolumeId | volume_id))))
  | require(unique_devices(["DeviceName"]; ["Ebs","VolumeId"]))
  | require(any(.[]; .DeviceName == $expected.root_device))
  | all(.[]; if .DeviceName == $expected.root_device then
               .Ebs.VolumeId == $expected.volume and .Ebs.DeleteOnTermination == true
             else .Ebs.DeleteOnTermination == false end);

def group_presence:
  $policy[0].group as $expected
  | $group[0] | require(type == "object" and (keys - ["SecurityGroups","NextToken"]) == []
                       and .NextToken == null and (.SecurityGroups | type == "array"))
  | .SecurityGroups
  | if length == 0 then "absent"
    elif length == 1 and .[0].GroupId == $expected then "present"
    else error("unqualified security group") end;

if $mode == "request" then $request[0] | request
elif $mode == "observed" then observed
elif $mode == "native_policy" then $request[0] | native_policy
elif $mode == "current_devices" then current_devices
elif $mode == "group_presence" then group_presence
elif $mode == "allocation_scope" then
  $request[0] | type == "object" and keys == ["action","scope"] and .action == "verify_allocation_scope"
    and (.scope | type == "object" and keys == ["account_id","region"]
      and (.account_id | type == "string" and test("^[0-9]{12}$"))
      and (.region | type == "string" and test("^[a-z][a-z0-9-]{0,62}$")))
elif $mode == "allocation_match" then
  $instance[0] | type == "object" and .Account == $request[0].scope.account_id
    and (.Arn | type == "string" and length > 0) and (.UserId | type == "string" and length > 0)
else error("mode") end
