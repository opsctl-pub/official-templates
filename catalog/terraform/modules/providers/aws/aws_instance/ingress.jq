include "network_policy";

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

def configuration_rules:
  type == "array" and length <= 67 and all(.[]; rule) and length == (unique | length);
def private_rule:
  exact(["protocol","port","source_addresses"]) and .protocol == "tcp" and (.port | port)
  and (.source_addresses | type == "array" and length == 1 and (.[0] | host_cidr));
def private_rules:
  type == "array" and length <= 64 and all(.[]; private_rule) and length == (unique | length);
def request_tuple:
  [.protocol,.port] + (.source_addresses // []);
def state_rules:
  (.managed_rules + .managed_private_rules) | map(request_tuple) | sort;
def configuration_state:
  exact(["managed_rules","managed_private_rules"]) and
  (.managed_rules | configuration_rules and length <= 35) and (.managed_private_rules | private_rules);
def configuration_request:
  . as $r
  | require(exact(["format_version","action","provider_instance_id","firewall_id","region",
      "ssh_port","managed_rules","managed_private_rules"] +
      (if .action == "change" then ["step","expected_before","expected_after","preserved_policy",
       "expected_before_fingerprint"] else [] end)))
  | require(.format_version == 1 and (.action == "observe" or .action == "change"))
  | require((.provider_instance_id | instance_id) and (.firewall_id | group_id))
  | require(.region | type == "string" and test("^[a-z]{2}(-[a-z]+)+-[0-9]+$"))
  | require((.ssh_port | port) and (.managed_rules | configuration_rules) and
      (.managed_private_rules | private_rules and all(.[]; .port != $r.ssh_port)))
  | require(any(.managed_rules[]; .protocol == "tcp" and .port == $r.ssh_port))
  | if .action == "change" then
      require((.expected_before | configuration_state) and (.expected_after | configuration_state))
      | require(.step | exact(["action","rule"]) and (.action == "add" or .action == "remove")
                              and (.rule | rule or private_rule))
      | require(.step.rule != {protocol:"tcp",port:.ssh_port})
      | require((.expected_before_fingerprint | type == "string" and test("^[0-9a-f]{64}$"))
                and (.preserved_policy | type == "object"))
      | ($r | state_rules) as $union
      | (.expected_before | state_rules) as $before | (.expected_after | state_rules) as $after
      | require(all(($before + $after)[]; . as $rule | any($union[]; . == $rule)))
      | (.step.rule | request_tuple) as $step
      | require(if .step.action == "add" then
          (any($before[]; . == $step) | not) and (($before + [$step]) | sort) == $after
        else any($before[]; . == $step) and (($before - [$step]) | sort) == $after end)
    else . end
  | true;

def public_tuple:
  .fact as $f
  | if ($f.egress | not) and ($f.rule.protocol == "tcp" or $f.rule.protocol == "udp")
        and $f.rule.port_start == $f.rule.port_end
        and $f.rule.peers[0].identity == "0.0.0.0/0" then [$f.rule.protocol,$f.rule.port_start]
    else null end;
def private_tuple:
  .fact as $f
  | if ($f.egress | not) and $f.rule.protocol == "tcp" and $f.rule.port_start == $f.rule.port_end
        and ($f.rule.peers[0].identity | host_cidr)
    then ["tcp",$f.rule.port_start,$f.rule.peers[0].identity] else null end;
def private_description: "OpsControl declared private ingress";
def declared_tuple:
  if .fact.description == "OpsControl declared ingress" then public_tuple
  elif .fact.description == private_description then private_tuple
  else null end;
def configuration_projection:
  $request[0] as $r
  | ($group[0] | qualified_group($r.firewall_id)) as $sg
  | (if $r.managed_private_rules == [] then null else $domain[0] end) as $selected
  | exclusive_attachment($r;$sg;$instance[0];$interfaces[0];$selected) as $attachment
  | require(all($r.managed_private_rules[]; .source_addresses[0] | split("/")[0] |
        . != $attachment.host and usable_host($selected)))
  | ($native_rules[0] | exact_rows($sg)) as $rows
  | ["tcp",$r.ssh_port] as $ssh
  | ($rows | map(select(declared_tuple == $ssh))) as $protected
  | require(($protected | length) == 1)
  | ($r | state_rules) as $union
  | ($rows | map(select(declared_tuple as $tuple | $tuple != null and any($union[]; . == $tuple)))) as $managed
  | ($rows - $managed) as $foreign
  | ($managed | map(declared_tuple) | sort) as $logical
  | require(($logical | unique) == $logical)
  | {name:$sg.GroupName, attachment:($attachment | del(.host,.subnet,.ipv4_cidr)),
      private_attachment:(if $selected == null then null else $attachment | {host,subnet,ipv4_cidr} end),
      rules:($logical | map(select(length == 2))),
      private_rules:($logical | map(select(length == 3))), rows:$rows,
      protected:($foreign + $protected | sort_by(.id)),
      unrelated:[$foreign[] | select(.fact.egress | not) | .fact.rule] | sort,
      outbound:[$foreign[] | select(.fact.egress) | .fact.rule] | sort};
def configuration_observation:
  $request[0] as $r | $projection[0] as $p
  | {provider_instance_id:$r.provider_instance_id,firewall_id:$r.firewall_id,rules:$p.rules,private_rules:$p.private_rules,
     attached_firewall_ids:[$r.firewall_id],attached_instance_ids:[$r.provider_instance_id],settled:true,
     policy_fingerprint:$digest,fingerprint:$fingerprint,
     preserved_policy:{name:$p.name,unrelated_ingress:$p.unrelated,outbound:$p.outbound,
       attached_firewall_ids:[$r.firewall_id],attached_instance_ids:[$r.provider_instance_id],fingerprint:$digest},
     observed_at:$observed,observation_complete:true}
  + (if $r.action == "observe" then {network_id:$p.attachment.vpc} else {} end);
def configuration_change:
  $request[0] as $r | $projection[0] as $p | ($r.step.rule | request_tuple) as $step
  | ($step | length == 3) as $private
  | if $private then
      ($r | state_rules) as $union
      | require(all($p.rows[]; if (.fact.egress | not) and (.fact | covers_tcp($step[1]))
           then declared_tuple as $candidate
           | $candidate != null and ($candidate | length) == 3 and any($union[]; . == $candidate)
           else true end))
    else . end
  | if $r.step.action == "add" then
      require(all($p.rows[]; (if $private then private_tuple else public_tuple end) != $step))
      | [{IpProtocol:$step[0],FromPort:$step[1],ToPort:$step[1],
          IpRanges:[(if $private then {CidrIp:$step[2],Description:private_description}
                     else {CidrIp:"0.0.0.0/0",Description:"OpsControl declared ingress"} end)]}]
    else [$p.rows[] | select(declared_tuple == $step) | .id] | require(length == 1) | .[0] end;
def configuration_after:
  ($request[0].step.rule | request_tuple) as $step
  | $before[0].private_attachment == $projection[0].private_attachment
    and ($before[0].rows | map(select(declared_tuple != $step))) ==
    ($projection[0].rows | map(select(declared_tuple != $step)));

if $mode == "request" then $request[0] | if .action == "creation" then request else configuration_request end
elif $mode == "configuration_vpc_id" then $group[0] | qualified_group($request[0].firewall_id) | .VpcId
elif $mode == "configuration_domain" then
  ($identity[0] | identity_account) as $account
  | ($group[0] | qualified_group($request[0].firewall_id)) as $sg
  | $vpc[0] | qualified_vpc($sg.VpcId;$account;$request[0].region)
elif $mode == "configuration_projection" then configuration_projection
elif $mode == "configuration_observation" then configuration_observation
elif $mode == "configuration_change" then configuration_change
elif $mode == "configuration_after" then configuration_after
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
