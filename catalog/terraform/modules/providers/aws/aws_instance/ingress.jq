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

def native_id($prefix): type == "string" and test("^" + $prefix + "-([0-9a-f]{8}|[0-9a-f]{17})$");
def bounded_text: type == "string" and length > 0 and length <= 255 and all(explode[]; . >= 32 and . != 127);
def configuration_rules:
  type == "array" and length <= 67 and all(.[]; rule) and length == (unique | length);
def configuration_state:
  exact(["managed_rules","managed_private_rules"]) and
  (.managed_rules | configuration_rules and length <= 35) and .managed_private_rules == [];
def configuration_request:
  . as $r
  | require(exact(["format_version","action","provider_instance_id","firewall_id","region",
      "ssh_port","managed_rules","managed_private_rules"] +
      (if .action == "change" then ["step","expected_before","expected_after","preserved_policy",
       "expected_before_fingerprint"] else [] end)))
  | require(.format_version == 1 and (.action == "observe" or .action == "change"))
  | require((.provider_instance_id | instance_id) and (.firewall_id | group_id))
  | require(.region | type == "string" and test("^[a-z]{2}(-[a-z]+)+-[0-9]+$"))
  | require((.ssh_port | port) and (.managed_rules | configuration_rules) and .managed_private_rules == [])
  | require(any(.managed_rules[]; .protocol == "tcp" and .port == $r.ssh_port))
  | if .action == "change" then
      require((.expected_before | configuration_state) and (.expected_after | configuration_state))
      | require(.step | exact(["action","rule"]) and (.action == "add" or .action == "remove") and (.rule | rule))
      | require(.step.rule != {protocol:"tcp",port:.ssh_port})
      | require((.expected_before_fingerprint | type == "string" and test("^[0-9a-f]{64}$"))
                and (.preserved_policy | type == "object"))
      | require(all(($r.expected_before.managed_rules + $r.expected_after.managed_rules)[]; . as $rule
          | any($r.managed_rules[]; . == $rule)))
      | .step.rule as $step
      | require(if .step.action == "add" then
          (.expected_before.managed_rules | index($step)) == null and
          ((.expected_before.managed_rules + [$step]) | sort) == (.expected_after.managed_rules | sort)
        else (.expected_before.managed_rules | index($step)) != null and
          ((.expected_before.managed_rules - [$step]) | sort) == (.expected_after.managed_rules | sort) end)
    else . end
  | true;

def cidr($v6):
  require(type == "string" and length <= 49)
  | . as $cidr | split("/") | require(length == 2 and (.[1] | test("^(0|[1-9][0-9]{0,2})$")))
  | (.[1] | tonumber) as $mask
  | if $v6 then
      require($mask <= 128 and (.[0] | test("^[0-9a-fA-F:]+$")))
      | .[0] | split("::")
      | require(length <= 2)
      | ([.[] | select(length > 0) | split(":")[]]) as $groups
      | require(all($groups[]; test("^[0-9a-fA-F]{1,4}$"))
          and (if length == 1 then ($groups | length) == 8 else ($groups | length) < 8 end))
    else
      require($mask <= 32)
      | .[0] | split(".")
      | require(length == 4 and all(.[]; test("^(0|[1-9][0-9]{0,2})$") and tonumber <= 255))
    end
  | $cidr;

def native_fact($native; $peer; $description; $egress):
  require(($description == null or ($description | type == "string" and length <= 255))
      and ($egress | type == "boolean"))
  | ($native | if .IpProtocol == "-1" then
       require((has("FromPort") | not) and (has("ToPort") | not) or (.FromPort == -1 and .ToPort == -1))
       | {protocol:"all",port_start:null,port_end:null}
     else require((.IpProtocol == "tcp" or .IpProtocol == "udp") and (.FromPort | port) and (.ToPort | port)
                  and .FromPort <= .ToPort)
       | {protocol:.IpProtocol,port_start:.FromPort,port_end:.ToPort} end) as $rule
  | {egress:$egress, description:$description,
     rule:($rule + {peers:[{kind:"address",identity:$peer}]})};
def detailed_rule($group):
  require(type == "object" and (keys - ["SecurityGroupRuleId","GroupId","GroupOwnerId","IsEgress",
      "IpProtocol","FromPort","ToPort","CidrIpv4","CidrIpv6","Description","SecurityGroupRuleArn","Tags"]) == [])
  | require(.GroupId == $group.GroupId and (.GroupOwnerId == null or .GroupOwnerId == $group.OwnerId))
  | require(.SecurityGroupRuleId | native_id("sgr"))
  | require((.CidrIpv4 == null) != (.CidrIpv6 == null))
  | (if .CidrIpv4 != null then .CidrIpv4 | cidr(false) else .CidrIpv6 | cidr(true) end) as $peer
  | {id:.SecurityGroupRuleId, fact:native_fact(.;$peer;.Description;.IsEgress)};
def group_rules($egress):
  require(type == "array" and length <= 100)
  | [.[] | require(type == "object" and (keys - ["IpProtocol","FromPort","ToPort",
      "IpRanges","Ipv6Ranges","UserIdGroupPairs","PrefixListIds"]) == []
      and (.UserIdGroupPairs // []) == [] and (.PrefixListIds // []) == []
      and ((.IpRanges // []) | type == "array") and ((.Ipv6Ranges // []) | type == "array"))
      | . as $permission
      | ([ (.IpRanges // [])[] | require((keys - ["CidrIp","Description"]) == [])
           | {peer:(.CidrIp | cidr(false)), description:.Description} ]
         + [ (.Ipv6Ranges // [])[] | require((keys - ["CidrIpv6","Description"]) == [])
           | {peer:(.CidrIpv6 | cidr(true)), description:.Description} ])
      | require(length > 0 and length <= 100)
      | .[] as $peer
      | native_fact($permission;$peer.peer;$peer.description;$egress)]
  | require(length <= 100);

def exclusive_attachment($r; $sg):
  ($instance[0] | require(type == "object" and .NextToken == null and
       (.Reservations | type == "array" and length == 1 and
        (.[0].Instances | type == "array" and length == 1)))
       | .Reservations[0].Instances[0]) as $host
  | require($host.InstanceId == $r.provider_instance_id and $host.VpcId == $sg.VpcId
        and ($host.SecurityGroups | map(.GroupId)) == [$sg.GroupId]
        and ($host.NetworkInterfaces | type == "array" and length == 1))
  | ($interfaces[0] | require(type == "object" and (keys - ["NetworkInterfaces","NextToken"]) == []
        and .NextToken == null and (.NetworkInterfaces | type == "array" and length == 1))
      | .NetworkInterfaces[0]) as $eni
  | require(($eni.NetworkInterfaceId | native_id("eni")) and $eni.VpcId == $sg.VpcId
        and $eni.Status == "in-use" and ($eni.Groups | map(.GroupId)) == [$sg.GroupId]
        and $eni.Attachment.InstanceId == $r.provider_instance_id
        and $eni.Attachment.Status == "attached" and $eni.Attachment.DeviceIndex == 0
        and ($eni.Attachment.AttachmentId | native_id("eni-attach")))
  | require($host.NetworkInterfaces[0] as $local | $local.NetworkInterfaceId == $eni.NetworkInterfaceId
        and $local.VpcId == $eni.VpcId and $local.Attachment.AttachmentId == $eni.Attachment.AttachmentId
        and ($local.Groups | map(.GroupId)) == [$sg.GroupId])
  | {instance:$r.provider_instance_id, firewall:$sg.GroupId, vpc:$sg.VpcId,
     owner:$sg.OwnerId, interface:$eni.NetworkInterfaceId, attachment:$eni.Attachment.AttachmentId};

def public_tuple:
  .fact as $f
  | if ($f.egress | not) and ($f.rule.protocol == "tcp" or $f.rule.protocol == "udp")
        and $f.rule.port_start == $f.rule.port_end
        and $f.rule.peers[0].identity == "0.0.0.0/0" then [$f.rule.protocol,$f.rule.port_start]
    else null end;
def declared_tuple:
  if .fact.description == "OpsControl declared ingress" then public_tuple else null end;
def includes($tuple): any($request[0].managed_rules[]; [.protocol,.port] == $tuple);
def configuration_projection:
  $request[0] as $r
  | ($group[0] | require(type == "object" and (keys - ["SecurityGroups","NextToken"]) == []
       and .NextToken == null and (.SecurityGroups | type == "array" and length == 1))
      | .SecurityGroups[0]) as $sg
  | require($sg.GroupId == $r.firewall_id and ($sg.GroupName | bounded_text) and ($sg.VpcId | native_id("vpc"))
      and ($sg.OwnerId | type == "string" and test("^[0-9]{12}$")))
  | exclusive_attachment($r;$sg) as $attachment
  | ($native_rules[0] | require(type == "object" and (keys - ["SecurityGroupRules","NextToken"]) == []
       and .NextToken == null and (.SecurityGroupRules | type == "array" and length <= 200))
     | .SecurityGroupRules | map(detailed_rule($sg)) | sort_by(.id)) as $rows
  | require(($rows | map(.id) | unique | length) == ($rows | length))
  | require(($rows | map(.fact) | sort) ==
      ((($sg.IpPermissions | group_rules(false)) + ($sg.IpPermissionsEgress | group_rules(true))) | sort))
  | ["tcp",$r.ssh_port] as $ssh
  | ($rows | map(select(declared_tuple == $ssh))) as $protected
  | require(($protected | length) == 1)
  | ($rows | map(select(declared_tuple as $tuple | $tuple != null and includes($tuple)))) as $managed
  | ($rows - $managed) as $foreign
  | ($managed | map(declared_tuple) | sort) as $logical
  | require(($logical | unique) == $logical)
  | {name:$sg.GroupName, attachment:$attachment, rules:$logical, rows:$rows,
      protected:($foreign + $protected | sort_by(.id)),
      unrelated:[$foreign[] | select(.fact.egress | not) | .fact.rule] | sort,
      outbound:[$foreign[] | select(.fact.egress) | .fact.rule] | sort};
def configuration_observation:
  $request[0] as $r | $projection[0] as $p
  | {provider_instance_id:$r.provider_instance_id,firewall_id:$r.firewall_id,rules:$p.rules,private_rules:[],
     attached_firewall_ids:[$r.firewall_id],attached_instance_ids:[$r.provider_instance_id],settled:true,
     policy_fingerprint:$digest,fingerprint:$fingerprint,
     preserved_policy:{name:$p.name,unrelated_ingress:$p.unrelated,outbound:$p.outbound,
       attached_firewall_ids:[$r.firewall_id],attached_instance_ids:[$r.provider_instance_id],fingerprint:$digest},
     observed_at:$observed,observation_complete:true};
def configuration_change:
  $request[0] as $r | $projection[0] as $p | [$r.step.rule.protocol,$r.step.rule.port] as $step
  | if $r.step.action == "add" then
      require(all($p.rows[]; public_tuple != $step))
      | [{IpProtocol:$step[0],FromPort:$step[1],ToPort:$step[1],
          IpRanges:[{CidrIp:"0.0.0.0/0",Description:"OpsControl declared ingress"}]}]
    else [$p.rows[] | select(declared_tuple == $step) | .id] | require(length == 1) | .[0] end;
def configuration_after:
  [$request[0].step.rule.protocol,$request[0].step.rule.port] as $step
  | ($before[0].rows | map(select(declared_tuple != $step))) ==
    ($projection[0].rows | map(select(declared_tuple != $step)));

if $mode == "request" then $request[0] | if .action == "creation" then request else configuration_request end
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
