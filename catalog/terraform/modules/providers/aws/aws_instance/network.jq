include "network_policy";

def request($region):
  . as $r
  | require(exact(["format_version","action","network_id","region","ipv4_cidr","members","listeners"]))
  | require(.format_version == 1 and (.action == "domain" or .action == "targets")
      and (.network_id | native_id("vpc")))
  | require(($region | test("^[a-z]{2}(-[a-z]+)+-[0-9]+$"))
      and (.region == null or .region == $region)
      and (.ipv4_cidr == null or (.ipv4_cidr | ipv4_network | true)))
  | require(.members | type == "array" and length <= 2 and length == (unique | length)
      and all(.[]; native_id("i")))
  | require(.listeners | type == "array" and length <= 128 and length == (unique | length)
      and all(.[]; exact(["from_id","to_id","protocol","port"]) and .protocol == "tcp"
        and (.port | port) and .from_id != .to_id
        and (.from_id as $id | ($r.members | index($id)) != null)
        and (.to_id as $id | ($r.members | index($id)) != null)))
  | if .action == "domain" then require(.members == [] and .listeners == [])
    else require(.region == $region and .ipv4_cidr != null and (.members | length) > 0) end;

def member_group($id; $domain):
  instance_reservation
  | require(.OwnerId == $domain.account)
  | .Instances[0]
  | require(.InstanceId == $id and .VpcId == $domain.id and .State.Name == "running")
  | .SecurityGroups | require(type == "array" and length == 1)
  | .[0].GroupId | require(native_id("sg"));

def member($id; $firewall; $instances; $groups; $interfaces; $rules; $domain):
  ($groups | qualified_group($firewall)) as $sg
  | exclusive_attachment({provider_instance_id:$id};$sg;$instances;$interfaces;$domain) as $attachment
  | ($rules | exact_rows($sg)) as $policy
  | {id:$id, host:$attachment.host, attachment:$attachment, policy:$policy};

def member_selection($ids; $domain):
  ($ids | length) as $count
  | bounded_page("Reservations";$count)
  | [ .[] | require(.OwnerId == $domain.account
                    and (.Instances | type == "array" and length > 0 and length <= $count))
      | .OwnerId as $owner | .Instances[] | {OwnerId:$owner, Instances:[.]} ]
  | require((map(.Instances[0].InstanceId) | sort) == ($ids | sort))
  | . as $reservations
  | [ $ids[] as $id
      | {Reservations:[$reservations[] | select(.Instances[0].InstanceId == $id)]} as $instances
      | {id:$id, firewall:($instances | member_group($id;$domain)), instances:$instances} ]
  | require((map(.firewall) | unique | length) == $count);

def qualified_members($selection; $group_reply; $interface_reply; $rule_reply; $domain):
  ($selection | map(.firewall) | sort) as $firewalls
  | ($firewalls | length) as $count
  | ($group_reply | bounded_page("SecurityGroups";$count)
      | require((map(.GroupId) | sort) == $firewalls)) as $groups
  | ($interface_reply | bounded_page("NetworkInterfaces";$count)
      | require(all(.[]; .Groups | type == "array" and length == 1)
          and (map(.Groups[0].GroupId) | sort) == $firewalls
          and (map(.NetworkInterfaceId) | unique | length) == $count)) as $interfaces
  | ($rule_reply | bounded_page("SecurityGroupRules";($count * 200))
      | require(all(.[]; .GroupId as $id | ($firewalls | index($id)) != null)
          and (map(.SecurityGroupRuleId) | unique | length) == length)) as $rules
  | $selection[] as $member
  | $member.firewall as $firewall
  | member($member.id;$firewall;$member.instances;
      {SecurityGroups:[$groups[] | select(.GroupId == $firewall)]};
      {NetworkInterfaces:[$interfaces[] | select(.Groups[0].GroupId == $firewall)]};
      {SecurityGroupRules:[$rules[] | select(.GroupId == $firewall)]};$domain);

def permits_host($host):
  ($host | ipv4_number) as $ip
  | .rule.peers[0].identity
  | if contains(":") then false
    else ipv4_network | $ip >= .base and $ip <= .end end;
def listener($members; $listeners):
  . as $l
  | ($members[] | select(.id == $l.from_id)) as $source
  | ($members[] | select(.id == $l.to_id)) as $target
  | [$target.policy[].fact | select((.egress | not) and covers_tcp($l.port))] as $inbound
  | [$listeners[] | select(.to_id == $l.to_id and .port == $l.port) | .from_id] as $approved
  | require(all($inbound[]; . as $row | $row.rule.protocol == "tcp"
      and $row.rule.port_start == $l.port and $row.rule.port_end == $l.port and
      any($members[]; . as $peer | ($approved | index($peer.id)) != null
           and $row.rule.peers[0].identity == ($peer.host + "/32"))))
  | require(any($source.policy[].fact; .egress and covers_tcp($l.port) and permits_host($target.host)))
  | any($inbound[]; permits_host($source.host));

$request[0] as $r
| if $mode == "request" then $r | request($region)
  elif $mode == "identity" then $payload[0] | identity_account
  elif $mode == "domain" then
    $payload[0] | qualified_vpc($r.network_id;$account;$region)
    | require($r.ipv4_cidr == null or $r.ipv4_cidr == .ipv4_cidr)
  elif $mode == "instances" then $instance[0] | member_selection($r.members;$domain[0])
  elif $mode == "members" then
    qualified_members($selection[0];$group[0];$interfaces[0];$rules[0];$domain[0])
  elif $mode == "listeners" then
    $members | require((map(.host) | unique | length) == length)
    | require((map(.attachment.firewall) | unique | length) == length
         and (map(.attachment.interface) | unique | length) == length
         and (map(.attachment.attachment) | unique | length) == length)
    | [$r.listeners[] | select((listener($members;$r.listeners)) | not)]
  else error("mode") end
