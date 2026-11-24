# Canonical EC2 policy and identity facts shared by ingress and provider-network reads.
def require($ok): if $ok then . else error("unqualified") end;
def exact($fields): type == "object" and keys == ($fields | sort);
def port: type == "number" and floor == . and . >= 1 and . <= 65535;
def native_id($prefix): type == "string" and test("^" + $prefix + "-([0-9a-f]{8}|[0-9a-f]{17})$");
def bounded_text: type == "string" and length > 0 and length <= 255 and all(explode[]; . >= 32 and . != 127);
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

def bounded_page($field; $limit):
  require(type == "object" and (keys - [$field,"NextToken"]) == [] and .NextToken == null)
  | .[$field] | require(type == "array" and length <= $limit);
def instance_reservation:
  bounded_page("Reservations";1)
  | require(length == 1 and (.[0].Instances | type == "array" and length == 1))
  | .[0];
def ipv4_number:
  require(type == "string" and test("^(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}$"))
  | split(".") | map(tonumber) | require(all(.[]; . <= 255))
  | reduce .[] as $n (0; . * 256 + $n);
def ipv4_network:
  . as $raw | split("/") | require(length == 2 and (.[1] | test("^(0|[1-9][0-9]?)$")))
  | (.[0] | ipv4_number) as $base | (.[1] | tonumber) as $bits
  | require($bits <= 32)
  | pow(2;32-$bits) as $size | require($base % $size == 0)
  | {base:$base, end:($base + $size - 1), text:$raw};
def usable_host($domain):
  ipv4_number as $ip | ($domain.ipv4_cidr | ipv4_network) as $net
  | $ip > $net.base and $ip < $net.end;
def identity_account:
  require(type == "object" and (.Account | type == "string" and test("^[0-9]{12}$"))
     and (.Arn | bounded_text) and (.UserId | bounded_text)) | .Account;
def qualified_vpc($id; $account; $region):
  bounded_page("Vpcs";1) | require(length == 1) | .[0]
  | require((.VpcId | native_id("vpc")) and .VpcId == $id and .OwnerId == $account and .State == "available")
  | .CidrBlock as $cidr
  | require((.Ipv6CidrBlockAssociationSet // []) == []
      and (.CidrBlockAssociationSet | type == "array" and length == 1
           and .[0].CidrBlock == $cidr and .[0].CidrBlockState.State == "associated"))
  | (.CidrBlock | ipv4_network) as $net
  | require(any(["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"][] | ipv4_network;
        $net.base >= .base and $net.end <= .end))
  | {id:.VpcId, account:$account, region:$region, ipv4_cidr:.CidrBlock};
def qualified_group($firewall):
  bounded_page("SecurityGroups";1) | require(length == 1) | .[0]
  | require(.GroupId == $firewall and (.GroupName | bounded_text) and (.VpcId | native_id("vpc"))
      and (.OwnerId | type == "string" and test("^[0-9]{12}$")));
def exact_rows($group):
  bounded_page("SecurityGroupRules";200) | map(detailed_rule($group)) | sort_by(.id)
  | require((map(.id) | unique | length) == length)
  | require((map(.fact) | sort) ==
      ((($group.IpPermissions | group_rules(false)) + ($group.IpPermissionsEgress | group_rules(true))) | sort));
def covers_tcp($port):
  .rule | .protocol == "all" or (.protocol == "tcp" and .port_start <= $port and .port_end >= $port);
def host_cidr:
  type == "string" and endswith("/32") and (try (ipv4_network | true) catch false);

def exclusive_attachment($r; $sg; $instance_response; $interface_response; $domain):
  ($instance_response | require(type == "object" and .NextToken == null and
       (.Reservations | type == "array" and length == 1 and
        (.[0].Instances | type == "array" and length == 1)))
       | .Reservations[0].Instances[0]) as $host
  | require($host.InstanceId == $r.provider_instance_id and $host.VpcId == $sg.VpcId
        and ($host.SecurityGroups | map(.GroupId)) == [$sg.GroupId]
        and ($host.NetworkInterfaces | type == "array" and length == 1))
  | ($interface_response | require(type == "object" and (keys - ["NetworkInterfaces","NextToken"]) == []
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
     owner:$sg.OwnerId, interface:$eni.NetworkInterfaceId, attachment:$eni.Attachment.AttachmentId}
  | if $domain == null then .
    else
      ($instance_response | instance_reservation) as $reservation
      | $host.NetworkInterfaces[0] as $local
      | $domain.account as $account
      | $host.PrivateIpAddress as $ip
      | require($host.State.Name == "running" and $sg.VpcId == $domain.id and $sg.OwnerId == $account
          and $reservation.OwnerId == $account and $eni.OwnerId == $account
          and $eni.Attachment.InstanceOwnerId == $account and $eni.RequesterManaged == false
          and ($eni.InterfaceType // "interface") == "interface"
          and ($local.OwnerId == null or $local.OwnerId == $account)
          and $local.Attachment.DeviceIndex == 0 and $local.Attachment.Status == "attached"
          and ($eni.SubnetId | native_id("subnet")) and $host.SubnetId == $eni.SubnetId
          and $local.SubnetId == $eni.SubnetId and ($ip | usable_host($domain))
          and all($eni,$local; .PrivateIpAddress == $ip
              and (.PrivateIpAddresses | type == "array" and length == 1
                  and .[0].Primary == true and .[0].PrivateIpAddress == $ip)))
      | . + {host:$ip, subnet:$eni.SubnetId, ipv4_cidr:$domain.ipv4_cidr}
    end;
