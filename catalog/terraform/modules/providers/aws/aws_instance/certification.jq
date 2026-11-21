def demand($value): if $value then . else error("unqualified") end;
def exact($fields): type == "object" and keys == ($fields | sort);
def native_id($kind):
  {"instance":"i","security_group":"sg","volume":"vol"}[$kind] as $prefix
  | type == "string" and test("^"+$prefix+"-([0-9a-f]{8}|[0-9a-f]{17})$");
def request:
  demand(exact(["action","region","name","tags","resources"]))
  | demand(.action == "preflight" or .action == "discover" or .action == "cleanup" or .action == "absence")
  | demand(.region | type == "string" and test("^[a-z]{2}(-[a-z]+)+-[0-9]+$"))
  | demand(.name | type == "string" and test("^opsctl-cert-[0-9a-f]{32}$"))
  | demand(.tags | type == "array" and length >= 2 and length <= 128
      and index("opsctl") != null and any(.[]; type == "string" and startswith("org-"))
      and all(.[]; type == "string" and length >= 1 and length <= 255 and . != "Name")
      and length == (unique | length))
  | demand(.resources | type == "array" and length <= 3
      and all(.[]; .kind as $kind | exact(["kind","id"])
          and (["instance","security_group","volume"] | index($kind) != null) and (.id | native_id($kind)))
      and length == (map(.kind) | unique | length))
  | demand(if .action == "cleanup" then (.resources | length > 0)
      elif .action == "absence" then true else .resources == [] end);

def page:
  {"instance":"Reservations","security_group":"SecurityGroups","volume":"Volumes"}[$kind] as $key
  | demand(type == "object" and (keys - [$key,"NextToken"]) == [])
  | demand(.[$key] | type == "array" and length <= 100)
  | demand(.NextToken == null or (.NextToken | type == "string" and length > 0 and length <= 4096
      and test("^[!-~]+$")))
  | {next:.NextToken, rows:(.[$key] | if $kind == "instance" then
      demand(all(.[]; type == "object" and (.Instances | type == "array" and length <= 100)))
      | [.[].Instances[]] else . end)};

def owned($request):
  demand(.Tags | type == "array" and length <= 256
    and all(.[]; type == "object" and (.Key | type == "string") and (.Value | type == "string"))
    and length == (map(.Key) | unique | length))
  | (.Tags | map({key:.Key,value:.Value}) | from_entries) as $actual
  | demand($actual.Name == $request.name and all($request.tags[]; $actual[.] == "true"));

def identity($kind):
  .[{"instance":"InstanceId","security_group":"GroupId","volume":"VolumeId"}[$kind]]
  | demand(native_id($kind));

def rows($kind; $expected):
  demand(type == "array" and length <= 1)
  | map(demand(type == "object") | owned($request[0])
      | identity($kind) as $id
      | demand($expected == "" or $id == $expected)
      | if $kind == "instance" then
          demand(.State.Name as $state | ["pending","running","stopping","stopped","shutting-down"] | index($state) != null)
        else . end);

def root_device($volume):
  demand(.RootDeviceType == "ebs" and (.RootDeviceName | type == "string" and length > 0))
  | .RootDeviceName as $device
  | demand(.BlockDeviceMappings | type == "array" and length == 1
      and .[0].DeviceName == $device and .[0].Ebs.VolumeId == $volume
      and .[0].Ebs.DeleteOnTermination == true)
  | $device;

def safe_volume($instance; $device):
  .VolumeId as $id
  | demand(.Attachments | type == "array" and length <= 1)
  | if .Attachments == [] then demand(.State == "available")
    else demand(.State == "in-use" and $instance != "" and .Attachments[0].InstanceId == $instance
      and .Attachments[0].VolumeId == $id and .Attachments[0].Device == $device
      and .Attachments[0].State == "attached") end;

def orphan_volume($proof_instance):
  .VolumeId as $id
  | demand(.Attachments | type == "array" and length <= 1
      and all(.[]; $proof_instance != null and .InstanceId == $proof_instance and .VolumeId == $id))
  | if .State == "deleting" or (.State == "in-use" and .Attachments[0].State == "detaching") then
      "unavailable"
    else safe_volume(""; "") | "safe" end;

if $mode == "request" then $request[0] | request
elif $mode == "page" then page
elif $mode == "rows" then rows($kind; $expected)
elif $mode == "references" then
  [ $instance[] | {kind:"instance",id:identity("instance")} ]
  + [ $group[] | {kind:"security_group",id:identity("security_group")} ]
  + [ $volume[] | {kind:"volume",id:identity("volume")} ]
elif $mode == "scope" then
  $request[0].resources as $held
  | demand(all(.[]; . as $ref | $held | index($ref) != null))
elif $mode == "safe" then
  ($request[0].resources | map(select(.kind == "volume")) | .[0].id) as $root
  | if ($instance | length) == 1 then
      ($instance[0] | root_device($root)) as $device
      | demand(($volume | length) == 1)
      | $volume[0] | safe_volume($instance[0].InstanceId; $device) | "safe"
    elif ($volume | length) == 1 then
      ($request[0].resources | map(select(.kind == "instance")) | .[0].id) as $proof_instance
      | $volume[0] | orphan_volume($proof_instance)
    else "safe" end
else error("invalid mode") end
