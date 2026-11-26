"""One bounded AWS SDK transport for the authored network.sh reads."""

import json
import os
import signal
import sys
import time
from datetime import datetime


class ReadDeadlineExceeded(Exception):
    """The wall timer expired inside this collection."""


def expire(_signal, _frame):
    raise ReadDeadlineExceeded()


def clients(region):
    import boto3
    from botocore.config import Config

    session = boto3.Session(
        aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        aws_session_token=os.environ.get("AWS_SECURITY_TOKEN") or os.environ.get("AWS_SESSION_TOKEN"),
        region_name=region,
    )
    config = Config(
        connect_timeout=5,
        read_timeout=12,
        retries={"mode": "standard", "total_max_attempts": 1},
        ignore_configured_endpoint_urls=True,
    )
    sts = session.client("sts", config=config)
    ec2 = session.client("ec2", config=config)
    return {
        "identity": (sts.get_caller_identity, None),
        "vpc": (ec2.describe_vpcs, "VpcIds"),
        "instances": (ec2.describe_instances, "InstanceIds"),
        "groups": (ec2.describe_security_groups, "GroupIds"),
        "interfaces": (ec2.describe_network_interfaces, "Filters"),
        "rules": (ec2.describe_security_group_rules, "Filters"),
    }


def encode_datetime(value):
    """Serialize SDK timestamps without dropping provider fields."""
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError()


def read(method, binding, identities):
    if binding is None:
        if identities:
            raise ValueError()
        result = method()
    else:
        if not identities:
            raise ValueError()
        values = identities
        if binding == "Filters":
            values = [{"Name": "group-id", "Values": identities}]
        result = method(**{binding: values})
    result.pop("ResponseMetadata", None)
    data = json.dumps(result, default=encode_datetime, separators=(",", ":"), allow_nan=False)
    if len(data) + 1 > 262144:
        raise ValueError()
    return data


def main(region, deadline):
    """Use the entrypoint's absolute deadline and one wall timer per request."""
    stop = time.monotonic() + (deadline - time.time())
    signal.signal(signal.SIGALRM, expire)
    methods = None
    for expected in ("identity", "vpc", "instances", "groups", "interfaces", "rules"):
        line = sys.stdin.readline(4097)
        if not line:
            return
        try:
            duration = min(12, stop - time.monotonic())
            if duration <= 0:
                raise ReadDeadlineExceeded()
            signal.setitimer(signal.ITIMER_REAL, duration)
            role, *identities = line.split()
            if len(line) > 4096 or not line.endswith("\n") or role != expected:
                raise ValueError()
            if methods is None:
                methods = clients(region)
            data = read(*methods[role], identities)
        except ReadDeadlineExceeded:
            print(124, flush=True)
            return
        except Exception:
            print(1, flush=True)
            return
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
        print(f"0\n{data}", flush=True)


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]))
