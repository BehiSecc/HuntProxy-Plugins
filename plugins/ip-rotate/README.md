# IpRotate

IpRotate enables project-level AWS API Gateway routing for one exact target
origin. While enabled, matching Proxy, Browser, Reply, Fuzzer, crawler, and
semantic plugin requests automatically rotate across the configured regions.
Raw HTTP operations remain exact and bypass rotation.

Copy `aws-credentials.toml.example` to `aws-credentials.toml` and add the keys.
Python 3 with the official `boto3` package must be available to HuntProxy.

Use `enable` with the target origin and regions, `status` to inspect active or
cleanup-pending profiles, and `disable` when finished. Disable stops routing
before deleting the HuntProxy-managed API Gateways. If AWS cleanup partly
fails, run `disable` again.
