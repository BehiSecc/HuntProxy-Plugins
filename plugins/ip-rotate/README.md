# IpRotate

IpRotate provisions regional AWS API Gateways and routes matching HuntProxy traffic through them in round-robin order. Each profile belongs to one HuntProxy project, matches one exact target origin, and remains active until it is disabled.

IpRotate is a traffic-routing utility rather than a vulnerability scanner. Its actions manage the gateway lifecycle and return status instead of creating findings.

## Requirements

You need:

- Python 3 with `boto3` importable by the same environment that runs HuntProxy;
- an AWS access key and secret, with an optional session token;
- permission to create, configure, deploy, inspect, and delete API Gateway REST APIs in every selected region; and
- the exact HTTP or HTTPS origin and one or more AWS regions.

Credentials stay in the plugin directory and are read by HuntProxy rather than plugin JavaScript.

Choose 1–30 unique AWS regions. The deployment stage defaults to `huntproxy`; an existing profile for the same project and origin must be disabled and cleaned up before it can be replaced.

## Set Up AWS Credentials

For a default HuntProxy installation:

```bash
cp ~/.huntproxy/plugins/ip-rotate/aws-credentials.toml.example \
   ~/.huntproxy/plugins/ip-rotate/aws-credentials.toml
chmod 600 ~/.huntproxy/plugins/ip-rotate/aws-credentials.toml
```

Then edit the file:

```toml
access_key_id = "..."
secret_access_key = "..."
# session_token = "..."
```

Confirm that the Python environment HuntProxy will use can load the AWS SDK:

```bash
python3 -c 'import boto3'
```

## Example Prompts

Enable rotation:

```text
Use HuntProxy MCP. Enable IpRotate in project 1 for
https://api.example.com across us-east-1, us-west-2, and eu-west-1.
Show me the provisioned regions when it is ready.
```

Inspect or remove it later:

```text
Show the IpRotate status for project 1.
```

```text
Disable IpRotate for https://api.example.com in project 1 and show me whether
any AWS regions still need cleanup.
```

## How It Works

| Action | What Happens |
| --- | --- |
| `enable` | Creates one regional REST API per selected region, deploys a proxy stage, and saves an active project profile. |
| `status` | Lists enabled and cleanup-pending profiles for the project. |
| `disable` | Stops local rotation first, then deletes the HuntProxy-managed gateways. Failed regions remain visible so `disable` can be run again. |

Matching requests rotate through the provisioned gateway endpoints while HuntProxy History keeps the original target URL and records the selected region.

## What Uses Rotation

| Uses IpRotate | Bypasses IpRotate |
| --- | --- |
| Proxy and managed Browser HTTP traffic | Raw HTTP/1 and raw HTTP/2 operations |
| Reply and Fuzzer requests | HTTP/1 last-byte and HTTP/2 synchronized races |
| Crawler and semantic plugin requests | WebSocket upgrades |

Matching is exact across scheme, host, and port. A different subdomain, scheme, or port needs its own profile.

## Costs and Cleanup

IpRotate creates real public AWS Regional REST APIs. AWS charges for API calls and data transferred, with rates depending on the account and region. See [Amazon API Gateway pricing](https://aws.amazon.com/api-gateway/pricing/).

The plugin does not enforce a spending limit or automatic expiration. Disable profiles when finished and check `status` until no cleanup-pending regions remain. A project cannot be deleted while one of these profiles still exists.

Gateway endpoints use no API Gateway authorization layer. The upstream application's own authentication still applies, but anyone who learns a gateway URL can send traffic through it.

## Current Limits

- Rotation selects gateway regions, not a guaranteed new or unique source IP for every request; AWS controls actual egress addresses.
- API Gateway can normalize headers and protocol behavior and applies AWS payload, timeout, and service limits, so raw and byte-exact transports bypass it.
- The target must be publicly reachable from AWS over HTTP or HTTPS; private VPC integrations are not created.
- A failed enable performs best-effort cleanup but can leave an untracked `HuntProxy-IpRotate-*` API. Check the selected regions in AWS after provisioning failures.
- There is no automatic TTL, scheduled cleanup, spending cap, or gateway API-key protection.
