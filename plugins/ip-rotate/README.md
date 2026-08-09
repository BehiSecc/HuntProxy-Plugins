# IpRotate

IpRotate creates regional AWS API Gateway HTTP proxy integrations for a scoped
target, cycles a saved HuntProxy request through those endpoints, and removes
the created REST APIs afterward.

Copy `aws-credentials.toml.example` to `aws-credentials.toml` and add the keys.
The host reads this file; its contents are never passed to plugin JavaScript or
returned in job data. Python 3 with the official `boto3` package must be
available to the HuntProxy process.

Use `target_scope` for an exact hostname or a suffix such as `*.example.com`.
Use the target origin (for example `https://api.example.com`) for `target_url`.
Run `provision`, pass its `gateway_endpoints` to `rotate`, then pass its
`deployments` to `cleanup`.
