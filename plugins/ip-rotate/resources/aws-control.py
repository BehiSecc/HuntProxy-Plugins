import json
import os
import sys
import uuid

try:
    import boto3
except ImportError:
    print("Python package boto3 is not installed", file=sys.stderr)
    raise SystemExit(2)


PREFIX = "HuntProxy-IpRotate-"


def client(region):
    return boto3.client(
        "apigateway",
        region_name=region,
        aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
        aws_session_token=os.environ.get("AWS_SESSION_TOKEN"),
    )


def provision(api, request):
    region = request["region"]
    stage = request["stage_name"]
    target = request["target_url"].rstrip("/")
    created = api.create_rest_api(
        name=PREFIX + uuid.uuid4().hex[:12],
        endpointConfiguration={"types": ["REGIONAL"]},
    )
    rest_api_id = created["id"]
    try:
        resources = api.get_resources(restApiId=rest_api_id)["items"]
        root_id = next(item["id"] for item in resources if item.get("path") == "/")
        proxy_id = api.create_resource(
            restApiId=rest_api_id,
            parentId=root_id,
            pathPart="{proxy+}",
        )["id"]
        api.put_method(
            restApiId=rest_api_id,
            resourceId=root_id,
            httpMethod="ANY",
            authorizationType="NONE",
        )
        api.put_method(
            restApiId=rest_api_id,
            resourceId=proxy_id,
            httpMethod="ANY",
            authorizationType="NONE",
            requestParameters={"method.request.path.proxy": True},
        )
        api.put_integration(
            restApiId=rest_api_id,
            resourceId=root_id,
            httpMethod="ANY",
            type="HTTP_PROXY",
            integrationHttpMethod="ANY",
            uri=target + "/",
            connectionType="INTERNET",
        )
        api.put_integration(
            restApiId=rest_api_id,
            resourceId=proxy_id,
            httpMethod="ANY",
            type="HTTP_PROXY",
            integrationHttpMethod="ANY",
            uri=target + "/{proxy}",
            connectionType="INTERNET",
            requestParameters={
                "integration.request.path.proxy": "method.request.path.proxy"
            },
        )
        api.create_deployment(restApiId=rest_api_id, stageName=stage)
    except Exception:
        try:
            api.delete_rest_api(restApiId=rest_api_id)
        except Exception:
            pass
        raise
    return {
        "action": "provisioned",
        "region": region,
        "rest_api_id": rest_api_id,
        "stage_name": stage,
        "endpoint": "https://{}.execute-api.{}.amazonaws.com/{}".format(
            rest_api_id, region, stage
        ),
    }


def delete(api, request):
    rest_api_id = request["rest_api_id"]
    current = api.get_rest_api(restApiId=rest_api_id)
    if not current.get("name", "").startswith(PREFIX):
        raise RuntimeError("refusing to delete an API not created by HuntProxy IpRotate")
    api.delete_rest_api(restApiId=rest_api_id)
    return {
        "action": "deleted",
        "region": request["region"],
        "rest_api_id": rest_api_id,
    }


def main():
    request = json.load(sys.stdin)
    api = client(request["region"])
    if request["action"] == "provision":
        result = provision(api, request)
    elif request["action"] == "delete":
        result = delete(api, request)
    else:
        raise ValueError("unsupported AWS control action")
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("{}: {}".format(type(error).__name__, error), file=sys.stderr)
        raise SystemExit(1)
