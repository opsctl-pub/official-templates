import json
import ssl
import sys
import urllib.error
import urllib.request

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

url, expected_raw, needle, headers_raw, validate_raw = sys.argv[1:6]
expected = int(expected_raw)
validate_certs = validate_raw == "true"
result = {
    "body_match": needle == "",
    "error_code": "connection_failed",
    "status": 0,
}
try:
    headers = json.loads(headers_raw)
    if not isinstance(headers, dict):
        raise ValueError("health headers must be an object")
    request = urllib.request.Request(url, headers=headers)
    handlers = [NoRedirectHandler()]
    if url.startswith("https://") and not validate_certs:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        handlers.append(
            urllib.request.HTTPSHandler(
                context=ssl_context
            )
        )
    opener = urllib.request.build_opener(*handlers)
    try:
        response = opener.open(request, timeout=6)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        result["status"] = response.getcode()
        body = response.read(65537)
    if len(body) > 65536:
        result["error_code"] = "response_too_large"
        print(json.dumps(result, separators=(",", ":")))
        raise SystemExit(4)
    result["body_match"] = (
        needle == ""
        or needle in body.decode("utf-8", errors="replace")
    )
    if result["status"] != expected:
        result["error_code"] = "status_mismatch"
        print(json.dumps(result, separators=(",", ":")))
        raise SystemExit(2)
    if not result["body_match"]:
        result["error_code"] = "content_mismatch"
        print(json.dumps(result, separators=(",", ":")))
        raise SystemExit(3)
    result["error_code"] = "none"
    print(json.dumps(result, separators=(",", ":")))
except Exception:
    print(json.dumps(result, separators=(",", ":")))
    raise SystemExit(5)
