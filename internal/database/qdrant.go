package database

const qdrantUtilityImage = "python:3.13-alpine"

func qdrantEnvironment(host string, credentials map[string]string, filename string) map[string]string {
	return map[string]string{
		"DOCKYARD_QDRANT_HOST":     host,
		"DOCKYARD_QDRANT_PORT":     nativePort(credentials, 6333),
		"DOCKYARD_QDRANT_API_KEY":  credentials["password"],
		"DOCKYARD_QDRANT_ARTIFACT": filename,
	}
}

func qdrantBackupPlan(host string, credentials map[string]string, filename string) BackupPlan {
	return BackupPlan{
		Image:       qdrantUtilityImage,
		Command:     []string{"python3", "-c", qdrantBackupScript},
		Environment: qdrantEnvironment(host, credentials, filename),
		Extension:   "tar.gz",
	}
}

func qdrantRestorePlan(host string, credentials map[string]string, filename string) RestorePlan {
	return RestorePlan{
		Image:       qdrantUtilityImage,
		Command:     []string{"python3", "-c", qdrantRestoreScript},
		Environment: qdrantEnvironment(host, credentials, filename),
		Extension:   "tar.gz",
	}
}

func qdrantReadinessPlan(host string, credentials map[string]string) BackupPlan {
	return BackupPlan{
		Image:   qdrantUtilityImage,
		Command: []string{"python3", "-c", qdrantReadinessScript},
		Environment: map[string]string{
			"DOCKYARD_QDRANT_HOST":    host,
			"DOCKYARD_QDRANT_PORT":    nativePort(credentials, 6333),
			"DOCKYARD_QDRANT_API_KEY": credentials["password"],
		},
	}
}

const qdrantBackupScript = `
import json
import os
import shutil
import tarfile
import tempfile
import urllib.parse
import urllib.request

base = "http://%s:%s" % (os.environ["DOCKYARD_QDRANT_HOST"], os.environ["DOCKYARD_QDRANT_PORT"])
headers = {"api-key": os.environ["DOCKYARD_QDRANT_API_KEY"]}
target = "/backup/" + os.environ["DOCKYARD_QDRANT_ARTIFACT"]

def request(method, path, body=None):
    request_headers = dict(headers)
    if body is not None:
        request_headers["content-type"] = "application/json"
    return urllib.request.urlopen(urllib.request.Request(base + path, data=body, headers=request_headers, method=method), timeout=120)

with request("GET", "/collections") as response:
    collections = [item["name"] for item in json.load(response)["result"]["collections"]]

with tempfile.TemporaryDirectory(dir="/backup") as directory:
    manifest = []
    for index, collection in enumerate(sorted(collections)):
        encoded = urllib.parse.quote(collection, safe="")
        with request("POST", "/collections/%s/snapshots" % encoded, b"{}") as response:
            snapshot = json.load(response)["result"]["name"]
        archive_name = "snapshots/%d.snapshot" % index
        local_name = os.path.join(directory, "%d.snapshot" % index)
        snapshot_path = "/collections/%s/snapshots/%s" % (encoded, urllib.parse.quote(snapshot, safe=""))
        with request("GET", snapshot_path) as response, open(local_name, "wb") as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
        manifest.append({"collection": collection, "snapshot": snapshot, "file": archive_name})
    manifest_name = os.path.join(directory, "manifest.json")
    with open(manifest_name, "w", encoding="utf-8") as output:
        json.dump({"version": 1, "collections": manifest}, output, separators=(",", ":"))
    with tarfile.open(target, "w:gz") as archive:
        archive.add(manifest_name, arcname="manifest.json")
        for index in range(len(manifest)):
            archive.add(os.path.join(directory, "%d.snapshot" % index), arcname="snapshots/%d.snapshot" % index)
`

const qdrantRestoreScript = `
import http.client
import json
import os
import tarfile
import urllib.parse

host = os.environ["DOCKYARD_QDRANT_HOST"]
port = int(os.environ["DOCKYARD_QDRANT_PORT"])
api_key = os.environ["DOCKYARD_QDRANT_API_KEY"]
source = "/backup/" + os.environ["DOCKYARD_QDRANT_ARTIFACT"]

with tarfile.open(source, "r:gz") as archive:
    manifest_member = archive.getmember("manifest.json")
    if not manifest_member.isfile() or manifest_member.size > 1024 * 1024:
        raise RuntimeError("invalid Qdrant backup manifest")
    manifest = json.load(archive.extractfile(manifest_member))
    if manifest.get("version") != 1 or not isinstance(manifest.get("collections"), list):
        raise RuntimeError("unsupported Qdrant backup manifest")
    for item in manifest["collections"]:
        collection = item["collection"]
        snapshot_name = item["snapshot"]
        archive_name = item["file"]
        if not isinstance(collection, str) or not collection or not isinstance(snapshot_name, str) or not snapshot_name.endswith(".snapshot"):
            raise RuntimeError("invalid Qdrant snapshot metadata")
        if not isinstance(archive_name, str) or not archive_name.startswith("snapshots/") or archive_name.count("/") != 1 or ".." in archive_name:
            raise RuntimeError("invalid Qdrant snapshot path")
        member = archive.getmember(archive_name)
        if not member.isfile():
            raise RuntimeError("invalid Qdrant snapshot entry")
        boundary = "dockyard-" + os.urandom(16).hex()
        prefix = ("--%s\r\nContent-Disposition: form-data; name=\"snapshot\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n" % (boundary, snapshot_name)).encode()
        suffix = ("\r\n--%s--\r\n" % boundary).encode()
        path = "/collections/%s/snapshots/upload?priority=snapshot" % urllib.parse.quote(collection, safe="")
        connection = http.client.HTTPConnection(host, port, timeout=300)
        connection.putrequest("POST", path)
        connection.putheader("api-key", api_key)
        connection.putheader("content-type", "multipart/form-data; boundary=" + boundary)
        connection.putheader("content-length", str(len(prefix) + member.size + len(suffix)))
        connection.endheaders()
        connection.send(prefix)
        snapshot = archive.extractfile(member)
        while True:
            chunk = snapshot.read(1024 * 1024)
            if not chunk:
                break
            connection.send(chunk)
        connection.send(suffix)
        response = connection.getresponse()
        response_body = response.read()
        connection.close()
        if response.status < 200 or response.status >= 300:
            raise RuntimeError("Qdrant snapshot restore failed with HTTP %d: %s" % (response.status, response_body[:512].decode(errors="replace")))
`

const qdrantReadinessScript = `
import os
import urllib.request

url = "http://%s:%s/readyz" % (os.environ["DOCKYARD_QDRANT_HOST"], os.environ["DOCKYARD_QDRANT_PORT"])
request = urllib.request.Request(url, headers={"api-key": os.environ["DOCKYARD_QDRANT_API_KEY"]})
with urllib.request.urlopen(request, timeout=10) as response:
    if response.status != 200:
        raise RuntimeError("Qdrant is not ready")
`
