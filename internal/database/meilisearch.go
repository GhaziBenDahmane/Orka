package database

const meilisearchUtilityImage = "python:3.13-alpine"

func meilisearchEnvironment(host string, credentials map[string]string, filename string) map[string]string {
	return map[string]string{
		"DOCKYARD_MEILI_HOST":       host,
		"DOCKYARD_MEILI_PORT":       nativePort(credentials, 7700),
		"DOCKYARD_MEILI_MASTER_KEY": credentials["password"],
		"DOCKYARD_MEILI_ARTIFACT":   filename,
	}
}

func meilisearchBackupPlan(host string, credentials map[string]string, filename string) BackupPlan {
	return BackupPlan{Image: meilisearchUtilityImage, Command: []string{"python3", "-c", meilisearchBackupScript}, Environment: meilisearchEnvironment(host, credentials, filename), Extension: "tar.gz"}
}

func meilisearchRestorePlan(host string, credentials map[string]string, filename string) RestorePlan {
	return RestorePlan{Image: meilisearchUtilityImage, Command: []string{"python3", "-c", meilisearchRestoreScript}, Environment: meilisearchEnvironment(host, credentials, filename), Extension: "tar.gz"}
}

func meilisearchReadinessPlan(host string, credentials map[string]string) BackupPlan {
	return BackupPlan{
		Image:   meilisearchUtilityImage,
		Command: []string{"python3", "-c", meilisearchReadinessScript},
		Environment: map[string]string{
			"DOCKYARD_MEILI_HOST":       host,
			"DOCKYARD_MEILI_PORT":       nativePort(credentials, 7700),
			"DOCKYARD_MEILI_MASTER_KEY": credentials["password"],
		},
	}
}

const meilisearchBackupScript = `
import json
import os
import tarfile
import tempfile
import urllib.parse
import urllib.request

base = "http://%s:%s" % (os.environ["DOCKYARD_MEILI_HOST"], os.environ["DOCKYARD_MEILI_PORT"])
headers = {"authorization": "Bearer " + os.environ["DOCKYARD_MEILI_MASTER_KEY"]}
target = "/backup/" + os.environ["DOCKYARD_MEILI_ARTIFACT"]

def get(path):
    with urllib.request.urlopen(urllib.request.Request(base + path, headers=headers), timeout=120) as response:
        return json.load(response)

def pages(path):
    offset = 0
    while True:
        separator = "&" if "?" in path else "?"
        page = get(path + separator + "limit=100&offset=" + str(offset))
        items = page.get("results", [])
        for item in items:
            yield item
        offset += len(items)
        if not items or offset >= page.get("total", offset):
            break

with tempfile.TemporaryDirectory(dir="/backup") as directory:
    indexes = []
    for index_number, index in enumerate(sorted(pages("/indexes"), key=lambda value: value["uid"])):
        uid = index["uid"]
        encoded = urllib.parse.quote(uid, safe="")
        index_directory = os.path.join(directory, "index-%d" % index_number)
        os.mkdir(index_directory)
        settings_name = os.path.join(index_directory, "settings.json")
        documents_name = os.path.join(index_directory, "documents.ndjson")
        with open(settings_name, "w", encoding="utf-8") as output:
            json.dump(get("/indexes/%s/settings" % encoded), output, separators=(",", ":"))
        count = 0
        with open(documents_name, "w", encoding="utf-8") as output:
            for document in pages("/indexes/%s/documents" % encoded):
                output.write(json.dumps(document, separators=(",", ":"), ensure_ascii=False) + "\n")
                count += 1
        indexes.append({"uid": uid, "primaryKey": index.get("primaryKey"), "settings": "indexes/%d/settings.json" % index_number, "documents": "indexes/%d/documents.ndjson" % index_number, "documentCount": count})
    keys = []
    for key in pages("/keys"):
        keys.append({field: key.get(field) for field in ("uid", "name", "description", "actions", "indexes", "expiresAt")})
    manifest_name = os.path.join(directory, "manifest.json")
    with open(manifest_name, "w", encoding="utf-8") as output:
        json.dump({"version": 1, "indexes": indexes, "keys": keys}, output, separators=(",", ":"), ensure_ascii=False)
    with tarfile.open(target, "w:gz") as archive:
        archive.add(manifest_name, arcname="manifest.json")
        for index_number in range(len(indexes)):
            archive.add(os.path.join(directory, "index-%d" % index_number, "settings.json"), arcname="indexes/%d/settings.json" % index_number)
            archive.add(os.path.join(directory, "index-%d" % index_number, "documents.ndjson"), arcname="indexes/%d/documents.ndjson" % index_number)
`

const meilisearchRestoreScript = `
import json
import os
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

base = "http://%s:%s" % (os.environ["DOCKYARD_MEILI_HOST"], os.environ["DOCKYARD_MEILI_PORT"])
headers = {"authorization": "Bearer " + os.environ["DOCKYARD_MEILI_MASTER_KEY"]}
source = "/backup/" + os.environ["DOCKYARD_MEILI_ARTIFACT"]

def request(method, path, value=None, expected=(200, 201, 202, 204)):
    request_headers = dict(headers)
    data = None
    if value is not None:
        data = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
        request_headers["content-type"] = "application/json"
    try:
        with urllib.request.urlopen(urllib.request.Request(base + path, data=data, headers=request_headers, method=method), timeout=120) as response:
            body = response.read()
            if response.status not in expected:
                raise RuntimeError("Meilisearch request failed with HTTP %d" % response.status)
            return json.loads(body) if body else None
    except urllib.error.HTTPError as error:
        raise RuntimeError("Meilisearch request failed with HTTP %d: %s" % (error.code, error.read()[:512].decode(errors="replace")))

def wait(task, ignored_error=None):
    uid = task["taskUid"]
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        state = request("GET", "/tasks/%s" % uid)
        if state["status"] == "succeeded":
            return
        if state["status"] in ("failed", "canceled"):
            if ignored_error is not None and state.get("error", {}).get("code") == ignored_error:
                return
            raise RuntimeError("Meilisearch task %s ended as %s: %s" % (uid, state["status"], state.get("error")))
        time.sleep(0.2)
    raise RuntimeError("Meilisearch task %s timed out" % uid)

def member(archive, name, maximum=None):
    if not isinstance(name, str) or name.startswith("/") or ".." in name.split("/"):
        raise RuntimeError("invalid Meilisearch archive path")
    entry = archive.getmember(name)
    if not entry.isfile() or (maximum is not None and entry.size > maximum):
        raise RuntimeError("invalid Meilisearch archive entry")
    return entry

with tarfile.open(source, "r:gz") as archive:
    manifest_entry = member(archive, "manifest.json", 1024 * 1024)
    manifest = json.load(archive.extractfile(manifest_entry))
    if manifest.get("version") != 1 or not isinstance(manifest.get("indexes"), list) or not isinstance(manifest.get("keys"), list):
        raise RuntimeError("unsupported Meilisearch backup manifest")
    for index in manifest["indexes"]:
        uid = index["uid"]
        if not isinstance(uid, str) or not uid:
            raise RuntimeError("invalid Meilisearch index UID")
        encoded = urllib.parse.quote(uid, safe="")
        try:
            wait(request("DELETE", "/indexes/" + encoded), "index_not_found")
        except RuntimeError as error:
            if "HTTP 404" not in str(error):
                raise
        create = {"uid": uid}
        if index.get("primaryKey") is not None:
            create["primaryKey"] = index["primaryKey"]
        wait(request("POST", "/indexes", create))
        settings_entry = member(archive, index["settings"], 16 * 1024 * 1024)
        settings = json.load(archive.extractfile(settings_entry))
        wait(request("PATCH", "/indexes/%s/settings" % encoded, settings))
        documents_entry = member(archive, index["documents"])
        documents = archive.extractfile(documents_entry)
        batch = []
        for line in documents:
            if line.strip():
                batch.append(json.loads(line))
            if len(batch) == 100:
                wait(request("POST", "/indexes/%s/documents" % encoded, batch))
                batch = []
        if batch:
            wait(request("POST", "/indexes/%s/documents" % encoded, batch))
    existing_keys = set()
    key_offset = 0
    while True:
        page = request("GET", "/keys?limit=100&offset=%d" % key_offset)
        items = page.get("results", [])
        existing_keys.update(item["uid"] for item in items)
        key_offset += len(items)
        if not items or key_offset >= page.get("total", key_offset):
            break
    for key in manifest["keys"]:
        if key.get("uid") not in existing_keys:
            request("POST", "/keys", key)
`

const meilisearchReadinessScript = `
import os
import urllib.request

url = "http://%s:%s/health" % (os.environ["DOCKYARD_MEILI_HOST"], os.environ["DOCKYARD_MEILI_PORT"])
request = urllib.request.Request(url, headers={"authorization": "Bearer " + os.environ["DOCKYARD_MEILI_MASTER_KEY"]})
with urllib.request.urlopen(request, timeout=10) as response:
    if response.status != 200:
        raise RuntimeError("Meilisearch is not healthy")
`
