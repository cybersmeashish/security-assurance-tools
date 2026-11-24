import json
from bundle_checker import check_bundle

def run(root,output):
    m=json.loads((root/"fixtures/manifest.json").read_text());valid=check_bundle(root/"fixtures/bundle",m)
    altered={"schema":1,"files":[dict(m["files"][0],sha256="0"*64)]};bad=check_bundle(root/"fixtures/bundle",altered)
    return {"scope":"actual local manifest and fixture byte checks; no authenticated signing or production admission","valid_bundle":valid,"mismatched_digest":bad,"tool_version":"0.1.0-contribution-preview"}
