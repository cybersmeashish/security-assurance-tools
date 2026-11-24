"""Bounded manifest/file checks; supplied manifests are not authenticated here."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,re

def check_bundle(root,manifest,max_bytes=8*1024*1024):
    root=Path(root).resolve(strict=True)
    if not root.is_dir() or type(max_bytes) is not int or max_bytes<1:raise ValueError("invalid root/limit")
    if not isinstance(manifest,dict) or set(manifest)!={"schema","files"} or type(manifest["schema"]) is not int or manifest["schema"]!=1:raise ValueError("unsupported manifest")
    entries=manifest["files"]
    if not isinstance(entries,list) or not 1<=len(entries)<=500:raise ValueError("invalid file count")
    seen=set();rows=[]
    for e in entries:
        if not isinstance(e,dict) or set(e)!={"path","sha256"}:raise ValueError("invalid entry fields")
        name=e["path"];digest=e["sha256"]
        if not isinstance(name,str) or not name or "\\" in name or "\x00" in name:raise ValueError("invalid path")
        parts=PurePosixPath(name)
        if parts.is_absolute() or ".." in parts.parts or str(parts)!=name or name in seen:raise ValueError("unsafe/duplicate path")
        seen.add(name)
        if not isinstance(digest,str) or not re.fullmatch(r"[0-9a-f]{64}",digest):raise ValueError("invalid digest")
        current=root
        for part in parts.parts:
            current=current/part
            if current.is_symlink():raise ValueError("symlink is outside the accepted bundle contract")
        try:path=current.resolve(strict=True)
        except FileNotFoundError as ex:raise ValueError("missing artifact") from ex
        if root not in path.parents or not path.is_file():raise ValueError("path escapes bundle or is not a regular file")
        if path.stat().st_size>max_bytes:raise ValueError("artifact exceeds byte limit")
        h=hashlib.sha256()
        with path.open("rb") as f:
            total=0
            for block in iter(lambda:f.read(65536),b""):
                total+=len(block)
                if total>max_bytes:raise ValueError("artifact grew beyond limit")
                h.update(block)
        rows.append({"path":name,"bytes":total,"digest_matches":h.hexdigest()==digest})
    return {"integrity_matches":all(x["digest_matches"] for x in rows),"authenticity_established":False,"files":rows,"scope":"integrity relative to a supplied manifest; stable owned files assumed during check"}

def parse_manifest(raw):
    if len(raw)>1024*1024:raise ValueError("manifest exceeds limit")
    def pairs(items):
        d={}
        for k,v in items:
            if k in d:raise ValueError("duplicate JSON key")
            d[k]=v
        return d
    return json.loads(raw,object_pairs_hook=pairs)

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("bundle",type=Path);p.add_argument("manifest",type=Path);a=p.parse_args()
    try:
        if not a.manifest.is_file():raise ValueError("manifest is not a regular file")
        with a.manifest.open("rb") as f:raw=f.read(1024*1024+1)
        v=check_bundle(a.bundle,parse_manifest(raw));print(json.dumps(v,indent=2));raise SystemExit(0 if v["integrity_matches"] else 2)
    except (ValueError,OSError) as e:print(json.dumps({"integrity_matches":False,"error":str(e)}));raise SystemExit(2)
