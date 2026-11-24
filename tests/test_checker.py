import sys,unittest,tempfile,hashlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from bundle_checker import check_bundle,parse_manifest
class CheckerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);(self.root/"x").write_bytes(b"SYN");self.m={"schema":1,"files":[{"path":"x","sha256":hashlib.sha256(b"SYN").hexdigest()}]}
 def tearDown(self):self.tmp.cleanup()
 def test_matching_bytes_without_authenticity_claim(self):
  v=check_bundle(self.root,self.m);self.assertTrue(v["integrity_matches"]);self.assertFalse(v["authenticity_established"])
 def test_changed_file_detected(self):
  (self.root/"x").write_bytes(b"changed");self.assertFalse(check_bundle(self.root,self.m)["integrity_matches"])
 def test_traversal_and_absolute_rejected(self):
  for p in ["../outside","/etc/passwd"]:
   with self.subTest(path=p),self.assertRaises(ValueError):check_bundle(self.root,{"schema":1,"files":[dict(self.m["files"][0],path=p)]})
 def test_symlink_rejected(self):
  (self.root/"link").symlink_to(self.root/"x")
  with self.assertRaises(ValueError):check_bundle(self.root,{"schema":1,"files":[dict(self.m["files"][0],path="link")]})
 def test_duplicate_path_rejected(self):
  with self.assertRaises(ValueError):check_bundle(self.root,{"schema":1,"files":self.m["files"]*2})
 def test_large_file_rejected(self):
  with self.assertRaises(ValueError):check_bundle(self.root,self.m,max_bytes=2)
 def test_missing_artifact_rejected(self):
  (self.root/"x").unlink()
  with self.assertRaises(ValueError):check_bundle(self.root,self.m)
 def test_duplicate_json_keys_rejected(self):
  with self.assertRaises(ValueError):parse_manifest(b'{"schema":1,"schema":2,"files":[]}')

 def test_noncanonical_alias_and_boolean_schema_rejected(self):
  with self.assertRaises(ValueError):check_bundle(self.root,{"schema":1,"files":[dict(self.m["files"][0],path="./x")]})
  with self.assertRaises(ValueError):check_bundle(self.root,dict(self.m,schema=True))
