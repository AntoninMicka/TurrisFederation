"""Exercise the remote shell scripts against an isolated, fake OpenWrt router.

Run: python3 scripts/test_zerotier.py
No SSH connections or system configuration changes are performed.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent
NETWORK = "0123456789abcdef"
OTHER = "1111111111111111"

FAKE_TOOL = r'''#!/usr/bin/python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ["TF_TEST_ROOT"])
state_path = root / "state.json"
state = json.loads(state_path.read_text())
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
def save(): state_path.write_text(json.dumps(state))
def die(): sys.exit(1)
if name == "id":
    print(state.get("uid", 0))
elif name == "uci":
    if args[0] == "-q": args = args[1:]
    op, *args = args
    if op == "changes":
        if state.get("pending"): print("uncommitted")
        sys.exit(0)
    if op in ("commit", "revert"):
        state[op] = state.get(op, 0) + 1; save(); sys.exit(0)
    if op == "add":
        key = "section" + str(len(state["sections"]))
        state["sections"][key] = {"type": args[1]}; save(); print(key); sys.exit(0)
    key, sep, value = args[0].partition("=")
    parts = key.split(".")
    section = parts[1]
    if section.startswith("@"):
        kind, index = section[1:].rstrip("]").split("[")
        candidates = [k for k,v in state["sections"].items() if v["type"] == kind]
        if int(index) >= len(candidates): die()
        section = candidates[int(index)]
    field = parts[2] if len(parts) > 2 else "type"
    if op == "get":
        try: value = state["sections"][section][field]
        except KeyError: die()
        print(" ".join(value) if isinstance(value,list) else value)
    elif op == "set":
        state["sections"].setdefault(section,{})[field] = value; save()
    elif op == "add_list":
        state["sections"][section].setdefault(field,[]).append(value); save()
    elif op == "delete":
        del state["sections"][section]; save()
    else: raise AssertionError(op)
elif name == "opkg":
    state.setdefault("opkg",[]).append(args[0]); save()
    if state.get("install_fail"): print("repository unavailable", file=sys.stderr); die()
    if args[0] == "install":
        executable = root / "bin" / "zerotier-cli"
        executable.write_text((root / "tool").read_text()); executable.chmod(0o755)
elif name == "zerotier-cli":
    if args[0] == "-j": args = args[1:]
    if args[0] == "info":
        if not state.get("running"): die()
        print(json.dumps({"address":"abcdef1234", "online":True,"version":"1.14.0"}))
    elif args[0] == "listnetworks":
        print(json.dumps([{"nwid":n,"status":"ACCESS_DENIED"} for n in state.get("joined",[])]))
    elif args[0] == "join":
        state["joined"] = sorted(set(state.get("joined",[]) + [args[1]])); save(); print("200 join OK")
    elif args[0] == "set":
        assert len(args) == 4, args
        state.setdefault("settings",{})[args[2]] = args[3]; save()
    else: raise AssertionError(args)
elif name == "zerotier":
    state.setdefault("service_calls",[]).append(args[0])
    if args[0] == "start": state["running"] = True
    if args[0] == "enable": state["enabled"] = True
    save()
    if args[0] == "enabled" and not state.get("enabled"): die()
'''


class RouterScripts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="tf-zerotier-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for part in ("bin", "etc/init.d", "etc/config", "var/lib/zerotier-one"):
            (self.root / part).mkdir(parents=True)
        (self.root / "tool").write_text(FAKE_TOOL)
        for name in ("uci", "id", "opkg", "zerotier-cli"):
            tool = self.root / "bin" / name
            tool.write_text(FAKE_TOOL)
            tool.chmod(0o755)
        (self.root / "etc/config/zerotier").write_text("original config\n")
        (self.root / "var/lib/zerotier-one/identity.secret").write_text("TEST_IDENTITY_SECRET\n")
        self.env = dict(os.environ, PATH=f"{self.root}/bin:/usr/bin:/bin", TF_TEST_ROOT=str(self.root))

    def write_state(self, schema="old", **extra):
        sections = {"existing": {"type": "zerotier", "enabled": "1", "join": [OTHER], "secret": "KEEP_SECRET"}}
        if schema == "new":
            sections = {"global": {"type": "zerotier", "enabled": "1", "secret": "KEEP_SECRET"}, "other": {"type": "network", "id": OTHER}}
        state = dict(sections=sections, running=True, joined=[OTHER], enabled=True)
        state.update(extra)
        self.store(state)
        service = self.root / "etc/init.d/zerotier"
        marker = "network" if schema == "new" else "zerotier"
        service.write_text(FAKE_TOOL + f"\n# config_foreach join_network {marker}\n")
        service.chmod(0o755)

    def store(self, state):
        (self.root / "state.json").write_text(json.dumps(state))

    def state(self):
        return json.loads((self.root / "state.json").read_text())

    def run_script(self, name):
        script = (SCRIPTS / name).read_text()
        script = script.replace("/etc/", f"{self.root}/etc/").replace("/var/lib/", f"{self.root}/var/lib/")
        return subprocess.run(["/bin/sh", "-c", f"TF_ZT_NETWORK={NETWORK}\n" + script], env=self.env, capture_output=True, text=True, timeout=15)

    def test_both_schemas_are_idempotent_and_preserve_other_networks(self):
        for schema in ("old", "new"):
            with self.subTest(schema=schema):
                self.write_state(schema)
                for _ in range(2):
                    result = self.run_script("zerotier-setup.sh")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("__TF_ZT_SETUP_OK__", result.stdout)
                    self.assertNotIn("KEEP_SECRET", result.stdout + result.stderr)
                state = self.state()
                self.assertEqual(state["joined"], sorted([NETWORK, OTHER]))
                self.assertNotIn("restart", state["service_calls"])
                self.assertNotIn("start", state["service_calls"])
                self.assertNotIn("opkg", state)
                self.assertEqual(state["settings"]["allowDefault"], "false")
                if schema == "old":
                    self.assertEqual(state["sections"]["existing"]["join"], [OTHER, NETWORK])
                    self.assertEqual(state["sections"]["existing"]["secret"], "KEEP_SECRET")
                else:
                    self.assertEqual(sum(s.get("id") == NETWORK for s in state["sections"].values()), 1)
                status = self.run_script("zerotier-status.sh")
                self.assertEqual(status.returncode, 0, status.stderr)
                self.assertIn("__TF_ZT_PERSISTENT__\n1", status.stdout)
                self.assertIn("ACCESS_DENIED", status.stdout)
                self.assertNotIn("KEEP_SECRET", status.stdout)

    def test_install_and_start_missing_service(self):
        self.write_state(running=False, enabled=False, sections={})
        (self.root / "bin/zerotier-cli").unlink()
        result = self.run_script("zerotier-setup.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state()["opkg"], ["update", "install"])
        self.assertIn("start", self.state()["service_calls"])
        self.assertTrue(self.state()["enabled"])

    def test_install_failure_does_not_configure(self):
        self.write_state(install_fail=True)
        before = self.state()["sections"]
        (self.root / "bin/zerotier-cli").unlink()
        result = self.run_script("zerotier-setup.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("repository unavailable", result.stderr)
        self.assertEqual(self.state()["sections"], before)
        self.assertNotIn("service_calls", self.state())

    def test_fresh_modern_install_removes_only_packaged_example(self):
        self.write_state("new", running=False, enabled=False, sections={
            "global": {"type": "zerotier", "enabled": "0"},
            "earth": {"type": "network", "id": "8056c2e21c000001"},
        })
        (self.root / "bin/zerotier-cli").unlink()
        (self.root / "etc/config/zerotier").unlink()
        result = self.run_script("zerotier-setup.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("earth", self.state()["sections"])
        self.assertEqual(self.state()["sections"]["global"]["secret"], "TEST_IDENTITY_SECRET")
        self.assertNotIn("TEST_IDENTITY_SECRET", result.stdout + result.stderr)

    def test_old_disabled_sample_is_not_enabled(self):
        self.write_state(running=False, enabled=False, sections={
            "sample": {"type": "zerotier", "enabled": "0", "join": ["8056c2e21c000001"]},
        })
        result = self.run_script("zerotier-setup.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state()["sections"]["sample"]["enabled"], "0")
        self.assertEqual(sum(s.get("enabled") == "1" for s in self.state()["sections"].values()), 1)

    def test_pending_changes_and_non_root_are_rejected(self):
        for kwargs in ({"pending": True}, {"uid": 1000}):
            self.write_state(**kwargs)
            before = self.state()["sections"]
            result = self.run_script("zerotier-setup.sh")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.state()["sections"], before)
            self.assertNotIn("service_calls", self.state())


if __name__ == "__main__":
    unittest.main()
