"""Easy Wallet Card tests: build passes with a throwaway self-signed test CA chain and check that
makepass.py, verifypass.py and finish.sh accept good passes and reject bad ones.

Nothing here touches Apple or the network. All keys and certs are generated into a temp dir per run.
"""
import fcntl, glob, hashlib, json, os, re, shutil, signal, stat, subprocess, sys, tempfile, time, unittest, zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAKEPASS = os.path.join(REPO, "makepass.py")
VERIFYPASS = os.path.join(REPO, "verifypass.py")
FINISH = os.path.join(REPO, "finish.sh")
CARD = os.path.join(REPO, "cards", "sample-card.json")
LOGO = os.path.join(REPO, "cards", "sample-logo.png")
EXAMPLES = os.path.join(REPO, "cards", "examples")
EXAMPLE_NAMES = ("loyalty", "business", "wifi-guest", "medical", "pet")
APPLE_WWDR_SUBJ = "/CN=Apple Worldwide Developer Relations Certification Authority/OU=G4/O=Apple Inc./C=US"  # DER order, as Apple issues it
PTI, TEAM = "pass.com.example.easywalletcard", "ABCDE12345"
OPENSSL = shutil.which("openssl")
TEST_BUILD = 4  # finish.sh exit code for a --test-unpinned-chain build


def tgt(out):
    """Where finish.sh --test-unpinned-chain leaves the pass (never at OUT itself)."""
    return out[:-len(".pkpass")] + ".TEST-UNPINNED.pkpass"


def sh(*args, **kw):
    kw.setdefault("stdout", subprocess.PIPE)
    kw.setdefault("stderr", subprocess.STDOUT)
    return subprocess.run(list(args), text=True, **kw)


def ossl(*args):
    r = sh(OPENSSL, *args)
    if r.returncode:
        raise RuntimeError(f"openssl {args[0]} failed: {r.stdout}")


def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def patched_tool(where, chain):
    """Copy of the tools with the Apple pins swapped for `chain`'s, to exercise the real pinned path."""
    tool = os.path.join(where, "tool")
    os.mkdir(tool)
    for n in ("finish.sh", "makepass.py", "verifypass.py", "fetch-apple-certs.sh"):
        shutil.copy2(os.path.join(REPO, n), tool)
    der = lambda pem: hashlib.sha256(subprocess.run([OPENSSL, "x509", "-in", pem, "-outform", "DER"],
                                                    stdout=subprocess.PIPE, check=True).stdout).hexdigest()
    pins = {"ea4757885538dd8cb59ff4556f676087d83c85e70902c122e42c0808b5bce14c": (der(chain.inter), sha256(chain.inter)),
            "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024": (der(chain.root), sha256(chain.root))}
    for n, idx in (("verifypass.py", 0), ("fetch-apple-certs.sh", 1)):
        p = os.path.join(tool, n)
        s = open(p).read()
        for apple, mine in pins.items():
            assert apple in s
            s = s.replace(apple, mine[idx])
        open(p, "w").write(s)
    return tool


class Chain:
    """root -> intermediate -> signer, all throwaway."""

    def __init__(self, d, name, inter_subj=APPLE_WWDR_SUBJ):
        self.d = d
        p = lambda s: os.path.join(d, f"{name}-{s}")
        self.root_key, self.root = p("root.key"), p("root.pem")
        self.inter_key, self.inter = p("wwdr.key"), p("wwdr.pem")
        self.key, self.cert = p("signer.key"), p("signer.pem")
        ca_ext = p("ca.ext")
        with open(ca_ext, "w") as f:
            f.write("basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n")
        leaf_ext = p("leaf.ext")
        with open(leaf_ext, "w") as f:
            f.write("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n")
        for k in (self.root_key, self.inter_key, self.key):
            ossl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", k)
            os.chmod(k, 0o600)
        ossl("req", "-x509", "-new", "-key", self.root_key, "-out", self.root, "-days", "30",
             "-subj", f"/C=US/O=Test {name}/CN=Test {name} Root CA",
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        csr = p("wwdr.csr")
        ossl("req", "-new", "-key", self.inter_key, "-out", csr, "-subj", inter_subj)
        ossl("x509", "-req", "-in", csr, "-CA", self.root, "-CAkey", self.root_key, "-CAcreateserial",
             "-out", self.inter, "-days", "30", "-extfile", ca_ext)
        csr = p("signer.csr")
        ossl("req", "-new", "-key", self.key, "-out", csr,
             "-subj", f"/UID={PTI}/CN=Pass Type ID: {PTI}/OU={TEAM}/O=Example Test/C=US")
        ossl("x509", "-req", "-in", csr, "-CA", self.inter, "-CAkey", self.inter_key, "-CAcreateserial",
             "-out", self.cert, "-days", "30", "-extfile", leaf_ext)


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="ewc-test-")
        cls.good = Chain(cls.tmp, "good")
        cls.badissuer = Chain(cls.tmp, "badissuer", "/C=US/O=Not Apple/CN=Not The WWDR CA")
        cls.other = Chain(cls.tmp, "other")  # Apple-like DN, but a different root

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.w = tempfile.mkdtemp(prefix="case-", dir=self.tmp)

    def make(self, chain=None, card=CARD, out=None, extra_env=None):
        chain = chain or self.good
        out = out or os.path.join(self.w, "p.pkpass")
        env = dict(os.environ, **(extra_env or {}))
        r = sh(sys.executable, MAKEPASS, "--card", card, "--logo", LOGO, "--cert", chain.cert, "--key", chain.key,
               "--wwdr", chain.inter, "--out", out, env=env)
        return r, out

    def verify(self, pkpass, chain=None, *extra, chain_args=True, unpinned=True, env=None):
        chain = chain or self.good
        args = [sys.executable, VERIFYPASS, pkpass]
        if chain_args:
            args += ["--root", chain.root, "--wwdr", chain.inter]
            if unpinned:
                args += ["--test-unpinned-chain"]
        return sh(*args, *extra, env=env)

    def keydir(self, chain=None):
        chain = chain or self.good
        k = os.path.join(self.w, "keys")
        os.makedirs(k, mode=0o700, exist_ok=True)
        shutil.copy(chain.cert, os.path.join(k, "pass.cer"))
        shutil.copy(chain.key, os.path.join(k, "pass-signing.key"))
        os.chmod(os.path.join(k, "pass-signing.key"), 0o600)
        shutil.copy(chain.inter, os.path.join(k, "AppleWWDRCAG4.cer"))
        shutil.copy(chain.root, os.path.join(k, "AppleIncRootCertificate.cer"))
        return k

    def finish_args(self, keys, out, *extra):
        return ["bash", FINISH, "--test-unpinned-chain", "--card", CARD, "--logo", LOGO,
                "--keys", keys, "--out", out, *extra]

    def finish(self, keys, out, *extra, env=None):
        return sh(*self.finish_args(keys, out, *extra), env=env)

    def leftovers(self, d):
        return [os.path.basename(p) for p in glob.glob(os.path.join(d, ".*-*"))]


class MakeVerifyTests(Base):
    def test_roundtrip_ok(self):
        r, out = self.make()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o600)
        v = self.verify(out, None, "--cert", self.good.cert, "--card", CARD)
        self.assertEqual(v.returncode, 3, v.stdout)
        self.assertIn("RESULT OK-TEST-UNPINNED", v.stdout)
        self.assertNotIn("FAIL ", v.stdout)

    def test_no_temp_dirs_left(self):
        r, out = self.make()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.verify(out)
        self.assertEqual(self.leftovers(self.w), [])

    def test_pinned_mode_rejects_test_chain(self):
        _, out = self.make()
        v = self.verify(out, unpinned=False)
        self.assertEqual(v.returncode, 1, v.stdout)
        self.assertIn("pinned SHA-256", v.stdout)

    def test_tampered_pass_json_fails(self):
        _, out = self.make()
        bad = os.path.join(self.w, "bad.pkpass")
        with zipfile.ZipFile(out) as zin, zipfile.ZipFile(bad, "w") as zout:
            for n in zin.namelist():
                data = zin.read(n)
                if n == "pass.json":
                    pj = json.loads(data); pj["description"] = "tampered"; data = json.dumps(pj).encode()
                zout.writestr(n, data)
        v = self.verify(bad)
        self.assertEqual(v.returncode, 1, v.stdout)
        self.assertIn("RESULT FAILED", v.stdout)

    def test_extra_file_fails(self):
        _, out = self.make()
        with zipfile.ZipFile(out, "a") as z:
            z.writestr("extra.png", b"x")
        v = self.verify(out)
        self.assertEqual(v.returncode, 1, v.stdout)

    def test_wrong_issuer_fails(self):
        _, out = self.make(self.badissuer)
        v = self.verify(out, self.badissuer)
        self.assertEqual(v.returncode, 1, v.stdout)
        self.assertIn("FAIL signer issuer DN is exactly", v.stdout)

    def test_untrusted_root_fails_with_chain(self):
        _, out = self.make(self.other)
        v = self.verify(out, None)  # good root/wwdr: the signer's real root is not trusted
        self.assertEqual(v.returncode, 1, v.stdout)
        self.assertIn("FAIL signature + chain verify", v.stdout)

    def test_env_trust_store_ignored(self):
        _, out = self.make(self.other)
        env = dict(os.environ, SSL_CERT_FILE=self.other.root, SSL_CERT_DIR=self.tmp)
        v = self.verify(out, None, env=env)
        self.assertEqual(v.returncode, 1, v.stdout)

    def test_no_chain_exits_3(self):
        _, out = self.make()
        v = sh(sys.executable, VERIFYPASS, out, "--no-chain")
        self.assertEqual(v.returncode, 3, v.stdout)
        self.assertIn("RESULT OK-UNTRUSTED", v.stdout)
        self.assertNotIn("RESULT OK\n", v.stdout)

    def test_no_chain_tampered_exits_1(self):
        _, out = self.make()
        with zipfile.ZipFile(out, "a") as z:
            z.writestr("extra.png", b"x")
        v = sh(sys.executable, VERIFYPASS, out, "--no-chain")
        self.assertEqual(v.returncode, 1, v.stdout)

    def test_usage_no_chain_args_exits_2(self):
        _, out = self.make()
        self.assertEqual(sh(sys.executable, VERIFYPASS, out).returncode, 2)

    def test_usage_root_without_wwdr_exits_2(self):
        _, out = self.make()
        self.assertEqual(sh(sys.executable, VERIFYPASS, out, "--root", self.good.root).returncode, 2)

    def test_usage_no_chain_with_root_exits_2(self):
        _, out = self.make()
        r = sh(sys.executable, VERIFYPASS, out, "--no-chain", "--root", self.good.root, "--wwdr", self.good.inter)
        self.assertEqual(r.returncode, 2)

    def test_abbreviated_flag_rejected(self):
        _, out = self.make()
        self.assertEqual(sh(sys.executable, VERIFYPASS, out, "--no-ch").returncode, 2)

    def test_signer_differs_from_cert_fails(self):
        _, out = self.make()
        v = self.verify(out, None, "--cert", self.other.cert)
        self.assertEqual(v.returncode, 1, v.stdout)

    def test_sharing_prohibited_mismatch_fails(self):
        _, out = self.make()
        card = json.load(open(CARD)); card["sharingProhibited"] = False
        c2 = os.path.join(self.w, "c2.json"); json.dump(card, open(c2, "w"))
        v = self.verify(out, None, "--card", c2)
        self.assertEqual(v.returncode, 1, v.stdout)
        self.assertIn("FAIL sharingProhibited", v.stdout)

    def test_field_values_not_printed_by_default(self):
        _, out = self.make()
        v = self.verify(out)
        self.assertNotIn("JANE SAMPLE", v.stdout)
        self.assertNotIn("EXAMPLE000001", v.stdout)

    def test_makepass_rejects_group_readable_key(self):
        k = os.path.join(self.w, "k.key"); shutil.copy(self.good.key, k); os.chmod(k, 0o640)
        r = sh(sys.executable, MAKEPASS, "--card", CARD, "--logo", LOGO, "--cert", self.good.cert, "--key", k,
               "--wwdr", self.good.inter, "--out", os.path.join(self.w, "p.pkpass"))
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_makepass_rejects_web_service(self):
        card = json.load(open(CARD)); card["webServiceURL"] = "https://example.com"
        c2 = os.path.join(self.w, "c2.json"); json.dump(card, open(c2, "w"))
        r, out = self.make(card=c2)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertFalse(os.path.exists(out))

    def test_unpinned_verify_is_never_plain_ok(self):
        _, out = self.make()
        v = self.verify(out)  # --test-unpinned-chain
        self.assertEqual(v.returncode, 3, v.stdout)
        self.assertIn("RESULT OK-TEST-UNPINNED", v.stdout)
        self.assertNotIn("RESULT OK\n", v.stdout)

    def test_pinned_ok_with_patched_pins(self):
        tool = patched_tool(self.w, self.good)
        _, out = self.make()
        v = sh(sys.executable, os.path.join(tool, "verifypass.py"), out, "--root", self.good.root,
               "--wwdr", self.good.inter, "--cert", self.good.cert, "--card", CARD)
        self.assertEqual(v.returncode, 0, v.stdout)
        self.assertTrue(v.stdout.endswith("RESULT OK\n"), v.stdout)

    def test_makepass_refuses_symlinked_key(self):
        k = os.path.join(self.w, "real.key"); shutil.copy(self.good.key, k); os.chmod(k, 0o600)
        link = os.path.join(self.w, "link.key"); os.symlink(k, link)
        out = os.path.join(self.w, "p.pkpass")
        r = sh(sys.executable, MAKEPASS, "--card", CARD, "--logo", LOGO, "--cert", self.good.cert, "--key", link,
               "--wwdr", self.good.inter, "--out", out)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("symlink", r.stdout)
        self.assertFalse(os.path.exists(out))

    def test_python_tools_accept_dash_paths_with_equals_or_double_dash(self):
        for src, dst in ((CARD, "-card.json"), (LOGO, "-logo.png")):
            shutil.copy(src, os.path.join(self.w, dst))
        r = sh(sys.executable, MAKEPASS, "--card=-card.json", "--logo=-logo.png", "--cert", self.good.cert,
               "--key", self.good.key, "--wwdr", self.good.inter, "--out=-p.pkpass", cwd=self.w)
        self.assertEqual(r.returncode, 0, r.stdout)
        v = sh(sys.executable, VERIFYPASS, "--no-chain", "--", "-p.pkpass", cwd=self.w)
        self.assertEqual(v.returncode, 3, v.stdout)
        bad = sh(sys.executable, MAKEPASS, "--card", "-card.json", "--logo", LOGO, "--cert", self.good.cert,
                 "--key", self.good.key, "--wwdr", self.good.inter, "--out", "x.pkpass", cwd=self.w)
        self.assertEqual(bad.returncode, 2)
        self.assertIn("./-name", sh(sys.executable, MAKEPASS, "--help").stdout)

    def test_gitignore_keeps_private_files_out(self):
        g = os.path.join(self.w, "scratch")
        os.makedirs(os.path.join(g, "cards"))
        git = lambda *a: sh("git", "-C", g, "-c", "core.excludesFile=/dev/null", *a)
        self.assertEqual(git("init", "-q").returncode, 0)
        shutil.copy(os.path.join(REPO, ".gitignore"), g)
        for n in ("sample-card.json", "sample-logo.png"):
            shutil.copy(os.path.join(REPO, "cards", n), os.path.join(g, "cards", n))
        private = ["cards/my-card.json", "cards/my-logo.png", "cards/my-mark.png", ".lock", "x.certSigningRequest", "x.crt", "x.der", "x.pfx",
                   "x.key", "x.pem", "x.p12", "x.cer", "x.csr", "x.pkpass", "keys/pass.cer", "out/x.pkpass",
                   ".makepass-ab12/pass.json", ".verifypass-cd34/pass/pass.json", ".finish-ef56/unverified.pkpass",
                   "sub/.makepass-x/pass.json"]
        for f in private:
            os.makedirs(os.path.dirname(os.path.join(g, f)) or g, exist_ok=True)
            with open(os.path.join(g, f), "w") as fh:
                fh.write("private")
        self.assertEqual(git("add", "-A").returncode, 0)
        staged = set(git("diff", "--cached", "--name-only").stdout.split())
        self.assertEqual(staged, {".gitignore", "cards/sample-card.json", "cards/sample-logo.png"})

    def test_verifypass_signal_cleans_temp(self):
        _, out = self.make()
        shim = os.path.join(self.w, "shim"); os.mkdir(shim)
        with open(os.path.join(shim, "openssl"), "w") as f:
            f.write(f"#!/bin/sh\nsleep 1\nexec '{OPENSSL}' \"$@\"\n")
        os.chmod(os.path.join(shim, "openssl"), 0o755)
        env = dict(os.environ, PATH=shim + os.pathsep + os.environ["PATH"])
        p = subprocess.Popen([sys.executable, VERIFYPASS, out, "--no-chain"], env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertTrue(self._wait_for(lambda: glob.glob(os.path.join(self.w, ".verifypass-*"))))
        p.send_signal(signal.SIGTERM)
        p.wait(timeout=20)
        self.assertEqual(p.returncode, -signal.SIGTERM)
        self.assertEqual(self.leftovers(self.w), [])

    @staticmethod
    def _wait_for(cond, timeout=15):
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.05)
        return False


class FinishTests(Base):
    def test_finish_roundtrip_ok(self):
        keys, out = self.keydir(), os.path.join(self.w, "out", "card.pkpass")
        r = self.finish(keys, out)
        self.assertEqual(r.returncode, TEST_BUILD, r.stdout)
        self.assertIn("RESULT OK-TEST-UNPINNED", r.stdout)
        self.assertEqual(stat.S_IMODE(os.stat(tgt(out)).st_mode), 0o600)
        self.assertEqual(self.leftovers(os.path.dirname(out)), [])
        self.assertEqual(self.verify(tgt(out)).returncode, 3)
        self.assertFalse(os.path.exists(out))

    def test_finish_usage_exits_2(self):
        self.assertEqual(sh("bash", FINISH).returncode, 2)
        self.assertEqual(sh("bash", FINISH, "--bogus").returncode, 2)

    def test_no_overwrite_without_force(self):
        keys, out = self.keydir(), os.path.join(self.w, "out", "card.pkpass")
        self.assertEqual(self.finish(keys, out).returncode, TEST_BUILD)
        before = sha256(tgt(out))
        r = self.finish(keys, out)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("--force", r.stdout)
        self.assertEqual(sha256(tgt(out)), before)

    def test_force_overwrites(self):
        keys, out = self.keydir(), os.path.join(self.w, "out", "card.pkpass")
        self.assertEqual(self.finish(keys, out).returncode, TEST_BUILD)
        before = sha256(tgt(out))
        time.sleep(1.1)  # signingTime has 1 s resolution
        r = self.finish(keys, out, "--force")
        self.assertEqual(r.returncode, TEST_BUILD, r.stdout)
        self.assertNotEqual(sha256(tgt(out)), before)

    def test_lock_symlink_to_outside_file_untouched(self):
        keys, outdir = self.keydir(), os.path.join(self.w, "out")
        os.mkdir(outdir, 0o700)
        victim = os.path.join(self.w, "victim.txt")
        with open(victim, "w") as f:
            f.write("keep me")
        os.symlink(victim, os.path.join(outdir, ".lock"))
        r = self.finish(keys, os.path.join(outdir, "card.pkpass"))
        self.assertEqual(r.returncode, TEST_BUILD, r.stdout)
        with open(victim) as f:
            self.assertEqual(f.read(), "keep me")

    def test_lock_symlink_to_missing_path_creates_nothing(self):
        keys, outdir = self.keydir(), os.path.join(self.w, "out")
        os.mkdir(outdir, 0o700)
        target = os.path.join(self.w, "should-not-exist")
        os.symlink(target, os.path.join(outdir, ".lock"))
        r = self.finish(keys, os.path.join(outdir, "card.pkpass"))
        self.assertEqual(r.returncode, TEST_BUILD, r.stdout)
        self.assertFalse(os.path.lexists(target))

    def test_overlapping_run_refused(self):
        keys, outdir = self.keydir(), os.path.join(self.w, "out")
        os.mkdir(outdir, 0o700)
        fd = os.open(outdir, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            r = self.finish(keys, os.path.join(outdir, "card.pkpass"))
        finally:
            os.close(fd)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("holds the lock", r.stdout)
        self.assertFalse(os.path.exists(os.path.join(outdir, "card.pkpass")))

    def test_overlap_does_not_sweep_live_temp_dir(self):
        keys, outdir = self.keydir(), os.path.join(self.w, "out")
        os.mkdir(outdir, 0o700)
        live = os.path.join(outdir, ".finish-live01"); os.mkdir(live)
        fd = os.open(outdir, os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.finish(keys, os.path.join(outdir, "card.pkpass"))
        finally:
            os.close(fd)
        self.assertTrue(os.path.isdir(live))

    def test_stale_temp_dirs_swept(self):
        keys, outdir = self.keydir(), os.path.join(self.w, "out")
        os.mkdir(outdir, 0o700)
        for n in (".makepass-old", ".verifypass-old", ".finish-old"):
            os.mkdir(os.path.join(outdir, n))
        r = self.finish(keys, os.path.join(outdir, "card.pkpass"))
        self.assertEqual(r.returncode, TEST_BUILD, r.stdout)
        self.assertEqual(self.leftovers(outdir), [])

    def test_expect_guards(self):
        keys, out = self.keydir(), os.path.join(self.w, "out", "card.pkpass")
        r = self.finish(keys, out, env=dict(os.environ, EXPECT_TEAM_ID="ZZZZZZZZZZ"))
        self.assertEqual(r.returncode, 1, r.stdout)
        r = self.finish(keys, out, env=dict(os.environ, EXPECT_PASS_TYPE_ID="pass.com.example.other"))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertFalse(os.path.exists(out) or os.path.exists(tgt(out)))
        r = self.finish(keys, out, env=dict(os.environ, EXPECT_TEAM_ID=TEAM, EXPECT_PASS_TYPE_ID=PTI))
        self.assertEqual(r.returncode, TEST_BUILD, r.stdout)

    def test_finish_wrong_issuer_refused(self):
        keys, out = self.keydir(self.badissuer), os.path.join(self.w, "out", "card.pkpass")
        r = self.finish(keys, out)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("is not exactly", r.stdout)
        self.assertFalse(os.path.exists(out) or os.path.exists(tgt(out)))

    def test_finish_mismatched_key_refused(self):
        keys, out = self.keydir(), os.path.join(self.w, "out", "card.pkpass")
        shutil.copy(self.other.key, os.path.join(keys, "pass-signing.key"))
        r = self.finish(keys, out)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertFalse(os.path.exists(out) or os.path.exists(tgt(out)))

    def test_finish_unpinned_never_installed_at_out(self):
        keys, out = self.keydir(), os.path.join(self.w, "out", "card.pkpass")
        r = self.finish(keys, out)
        self.assertEqual(r.returncode, TEST_BUILD, r.stdout)
        self.assertIn("TEST BUILD", r.stdout)
        self.assertNotIn("READY", r.stdout)
        self.assertFalse(os.path.exists(out))
        self.assertTrue(os.path.isfile(tgt(out)))

    def test_finish_pinned_ready_with_patched_pins(self):
        tool = patched_tool(self.w, self.good)
        keys, out = self.keydir(), os.path.join(self.w, "out", "card.pkpass")
        r = sh("bash", os.path.join(tool, "finish.sh"), "--card", CARD, "--logo", LOGO, "--keys", keys, "--out", out)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("finish: READY", r.stdout)
        self.assertTrue(os.path.isfile(out))
        self.assertFalse(os.path.exists(tgt(out)))

    def test_finish_refuses_symlinked_key(self):
        keys, out = self.keydir(), os.path.join(self.w, "out", "card.pkpass")
        k = os.path.join(keys, "pass-signing.key")
        real = os.path.join(self.w, "real.key"); os.replace(k, real); os.symlink(real, k)
        r = self.finish(keys, out)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("is a symlink; it must be the real key file", r.stdout)  # finish.sh refuses before building
        self.assertNotIn("makepass", r.stdout)
        self.assertFalse(os.path.exists(out) or os.path.exists(tgt(out)))

    def test_finish_leading_dash_paths(self):
        for src, dst in ((CARD, "-card.json"), (LOGO, "-logo.png")):
            shutil.copy(src, os.path.join(self.w, dst))
        keys = self.keydir()
        os.rename(keys, os.path.join(self.w, "-keys"))
        r = sh("bash", FINISH, "--test-unpinned-chain", "--card", "-card.json", "--logo", "-logo.png",
               "--icon", "-logo.png", "--keys", "-keys", "--out", "-out/card.pkpass", cwd=self.w)
        self.assertEqual(r.returncode, TEST_BUILD, r.stdout)
        self.assertTrue(os.path.isfile(os.path.join(self.w, "-out", "card.TEST-UNPINNED.pkpass")))

    def test_temp_dir_cleaned_on_signal(self):
        keys, outdir = self.keydir(), os.path.join(self.w, "out")
        os.mkdir(outdir, 0o700)
        shim = os.path.join(self.w, "shim"); os.mkdir(shim)
        with open(os.path.join(shim, "openssl"), "w") as f:
            f.write(f"#!/bin/sh\nsleep 0.5\nexec '{OPENSSL}' \"$@\"\n")
        os.chmod(os.path.join(shim, "openssl"), 0o755)
        env = dict(os.environ, PATH=shim + os.pathsep + os.environ["PATH"])
        out = os.path.join(outdir, "card.pkpass")
        p = subprocess.Popen(self.finish_args(keys, out), env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.assertTrue(MakeVerifyTests._wait_for(lambda: glob.glob(os.path.join(outdir, ".finish-*"))))
        p.send_signal(signal.SIGTERM)
        p.wait(timeout=30)
        self.assertEqual(p.returncode, 143)
        self.assertEqual(self.leftovers(outdir), [])
        self.assertFalse(os.path.exists(out) or os.path.exists(tgt(out)))


class KeyOpenTests(Base):
    """N2: no symlink anywhere on the key's path. N3: the key is opened once (O_NOFOLLOW) and openssl only ever
    gets that fd as /dev/fd/N, so swapping the path mid-run can't change which key signs."""

    def _shim(self, delay_smime=0.0):
        shim = os.path.join(self.w, "shim"); os.makedirs(shim, exist_ok=True)
        log, mark = os.path.join(self.w, "openssl-argv.log"), os.path.join(self.w, "smime-started")
        with open(os.path.join(shim, "openssl"), "w") as f:
            f.write("#!/bin/sh\n"
                    f"for a in \"$@\"; do printf '%s\\n' \"$a\" >>'{log}'; done\n"
                    f"if [ \"$1\" = smime ] && [ \"$2\" = -binary ]; then : >'{mark}'; sleep {delay_smime}; fi\n"
                    f"exec '{OPENSSL}' \"$@\"\n")
        os.chmod(os.path.join(shim, "openssl"), 0o755)
        return dict(os.environ, PATH=shim + os.pathsep + os.environ["PATH"]), log, mark

    def _swap_to_644_symlink(self, key):
        """Replace the key path with a symlink to a mode-644 copy of a DIFFERENT key (atomic rename)."""
        evil = os.path.join(self.w, "evil-644.key")
        shutil.copy(self.other.key, evil); os.chmod(evil, 0o644)
        tmp = key + ".swap"; os.symlink(evil, tmp); os.replace(tmp, key)
        self.assertTrue(os.path.islink(key))

    def _refuse_msg(self, r):
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertFalse(os.path.exists(os.path.join(self.w, "out", "card.pkpass")))
        low = (r.stdout or "").lower()
        self.assertTrue("symlink" in low or "readable only by you" in low or "not a directory" in low
                        or "not found" in low or "unsafe" in low, r.stdout)

    def test_makepass_refuses_symlinked_key_dir(self):
        real = os.path.join(self.w, "realkeys"); os.mkdir(real, 0o700)
        shutil.copy(self.good.key, os.path.join(real, "pass-signing.key"))
        os.chmod(os.path.join(real, "pass-signing.key"), 0o600)
        os.symlink(real, os.path.join(self.w, "keys"))
        os.makedirs(os.path.join(self.w, "a")); os.symlink(self.w, os.path.join(self.w, "a", "link"))
        out = os.path.join(self.w, "out", "card.pkpass"); os.makedirs(os.path.dirname(out), exist_ok=True)
        # symlinked keys/ parent
        r = sh(sys.executable, MAKEPASS, "--card", CARD, "--logo", LOGO, "--cert", self.good.cert,
               "--key", os.path.join(self.w, "keys", "pass-signing.key"), "--wwdr", self.good.inter, "--out", out)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("symlink", r.stdout.lower())
        self.assertFalse(os.path.exists(out))
        # first / middle component link: a/link/keys/pass-signing.key
        r = sh(sys.executable, MAKEPASS, "--card", CARD, "--logo", LOGO, "--cert", self.good.cert,
               "--key", os.path.join(self.w, "a", "link", "keys", "pass-signing.key"),
               "--wwdr", self.good.inter, "--out", out)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("symlink", r.stdout.lower())
        # trailing slash
        r = sh(sys.executable, MAKEPASS, "--card", CARD, "--logo", LOGO, "--cert", self.good.cert,
               "--key", os.path.join(self.w, "keys", "pass-signing.key") + "/",
               "--wwdr", self.good.inter, "--out", out)
        self.assertEqual(r.returncode, 1, r.stdout)
        # key-is-symlink (already covered by test_makepass_refuses_symlinked_key; keep one here too)
        kdir = os.path.join(self.w, "plainkeys"); os.mkdir(kdir, 0o700)
        realk = os.path.join(kdir, "real.key"); shutil.copy(self.good.key, realk); os.chmod(realk, 0o600)
        linkk = os.path.join(kdir, "pass-signing.key"); os.symlink(realk, linkk)
        r = sh(sys.executable, MAKEPASS, "--card", CARD, "--logo", LOGO, "--cert", self.good.cert,
               "--key", linkk, "--wwdr", self.good.inter, "--out", out)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("symlink", r.stdout.lower())
        # directory as key
        r = sh(sys.executable, MAKEPASS, "--card", CARD, "--logo", LOGO, "--cert", self.good.cert,
               "--key", kdir, "--wwdr", self.good.inter, "--out", out)
        self.assertEqual(r.returncode, 1, r.stdout)
        # mode 640 / 604
        for mode in (0o640, 0o604):
            bad = os.path.join(kdir, f"m{mode:o}.key")
            shutil.copy(self.good.key, bad); os.chmod(bad, mode)
            r = sh(sys.executable, MAKEPASS, "--card", CARD, "--logo", LOGO, "--cert", self.good.cert,
                   "--key", bad, "--wwdr", self.good.inter, "--out", out)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("readable only by you", r.stdout)
        # hardlink to 644 refused (same inode, mode of the opened fd's inode)
        hard = os.path.join(kdir, "hard.key"); soft644 = os.path.join(kdir, "soft644.key")
        shutil.copy(self.good.key, soft644); os.chmod(soft644, 0o644)
        try:
            os.link(soft644, hard)
        except OSError:
            self.skipTest("hardlink not supported here")
        r = sh(sys.executable, MAKEPASS, "--card", CARD, "--logo", LOGO, "--cert", self.good.cert,
               "--key", hard, "--wwdr", self.good.inter, "--out", out)
        self.assertEqual(r.returncode, 1, r.stdout)
        # FIFO: must not hang
        fifo = os.path.join(kdir, "fifo.key")
        os.mkfifo(fifo)
        r = sh(sys.executable, MAKEPASS, "--card", CARD, "--logo", LOGO, "--cert", self.good.cert,
               "--key", fifo, "--wwdr", self.good.inter, "--out", out, timeout=5)
        self.assertEqual(r.returncode, 1, r.stdout)
        # symlink/.. form: keys points at real, path uses keys/../realkeys/pass-signing.key through the link
        # (lexical .. after a symlink component — still walks the symlink dir first and refuses)
        r = sh(sys.executable, MAKEPASS, "--card", CARD, "--logo", LOGO, "--cert", self.good.cert,
               "--key", os.path.join(self.w, "keys", "..", "realkeys", "pass-signing.key"),
               "--wwdr", self.good.inter, "--out", out)
        self.assertEqual(r.returncode, 1, r.stdout)

    def test_finish_refuses_symlinked_key_dir(self):
        real = os.path.join(self.w, "realkeys"); os.mkdir(real, 0o700)
        for n in ("pass-signing.key",):
            shutil.copy(self.good.key, os.path.join(real, n)); os.chmod(os.path.join(real, n), 0o600)
        # finish's keydir() lays out certs; build a normal keydir then replace keys with a symlink
        keys = self.keydir()
        # Move real contents aside and make keys a symlink to realkeys with the signing key
        # Simpler: point --keys at a dir whose pass-signing.key path goes through a symlink parent.
        link_root = os.path.join(self.w, "linkroot"); os.makedirs(link_root)
        # Copy the whole keydir into realkeys-style and symlink
        target = os.path.join(self.w, "real-keydir")
        shutil.copytree(keys, target)
        os.symlink(target, os.path.join(self.w, "symkeys"))
        out = os.path.join(self.w, "out", "card.pkpass")
        r = self.finish(os.path.join(self.w, "symkeys"), out)
        self.assertEqual(r.returncode, 1, r.stdout)
        # Must be finish.sh's open_key pre-check (not makepass): old finish.sh lacks this and would reach makepass.
        self.assertIn("finish:", r.stdout)
        self.assertIn("symlink", r.stdout.lower())
        self.assertNotIn("makepass:", r.stdout)
        self.assertFalse(os.path.exists(out) or os.path.exists(tgt(out)))

    def test_makepass_signs_with_opened_fd_when_key_swapped_mid_run(self):
        env, _, mark = self._shim(delay_smime=2)
        out = os.path.join(self.w, "out", "card.pkpass"); os.makedirs(os.path.dirname(out), exist_ok=True)
        key = os.path.join(self.w, "swap.key"); shutil.copy(self.good.key, key); os.chmod(key, 0o600)
        p = subprocess.Popen(
            [sys.executable, MAKEPASS, "--card", CARD, "--logo", LOGO, "--cert", self.good.cert,
             "--key", key, "--wwdr", self.good.inter, "--out", out],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.assertTrue(MakeVerifyTests._wait_for(lambda: os.path.exists(mark)))
        self._swap_to_644_symlink(key)
        so, _ = p.communicate(timeout=60)
        self.assertEqual(p.returncode, 0, so)
        # Signed with the original key (matches good cert); verify OK-TEST-UNPINNED
        self.assertEqual(self.verify(out, None, "--cert", self.good.cert).returncode, 3)

    def test_finish_signs_with_opened_fd_when_key_swapped_mid_run(self):
        env, _, mark = self._shim(delay_smime=2)
        keys, out = self.keydir(), os.path.join(self.w, "out", "card.pkpass")
        p = subprocess.Popen(self.finish_args(keys, out), env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True)
        self.assertTrue(MakeVerifyTests._wait_for(lambda: os.path.exists(mark)))
        self._swap_to_644_symlink(os.path.join(keys, "pass-signing.key"))
        so, _ = p.communicate(timeout=60)
        self.assertEqual(p.returncode, TEST_BUILD, so)
        self.assertEqual(self.verify(tgt(out), None, "--cert", self.good.cert).returncode, 3)

    def test_openssl_never_gets_the_key_path(self):
        env, log, _ = self._shim()
        keys, out = self.keydir(), os.path.join(self.w, "out", "card.pkpass")
        r = self.finish(keys, out, env=env)
        self.assertEqual(r.returncode, TEST_BUILD, r.stdout)
        with open(log) as f:
            argv = f.read().splitlines()
        self.assertFalse([a for a in argv if "pass-signing.key" in a], "openssl was given the key by path")
        self.assertGreaterEqual(sum(a.startswith("/dev/fd/") for a in argv), 2)  # pubkey match + signing

    def test_system_link_rule(self):
        sys.path.insert(0, REPO)
        try:
            import makepass
        finally:
            sys.path.remove(REPO)
        fake = lambda uid: os.stat_result((stat.S_IFLNK | 0o777, 0, 0, 1, uid, 0, 0, 0, 0, 0))
        self.assertEqual(makepass._system_link(fake(0)), os.geteuid() != 0)  # root-owned, e.g. macOS /var
        self.assertFalse(makepass._system_link(fake(os.geteuid() or 1000)))  # anything a user could plant


class ExampleCardTests(Base):
    """NIC-61: example templates build, and every string field is allowlisted fake data (no personal denylist)."""

    WIFI_OK = "WIFI:T:WPA;S:ExampleGuest;P:not-a-real-password;;"
    ALLOWED_GIVENS = {"Jordan", "Alex", "Sam", "Casey", "Robin", "Pickles"}
    ALLOWED_SURNAMES = {"Sample", "Example"}
    NAME_KEYS = {"name", "member", "owner", "pet", "emergency", "contact"}
    EXAMPLE_HOSTS = ("example.com", "example.org", "example.net")

    def _load(self, name):
        path = os.path.join(EXAMPLES, f"{name}-card.json")
        with open(path) as f:
            return path, json.load(f)

    def _strings(self, card):
        for sec in ("header", "primary", "secondary", "auxiliary", "back"):
            for f in card.get(sec, []) or []:
                if not isinstance(f, dict):
                    continue
                key = f.get("key", "?")
                for fk in ("label", "value"):
                    if isinstance(f.get(fk), str):
                        yield f"{sec}.{key}.{fk}", key, f[fk]
        for k in ("description", "organizationName", "logoText", "serialNumber"):
            if isinstance(card.get(k), str):
                yield k, k, card[k]
        bc = card.get("barcode") or {}
        for k in ("message", "altText"):
            if isinstance(bc.get(k), str):
                yield f"barcode.{k}", k, bc[k]

    def _assert_fake(self, card, where_prefix=""):
        for where, key, val in self._strings(card):
            loc = f"{where_prefix}{where}"
            # URLs / emails: host must be example.com|org|net only
            for m in re.finditer(r"(?i)\b(?:https?://|mailto:)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", val):
                host = m.group(1).lower()
                if host.startswith("www."):
                    host = host[4:]
                # skip pure numeric (phones handled below) and UUID-like
                if re.fullmatch(r"[\d.]+", host):
                    continue
                self.assertIn(host, self.EXAMPLE_HOSTS, f"{loc}: non-example host {host!r} in {val!r}")
            # Phones: only 555-01xx. Any other 555-xxxx fails; other phone-like forms caught via digit runs.
            for phone in re.findall(r"\b555-\d{4}\b", val):
                self.assertRegex(phone, r"\A555-01\d\d\Z", f"{loc}: non-fiction phone {phone!r}")
            # Letter-prefixed IDs: only EXAMPLE… / SAMPLE… (rejects ABC123456789)
            bad_id = re.search(r"\b(?!(?:EXAMPLE|SAMPLE)\d)[A-Z]{2,}\d{6,}\b", val)
            self.assertIsNone(bad_id, f"{loc}: letter-prefixed ID not EXAMPLE/SAMPLE: {val!r}")
            # Digit runs of 6+: all-zero OK; otherwise must be glued to EXAMPLE/SAMPLE.
            # Template serialNumbers are fixed zero-ish UUIDs; allow that one shape.
            if where == "serialNumber":
                self.assertRegex(val, r"\A00000000-0000-4000-8000-00000000000[2-6]\Z",
                                 f"{loc}: serialNumber must be the template UUID shape")
            else:
                for m in re.finditer(r"\d{6,}", val):
                    d = m.group(0)
                    if set(d) == {"0"}:
                        continue
                    pre = val[max(0, m.start() - 16):m.start()]
                    self.assertRegex(pre, r"(?i)(?:EXAMPLE|SAMPLE)$",
                                     f"{loc}: digit run {d!r} not EXAMPLE/SAMPLE-prefixed")
            # Capitalized two-word names in name/contact-like fields (Title Case or ALL CAPS)
            if key in self.NAME_KEYS:
                for m in re.finditer(r"\b([A-Z][A-Za-z]+)\s+([A-Z][A-Za-z]+)\b", val):
                    g, sur = m.group(1).title(), m.group(2).title()
                    self.assertIn(g, self.ALLOWED_GIVENS, f"{loc}: given name {m.group(1)!r} not in allowlist")
                    self.assertIn(sur, self.ALLOWED_SURNAMES, f"{loc}: surname {m.group(2)!r} not in allowlist")
            # Wi-Fi payload
            if val.startswith("WIFI:"):
                self.assertEqual(val, self.WIFI_OK, f"{loc}: Wi-Fi string must be the documented placeholder")

    def test_examples_build_and_verify(self):
        for n in EXAMPLE_NAMES:
            path, card = self._load(n)
            logo = os.path.join(EXAMPLES, f"{n}-logo.png")
            self.assertTrue(os.path.isfile(logo), logo)
            # logo size
            from PIL import Image
            im = Image.open(logo)
            self.assertEqual(im.size, (320, 100), n)
            out = os.path.join(self.w, f"{n}.pkpass")
            r = sh(sys.executable, MAKEPASS, "--card", path, "--logo", logo,
                   "--cert", self.good.cert, "--key", self.good.key, "--wwdr", self.good.inter, "--out", out)
            self.assertEqual(r.returncode, 0, r.stdout)
            v = self.verify(out, None, "--cert", self.good.cert)
            self.assertEqual(v.returncode, 3, v.stdout)
            self.assertIn("RESULT OK-TEST-UNPINNED", v.stdout)
            # barcode format sanity
            bc = card.get("barcode") or {}
            if n == "loyalty":
                self.assertEqual(bc.get("format"), "PKBarcodeFormatCode128")

    def test_examples_hold_only_fake_data(self):
        for n in EXAMPLE_NAMES:
            _, card = self._load(n)
            self._assert_fake(card, where_prefix=f"{n}:")
            # medical disclaimer
            if n == "medical":
                back = " ".join(f.get("value", "") for f in card.get("back", []))
                self.assertIn("This is not a medical record and not medical advice.", back)
            # made-up note on every card
            back = " ".join(f.get("value", "") for f in card.get("back", []))
            self.assertIn("made-up data", back.lower())

    def test_examples_gitignore_tracks_only_named_files(self):
        g = os.path.join(self.w, "scratch")
        os.makedirs(os.path.join(g, "cards", "examples"))
        git = lambda *a: sh("git", "-C", g, "-c", "core.excludesFile=/dev/null", *a)
        self.assertEqual(git("init", "-q").returncode, 0)
        shutil.copy(os.path.join(REPO, ".gitignore"), g)
        for n in EXAMPLE_NAMES:
            for suf in ("-card.json", "-logo.png"):
                src = os.path.join(EXAMPLES, f"{n}{suf}")
                shutil.copy(src, os.path.join(g, "cards", "examples", f"{n}{suf}"))
        shutil.copy(os.path.join(EXAMPLES, "make_logos.py"), os.path.join(g, "cards", "examples", "make_logos.py"))
        # extras must stay ignored
        Path = __import__("pathlib").Path; Path(os.path.join(g, "cards", "examples", "my-card.json")).write_text("{}")
        open(os.path.join(g, "cards", "examples", "loyalty-card.json.bak"), "w").write("{}")
        r = git("status", "--porcelain", "--ignored", "cards")
        tracked_ok = {f"cards/examples/{n}{s}" for n in EXAMPLE_NAMES for s in ("-card.json", "-logo.png")}
        tracked_ok.add("cards/examples/make_logos.py")
        # use check-ignore
        for n in EXAMPLE_NAMES:
            for suf in ("-card.json", "-logo.png"):
                rel = f"cards/examples/{n}{suf}"
                self.assertNotEqual(git("check-ignore", "-q", rel).returncode, 0, rel)
        self.assertNotEqual(git("check-ignore", "-q", "cards/examples/make_logos.py").returncode, 0)
        self.assertEqual(git("check-ignore", "-q", "cards/examples/my-card.json").returncode, 0)
        self.assertEqual(git("check-ignore", "-q", "cards/examples/loyalty-card.json.bak").returncode, 0)

    def test_fake_data_allowlist_rejects_altered_cards(self):
        """Negative cases: each altered field must be caught by _assert_fake."""
        _, base = self._load("business")
        cases = []
        # real-looking name
        c = json.loads(json.dumps(base)); c["primary"][0]["value"] = "John Smith"; cases.append(("name", c))
        # letter-prefixed ID
        c = json.loads(json.dumps(base)); c["secondary"][0]["value"] = "ABC123456789"; cases.append(("ABC id", c))
        # 6-digit ID
        c = json.loads(json.dumps(base)); c["secondary"].append({"key": "mid", "label": "ID", "value": "123456"}); cases.append(("6digit", c))
        # bare non-example domain
        c = json.loads(json.dumps(base)); c["back"][0]["value"] = "https://acme-corp.com/x"; cases.append(("domain", c))
        # real Wi-Fi password
        _, wifi = self._load("wifi-guest")
        c = json.loads(json.dumps(wifi)); c["barcode"]["message"] = "WIFI:T:WPA;S:ExampleGuest;P:s3cret-real;;"; cases.append(("wifi", c))
        # real phone in barcode.message
        c = json.loads(json.dumps(base)); c["barcode"]["message"] = "555-2368"; cases.append(("phone-bc", c))
        # real-looking microchip in barcode
        _, pet = self._load("pet")
        c = json.loads(json.dumps(pet)); c["barcode"]["message"] = "981020000000000"; cases.append(("chip", c))
        for label, card in cases:
            with self.assertRaises(AssertionError, msg=label):
                self._assert_fake(card, where_prefix=f"neg-{label}:")


if __name__ == "__main__":
    unittest.main()
