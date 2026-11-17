"""Offline auth persistence tests. Every password is a disposable fixture."""
import base64
from contextlib import ExitStack
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from runtime import credentials as C

ROOT = Path(__file__).resolve().parents[1]
OLD = "old"
NEW = "new-fixture-password-42"


def config(password=OLD, app="v2rayn"):
    salt = bytes(range(16))
    return {"app": app, "title": "v2rayN" if app == "v2rayn" else "Clash Verge Rev",
            "password_salt": salt.hex(), "password_hash": hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32).hex(),
            "vnc_password": "fixture8", "retained_future_setting": True}


class PasswordValueTests(unittest.TestCase):
    def test_legacy_short_password_stays_valid_but_new_password_requires_strength(self):
        value = config()
        self.assertTrue(C.verify_password(value, OLD))
        with self.assertRaises(C.CredentialError):C.validate_new_password(OLD)

    def test_new_password_supports_unicode_and_spaces_without_trimming(self):
        value = "  测试访问密码与空格保留  "
        self.assertEqual(C.validate_new_password(value), value)

    def test_new_password_rejects_controls_overlong_and_empty_values(self):
        for value in (None, "a" * 11, "a" * 129, " " * 12, "new-password\n", "new-password\0", "new-password\x7f", "\ud800" * 12):
            with self.subTest(shape=type(value).__name__), self.assertRaises(C.CredentialError):C.validate_new_password(value)

    def test_wrong_password_and_unknown_app_do_not_echo_inputs(self):
        self.assertFalse(C.verify_password(config(), "wrong-fixture-input"))
        with self.assertRaises(C.CredentialError) as error:C.validate_config(config(), "clash")
        self.assertNotIn("fixture8", str(error.exception))

    def test_salt_and_revision_change_credential_fingerprint(self):
        first = config(); second = copy.deepcopy(first);second["password_revision"] = "fixture-revision"
        self.assertNotEqual(C.credential_revision(first), C.credential_revision(second))

    def test_root_mutation_is_rejected_without_admin_privilege(self):
        with patch.object(C.os, "geteuid", return_value=1001, create=True), patch.object(C, "_ROOT_UID", 0):
            with self.assertRaises(PermissionError):C.require_administrator()


@unittest.skipUnless(os.name == "posix", "POSIX descriptor ownership and atomic filesystem verification")
class CredentialStorageTests(unittest.TestCase):
    def setUp(self):
        workspace=ROOT/"work/credential-tests";workspace.mkdir(parents=True, exist_ok=True)
        temporary=tempfile.TemporaryDirectory(dir=workspace);self.addCleanup(temporary.cleanup)
        self.var=Path(temporary.name);self.var.chmod(0o755)
        self.ui=self.var/"ui";self.private=self.var/"private"
        for directory in (self.ui,self.private):directory.mkdir(mode=0o700);directory.chmod(0o700)
        self.config_path=self.ui/"portal.json";self.access=self.private/"access.txt"
        self.config_path.write_text(json.dumps(config()),encoding="utf-8");self.config_path.chmod(0o600)
        self.access.write_text("original fixture access record\n",encoding="utf-8");self.access.chmod(0o600)
        self.profile=self.var/"p";self.profile.mkdir();(self.profile/"node-profile").write_text("preserve fixture node")
        (self.ui/"tls.key").write_text("fixture-key");(self.ui/"tls.crt").write_text("fixture-cert")
        # The real CI user owns the synthetic root domain; production remains
        # fixed to UID0. No privileged root test is silently skipped on Linux.
        role=patch.object(C,"_ROOT_UID",os.geteuid());role.start();self.addCleanup(role.stop)

    def rotate(self,current=OLD,new=NEW,**kwargs):
        revision=C.credential_revision(C.read_portal_config(self.config_path))
        return C.change_password(self.var,"v2rayn",current,new,expected_revision=kwargs.get("revision",revision))

    def assert_preserved(self):
        self.assertEqual((self.profile/"node-profile").read_text(),"preserve fixture node")
        self.assertEqual((self.ui/"tls.key").read_text(),"fixture-key")
        self.assertEqual((self.ui/"tls.crt").read_text(),"fixture-cert")

    def test_rotation_persists_new_password_updates_root_record_and_preserves_profile(self):
        result=self.rotate();self.assertEqual(result,{"ok":True,"reauthenticate":True})
        updated=C.read_portal_config(self.config_path)
        self.assertTrue(C.verify_password(updated,NEW));self.assertFalse(C.verify_password(updated,OLD))
        self.assertTrue(updated["retained_future_setting"])
        self.assertIn(NEW,self.access.read_text())
        self.assertNotIn(NEW,self.config_path.read_text())
        self.assertEqual(stat.S_IMODE(self.access.stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE(self.config_path.stat().st_mode),0o600)
        self.assertFalse((self.private/C._JOURNAL).exists());self.assert_preserved()

    def test_wrong_old_password_and_stale_revision_leave_both_files_unchanged(self):
        original=(self.config_path.read_bytes(),self.access.read_bytes())
        for current,revision in (("wrong-fixture-input",None),(OLD,"stale-revision")):
            with self.subTest(case=revision),self.assertRaises(C.CredentialError):
                self.rotate(current=current,**({"revision":revision} if revision else {}))
            self.assertEqual((self.config_path.read_bytes(),self.access.read_bytes()),original)

    def test_same_password_is_rejected_even_for_admin_reset(self):
        C.reset_password(self.var,"v2rayn",NEW)
        with self.assertRaises(C.CredentialError):C.reset_password(self.var,"v2rayn",NEW)

    def test_admin_reset_requires_no_old_password_and_does_not_change_other_app(self):
        other=self.var/"other-app";other.mkdir();(other/"config").write_text("other application fixture")
        C.reset_password(self.var,"v2rayn",NEW)
        self.assertTrue(C.verify_password(C.read_portal_config(self.config_path),NEW))
        self.assertEqual((other/"config").read_text(),"other application fixture");self.assert_preserved()

    def test_wrong_app_is_rejected_before_any_credentials_change(self):
        original=self.config_path.read_bytes()
        with self.assertRaises(C.CredentialError):C.reset_password(self.var,"clash",NEW)
        self.assertEqual(self.config_path.read_bytes(),original)

    def test_ordinary_public_write_failure_rolls_back_both_files(self):
        old=(self.config_path.read_bytes(),self.access.read_bytes());real=C._write_at;failed=False
        def fail_once(directory,name,*args):
            nonlocal failed
            if name=="portal.json" and not failed:failed=True;raise OSError("synthetic filesystem failure")
            return real(directory,name,*args)
        with patch.object(C,"_write_at",side_effect=fail_once),self.assertRaises(C.CredentialError):self.rotate()
        self.assertEqual((self.config_path.read_bytes(),self.access.read_bytes()),old)
        self.assertFalse((self.private/C._JOURNAL).exists())

    def pending(self,committed):
        old_config=self.config_path.read_bytes();old_access=self.access.read_bytes()
        value=config(NEW);value["password_revision"]="next-fixture-revision"
        new_config=json.dumps(value).encode();new_access=("Password: "+NEW+"\n").encode()
        journal={"schema":1,"app":"v2rayn",**{key:base64.b64encode(data).decode() for key,data in {
            "old_config":old_config,"new_config":new_config,"old_access":old_access,"new_access":new_access}.items()}}
        path=self.private/C._JOURNAL;path.write_text(json.dumps(journal));path.chmod(0o600)
        self.access.write_bytes(new_access)
        if committed:self.config_path.write_bytes(new_config)
        return old_config,old_access

    def test_interrupted_precommit_transaction_recovers_exact_previous_state(self):
        old=self.pending(False)
        self.assertTrue(C.recover_pending(self.var,"v2rayn"))
        self.assertEqual((self.config_path.read_bytes(),self.access.read_bytes()),old);self.assert_preserved()

    def test_interrupted_committed_transaction_finishes_new_password_on_restart(self):
        self.pending(True)
        self.assertTrue(C.recover_pending(self.var,"v2rayn"))
        self.assertTrue(C.verify_password(C.read_portal_config(self.config_path),NEW))
        self.assertIn(NEW,self.access.read_text());self.assertFalse((self.private/C._JOURNAL).exists())

    def test_corrupt_recovery_record_is_retained_without_overwriting_state(self):
        path=self.private/C._JOURNAL;path.write_text('{"schema":99}');path.chmod(0o600)
        old=(self.config_path.read_bytes(),self.access.read_bytes())
        with self.assertRaises(C.CredentialError):C.recover_pending(self.var,"v2rayn")
        self.assertEqual((self.config_path.read_bytes(),self.access.read_bytes()),old);self.assertTrue(path.exists())

    def test_linked_public_config_cannot_read_or_overwrite_outside_file(self):
        outside=self.var/"outside";outside.write_bytes(self.config_path.read_bytes());outside.chmod(0o600)
        self.config_path.unlink();self.config_path.symlink_to(outside)
        old=outside.read_bytes()
        with self.assertRaises(C.CredentialError):self.rotate()
        self.assertEqual(outside.read_bytes(),old)

    def test_linked_access_file_cannot_overwrite_profile(self):
        outside=self.profile/"node-profile";old=outside.read_bytes()
        self.access.unlink();self.access.symlink_to(outside)
        with self.assertRaises(C.CredentialError):self.rotate()
        self.assertEqual(outside.read_bytes(),old)

    def test_group_readable_private_state_is_rejected(self):
        self.private.chmod(0o750)
        with self.assertRaises(C.CredentialError):self.rotate()

    def test_group_writable_public_config_is_rejected(self):
        self.config_path.chmod(0o660)
        with self.assertRaises(C.CredentialError):self.rotate()

    def test_hardlinked_public_config_is_rejected(self):
        os.link(self.config_path,self.var/"alias")
        with self.assertRaises(C.CredentialError):self.rotate()


class PasswordCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location("reset_password_cli",ROOT/"tools/reset_portal_password.py")
        cls.cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.cli)

    def test_unrecognized_password_argument_is_not_echoed(self):
        output=io.StringIO()
        with patch("sys.argv",["reset","--password","do-not-echo-fixture-value"]),patch("sys.stderr",output),self.assertRaises(SystemExit):self.cli.main()
        self.assertNotIn("do-not-echo-fixture-value",output.getvalue())

    def test_stdin_confirmation_is_checked_and_never_echoed(self):
        output=io.StringIO();body=NEW+"\n"+NEW+"\n"
        with patch("sys.argv",["reset","--app","v2rayn","--var","fixture-dir","--password-stdin"]),patch("sys.stdin",io.StringIO(body)),patch("sys.stdout",output),patch.object(self.cli,"require_administrator"),patch.object(self.cli,"reset_password") as reset:
            self.assertEqual(self.cli.main(),0)
        reset.assert_called_once_with(Path("fixture-dir"),"v2rayn",NEW)
        self.assertNotIn(NEW,output.getvalue())

    def test_missing_admin_permission_does_not_prompt_for_or_consume_password(self):
        body=io.StringIO(NEW+"\n"+NEW+"\n")
        with patch("sys.argv",["reset","--app","clash","--var","fixture-dir","--password-stdin"]),patch("sys.stdin",body),patch("sys.stderr",io.StringIO()),patch.object(self.cli,"require_administrator",side_effect=PermissionError()),patch.object(self.cli,"reset_password") as reset:
            self.assertEqual(self.cli.main(),1)
        reset.assert_not_called();self.assertEqual(body.tell(),0)


if __name__=="__main__":unittest.main()
