from __future__ import annotations

import hashlib
import http.client
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import pin_gate  # noqa: E402

PINS = {"portfolio/pin/app": "4821", "portfolio/pin/docs": "1357"}
KEY = "test-signing-key"
KEY_ENTRY = "portfolio/pin-signing-key"


class FakeSecrets:
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self.values = {**PINS, KEY_ENTRY: KEY, **(values or {})}
        self.write_fails = False
        self.write_is_lost = False
        self.locked = False

    def get(self, entry: str) -> str:
        if self.locked:
            raise pin_gate.SecretError("vault is locked")
        try:
            return self.values[entry]
        except KeyError:
            raise pin_gate.SecretError(f"no secret {entry}") from None

    def set(self, entry: str, value: str) -> None:
        if self.locked:
            raise pin_gate.SecretError("vault is locked")
        if self.write_fails:
            raise pin_gate.SecretError("auto-pass refused")
        if not self.write_is_lost:
            self.values[entry] = value


class FakeNotifier:
    def __init__(self) -> None:
        self.events: list[pin_gate.Newly] = []
        self.announcements: list[tuple[str, str]] = []

    def announce(self, subject: str, body: str) -> None:
        self.announcements.append((subject, body))

    def notify(self, event: pin_gate.Newly) -> None:
        self.events.append(event)


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


DAY = 86400


def make_gate(tmp: Path, clock: Clock, secrets=None, policy=None, rotation=None, seal_key=None):
    sites = {
        "app": pin_gate.SiteConfig("app", "portfolio/pin/app", 12 * 3600),
        "docs": pin_gate.SiteConfig("docs", "portfolio/pin/docs", 3600),
    }
    lockouts = pin_gate.Lockouts(
        pin_gate.StateStore(tmp / "state.json"),
        policy or pin_gate.Policy(site_max_fails=3, ip_max_fails=5, base_lock_seconds=60),
        clock=clock,
    )
    notifier = FakeNotifier()
    rotation = pin_gate.Rotation(lockouts.store, rotation or pin_gate.RotationPolicy(), clock=clock)
    seal = pin_gate.Seal(seal_key, lockouts.store) if seal_key else None
    gate = pin_gate.Gate(sites, secrets or FakeSecrets(), lockouts, notifier, clock=clock, rotation=rotation, seal=seal)
    return gate, notifier


class CookieTests(unittest.TestCase):
    def test_round_trip_and_expiry(self) -> None:
        cookie = pin_gate.make_cookie_value(KEY, "app", "4821", 2000)
        self.assertTrue(pin_gate.cookie_valid(cookie, KEY, "app", "4821", 1999))
        self.assertFalse(pin_gate.cookie_valid(cookie, KEY, "app", "4821", 2000))

    def test_cookie_is_bound_to_site_pin_and_key(self) -> None:
        cookie = pin_gate.make_cookie_value(KEY, "app", "4821", 2000)
        self.assertFalse(pin_gate.cookie_valid(cookie, KEY, "docs", "4821", 1))
        self.assertFalse(pin_gate.cookie_valid(cookie, KEY, "app", "9999", 1))  # a rotated PIN revokes it
        self.assertFalse(pin_gate.cookie_valid(cookie, "other-key", "app", "4821", 1))

    def test_malformed_and_tampered_cookies_are_rejected(self) -> None:
        good = pin_gate.make_cookie_value(KEY, "app", "4821", 2000)
        for bad in ("", "garbage", "app.x.y", good + "0", good.replace(".2000.", ".9999999.")):
            with self.subTest(bad=bad):
                self.assertFalse(pin_gate.cookie_valid(bad, KEY, "app", "4821", 1))


class LockoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.clock = Clock()

    def test_site_locks_after_max_failures_for_any_client(self) -> None:
        gate, notifier = make_gate(self.tmp, self.clock)
        for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            gate.attempt(gate.sites["app"], ip, "0000")
        self.assertEqual([(e.kind, e.key) for e in notifier.events], [("site", "app")])
        outcome, seconds, cookie = gate.attempt(gate.sites["app"], "10.0.0.9", "4821")
        self.assertEqual((outcome, cookie), ("locked", None))
        self.assertGreater(seconds, 0)

    def test_ip_locks_across_sites(self) -> None:
        gate, notifier = make_gate(self.tmp, self.clock, policy=pin_gate.Policy(site_max_fails=99, ip_max_fails=4))
        for site in ("app", "docs", "app", "docs"):
            gate.attempt(gate.sites[site], "10.0.0.1", "0000")
        self.assertEqual([(e.kind, e.key) for e in notifier.events], [("ip", "10.0.0.1")])
        self.assertEqual(gate.attempt(gate.sites["docs"], "10.0.0.1", "1357")[0], "locked")
        self.assertEqual(gate.attempt(gate.sites["docs"], "10.0.0.2", "1357")[0], "ok")

    def test_lock_expires_and_doubles_when_repeated(self) -> None:
        gate, _ = make_gate(self.tmp, self.clock)
        site = gate.sites["app"]
        for _ in range(3):
            gate.attempt(site, "10.0.0.1", "0000")
        self.assertEqual(gate.lockouts.locked_for("app", "10.0.0.2"), 60)
        self.clock.now += 61
        self.assertEqual(gate.lockouts.locked_for("app", "10.0.0.2"), 0)
        for _ in range(3):
            gate.attempt(site, "10.0.0.2", "0000")
        self.assertEqual(gate.lockouts.locked_for("app", "10.0.0.3"), 120)

    def test_lock_length_is_capped(self) -> None:
        policy = pin_gate.Policy(site_max_fails=1, ip_max_fails=99, base_lock_seconds=60, max_lock_seconds=100)
        gate, _ = make_gate(self.tmp, self.clock, policy=policy)
        for _ in range(4):
            gate.attempt(gate.sites["app"], "10.0.0.1", "0000")
            self.clock.now += 101
        gate.attempt(gate.sites["app"], "10.0.0.1", "0000")
        self.assertEqual(gate.lockouts.locked_for("app", "10.0.0.2"), 100)

    def test_counters_decay_after_a_quiet_period(self) -> None:
        policy = pin_gate.Policy(site_max_fails=3, ip_max_fails=99, base_lock_seconds=60, decay_seconds=1000)
        gate, _ = make_gate(self.tmp, self.clock, policy=policy)
        for _ in range(3):
            gate.attempt(gate.sites["app"], "10.0.0.1", "0000")
        self.clock.now += 5000
        for _ in range(3):
            gate.attempt(gate.sites["app"], "10.0.0.1", "0000")
        self.assertEqual(gate.lockouts.locked_for("app", "10.0.0.1"), 60)  # level reset, not 120

    def test_correct_pin_clears_site_failures_but_not_ip_failures(self) -> None:
        gate, _ = make_gate(self.tmp, self.clock)
        gate.attempt(gate.sites["app"], "10.0.0.1", "0000")
        gate.attempt(gate.sites["app"], "10.0.0.1", "0000")
        self.assertEqual(gate.attempt(gate.sites["app"], "10.0.0.1", "4821")[0], "ok")
        snapshot = gate.lockouts.store.snapshot()
        self.assertNotIn("app", snapshot["sites"])
        self.assertEqual(snapshot["ips"]["10.0.0.1"]["fails"], 2)

    def test_state_survives_a_new_instance_and_reset_lifts_locks(self) -> None:
        gate, _ = make_gate(self.tmp, self.clock)
        for _ in range(3):
            gate.attempt(gate.sites["app"], "10.0.0.1", "0000")
        again, _ = make_gate(self.tmp, self.clock)
        self.assertGreater(again.lockouts.locked_for("app", "10.0.0.7"), 0)
        self.assertEqual(again.lockouts.store.reset(site="app"), 1)
        self.assertEqual(again.lockouts.locked_for("app", "10.0.0.7"), 0)
        self.assertEqual(again.lockouts.store.path.stat().st_mode & 0o777, 0o600)

    def test_malformed_guesses_count_as_failures(self) -> None:
        gate, _ = make_gate(self.tmp, self.clock)
        for guess in ("", "48211", "abcd"):
            self.assertEqual(gate.attempt(gate.sites["app"], "10.0.0.1", guess)[0], "wrong")

    def test_each_site_has_its_own_pin(self) -> None:
        gate, _ = make_gate(self.tmp, self.clock)
        self.assertEqual(gate.attempt(gate.sites["app"], "10.0.0.1", "1357")[0], "wrong")
        self.assertEqual(gate.attempt(gate.sites["docs"], "10.0.0.2", "1357")[0], "ok")


class ChangePinTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.clock = Clock()
        self.secrets = FakeSecrets()
        self.gate, self.notifier = make_gate(Path(self._tmp.name), self.clock, self.secrets)
        self.site = self.gate.sites["app"]

    def change(self, current="4821", new="7305", confirm=None, ip="10.0.0.1"):
        return self.gate.change_pin(self.site, ip, current, new, new if confirm is None else confirm)

    def test_weak_pins(self) -> None:
        for weak in ("0000", "7777", "1234", "0123", "9876", "3210"):
            self.assertTrue(pin_gate.weak_pin(weak), weak)
        for fine in ("7305", "1357", "2468", "1212", "4821"):
            self.assertFalse(pin_gate.weak_pin(fine), fine)

    def test_change_writes_the_pin_and_announces_it_without_the_value(self) -> None:
        outcome, _, cookie = self.change()
        self.assertEqual(outcome, "ok")
        self.assertEqual(self.secrets.values["portfolio/pin/app"], "7305")
        self.assertTrue(pin_gate.cookie_valid(cookie, KEY, "app", "7305", self.clock()))
        subject, body = self.notifier.announcements[0]
        self.assertIn("app", body)
        self.assertNotIn("7305", subject + body)
        self.assertNotIn("4821", subject + body)

    def test_existing_cookies_stop_working_after_a_change(self) -> None:
        old = pin_gate.make_cookie_value(KEY, "app", "4821", int(self.clock()) + 100)
        self.change()
        self.assertFalse(self.gate.has_valid_cookie(self.site, f"__Host-pin={old}"))

    def test_the_new_pin_then_unlocks_and_the_old_one_does_not(self) -> None:
        self.change()
        self.assertEqual(self.gate.attempt(self.site, "10.0.0.2", "4821")[0], "wrong")
        self.assertEqual(self.gate.attempt(self.site, "10.0.0.2", "7305")[0], "ok")

    def test_wrong_current_pin_counts_toward_the_lockouts_and_writes_nothing(self) -> None:
        for _ in range(3):
            self.assertIn(self.change(current="0000")[0], {"wrong", "locked"})
        self.assertEqual(self.secrets.values["portfolio/pin/app"], "4821")
        self.assertEqual(self.change()[0], "locked")  # the right PIN is refused while locked
        self.assertEqual([(e.kind, e.key) for e in self.notifier.events], [("site", "app")])

    def test_rejected_new_pins_write_nothing_and_are_not_counted_as_guesses(self) -> None:
        cases = [({"new": "0000"}, "weak"), ({"new": "7305", "confirm": "7306"}, "mismatch")]
        cases += [({"new": "73"}, "mismatch"), ({"new": "abcd"}, "mismatch")]
        for kwargs, expected in cases:
            with self.subTest(kwargs=kwargs):
                self.assertEqual(self.change(**kwargs)[0], expected)
        self.assertEqual(self.secrets.values["portfolio/pin/app"], "4821")
        self.assertEqual(self.notifier.announcements, [])
        self.assertEqual(self.gate.lockouts.store.snapshot()["ips"], {})

    def test_a_failed_write_leaves_the_pin_unchanged(self) -> None:
        self.secrets.write_fails = True
        self.assertEqual(self.change()[0], "unavailable")
        self.assertEqual(self.secrets.values["portfolio/pin/app"], "4821")
        self.assertEqual(self.notifier.announcements, [])

    def test_a_write_that_does_not_read_back_is_reported_not_trusted(self) -> None:
        self.secrets.write_is_lost = True
        self.assertEqual(self.change()[0], "unavailable")
        self.assertEqual(self.notifier.announcements, [])


class RotationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.clock = Clock()
        self.secrets = FakeSecrets()
        self.gate, self.notifier = make_gate(self.tmp, self.clock, self.secrets)
        self.site = self.gate.sites["app"]
        self.rotation = self.gate.rotation
        self.rotation.ensure(["app", "docs"])  # what `serve` does at start: the clock begins here

    def age(self, days: float) -> None:
        self.clock.now += days * DAY

    def test_policy_defaults_and_environment(self) -> None:
        defaults = pin_gate.RotationPolicy()
        self.assertEqual((defaults.max_age_days, defaults.warn_days, defaults.allow_reuse), (180, 30, True))
        env = {"WH_PIN_ROTATE_DAYS": "90", "WH_PIN_WARN_DAYS": "10", "WH_PIN_ALLOW_REUSE": "no"}
        policy = pin_gate.RotationPolicy.from_env(env)
        self.assertEqual((policy.max_age_days, policy.warn_days, policy.allow_reuse), (90, 10, False))

    def test_a_pin_is_ok_then_warns_for_its_last_month_then_expires(self) -> None:
        self.assertEqual(self.rotation.status("app"), ("ok", 180))
        self.age(149)
        self.assertEqual(self.rotation.status("app")[0], "ok")
        self.age(1)
        self.assertEqual(self.rotation.status("app"), ("warn", 30))
        self.age(29)
        self.assertEqual(self.rotation.status("app"), ("warn", 1))
        self.age(1)
        self.assertEqual(self.rotation.status("app")[0], "overdue")

    def test_rotation_can_be_switched_off(self) -> None:
        gate, _ = make_gate(self.tmp / "off", Clock(), rotation=pin_gate.RotationPolicy(max_age_days=0))
        gate.clock.now += 10_000 * DAY
        self.assertEqual(gate.rotation.status("app")[0], "ok")

    def test_the_clock_survives_a_restart_and_a_change_restarts_it(self) -> None:
        self.age(100)
        again, _ = make_gate(self.tmp, self.clock)
        self.assertEqual(again.rotation.status("app"), ("ok", 80))
        again.rotation.record_change("app")
        self.assertEqual(again.rotation.status("app"), ("ok", 180))

    def test_lockout_reset_does_not_forget_pin_ages(self) -> None:
        self.age(160)
        self.rotation.status("app")
        self.gate.lockouts.store.reset(everything=True)
        self.assertEqual(self.rotation.status("app")[0], "warn")

    def test_notices_are_sent_once_per_phase_and_again_after_a_change(self) -> None:
        self.rotation.ensure(["app", "docs"])
        self.assertEqual(self.gate.send_rotation_notices(), 0)
        self.age(151)
        self.assertEqual(self.gate.send_rotation_notices(), 2)
        self.assertEqual(self.gate.send_rotation_notices(), 0)
        self.age(30)
        self.assertEqual(self.gate.send_rotation_notices(), 2)  # overdue is a separate notice
        self.assertEqual(self.gate.send_rotation_notices(), 0)
        subjects = [subject for subject, _ in self.notifier.announcements]
        self.assertEqual(subjects.count("wiring-harness: PIN due for rotation"), 2)
        self.assertEqual(subjects.count("wiring-harness: PIN expired"), 2)
        self.rotation.record_change("app")
        self.age(151)
        self.assertEqual(self.gate.send_rotation_notices(), 1)  # app again; docs already past warn+overdue

    def test_notices_never_contain_a_pin(self) -> None:
        self.age(151)
        self.gate.send_rotation_notices()
        text = " ".join(f"{a} {b}" for a, b in self.notifier.announcements)
        self.assertNotIn("4821", text)
        self.assertIn("29 days", text)

    def test_an_overdue_pin_does_not_unlock_but_the_wrong_pin_still_counts(self) -> None:
        self.age(181)
        self.assertEqual(self.gate.attempt(self.site, "10.0.0.1", "4821"), ("expired", 0, None))
        self.assertEqual(self.gate.attempt(self.site, "10.0.0.1", "0000")[0], "wrong")

    def test_overdue_ends_existing_sessions(self) -> None:
        cookie = self.gate.attempt(self.site, "10.0.0.1", "4821")[2]
        self.assertTrue(self.gate.has_valid_cookie(self.site, f"__Host-pin={cookie}"))
        self.age(181)
        self.assertFalse(self.gate.has_valid_cookie(self.site, f"__Host-pin={cookie}"))

    def test_changing_an_expired_pin_restores_access(self) -> None:
        self.age(181)
        outcome, _, cookie = self.gate.change_pin(self.site, "10.0.0.1", "4821", "7305", "7305")
        self.assertEqual(outcome, "ok")
        self.assertEqual(self.rotation.status("app")[0], "ok")
        self.assertTrue(self.gate.has_valid_cookie(self.site, f"__Host-pin={cookie}"))

    def test_other_sites_are_unaffected_by_one_sites_expiry(self) -> None:
        self.rotation.record_change("docs")
        self.age(181)
        self.rotation.record_change("docs")
        self.assertEqual(self.gate.attempt(self.gate.sites["docs"], "10.0.0.1", "1357")[0], "ok")
        self.assertEqual(self.gate.attempt(self.site, "10.0.0.1", "4821")[0], "expired")

    def test_reusing_the_current_pin_is_allowed_for_now_and_restarts_the_clock_without_a_write(self) -> None:
        self.age(181)
        writes = []
        original = self.secrets.set
        self.secrets.set = lambda entry, value: (writes.append(entry), original(entry, value))
        outcome, _, cookie = self.gate.change_pin(self.site, "10.0.0.1", "4821", "4821", "4821")
        self.assertEqual(outcome, "ok")
        self.assertEqual(writes, [])
        self.assertEqual(self.rotation.status("app"), ("ok", 180))
        self.assertTrue(self.gate.has_valid_cookie(self.site, f"__Host-pin={cookie}"))

    def test_reuse_is_refused_when_the_policy_forbids_it(self) -> None:
        gate, _ = make_gate(
            self.tmp / "strict", Clock(), self.secrets, rotation=pin_gate.RotationPolicy(allow_reuse=False)
        )
        self.assertEqual(gate.change_pin(gate.sites["app"], "10.0.0.1", "4821", "4821", "4821")[0], "same")
        self.assertEqual(self.secrets.values["portfolio/pin/app"], "4821")

    def test_a_weak_pin_is_refused_even_when_it_is_the_current_one(self) -> None:
        self.secrets.values["portfolio/pin/app"] = "0000"
        self.assertEqual(self.gate.change_pin(self.site, "10.0.0.1", "0000", "0000", "0000")[0], "weak")


class RotationHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.clock = Clock()
        self.secrets = FakeSecrets()
        self.gate, self.notifier = make_gate(Path(self._tmp.name), self.clock, self.secrets)
        self.gate.rotation.ensure(["app", "docs"])
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), pin_gate.make_handler(self.gate))
        threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def request(self, method, path, *, body="", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        send = {"X-Pin-Site": "app", "X-Forwarded-For": "10.0.0.1", "Host": "app.test"}
        if body:
            send["Content-Type"] = "application/x-www-form-urlencoded"
        send.update(headers or {})
        conn.request(method, path, body=body or None, headers=send)
        response = conn.getresponse()
        data = response.read().decode()
        conn.close()
        return response, data

    def age(self, days: float) -> None:
        self.clock.now += days * DAY

    def test_unlocking_in_the_warning_window_shows_the_notice_then_the_site(self) -> None:
        self.age(160)
        response, _ = self.request("POST", "/_pin/unlock", body="pin=4821&next=/dash")
        self.assertEqual(response.status, 303)
        self.assertTrue(response.getheader("Location").startswith("/_pin/notice?next=/dash"))
        self.assertIn("__Host-pin=", response.getheader("Set-Cookie"))
        cookie = response.getheader("Set-Cookie").split(";")[0]
        page, body = self.request("GET", "/_pin/notice?next=/dash", headers={"Cookie": cookie})
        self.assertEqual(page.status, 200)
        self.assertIn("within 20 days", body)
        self.assertIn("/_pin/change?next=/dash", body)
        self.assertIn('href="/dash"', body)  # remind me later
        self.assertEqual(self.request("GET", "/_pin/verify", headers={"Cookie": cookie})[0].status, 204)

    def test_no_notice_outside_the_window_and_the_notice_needs_an_unlocked_session(self) -> None:
        response, _ = self.request("POST", "/_pin/unlock", body="pin=4821&next=/dash")
        self.assertEqual(response.getheader("Location"), "/dash")
        anonymous, _ = self.request("GET", "/_pin/notice?next=/dash")
        self.assertEqual(anonymous.status, 303)
        self.assertTrue(anonymous.getheader("Location").startswith("/_pin/unlock"))
        cookie = response.getheader("Set-Cookie").split(";")[0]
        later, _ = self.request("GET", "/_pin/notice?next=/dash", headers={"Cookie": cookie})
        self.assertEqual((later.status, later.getheader("Location")), (303, "/dash"))

    def test_an_expired_pin_sends_the_user_to_the_change_page_without_a_cookie(self) -> None:
        self.age(181)
        response, _ = self.request("POST", "/_pin/unlock", body="pin=4821&next=/dash")
        self.assertEqual(response.status, 303)
        self.assertEqual(response.getheader("Location"), "/_pin/change?reason=expired&next=/dash")
        self.assertIsNone(response.getheader("Set-Cookie"))
        page, body = self.request("GET", "/_pin/change?reason=expired&next=/dash")
        self.assertIn("has expired", body)

    def test_full_expiry_cycle_over_http(self) -> None:
        cookie = self.request("POST", "/_pin/unlock", body="pin=4821&next=/")[0].getheader("Set-Cookie").split(";")[0]
        self.age(181)
        self.assertEqual(self.request("GET", "/_pin/verify", headers={"Cookie": cookie})[0].status, 303)
        changed, _ = self.request("POST", "/_pin/change", body="current=4821&new=7305&confirm=7305&next=/")
        self.assertEqual(changed.status, 303)
        fresh = changed.getheader("Set-Cookie").split(";")[0]
        self.assertEqual(self.request("GET", "/_pin/verify", headers={"Cookie": fresh})[0].status, 204)
        self.assertEqual(self.request("GET", "/_pin/verify", headers={"Cookie": cookie})[0].status, 303)


SEAL_KEY = b"k" * 32


class SealedTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.clock = Clock()
        self.secrets = FakeSecrets()
        self.gate, self.notifier = make_gate(self.tmp, self.clock, self.secrets, seal_key=SEAL_KEY)
        self.gate.rotation.ensure(["app", "docs"])
        self.site = self.gate.sites["app"]

    def test_sync_seals_a_fingerprint_for_every_site(self) -> None:
        self.assertEqual(self.gate.sync_sealed(), 2)
        self.assertEqual(self.gate.sync_sealed(), 0)  # nothing new the second time
        for name in ("app", "docs"):
            self.assertIsNotNone(self.gate.seal.verifier_for(name))

    def test_the_gate_keeps_working_with_the_vault_locked_once_sealed(self) -> None:
        self.gate.sync_sealed()
        self.secrets.locked = True
        outcome, _, cookie = self.gate.attempt(self.site, "10.0.0.1", "4821")
        self.assertEqual(outcome, "ok")
        self.assertTrue(self.gate.has_valid_cookie(self.site, f"__Host-pin={cookie}"))
        self.assertEqual(self.gate.attempt(self.site, "10.0.0.1", "0000")[0], "wrong")
        self.assertEqual(self.gate.attempt(self.gate.sites["docs"], "10.0.0.1", "1357")[0], "ok")

    def test_before_the_first_sync_the_vault_is_still_required(self) -> None:
        self.secrets.locked = True
        with self.assertRaises(pin_gate.SecretError):
            self.gate.attempt(self.site, "10.0.0.1", "4821")

    def test_without_a_sealed_key_nothing_changes(self) -> None:
        gate, _ = make_gate(self.tmp / "plain", self.clock, self.secrets)
        self.assertEqual(gate.sync_sealed(), 0)
        self.assertEqual(gate.attempt(gate.sites["app"], "10.0.0.1", "4821")[0], "ok")

    def test_the_state_file_holds_neither_pins_nor_the_key(self) -> None:
        self.gate.sync_sealed()
        text = json.dumps(self.gate.lockouts.store.snapshot())
        for secret in ("4821", "1357", SEAL_KEY.decode(), KEY):
            self.assertNotIn(secret, text)
        unkeyed = hashlib.sha256(b"pin-verifier:app:4821").hexdigest()
        self.assertNotIn(unkeyed, text)  # not reproducible without the key

    def test_fingerprints_depend_on_the_key_and_the_site(self) -> None:
        other = pin_gate.Seal(b"z" * 32, self.gate.lockouts.store)
        self.assertNotEqual(self.gate.seal.compute("app", "4821"), other.compute("app", "4821"))
        self.assertNotEqual(self.gate.seal.compute("app", "4821"), self.gate.seal.compute("docs", "4821"))
        self.assertNotEqual(self.gate.seal.cookie_key(), other.cookie_key())

    def test_a_pin_edited_in_the_vault_is_noticed_and_ends_sessions(self) -> None:
        self.gate.sync_sealed()
        cookie = self.gate.attempt(self.site, "10.0.0.1", "4821")[2]
        self.clock.now += 100 * DAY
        self.secrets.values["portfolio/pin/app"] = "7305"
        self.assertEqual(self.gate.sync_sealed(), 1)
        self.assertFalse(self.gate.has_valid_cookie(self.site, f"__Host-pin={cookie}"))
        self.assertEqual(self.gate.attempt(self.site, "10.0.0.2", "7305")[0], "ok")
        self.assertEqual(self.gate.rotation.status("app"), ("ok", 180))

    def test_sync_skips_a_locked_vault_and_keeps_the_old_fingerprint(self) -> None:
        self.gate.sync_sealed()
        before = self.gate.seal.verifier_for("app")
        self.secrets.locked = True
        self.assertEqual(self.gate.sync_sealed(), 0)
        self.assertEqual(self.gate.seal.verifier_for("app"), before)

    def test_sync_refuses_to_seal_a_malformed_pin(self) -> None:
        self.secrets.values["portfolio/pin/app"] = "12"
        self.gate.sync_sealed()
        self.assertIsNone(self.gate.seal.verifier_for("app"))

    def test_changing_a_pin_updates_the_vault_and_the_fingerprint(self) -> None:
        self.gate.sync_sealed()
        outcome, _, cookie = self.gate.change_pin(self.site, "10.0.0.1", "4821", "7305", "7305")
        self.assertEqual(outcome, "ok")
        self.assertEqual(self.secrets.values["portfolio/pin/app"], "7305")
        self.secrets.locked = True
        self.assertTrue(self.gate.has_valid_cookie(self.site, f"__Host-pin={cookie}"))
        self.assertEqual(self.gate.attempt(self.site, "10.0.0.2", "7305")[0], "ok")
        self.assertEqual(self.gate.attempt(self.site, "10.0.0.2", "4821")[0], "wrong")

    def test_changing_a_pin_needs_the_vault_and_otherwise_changes_nothing(self) -> None:
        self.gate.sync_sealed()
        self.secrets.locked = True
        self.assertEqual(self.gate.change_pin(self.site, "10.0.0.1", "4821", "7305", "7305")[0], "unavailable")
        self.assertEqual(self.gate.attempt(self.site, "10.0.0.2", "4821")[0], "ok")
        self.assertEqual(self.gate.attempt(self.site, "10.0.0.2", "7305")[0], "wrong")

    def test_reusing_the_current_pin_works_from_the_fingerprint_alone(self) -> None:
        self.gate.sync_sealed()
        self.secrets.locked = True
        self.assertEqual(self.gate.change_pin(self.site, "10.0.0.1", "4821", "4821", "4821")[0], "ok")

    def test_lockout_reset_keeps_the_fingerprints(self) -> None:
        self.gate.sync_sealed()
        self.gate.lockouts.store.reset(everything=True)
        self.assertIsNotNone(self.gate.seal.verifier_for("app"))

    def test_the_key_is_read_from_the_credentials_directory_or_an_override(self) -> None:
        store = self.gate.lockouts.store
        key_file = self.tmp / pin_gate.Seal.CREDENTIAL
        key_file.write_bytes(SEAL_KEY + b"\n")
        from_dir = pin_gate.Seal.from_environment(store, {"CREDENTIALS_DIRECTORY": str(self.tmp)})
        from_override = pin_gate.Seal.from_environment(store, {"WH_PIN_SEAL_KEY_FILE": str(key_file)})
        self.assertEqual(from_dir.compute("app", "4821"), self.gate.seal.compute("app", "4821"))
        self.assertEqual(from_override.compute("app", "4821"), self.gate.seal.compute("app", "4821"))

    def test_a_missing_or_short_key_means_vault_mode_not_a_crash(self) -> None:
        store = self.gate.lockouts.store
        self.assertIsNone(pin_gate.Seal.from_environment(store, {}))
        self.assertIsNone(pin_gate.Seal.from_environment(store, {"WH_PIN_SEAL_KEY_FILE": str(self.tmp / "absent")}))
        short = self.tmp / "short"
        short.write_bytes(b"abc")
        self.assertIsNone(pin_gate.Seal.from_environment(store, {"WH_PIN_SEAL_KEY_FILE": str(short)}))

    def test_the_keypad_works_over_http_with_the_vault_locked(self) -> None:
        self.gate.sync_sealed()
        self.secrets.locked = True
        server = ThreadingHTTPServer(("127.0.0.1", 0), pin_gate.make_handler(self.gate))
        threading.Thread(target=server.serve_forever, args=(0.01,), daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        conn.request(
            "POST",
            "/_pin/unlock",
            body="pin=4821&next=/",
            headers={
                "X-Pin-Site": "app",
                "X-Forwarded-For": "10.0.0.1",
                "Host": "app.test",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        response = conn.getresponse()
        response.read()
        self.assertEqual(response.status, 303)
        cookie = response.getheader("Set-Cookie").split(";")[0]
        conn.request("GET", "/_pin/verify", headers={"X-Pin-Site": "app", "Cookie": cookie})
        self.assertEqual(conn.getresponse().status, 204)


class AutoPassSecretsTests(unittest.TestCase):
    def test_defaults_to_the_infra_vault_never_master(self) -> None:
        self.assertEqual(pin_gate.AutoPassSecrets().vault, "infra")

    def test_reads_through_the_daemon_from_the_named_vault_and_caches(self) -> None:
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="4821\n", stderr="")

        secrets = pin_gate.AutoPassSecrets(vault="master")
        with mock.patch.object(pin_gate.subprocess, "run", fake_run):
            self.assertEqual(secrets.get("portfolio/pin/app"), "4821")
            self.assertEqual(secrets.get("portfolio/pin/app"), "4821")
        self.assertEqual(calls, [["auto-pass", "provision-get", "--db", "master", "portfolio/pin/app"]])

    def test_set_goes_through_the_daemon_client_and_drops_the_cached_value(self) -> None:
        client = mock.MagicMock()
        module = mock.MagicMock(ProvisioningClient=mock.MagicMock(return_value=client))
        module.ProvisioningClientError = RuntimeError
        secrets = pin_gate.AutoPassSecrets(vault="master")
        secrets._cache["portfolio/pin/app"] = (0.0, "old")
        with mock.patch.dict(sys.modules, {"auto_pass": mock.MagicMock(), "auto_pass.client": module}):
            secrets.set("portfolio/pin/app", "7305")
        client.set.assert_called_once_with("portfolio/pin/app", "7305", db="master")
        self.assertNotIn("portfolio/pin/app", secrets._cache)

    def test_set_failure_is_a_secret_error_that_does_not_carry_the_value(self) -> None:
        client = mock.MagicMock()
        client.set.side_effect = RuntimeError("not permitted to write")
        module = mock.MagicMock(ProvisioningClient=mock.MagicMock(return_value=client))
        module.ProvisioningClientError = RuntimeError
        with (
            mock.patch.dict(sys.modules, {"auto_pass": mock.MagicMock(), "auto_pass.client": module}),
            self.assertRaises(pin_gate.SecretError) as caught,
        ):
            pin_gate.AutoPassSecrets().set("portfolio/pin/app", "7305")
        self.assertNotIn("7305", str(caught.exception))

    def test_a_refused_read_fails_closed(self) -> None:
        refused = subprocess.CompletedProcess([], 1, stdout="", stderr="not permitted")
        with (
            mock.patch.object(pin_gate.subprocess, "run", return_value=refused),
            self.assertRaises(pin_gate.SecretError),
        ):
            pin_gate.AutoPassSecrets().get("portfolio/pin/app")


class SecretFailureReasonTests(unittest.TestCase):
    def read(self, **run_kwargs):
        with (
            mock.patch.object(pin_gate.subprocess, "run", **run_kwargs),
            self.assertRaises(pin_gate.SecretError) as caught,
        ):
            pin_gate.AutoPassSecrets().get("portfolio/pin/app")
        return caught.exception

    def test_a_missing_binary_is_reported_as_missing_not_locked(self) -> None:
        error = self.read(side_effect=FileNotFoundError(2, "No such file or directory: 'auto-pass'"))
        self.assertEqual(error.reason, "missing")
        self.assertIn("auto-pass", str(error))

    def test_a_locked_daemon_is_reported_as_locked(self) -> None:
        locked = subprocess.CompletedProcess([], 1, stdout="", stderr="error: daemon is locked")
        self.assertEqual(self.read(return_value=locked).reason, "locked")

    def test_a_refusal_is_reported_as_denied(self) -> None:
        refused = subprocess.CompletedProcess([], 1, stdout="", stderr="repo is not permitted")
        self.assertEqual(self.read(return_value=refused).reason, "denied")

    def test_other_launch_failures_are_a_generic_error(self) -> None:
        self.assertEqual(self.read(side_effect=PermissionError("denied")).reason, "error")


class LoggingTests(unittest.TestCase):
    def setUp(self) -> None:
        root = pin_gate.logging.getLogger()
        self.addCleanup(setattr, root, "handlers", list(root.handlers))
        self.addCleanup(root.setLevel, root.level)
        root.handlers = []

    def test_platform_defaults_are_per_user_locations(self) -> None:
        mac = pin_gate.default_log_path("darwin", {"HOME": "/Users/u"})
        win = pin_gate.default_log_path("win32", {"USERPROFILE": "C:/Users/u", "LOCALAPPDATA": "C:/L"})
        linux = pin_gate.default_log_path("linux", {"HOME": "/home/u", "XDG_STATE_HOME": "/s"})
        self.assertEqual(mac, Path("/Users/u/Library/Logs/wiring-harness/pin-gate.log"))
        self.assertEqual(win, Path("C:/L/wiring-harness/Logs/pin-gate.log"))
        self.assertEqual(linux, Path("/s/wiring-harness/pin-gate.log"))

    def test_file_is_on_for_mac_and_windows_and_off_for_linux_by_default(self) -> None:
        with mock.patch.dict(pin_gate.os.environ, {}, clear=False):
            pin_gate.os.environ.pop(pin_gate.LOG_FILE_ENV, None)
            self.assertIsNone(pin_gate.resolve_log_file(None, "linux"))
            self.assertIsNotNone(pin_gate.resolve_log_file(None, "darwin"))
            self.assertIsNotNone(pin_gate.resolve_log_file(None, "win32"))
            self.assertIsNone(pin_gate.resolve_log_file("off", "darwin"))
            self.assertIsNotNone(pin_gate.resolve_log_file("default", "linux"))

    def test_writes_an_owner_only_file_once_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "logs" / "gate.log"
            pin_gate.configure_logging("INFO", str(path))
            pin_gate.configure_logging("INFO", str(path))
            pin_gate.LOG.error("failing closed for app: auto-pass unavailable")
            for handler in pin_gate.logging.getLogger().handlers:
                handler.flush()
            self.assertEqual(path.read_text().count("failing closed"), 1)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(pin_gate.logging.getLogger().handlers), 2)
            for handler in pin_gate.logging.getLogger().handlers:
                handler.close()

    def test_an_unwritable_log_file_is_not_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            blocker = Path(tmp) / "file"
            blocker.write_text("x")
            pin_gate.configure_logging("INFO", str(blocker / "sub" / "gate.log"))
        self.assertEqual(len(pin_gate.logging.getLogger().handlers), 1)

    def test_unknown_level_falls_back_to_info(self) -> None:
        pin_gate.configure_logging("loud", "off")
        self.assertEqual(pin_gate.logging.getLogger().level, pin_gate.logging.INFO)


class SystemUnitTests(unittest.TestCase):
    """The gate runs as a system unit with a minimal PATH; it must still find `auto-pass`."""

    UNIT = Path(__file__).resolve().parents[1] / "config" / "systemd" / "wiring-harness-pin-gate.system.service.example"

    def test_unit_path_includes_the_user_local_bin_where_auto_pass_installs(self) -> None:
        lines = [x for x in self.UNIT.read_text().splitlines() if x.startswith("Environment=PATH=")]
        self.assertEqual(len(lines), 1, "the unit must set PATH explicitly")
        self.assertIn("<home>/.local/bin", lines[0].split("=", 2)[2].split(":"))

    def test_serve_logs_an_error_when_auto_pass_is_not_on_path(self) -> None:
        args = pin_gate.build_parser().parse_args(["serve"])
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(pin_gate, "sites_from_registry", return_value={"app": mock.MagicMock()}),
            mock.patch.object(pin_gate, "default_state_file", return_value=Path(tmp) / "state.json"),
            mock.patch.object(pin_gate.shutil, "which", return_value=None),
            mock.patch.object(pin_gate, "ThreadingHTTPServer", side_effect=RuntimeError("stop")),
            mock.patch.object(pin_gate.threading, "Thread"),
            mock.patch.object(pin_gate.Rotation, "ensure"),
            self.assertLogs(pin_gate.LOG, "ERROR") as logs,
            self.assertRaises(RuntimeError),
        ):
            pin_gate._cmd_serve(args)
        self.assertIn("not found on PATH", "\n".join(logs.output))


class HelperTests(unittest.TestCase):
    def test_safe_next_rejects_open_redirects(self) -> None:
        for bad in (None, "", "http://evil.test/", "//evil.test", "/\\evil", "/a\r\nSet-Cookie: x=1", "/_pin/unlock?x"):
            with self.subTest(bad=bad):
                self.assertEqual(pin_gate.safe_next(bad), "/")
        self.assertEqual(pin_gate.safe_next("/a/b?c=d"), "/a/b?c=d")

    def test_client_ip_takes_the_hop_caddy_saw(self) -> None:
        self.assertEqual(pin_gate.client_ip({"X-Forwarded-For": "1.2.3.4, 10.0.0.9"}), "10.0.0.9")
        self.assertEqual(pin_gate.client_ip({}), "unknown")

    def test_notifier_without_targets_is_inert(self) -> None:
        notifier = pin_gate.Notifier.from_env({})
        self.assertEqual(notifier.targets, {})
        notifier._send_all(pin_gate.Newly("site", "app", 60))

    def test_notifier_reads_every_channel_from_env(self) -> None:
        env = {"WH_PIN_NOTIFY_SIGNAL_TARGET": "+10000000000", "WH_PIN_NOTIFY_GMAIL_TARGET": "me@example.test"}
        self.assertEqual(set(pin_gate.Notifier.from_env(env).targets), {"signal", "gmail"})

    def test_registry_collects_only_pin_sites(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "services.toml"
            path.write_text(
                '[[services]]\nname = "a"\nhostname = "a.test"\nport = 1\n'
                '[[services]]\nname = "b"\nhostname = "b.test"\nport = 2\npin = true\npin_ttl_hours = 2\n'
                'pin_entry = "x/y"\n'
            )
            sites = pin_gate.sites_from_registry(path)
        self.assertEqual(sites, {"b": pin_gate.SiteConfig("b", "x/y", 7200)})


class ServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.clock = Clock()
        self.secrets = FakeSecrets()
        self.gate, self.notifier = make_gate(Path(self._tmp.name), self.clock, self.secrets)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), pin_gate.make_handler(self.gate))
        threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.port = self.server.server_address[1]

    def request(self, method, path, *, body="", site="app", ip="10.0.0.1", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        send = {"X-Forwarded-For": ip, "Host": "app.test"}
        if site:
            send["X-Pin-Site"] = site
        if body:
            send["Content-Type"] = "application/x-www-form-urlencoded"
        send.update(headers or {})
        conn.request(method, path, body=body or None, headers=send)
        response = conn.getresponse()
        data = response.read().decode()
        conn.close()
        return response, data

    def unlock(self, pin, **kw):
        return self.request("POST", "/_pin/unlock", body=f"pin={pin}&next=/dash", **kw)

    def test_verify_redirects_to_the_keypad_without_a_cookie(self) -> None:
        response, _ = self.request("GET", "/_pin/verify", headers={"X-Forwarded-Uri": "/dash?x=1"})
        self.assertEqual(response.status, 303)
        self.assertEqual(response.getheader("Location"), "/_pin/unlock?next=/dash%3Fx%3D1")

    def test_verify_gives_401_for_non_navigation(self) -> None:
        response, _ = self.request("GET", "/_pin/verify", headers={"X-Forwarded-Method": "POST"})
        self.assertEqual(response.status, 401)

    def test_unlock_sets_a_hardened_cookie_that_verify_accepts(self) -> None:
        response, _ = self.unlock("4821")
        self.assertEqual(response.status, 303)
        self.assertEqual(response.getheader("Location"), "/dash")
        set_cookie = response.getheader("Set-Cookie")
        for attribute in ("__Host-pin=app.", "Path=/", "Secure", "HttpOnly", "SameSite=Strict", "Max-Age=43200"):
            self.assertIn(attribute, set_cookie)
        cookie = set_cookie.split(";")[0]
        ok, _ = self.request("GET", "/_pin/verify", headers={"Cookie": cookie})
        self.assertEqual(ok.status, 204)

    def test_a_cookie_for_one_site_does_not_open_another(self) -> None:
        cookie = self.unlock("4821")[0].getheader("Set-Cookie").split(";")[0]
        response, _ = self.request("GET", "/_pin/verify", site="docs", headers={"Cookie": cookie})
        self.assertEqual(response.status, 303)

    def test_cookie_expires_after_the_site_ttl(self) -> None:
        cookie = self.unlock("4821")[0].getheader("Set-Cookie").split(";")[0]
        self.clock.now += 12 * 3600 + 1
        response, _ = self.request("GET", "/_pin/verify", headers={"Cookie": cookie})
        self.assertEqual(response.status, 303)

    def test_wrong_pin_is_401_then_the_lock_is_429_and_never_echoes_the_guess(self) -> None:
        for _ in range(2):
            response, body = self.unlock("0000")
            self.assertEqual(response.status, 401)
            self.assertNotIn("0000", body)
        response, body = self.unlock("0000")
        self.assertEqual(response.status, 429)
        self.assertIn("Try again", body)
        self.assertEqual(self.unlock("4821", ip="10.0.0.5")[0].status, 429)  # correct PIN refused while locked
        self.assertEqual(len(self.notifier.events), 1)

    def test_keypad_shows_lock_state(self) -> None:
        for _ in range(3):
            self.unlock("0000")
        response, body = self.request("GET", "/_pin/unlock?next=/dash")
        self.assertEqual(response.status, 200)
        self.assertIn("Too many attempts", body)

    def test_unknown_or_missing_site_header_is_rejected(self) -> None:
        for site in (None, "nope", "App", "a b"):
            with self.subTest(site=site):
                self.assertEqual(self.request("GET", "/_pin/verify", site=site)[0].status, 400)

    def test_cross_origin_unlock_is_refused_and_not_counted(self) -> None:
        for headers in ({"Sec-Fetch-Site": "cross-site"}, {"Origin": "https://evil.test"}):
            response, _ = self.request("POST", "/_pin/unlock", body="pin=0000", headers=headers)
            self.assertEqual(response.status, 403)
        self.assertEqual(self.gate.lockouts.store.snapshot()["sites"], {})

    def test_origin_null_from_no_referrer_pages_is_allowed(self) -> None:
        # The sites send Referrer-Policy: no-referrer, so browsers send Origin: null on same-origin posts.
        for headers in (
            {"Origin": "null", "Sec-Fetch-Site": "same-origin"},
            {"Origin": "null"},
            {"Sec-Fetch-Site": "same-origin"},
        ):
            with self.subTest(headers=headers):
                self.assertEqual(self.unlock("4821", headers=headers)[0].status, 303)

    def test_origin_null_from_another_site_is_still_refused(self) -> None:
        for headers in (
            {"Origin": "null", "Sec-Fetch-Site": "cross-site"},
            {"Origin": "null", "Sec-Fetch-Site": "same-site"},
            {"Origin": "https://evil.test", "Sec-Fetch-Site": "none"},
        ):
            with self.subTest(headers=headers):
                self.assertEqual(self.unlock("0000", headers=headers)[0].status, 403)
        self.assertEqual(self.gate.lockouts.store.snapshot()["sites"], {})

    def test_change_pin_accepts_origin_null_too(self) -> None:
        response, _ = self.request(
            "POST",
            "/_pin/change",
            body="current=4821&new=7305&confirm=7305",
            headers={"Origin": "null", "Sec-Fetch-Site": "same-origin"},
        )
        self.assertEqual(response.status, 303)

    def test_same_origin_unlock_is_allowed(self) -> None:
        response, _ = self.unlock("4821", headers={"Origin": "https://app.test", "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(response.status, 303)

    def test_oversized_body_is_refused(self) -> None:
        response, _ = self.request("POST", "/_pin/unlock", body="pin=" + "1" * 5000)
        self.assertEqual(response.status, 413)

    def test_fails_closed_when_secrets_are_unavailable(self) -> None:
        del self.secrets.values["portfolio/pin/app"]
        self.assertEqual(self.request("GET", "/_pin/verify", headers={"Cookie": "__Host-pin=app.1.x"})[0].status, 503)
        self.assertEqual(self.unlock("4821")[0].status, 503)

    def test_each_secret_failure_gets_its_own_honest_message(self) -> None:
        for reason, phrase in (
            ("locked", b"vault is locked"),
            ("missing", b"command was not found"),
            ("denied", b"refused the request"),
            ("error", b"see the PIN gate log"),
        ):
            with self.subTest(reason=reason):
                self.secrets.get = mock.Mock(side_effect=pin_gate.SecretError("x", reason))
                response, body = self.request("GET", "/_pin/verify", headers={"Cookie": "__Host-pin=app.1.x"})
                self.assertEqual(response.status, 503)
                self.assertIn(phrase, body if isinstance(body, bytes) else body.encode())
                self.assertEqual(body if isinstance(body, bytes) else body.encode(), pin_gate.UNAVAILABLE_BODIES[reason])

    def test_changing_the_pin_revokes_existing_cookies(self) -> None:
        cookie = self.unlock("4821")[0].getheader("Set-Cookie").split(";")[0]
        self.secrets.values["portfolio/pin/app"] = "9999"
        self.assertEqual(self.request("GET", "/_pin/verify", headers={"Cookie": cookie})[0].status, 303)

    def test_change_page_and_flow_over_http(self) -> None:
        response, body = self.request("GET", "/_pin/change?next=/dash")
        self.assertEqual(response.status, 200)
        self.assertIn("Current PIN", body)
        self.assertIn('value="/dash"', body)
        form = "current=4821&new=7305&confirm=7305&next=/dash"
        response, _ = self.request("POST", "/_pin/change", body=form)
        self.assertEqual(response.status, 303)
        self.assertEqual(response.getheader("Location"), "/dash")
        cookie = response.getheader("Set-Cookie").split(";")[0]
        self.assertEqual(self.secrets.values["portfolio/pin/app"], "7305")
        self.assertEqual(self.request("GET", "/_pin/verify", headers={"Cookie": cookie})[0].status, 204)

    def test_change_errors_use_distinct_statuses_and_never_echo_pins(self) -> None:
        for form, status in (
            ("current=0000&new=7305&confirm=7305", 401),
            ("current=4821&new=0000&confirm=0000", 422),
            ("current=4821&new=7305&confirm=7306", 422),
        ):
            with self.subTest(form=form):
                response, body = self.request("POST", "/_pin/change", body=form, ip="10.0.9.9")
                self.assertEqual(response.status, status)
                for secret in ("4821", "7305", "7306"):
                    self.assertNotIn(secret, body)

    def test_change_is_locked_out_like_unlocking(self) -> None:
        for _ in range(3):
            self.request("POST", "/_pin/change", body="current=0000&new=7305&confirm=7305")
        response, _ = self.request("POST", "/_pin/change", body="current=4821&new=7305&confirm=7305", ip="10.0.0.9")
        self.assertEqual(response.status, 429)
        self.assertEqual(self.secrets.values["portfolio/pin/app"], "4821")

    def test_change_refuses_cross_origin_posts(self) -> None:
        response, _ = self.request(
            "POST", "/_pin/change", body="current=4821&new=7305&confirm=7305", headers={"Sec-Fetch-Site": "cross-site"}
        )
        self.assertEqual(response.status, 403)
        self.assertEqual(self.secrets.values["portfolio/pin/app"], "4821")

    def test_a_failed_write_is_503_and_leaves_the_pin(self) -> None:
        self.secrets.write_fails = True
        response, _ = self.request("POST", "/_pin/change", body="current=4821&new=7305&confirm=7305")
        self.assertEqual(response.status, 503)
        self.assertEqual(self.secrets.values["portfolio/pin/app"], "4821")

    def test_the_keypad_links_to_the_change_page(self) -> None:
        self.assertIn("/_pin/change", self.request("GET", "/_pin/unlock")[1])

    def test_state_file_holds_counts_only_never_guesses(self) -> None:
        self.unlock("0007")
        text = json.dumps(self.gate.lockouts.store.snapshot())
        self.assertNotIn("0007", text)


if __name__ == "__main__":
    unittest.main()
