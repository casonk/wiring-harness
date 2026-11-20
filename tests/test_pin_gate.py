from __future__ import annotations

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

    def get(self, entry: str) -> str:
        try:
            return self.values[entry]
        except KeyError:
            raise pin_gate.SecretError(f"no secret {entry}") from None


class FakeNotifier:
    def __init__(self) -> None:
        self.events: list[pin_gate.Newly] = []

    def notify(self, event: pin_gate.Newly) -> None:
        self.events.append(event)


class Clock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def make_gate(tmp: Path, clock: Clock, secrets=None, policy=None):
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
    gate = pin_gate.Gate(sites, secrets or FakeSecrets(), lockouts, notifier, clock=clock)
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


class AutoPassSecretsTests(unittest.TestCase):
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

    def test_a_refused_read_fails_closed(self) -> None:
        refused = subprocess.CompletedProcess([], 1, stdout="", stderr="not permitted")
        with mock.patch.object(pin_gate.subprocess, "run", return_value=refused):
            with self.assertRaises(pin_gate.SecretError):
                pin_gate.AutoPassSecrets().get("portfolio/pin/app")


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

    def test_changing_the_pin_revokes_existing_cookies(self) -> None:
        cookie = self.unlock("4821")[0].getheader("Set-Cookie").split(";")[0]
        self.secrets.values["portfolio/pin/app"] = "9999"
        self.assertEqual(self.request("GET", "/_pin/verify", headers={"Cookie": cookie})[0].status, 303)

    def test_state_file_holds_counts_only_never_guesses(self) -> None:
        self.unlock("0007")
        text = json.dumps(self.gate.lockouts.store.snapshot())
        self.assertNotIn("0007", text)


if __name__ == "__main__":
    unittest.main()
