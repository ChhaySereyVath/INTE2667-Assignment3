"""R06: a small, documented load test: "The system remains responsive under the
documented prototype load test."

flask load-test                       run in-process against this app (no server needed)
flask load-test --url https://localhost:5000
                                      run against the real running server

The mix (per 10 requests): 6 public page loads, 3 election reads, 1 failed login.
It reports the 95th-percentile response times and the error rate. A 429 counts as the
rate limiter doing its job, not as an error.
"""
import ssl
import statistics
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import click
from flask import current_app
from flask.cli import with_appcontext

MIX = (("GET", "/"), ("GET", "/"), ("GET", "/login"), ("GET", "/"), ("GET", "/register"),
       ("GET", "/"), ("GET", "/elections"), ("GET", "/elections"), ("GET", "/elections"),
       ("POST", "/auth/login"))
# A login is slow ON PURPOSE: bcrypt takes about a quarter of a second (R09). So logins
# get their own, looser target; everything else must answer quickly.
TARGET_P95_MS = {"page": 800, "login": 3000}
TARGET_ERROR_RATE = 0.01


def _p95(times):
    times = sorted(times)
    return round(times[max(0, int(len(times) * 0.95) - 1)], 1) if times else 0.0


def summarise(results):
    """results: a list of (kind, status, milliseconds). Returns the report numbers."""
    errors = sum(1 for _, status, _ in results if status >= 500 or status == 0)
    report = {"requests": len(results),
              "p50_ms": round(statistics.median(ms for _, _, ms in results), 1)}
    for kind in TARGET_P95_MS:
        report[f"{kind}_p95_ms"] = _p95([ms for k, _, ms in results if k == kind])
    report["error_rate"] = errors / len(results)
    report["rate_limited"] = sum(1 for _, status, _ in results if status == 429)
    report["passed"] = (errors / len(results) < TARGET_ERROR_RATE and
                        all(report[f"{kind}_p95_ms"] < limit for kind, limit in TARGET_P95_MS.items()))
    return report


def run_load(send, total, workers):
    """Call send(method, path) `total` times from `workers` threads at once."""
    def one(number):
        method, path = MIX[number % len(MIX)]
        started = time.perf_counter()
        status = send(method, path)
        return ("login" if path == "/auth/login" else "page", status,
                (time.perf_counter() - started) * 1000)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return summarise(list(pool.map(one, range(total))))


def in_process_sender(app):
    def send(method, path):
        client = app.test_client()
        if method == "POST":
            return client.post(path, json={"username": "load-test", "password": "not-the-password"}).status_code
        return client.get(path).status_code
    return send


def http_sender(base_url):
    # the prototype's certificate is self-signed for localhost; only then is it accepted
    context = ssl.create_default_context()
    if base_url.startswith("https://localhost") or base_url.startswith("https://127.0.0.1"):
        context.check_hostname, context.verify_mode = False, ssl.CERT_NONE

    def send(method, path):
        data = b'{"username": "load-test", "password": "not-the-password"}' if method == "POST" else None
        request = urllib.request.Request(base_url.rstrip("/") + path, data=data, method=method,
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=10, context=context) as response:  # nosec B310
                return response.status
        except urllib.error.HTTPError as error:
            return error.code
        except OSError:
            return 0  # no answer at all counts as an error
    return send


@click.command("load-test")
@click.option("--requests", "total", default=2000, show_default=True)
@click.option("--workers", default=50, show_default=True, help="Simultaneous clients")
@click.option("--url", default=None, help="A running server, e.g. https://localhost:5000")
@with_appcontext
def load_test_command(total, workers, url):
    """Run the documented prototype load test and print the results."""
    send = http_sender(url) if url else in_process_sender(current_app._get_current_object())
    report = run_load(send, total, workers)
    for name, value in report.items():
        click.echo(f"{name}: {value}")
    click.echo(f"Target: p95 under {TARGET_P95_MS['page']} ms for pages and "
               f"{TARGET_P95_MS['login']} ms for logins, errors under {TARGET_ERROR_RATE:.0%}. "
               f"{'PASS' if report['passed'] else 'FAIL'}")
