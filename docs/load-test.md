# R06 prototype load test

**Requirement:** "The system remains responsive under the documented prototype load test."

## How it was run

1. Start the app: `python run.py`
2. In a second terminal: `flask load-test --url https://localhost:5000 --requests 2000 --workers 50`

50 clients send 2000 requests at once. Per 10 requests: 6 page loads, 3 election
reads (which also exercise the login check) and 1 failed login (which exercises
bcrypt, the failed-login lock and the audit trail).

## Targets

| Measure | Target |
|---|---|
| 95th-percentile response, pages and reads | under 800 ms |
| 95th-percentile response, logins (bcrypt is slow on purpose) | under 3000 ms |
| Errors (5xx or no answer) | under 1% |

## Result

These are the actual local load-test results:

| Measure | Result |
|---|---|
| Requests | 2000 |
| p50_ms | 2053.7 ms |
| page_p95_ms | 2074.4 ms |
| login_p95_ms | 2073.3 ms |
| error_rate | 0.01 (exactly 1%) |
| rate_limited | 630 |
| passed | False |

The login p95 met the 3000 ms target. The page p95 did not meet the 800 ms target.
The error rate was exactly 1%, so it did not satisfy the target of under 1%. Rate
limiting was active, with 630 requests receiving 429 responses.
