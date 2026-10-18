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

The task sheet records the following test-machine result. Its run date, computer, and
p50 value were not recorded; these values have not been rerun in this workspace.

| Measure | Result |
|---|---|
| Date and computer | Not recorded in the task sheet |
| Requests | 2000 |
| p50 | Not recorded in the task sheet |
| page_p95_ms | 307 ms |
| login_p95_ms | 506 ms |
| error_rate | 0% |
| rate_limited (429) | About half the requests |
| PASS / FAIL | PASS |

All 2000 requests come from one IP, so after the first 300 in a minute the rate limiter
answers 429 ("Too many requests"). That is R06 working, not an error: the service
stayed responsive because it refused the excess cheaply instead of trying to serve it.
