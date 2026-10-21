# Synthetic case: failures followed by success

This is a deliberately constructed test scenario, not a real incident.

Five failed logins for `demo-user` from `192.0.2.10` occur at 00:00 through 00:04 UTC. AUTH-001 fires on the fifth failure. A success at 00:04:30 produces AUTH-002 with the five failure IDs plus the success ID. A benign success from a different source/account produces no alert.

The observation supports an investigation hypothesis: password guessing followed by a successful login. It also fits benign explanations such as repeated typos. Without MFA, device, service, and user context, compromise is undetermined. The appropriate lab conclusion is “two rules matched,” not “an attacker was stopped.”

Reproduce with the README command and compare each evidence ID to `data/auth-demo.jsonl`. Move the success beyond five minutes after the final failure and observe AUTH-002 disappear. Run with threshold 6 and observe no alerts for the original fixture.
