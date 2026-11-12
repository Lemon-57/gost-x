# Connection-limit recovery and graceful deployment

The connection limiter closes a rejected connection and continues accepting.
It does not return a fatal listener error when one client exceeds its budget.
Underlying listener failures still propagate, and accepted connections release
their limiter slot on close. The configured limit remains enforced.

`recovery_manager.py` extends an existing authoritative fixed-egress manager.
It preserves that manager's identity, ownership, authentication and retirement
checks. Readiness also checks each dynamic service's actual runtime state.
A closed listener can be recreated only after four observations without
accepted connections, with an immediate second check before replacement.
Ready listeners, active handlers, unknown states and configuration drift are
never automatically replaced. A consumer witness can be mirrored to a retained
retirement worker without overwriting a newer witness.

The default connection budget is 1024; topology, credentials, explicit budgets
and the installed base-manager path are runtime configuration. Keep those
configuration files private and outside the repository.

## Deployment procedure

1. Build the main proxy locally against this module. Pin the main repository
   revision and this module's commit, and record SHA-256 for the finished Linux
   executable. No build or dependency installation is needed on application
   servers.
2. Run the wrapper/service regression tests and synthetic integration checks.
   Exercise the actual connection limit, rejection and recovery, live limiter
   updates with held tunnels, authentication, fixed source address, TLS, SSE,
   WebSocket, connection-preserving NAT changes and rollback.
3. Inspect resource headroom, application/dependency health, all consumers and
   active connections. Stage the same artifact on unused, protected listeners
   against the current authoritative ownership files.
4. Start the new manager and validate every service, its fixed source address,
   authentication reference, listener and connection budget. Validate real
   authenticated egress for selected existing identities.
5. Use an isolated canary route first. Complete an already established tunnel
   across the atomic new-connection route change. Validate rollback while both
   generations remain running, preserving tunnels established through each.
6. Commit all new connections only after candidate checks pass. Keep the old
   listeners available for their existing connections. Never flush conntrack,
   rewrite ownership history, rotate credentials or change an account's exit.
7. Keep startup restoration pointed at the verified generation. Observe real
   business outcomes, queues, resource use and dependencies after the switch.
   Retain a verified rollback generation; stop it only after natural drain and
   confirmation that it has no other consumers.

`generation_runtime.py` validates targets before changing its dedicated NAT
table. It retains the last verified route on errors. The runtime's bootstrap
mode restores guards and current authoritative addresses before starting and
validating the new generation. Rollback requires the old generation to be
running and compatible with current identities, and leaves existing new
connections alive. The optional drain observer can retain the old generation
as recovery material after it becomes idle.

## Local checks

```sh
go test ./limiter/conn/wrapper ./service ./registry
python -m unittest discover -s deployment -v
```

The deployment helpers are an adapter for an installed management service,
not a replacement allocator. Keep its complete ownership and permanent-denial
rules in force when adapting the runtime configuration.
