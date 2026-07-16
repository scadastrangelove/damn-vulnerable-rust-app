# Seccomp

DVRA does not ship a custom seccomp profile and the Compose file does not ask
Docker to relax syscall filtering. The lab containers also drop Linux
capabilities and set `no-new-privileges`.

The effective seccomp policy still depends on the host Docker daemon. If
`docker info` reports an unconfined daemon profile, fix the host configuration
or add an explicit scenario-specific profile before treating the container as a
security boundary.

If a future scenario needs a custom profile, keep it scenario-specific and
document why the default profile is insufficient.
