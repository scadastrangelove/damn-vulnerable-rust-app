# Threat Models

DVRA intentionally uses the same code under different assumptions. The result
is only a vulnerability when the assumptions make the path attacker-controlled
and impactful.

## TM-01: Trusted local operator

Configuration files and environment variables are controlled by a trusted
operator on the host. Shell execution in post-processing can be administrative
functionality under this model.

## TM-02: Tenant-controlled project configuration

A tenant can supply project processing configuration. The same shell execution
path becomes command injection because the command string is attacker-controlled.

## TM-03: Remote tenant user

The attacker has an authenticated tenant identity and can call public API
routes. This model is used by DVRA-001 and by reachability analysis for
DVRA-013.
