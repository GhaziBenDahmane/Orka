# Security policy

Please report vulnerabilities privately to the project owner rather than filing
a public issue. Production installations must use TLS, a randomly generated
master key, restricted access to the Docker socket, and a dedicated PostgreSQL
password.

Compose workloads are untrusted input. Dockyard rejects privileged mode, host
namespaces, Docker socket mounts, and absolute/relative bind mounts by default.
Setting `DOCKYARD_ALLOW_UNSAFE_WORKLOADS=true` disables these checks and should
only be used in an isolated cluster.

The control-plane container has access to the Swarm manager socket and is
therefore part of the host root trust boundary. Multi-cluster deployments should
move execution behind the planned outbound mTLS agent.
