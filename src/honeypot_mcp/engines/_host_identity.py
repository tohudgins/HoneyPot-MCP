"""The host identity engines share when they describe the machine they run on.

Every engine on a deployment answers from the same IP, so they are one host to anyone who compares
them. Redis reported kernel 5.15.0-101-generic, the Docker API 5.15.0-88-generic and the Kubernetes
node 5.15.0-1051-aws; an nmap sweep prints all three side by side (`redis-info`, `docker-version`,
the node object), and one machine cannot run three kernels. They read from here instead.
(Cowrie's persona filesystems are separate, per-distro identities by design.)
"""

KERNEL_RELEASE = "5.15.0-101-generic"
OS_PRETTY_NAME = "Ubuntu 22.04.3 LTS"
