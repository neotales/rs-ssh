# SSH real-peer tests

This unpublished package is separate from `neotales-ssh`. Selecting the library
package does not compile testcontainers. Both real peers run the same handshake,
pinned host-key acceptance/rejection, and authorized/unauthorized public-key
authentication cases. No in-process SSH fake is used.

The Docker image is `lscr.io/linuxserver/openssh-server`, pinned to OCI index
`sha256:161e0b670b31d9539ca1718bc5943e981779331b4e1c9d32e8929d7652a1f22f`.
The index digest was resolved with `docker buildx imagetools inspect` on
2026-11-11. The tag text does not override the content digest.
The testcontainers dependency is pinned to `=0.28.0`.

```sh
cargo test -p neotales-ssh-e2e
NEOTALES_SSH_E2E=1 cargo test -p neotales-ssh-e2e
```

Without the runtime gate both tests skip. Docker being unavailable skips the
Docker peer locally. The manual CI workflow explicitly runs `docker info`
before testing so a missing daemon fails that job. The native Unix fixture
skips if sshd or ssh-keygen is absent. Other platforms compile and skip the
native fixture. Native test keys and daemon configuration are temporary. The
child is killed and waited for before the temporary directory is removed.
The Docker peer reads only its host **public** key over Docker exec for pinning.
No private host key is read by the tests. Fixture identities are synthetic.
