# External database driver protocol

Trusted executable drivers extend the built-in database catalog without being
linked into the controller. Set `DOCKYARD_DATABASE_DRIVER_DIRECTORY` to an
absolute directory containing executable files owned by the controller's OS
user (root in the published container). The directory must have the same owner;
neither it nor its drivers may be group/world writable. A symlink cannot be
used as the directory, and symlinked entries and non-executable files are
ignored. Driver names cannot replace built-ins. External drivers are supported
only on Linux. Every invocation opens the driver without following symlinks,
revalidates the opened inode, and executes that file descriptor so a path swap
cannot bypass the startup checks. The controller also hashes the executable
used for `describe`, rejects files larger than 64 MiB, and refuses every later
operation if the newly opened artifact no longer matches that startup digest.
The digest, but never the host path, is exposed in engine inventory and AI
audit snapshots for release provenance.

Dockyard starts a fresh process for each call, writes one JSON request to stdin,
and reads one JSON response from stdout. Protocol version 1 supports
`describe`, `render`, `backup`, `restore`, and `readiness`. Calls time out after
15 seconds and output is capped at 4 MiB. Utility plans are executed in the
same isolated Docker jobs as built-in drivers; image names and artifact
extensions are validated before execution. Plans are limited to 128 non-empty
arguments (128 KiB total), 128 POSIX-named environment entries (1 MiB total),
and 32 basename-only helper files (1 MiB total). An argument is at most 16 KiB,
an environment value or helper file is at most 64 KiB, and NUL bytes are
rejected. The controller and remote cluster agent independently apply these
limits before creating files or invoking Docker. Backup and restore plans are
accepted only when `backup-restore` was declared, and their extension must
match `backupExtension`.

Driver stderr and protocol error text are deliberately not copied into API,
job, or audit errors: requests may contain plaintext database credentials and a
faulty driver could echo them. Failures identify only the trusted driver and
operation. Diagnose a driver locally with scrubbed test credentials before
installing it. The process receives a fixed system `PATH` and no inherited
controller environment.

Go plugins can import `github.com/bendahma/dokploy-go/pkg/databaseplugin`,
implement `databaseplugin.Driver`, and call:

```go
func main() {
    if err := databaseplugin.Serve(myDriver{}, os.Stdin, os.Stdout); err != nil {
        log.Fatal(err)
    }
}
```

`Describe` returns a lowercase unique name, default image version, and optional
`backup-restore` capability with `backupExtension`. `Render` returns Compose
YAML, runtime environment, one-time credentials, internal URL, and resolved
version. Utility methods return an image, argv array, environment, extension,
and optional small configuration files. Passwords belong in the environment or
files, never argv.

Drivers execute with controller privileges and receive plaintext generated
database credentials when operational plans are requested. Package, sign,
review, and deploy them as trusted control-plane artifacts. Restart controllers
after changing the directory; hot loading is intentionally unsupported.
