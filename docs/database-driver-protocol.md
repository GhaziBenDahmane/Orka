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
cannot bypass the startup checks.

Dockyard starts a fresh process for each call, writes one JSON request to stdin,
and reads one JSON response from stdout. Protocol version 1 supports
`describe`, `render`, `backup`, `restore`, and `readiness`. Calls time out after
15 seconds and output is capped at 4 MiB. Utility plans are executed in the
same isolated Docker jobs as built-in drivers; image names and artifact
extensions are validated before execution.

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
