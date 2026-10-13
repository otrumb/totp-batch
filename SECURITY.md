# Security

## Reporting

Report suspected vulnerabilities through GitHub private vulnerability reporting:
<https://github.com/otrumb/totp-batch/security/advisories/new>. Include version, OS,
command shape, expected result, and observed result. Never submit real secrets,
account labels, or generated codes.

## Secret handling

Default input uses one hidden terminal prompt. `--stdin` accepts redirected input.
Never place secrets in command arguments, environment variables, paths, filenames,
or URIs. Tool performs no network, storage, clipboard, QR, or telemetry operation.

Generated codes and input may remain exposed through terminal display, scrollback,
pipes, redirected standard output, receiving processes, process memory, swap, or
crash dumps. Python cannot guarantee secure erasure of immutable strings or bytes.
Protect host, terminal, shell, and downstream processes accordingly.
