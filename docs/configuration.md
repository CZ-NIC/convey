# Configuration

Every [CLI flag](convey-help-cmd-output.md) can be made permanent in the config file `convey.yaml`. It is created in the user config folder (ex: `~/.config/convey/`) at the first launch, together with the e-mail templates and the contact lists.

Open it with:

```bash
$ convey --config
```

Convey tries to open the file in the default GUI editor, or in the terminal editor if GUI is not an option. Other files can be opened the same way: `convey --config uwsgi`, `convey --config template`, `convey --config template_abroad`.

## File structure

The options are grouped in sections. The section names are shown in `convey --help` (*io options*, *cli options*, …). Put only the options you want to change.

```yaml
cli:
  autoopen_editor: True
  write_statistics: True
mod:
  dig: True      # enable DNS fields (a, mx, spf…)
  nmap: False
comp:
  external_fields:
    - /tmp/myfile.py
whois:
  local_country: cz
  backend: auto  # auto|rdap|whois
  ttl: 86400
sending:
  testing: True
  testing_mail: me@example.com
  email_from_name: My Name <me@example.com>
  contacts_cc: contacts_cc.csv
  contacts_abroad: contacts_abroad.csv
web:
  webservice_allow_unsafe_fields: []
```

A flag given on the command line wins over the config file.

Most flags have no section prefix on the command line (`--dig`, `--testing`). The `whois`, `otrs` and `web` sections keep it: `--whois.backend rdap`, `--whois.local-country cz`.

## Frequently changed options

| Option | Meaning |
|--------|---------|
| `mod.dig`, `mod.nmap`, `mod.web`, `mod.whois` | enable or disable the field modules |
| `comp.external_fields` | your own [external fields](fields/external-fields.md) |
| `comp.single_query_ignored_fields` | fields not computed in the [single value](single-value.md) mode (default: `html`) |
| `whois.local_country` | your country; IPs from elsewhere are considered *abroad* (see `incident_contact` in [computing fields](fields/computing-fields.md#whois)) |
| `sending.*` | SMTP host, sender, templates, testing mode, see [sending e-mails](sending-files.md) |
| `otrs.*` | OTRS connection |
| `web.webservice_allow_unsafe_fields` | re-enable `code` and `external` in the [web service](web-service.md) |

## Daemon

To start up quickly, convey keeps a warm background process (daemon) with the libraries loaded. The CLI connects to it automatically.

```bash
$ convey --daemon status     # start|restart|stop|status
$ convey --daemon False ...  # run this call without the daemon
```

The daemon is used for single queries and headless runs (no menu involved). Should it behave stale (ex: after upgrading convey), run `convey --daemon restart`.

## Files and logs

* The results of a CSV processing are saved next to the source file, in a directory like `file.csv_convey1791910245/` (together with the cache of the file settings).
* Warnings and errors are logged into `convey.log` in the user log dir (ex: `~/.cache/convey/log/`), change it by `--log-file`.
* `--write-statistics` writes a `statistics.txt` next to the analyzed file with the whois summary.
