# Web service

The [single value](single-value.md) mode may be exposed over HTTP, returning JSON.

## Launch

```bash
$ pip3 install uwsgi   # if not installed yet
$ convey --server
```

The server listens on the port 26683 by default. Its configuration (port, HTTPS, processes, timeouts) is in `uwsgi.ini`, open it by `convey --config uwsgi`.

* If you received or [generated](https://uwsgi-docs.readthedocs.io/en/latest/HTTPS.html#https-support-from-1-3) key and certificate, you may turn on HTTPS in `uwsgi.ini`.
* LACNIC may freeze for 300 s when its query rate is exceeded – consider raising the timeouts.
* Internally, flag `--server` launches uwsgi with the `wsgi.py` of your convey installation (find it by `pip3 show convey`):
    ```bash
    $ uwsgi --ini ~/.config/convey/uwsgi.ini --wsgi-file /home/$USER/.local/lib/python3.../site-packages/convey/wsgi.py
    ```

## Parameters

* `q` – search query
* `type` – same as the `--type` CLI flag
* `field` – same as the `--field` CLI flag, the full [field syntax](fields/computing-fields.md#field-syntax) is supported
    * Ex: `reg_s,l,L` performs regular substitution of *'l'* by *'L'*
    * The unsafe field types `code` and `external` are disabled by default. You may re-allow them in the `web.webservice_allow_unsafe_fields` [config option](configuration.md) – but beware, they let the caller run any code on your server.
* `clear=web` – clears the web scraping module cache

## Examples

Without a field, every computable information is returned.

```bash
$ curl "http://localhost:26683/?q=example.com"
{"cidr": "172.64.0.0/13", "country_name": "United States of America", "ip": "172.66.147.243", "tld": "com", "url": "http://example.com", "abusemail": "abuse@cloudflare.com", "asn": "as13335", "country": "us", "csirt_contact": "soc@us-cert.gov", "incident_contact": "us@@soc@us-cert.gov", "netname": "cloudflarenet", "prefix": "172.64.0.0/13", "http_status": "200", "text": "This domain is for use in documentation examples (...)", (...)}
```

```bash
$ curl "http://localhost:26683/?q=example.com&field=ip"
{"ip": "172.66.147.243"}

$ curl "http://localhost:26683/?q=hello&field=reg_s,l,L"
{"reg_s": "heLLo"}

$ curl "http://localhost:26683/?q=sc&type=country&field=country_name"
{"country_name": "Seychelles"}

$ curl "http://localhost:26683/?q=hello&field=code,x=1"
{"error": "could not process input", "message": "Unsafe field 'code' disabled via web"}
```
