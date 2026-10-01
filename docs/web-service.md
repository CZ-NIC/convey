# Web service
When launched as a web service, several parameters are available:

* `q` – search query
* `type` – same as `--type` CLI flag
* `field` – same as `--field` CLI flag.
    * Note that unsafe field types `code` and `external` are disabled in web service by default. You may re-allow them in `webservice_allow_unsafe_fields` config option
    * full syntax of CLI flag is supported
    > *FIELD[[CUSTOM]],[COLUMN],[SOURCE_TYPE],[CUSTOM],[CUSTOM]*

    Ex: `reg_s,l,L` performs regular substitution of *'l'* by *'L'*

* `clear=web` – clears web scrapping module cache

Quick deployment may be realized by a single command:
```bash
$ convey --server
```

* Note that convey must be installed via `pip`
* Note that LACNIC may freeze for 300 s, hence the timeout recommendation.
* Note that you may find your convey installation path by launching `pip3 show convey`
* If you received or [generated](https://uwsgi-docs.readthedocs.io/en/latest/HTTPS.html#https-support-from-1-3) key and certificate, you may turn on HTTPS in `uwsgi.ini` accesible by: `convey --config uwsgi`
* Internally, flag `--server` launches `wsgi.py` with a UWSGI session.
    ```bash
    $ uwsgi --http :26683 --http-timeout 310 --wsgi-file /home/$USER/.local/lib/python3.../site-packages/convey/wsgi.py
    ```


Access: `curl http://localhost:26683/?q=example.com`
```json
{"ip": "93.184.216.34", "prefix": "93.184.216.0-93.184.216.255", "asn": "", "abusemail": "abuse@verizondigitalmedia.com", "country": "unknown", "netname": "edgecast-netblk-03", "csirt-contact": "-", "incident-contact": "unknown", "status": 200, "text": "DNSThe free app that makes your (much longer text...)"}
```

Access: `curl http://localhost:26683/?q=example.com&field=ip`
```json
{"ip": "93.184.216.34"}
```

Access: `curl http://localhost:26683?q=hello&type=country&field=reg_s,l,L`
```json
{"reg_s": "heLLo"}
```

