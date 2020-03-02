import json
from collections import defaultdict
from urllib import parse

from convey.config import Config
from convey.controller import Controller
from convey.parser import Parser
from convey.types import Types, TypeGroup, Web

Types.refresh()
TypeGroup.init()
Config.integrity_check()
Config.init_verbosity(True, 30)
Config.set("single_query", True)
parser = Parser(prepare=False)
controller = Controller(parser)
unsafe_fields = [Types.code, Types.external]
for target_type in Config.get("webservice_allow_unsafe_fields", section="FIELDS", get=list):
    if hasattr(Types, target_type):
        unsafe_fields.remove(getattr(Types, target_type))


def application(env, start_response):
    """ WSGI launcher. You may expose installed convey as a web service.
        Launch: uwsgi --http :26683 --wsgi-file wsgi.py
        Access: http://localhost:26683/?q=example.com
    """
    headers = [('Access-Control-Allow-Origin', '*'), ('Content-Type', 'application/json')]
    argument = defaultdict(lambda: None, parse.parse_qsl(env["QUERY_STRING"]))  # XXX should this be sanitized?
    if "q" in argument:
        if not argument["q"].strip():
            status = '400 Bad Request'
            response = '{"error": "no input"}'
        else:
            try:
                if "clear" in argument:
                    if argument["clear"] == "web":
                        Web.cache.clear()

                res = parser.set_stdin([argument["q"]]).set_types(argument["type"]).prepare()
                if "field" in argument:  # XXX should this be sanitized?
                    target_type = controller.add_new_column(argument["field"], True)
                    if target_type in unsafe_fields:
                        raise SystemExit(f"Unsafe field '{target_type}' disabled via web")
                if res.is_single_query:
                    response = res.run_single_query(json=True)
                    status = '200 OK'
                else:
                    raise SystemExit("Too complicated")
            except SystemExit as e:
                d = {"error": "could not process input"}
                # XX we could change print("..."); quit(); to raising an exception so that we may catch a message
                # Now, everything will pop out to stdout, not to the web browser.
                if str(e):
                    d["message"] = str(e)
                response = json.dumps(d)
                status = '400 Bad Request'
    else:
        status = '400 Bad Request'
        response = '{"error": "put something in parameter \'q\' as query"}'
    start_response(status, headers)

    return [bytes(response, "UTF-8")]
