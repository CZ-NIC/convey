#!/usr/bin/env python3
import sys

__doc__ = """Convey – CSV swiss knife brought by CSIRT.cz"""
__author__ = "Edvard Rejthar, CSIRT.CZ"
__date__ = "$Feb 26, 2015 8:13:25 PM$"

if sys.version_info[0:2] < (3, 6):
    print("We need at least Python 3.6, your version is " + sys.version + ". Try an older Convey release or rather upgrade Python.")
    quit()


def main():
    try:
        from .controller import Controller
        Controller()
    except KeyboardInterrupt:
        print("Interrupted")
    except SystemExit as e:
        pass
    except:
        import traceback
        debug = True
        try:
            from .config import Config
            debug = Config.is_debug()
        except ImportError:
            Config = None

        if debug:
            try:
                import pudb as mod
            except ImportError:
                try:
                    import ipdb as mod
                except ImportError:
                    import pdb as mod
            type_, value, tb = sys.exc_info()
            traceback.print_exc()
            mod.post_mortem(tb)
        elif Config:
            print(f"Convey crashed at {sys.exc_info()[1]}")
            body = f"```bash\n{traceback.format_exc()}```\n\n```json\n{sys.exc_info()[2].tb_next.tb_frame.f_locals}```"
            Config.github_issue(f"crash: {sys.exc_info()[1]}", body.replace("\n", "%0A"))


class WebServer:
    source_parser = None


def application(env, start_response):
    """ WSGI launcher. You may expose installed convey as a web service.
        Launch: uwsgi --http :9090 --wsgi-file wsgi.py
        Access: http://localhost:9090/?q=1.2.3.4
    """
    if not WebServer.source_parser:
        from convey.config import Config
        from convey.sourceParser import SourceParser
        Config.init()
        WebServer.source_parser = SourceParser(prepare=False)

    headers = [('Access-Control-Allow-Origin', '*')]
    t = env["QUERY_STRING"].split("q=")  # XX sanitize?
    if len(t) == 2:
        res = WebServer.source_parser.set_stdin([t[1]]).prepare()
        if res.single_value:
            response = res.run_single_value(json=True)
            headers.append(('Content-Type', 'application/json'))
            status = '200 OK'
        else:
            response = '{"error": "could not process input"}'
            status = '400 Bad Request'
    else:
        status = '400 Bad Request'
        response = '{"error": "invalid input"}'
    start_response(status, headers)

    return [bytes(response, "UTF-8")]


if __name__ == "__main__":
    print("*************")
    main()
