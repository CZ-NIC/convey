#!/usr/bin/env python3
import bdb
import os
import socket
import sys

from .ipc import send, recv, socket_file, daemon_pid

__doc__ = """Convey – CSV swiss knife brought by CSIRT.cz"""
__author__ = "Edvard Rejthar, CSIRT.CZ"
__date__ = "$Feb 26, 2015 8:13:25 PM$"

if sys.version_info[0:2] < (3, 6):
    print("We need at least Python 3.6, your version is " + sys.version + ". Try an older Convey release or rather upgrade Python.")
    quit()


def main():
    if not sys.stdin.isatty():
        # we're already receiving something through a pipe
        # load it immediately and not in the wrapper because daemon could suck the pipe of the instance
        sys.argv.extend(["--input", sys.stdin.read().rstrip()])
    daemonize_on_exit = True
    if os.path.exists(socket_file):  # faster than importing Pathlib.path
        try:
            pipe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            pipe.connect(socket_file)
            pipe.settimeout(3)
        except ConnectionRefusedError:
            pass
        else:
            send(pipe, repr([os.getcwd()] + sys.argv))
            try:
                response = recv(pipe)
            except socket.timeout:
                print("It seems daemon is stuck. You may kill it with pkill `convey`.")
                from .config import Config
                if Config.get("github_crash_submit"):
                    Config.github_issue(f"daemon stuck", "Command line:\n```bash\n" + repr(sys.argv) + "\n```")
            else:
                # chr(4) at the end means this was not a single query check and we should load full convey libraries
                if type(response) is str:
                    if not response.endswith(chr(17)):  # daemon is stopping
                        daemonize_on_exit = False
                        if not response.endswith(chr(4)):  # daemon brings some results
                            print(response, end='')
                            quit()
            finally:
                pipe.close()

    try:
        from .controller import Controller
        Controller()
    except KeyboardInterrupt:
        print("Interrupted")
    except SystemExit:
        if daemonize_on_exit:
            from .config import Config
            try:
                if Config.get("daemonize", get=bool) and not daemon_pid():
                    # we are sure there is no running instance of the daemon
                    import subprocess
                    subprocess.Popen([sys.argv[0], '--daemon', 'server'], stdout=subprocess.DEVNULL)
            except FileNotFoundError:
                # XX we should check this code allows Win to run without daemon or rather make the daemon work on Win
                pass
    except bdb.BdbQuit:
        pass
    except:
        import traceback
        debug = True
        try:
            from .config import Config
            debug = Config.is_debug() or Config.get("crash_post_mortem")
        except ImportError:
            Config = None

        type_, value, tb = sys.exc_info()
        if debug:
            traceback.print_exc()
            import pdb
            mod = Config.get_debugger() if Config else pdb
            mod.post_mortem(tb)
        elif Config:
            # XX we should check the -3 line has something to do with the convey directory, otherwise print out other lines
            #   (we are not interested of the errors in other libraries)
            print(f"Convey crashed at {value} on {traceback.format_exc().splitlines()[-3].strip()}")
            if Config.get("github_crash_submit"):
                body = f"```bash\n{traceback.format_exc()}```\n\n```json5\n{tb.tb_next.tb_frame.f_locals}\n```"
                Config.github_issue(f"crash: {value}", body)


class WebServer:
    source_parser = None


def application(env, start_response):
    """ WSGI launcher. You may expose installed convey as a web service.
        Launch: uwsgi --http :9090 --wsgi-file wsgi.py
        Access: http://localhost:9090/?q=1.2.3.4
    """
    if not WebServer.source_parser:
        from convey.config import Config
        from convey.parser import Parser
        from convey.types import Types
        Types.refresh()
        Config.integrity_check()
        Config.init_verbosity()
        WebServer.source_parser = Parser(prepare=False)

    headers = [('Access-Control-Allow-Origin', '*')]
    t = env["QUERY_STRING"].split("q=")  # XX sanitize?
    if len(t) == 2:
        res = WebServer.source_parser.set_stdin([t[1]]).prepare
        if res.is_single_query:
            response = res.run_single_query(json=True)
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
