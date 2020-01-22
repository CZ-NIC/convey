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
        # this is not a terminal - we may already receiving something through a pipe
        # load it immediately and not in the wrapper because daemon could suck the pipe of the instance
        # however sys.stdin.read() is a blocking operation so that we stuck in a pipe without stdin
        #    ex: running tests from the IDE or launching subprocess.run("convey ...")
        # As a compromise we check current sys.argv if there is an input token or not.
        # Note that this way we still get stuck when launching with an implicit input `subprocess.run("convey file.csv")`,
        # we have to explicitly state `subprocess.run("convey --file file.csv")`
        if not any(x in sys.argv for x in ['-i', '--input', '-f', '--file']):
            sys.argv.extend(["--input", sys.stdin.read().rstrip()])
    daemonize_on_exit = True
    if os.path.exists(socket_file):  # faster than importing Pathlib.path
        try:
            pipe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            pipe.connect(socket_file)
            pipe.settimeout(10)  # it can take several seconds to call whois
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
                    if response.endswith(chr(3)):  # daemon has missing input
                        pass
                    elif not response.endswith(chr(17)):  # daemon is not stopping
                        daemonize_on_exit = False
                        if not response.endswith(chr(4)):  # daemon brings some results
                            print(response, end='')
                            quit()
            finally:
                pipe.close()

    try:
        from .controller import Controller
        Controller().run()
    except KeyboardInterrupt:
        print("Interrupted")
    except SystemExit as e:
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


if __name__ == "__main__":
    main()
