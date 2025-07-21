from dataclasses import fields, is_dataclass
import logging
import os
import socket
import subprocess
import sys
from ast import literal_eval
from io import StringIO
from pathlib import Path
from sys import exit
from tempfile import NamedTemporaryFile
from typing import Any, Optional, TYPE_CHECKING

from attr import mutable
from colorama import init as colorama_init, Fore
from prompt_toolkit import PromptSession, HTML
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.shortcuts import clear
from validate_email import validate_email
from mininterface import Mininterface
from mininterface.interfaces import TextInterface

from .aggregate import Aggregate, aggregate_functions
from .action import AggregateAction
from .action_controller import ActionController
from .args_controller import Env, get_parser, parse_args
from .attachment import Attachment
from .config import Config, console_handler, edit, get_path
from .contacts import Contacts
from .flag import MergeFlag, FlagController
from .decorators import PickBase, PickMethod, PickInput
from .dialogue import Cancelled, Debugged, Menu, csv_split, init_global_interface
from .field import Field
from .ipc import socket_file, recv, send, daemon_pid
from .mail_sender import MailSenderOtrs, MailSenderSmtp
from .parser import Parser
from .types import Types, TypeGroup
from .wizzard import bottom_plain_style
from .wrapper import Wrapper
from . import __version__

if TYPE_CHECKING:
    from socket import socket

logger = logging.getLogger(__name__)


def send_ipc(pipe, msg, refresh_stdout):
    sys.stdout = sys.stderr = StringIO()  # creating a new one is faster than truncating the old
    console_handler.setStream(sys.stdout)
    sys.stdout_real.write(refresh_stdout)
    return send(pipe, msg)


def control_daemon(cmd, in_daemon=False):
    if cmd == "stop":
        Config.get_env().process.daemonize = False  # daemon should not be started at the end
        print("Convey daemon stopping.")
    if cmd in ["restart", "start"]:
        if in_daemon:
            raise ConnectionResetError("restart.")
        else:
            Config.get_env().process.daemonize = True
            control_daemon("kill")
        if cmd == "start":
            print("Convey daemon starting.")
            exit()
    if cmd in ["kill", "stop"]:
        if in_daemon:
            raise ConnectionResetError("stop.")
        else:
            pid = daemon_pid()
            if pid:
                subprocess.run(["kill", pid])
            if Path(socket_file).exists():
                Path(socket_file).unlink()
    if cmd == "stop":
        exit()
    if cmd == "status":
        if daemon_pid():
            print(f"Convey daemon is listening at socket {socket_file}")
        else:
            print("Convey daemon seems not to be running.")
        exit()
    if cmd is False:
        if in_daemon:
            raise ConnectionAbortedError("Daemon should not be used")
        else:
            Config.get_env().process.daemonize = False
    if cmd == "server":
        if in_daemon:
            raise ConnectionAbortedError("The new process will become the new server.")
        else:
            control_daemon("kill")
    return cmd


class Controller:

    def __init__(self, parser=None):
        self.parser = parser

    def run(self, given_args: Optional[str] = None):
        """
        Args:
            given_args - Input for ArgumentParser. Else sys.argv used.
        """

        # load types so that we can print out computable types in the help text
        # Hence, we cannot use the Env object yet.
        Types.refresh(True)
        self.m = parse_args(args=given_args)
        Config.set_env(self.m.env)
        try:
            m = TextInterface()
        except ImportError:
            m = Mininterface()
        finally:
            init_global_interface(m)
        self.env = self.m.env

        self.see_menu = True
        self.check_server()
        is_daemon, stdout, server = self.check_daemon()
        self.assure_terminal(is_daemon)
        ac = self.process_args_from_daemon_or_locally(is_daemon, stdout, server)
        self.run_menu(ac)

    def check_server(self):
        if self.env.process.server:
            # XX not implemeneted: allow or disable fields via CLI by ex: `--web`
            print(f"Webserver configuration can be changed by `convey --config uwsgi`")
            print(get_path("uwsgi.ini").read_text())
            cmd = ["uwsgi", "--ini", get_path("uwsgi.ini"), "--wsgi-file", Path(Path(__file__).parent, "wsgi.py")]
            subprocess.run(cmd)
            exit()

    def check_daemon(self):
        daemon = self.env.process.daemon
        cli = self.env.cli
        if daemon is not None and control_daemon(daemon) == "server":
            # XX :( after a thousand requests, we start to slow down. Memory leak must be somewhere
            Config.get_env().process.daemonize = False  # do not restart daemon when killed, there must be a reason this daemon was killed
            if Path(socket_file).exists():
                Path(socket_file).unlink()

            try:
                Config.init_verbosity(cli.yes, 30 if cli.quiet else (10 if cli.verbose else None), True)
            except ConnectionAbortedError:
                print("Config file integrity check failed. Launch convey normally to upgrade config parameters.")
                exit()

            print("Opening socket...")
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(socket_file)
            server.listen()
            sys.stdout_real = stdout = sys.stdout
            sys.stdout = sys.stderr = StringIO()
            console_handler.setStream(sys.stdout)
            PromptSession.__init__ = lambda _, *ar, **kw: (_ for _ in ()).throw(
                ConnectionAbortedError('Prompt raised.'))
            return True, stdout, server
        return None, None, None

    def assure_terminal(self, is_daemon):
        if not is_daemon and not sys.stdin.isatty():  # piping to the process, no terminal
            try:
                sys.stdin = open("/dev/tty")
            except OSError:
                # this might work on Windows platform
                # Return "" for every input we got.
                PromptSession.prompt = lambda *ar, **kw: ""
            else:
                # Let's make a safe_prompt that is able to read from /dev/tty.
                # prompt_toolkit does not work with /dev/tty stdin
                # because it is a POSIX pipe only and it needs a "pseudo terminal pipe"
                # see https://github.com/prompt-toolkit/python-prompt-toolkit/issues/502
                # and menu does not work good
                def safe_prompt_2(*ar, **kw):
                    return input(ar[1] if len(ar) > 1 else kw["message"] if "message" in kw else "?")

                def safe_prompt(*ar, **kw):
                    print(
                        "This is just an emergency input mode because convey interactivity works bad when piping into.")
                    PromptSession.prompt = safe_prompt_2
                    return safe_prompt_2(*ar, **kw)

                PromptSession.prompt = safe_prompt

            self.see_menu = False
            self.env.cli.yes = True

    def process_args_from_daemon_or_locally(self, is_daemon, stdout, server):
        colorama_init()
        while True:
            try:
                if is_daemon:
                    stdout.write("Listening...\n")
                    stdout.flush()
                    pipe, _addr = server.accept()
                    msg = recv(pipe)
                    if not msg:
                        continue
                    stdout.write("Accepted: " + msg + "\n")
                    stdout.flush()
                    argv = literal_eval(msg)
                    if not argv:
                        raise ConnectionAbortedError("No arguments passed")
                    # elif "--disable-external" in argv:
                    #     # Param "disable_external" is parsed before the help text normally
                    #     # but we are in daemon and the help text has already been prepared with externals.
                    #     raise ConnectionAbortedError("Disable externals might change the behaviour (help text, ...)")
                    try:
                        os.chdir(Path(argv[0]))
                    except OSError:
                        stdout.write("Invalid cwd\n")
                        continue
                    # NOTE remove
                    # self.cleanup()  # reset new fields so that they will not be remembered in another query
                    try:
                        env = parse_args(argv[2:]).env  # the daemon has received a new command
                        # we have to copy the values into, to copy the values into self.env to keep references
                        self.copy_into(self.env, env)
                    except SystemExit as e:
                        if not sys.stdout.getvalue():
                            # argparse sent usage to stderr, we do not have in in stdout instance will rerun the command
                            raise ConnectionAbortedError("Error in help text")
                        else:
                            # argparse put everything in stdout
                            exit()
                    self.see_menu = True
                    control_daemon(self.env.process.daemon, True)
                ac = self.process_args(is_daemon)
                if not ac:
                    continue
            except ConnectionRefusedError as e:
                send_ipc(pipe, chr(3), f"Daemon has insufficient input: {e}\n")
                continue
            except (ConnectionAbortedError, IOError) as e:
                send_ipc(pipe, chr(4), "Daemon cannot help: " + (str(e) or "Probably a user dialog is needed.") + "\n")
                continue
            except ConnectionResetError as e:
                send_ipc(pipe, chr(17), f"Daemon killed: {e}\n")
                exit()
            except SystemExit:
                if is_daemon:
                    send_ipc(pipe, sys.stdout.getvalue(), "Result sent.\n")
                    continue  # wait for next IPC connection
                else:
                    raise
            break
        return ac

    def process_args(self, is_daemon) -> Optional[ActionController]:
        e = self.env
        # this try-block may send the results to the client convey processes when a daemon is used
        if e.process.server:
            raise ConnectionAbortedError("web server request")
        if e.env.config:
            if e.env.config is True:
                e.env.config = "config"
            edit(e.env.config, mode=3, restart_when_done=True)
            exit()
        e.io.stdout = e.io.output is True or None
        if e.io.output is True:
            # --output=True → no output file in favour of stdout (.stdout -> parser.stdout set)
            # --output=FILE → an output file generated (.output -> parser.target_file set)
            e.io.output = None

        if e.cli.headless or e.sending.send_test:
            e.cli.yes = True
            e.cli.quiet = True
            self.see_menu = False
        Config.init_verbosity(e.cli.yes, 30 if e.cli.quiet else (
            10 if e.cli.verbose else None), is_daemon)
        if is_daemon:
            logger.debug("This result comes from the daemon.")
        Types.refresh()  # reload Types for the second time so that the methods reflect CLI flags
        TypeGroup.init()
        if e.env.show_uml is not None:
            print(Types.get_uml(int(e.env.show_uml)))
            exit()
        if e.env.get_autocompletion:
            print(self.get_autocompletion(get_parser()))
            exit()
        if e.env.version:
            print(__version__)
            exit()
        if e.io.csv_processing:
            e.io.single_query = False
        if e.io.single_query or e.io.single_detect:
            e.io.single_query = True
            if e.io.single_detect:
                e.io.single_detect = True

        new_fields: list[tuple[bool, Any]] = []
        "User has requested to compute these. Defined by tuples: add (whether to include the column in the result), field definition"
        [new_fields.append((True, values)) for values in e.action.field]
        [new_fields.append((False, values)) for values in e.action.field_excluded]

        self.m.env.comp.adding_new_fields = bool(new_fields)
        self.wrapper = Wrapper(self.m, e.io.file_or_input, e.io.file, e.io.input,
                               e.action.type, e.process.fresh, e.process.reprocess,
                               e.whois.delete)
        self.parser: Parser = self.wrapper.parser
        ac = ActionController(self.parser, self.m, e.process.reprocess)

        if e.process.threads is not None:
            e.process.threads = e.process.threads

        def get_column_i(col, check):
            self.parser.is_processable = True
            return self.parser.identifier.get_column_i(col, check=check)

        # load flags
        for field in fields(e.otrs):
            val = getattr(e.otrs, field.name)
            if val:
                self.parser.__dict__[field.name] = val
                logger.debug(f"{field.name}: {val}")

        # prepare some columns to be removed
        if e.action.delete:
            for c in e.action.delete.split(","):
                self.parser.fields[get_column_i(c, "to be deleted")].is_chosen = False

        # append new fields from CLI
        for add, task in new_fields:
            ac.add_new_column(task, add)

        # merge
        fc = FlagController(self.parser)
        if e.action.merge:
            ac.add_merge(**fc.read(MergeFlag, e.action.merge))

        # run single value check if the input is not a CSV file
        if e.io.single_detect:
            exit()
        if self.parser.is_single_query:
            res = self.parser.run_single_query(json=e.comp.json)
            if res:
                print(res)
            exit()
        if is_daemon and self.see_menu:  # if we will need menu, daemon must stop here
            raise ConnectionAbortedError("displaying a menu is too complex")

        if e.action.aggregate:
            params = csv_split(e.action.aggregate)
            group: Optional[Field] = self.parser.fields[get_column_i(params.pop(), "to be grouped by")] \
                if len(params) % 2 else None
            if not params:
                ac.add_aggregation(Aggregate.count.__name__, group, exit_on_fail=True)
            else:
                for i in range(0, len(params), 2):
                    column_task, fn_name = params[i:i + 2]
                    ac.add_aggregation(fn_name, column_task, group, grouping_probably_wanted=False, exit_on_fail=True)

        if e.action.sort:
            self.parser.resort(csv_split(e.action.sort))
            self.parser.is_processable = True

        if e.action.split:
            self.parser.settings["split"] = get_column_i(e.action.split, "to be split with")

        if e.action.include_filter:
            col, val = csv_split(e.action.include_filter)
            ac.add_filtering(True, get_column_i(col, "to be filtered with"), val)

        if e.action.exclude_filter:
            col, val = csv_split(e.action.exclude_filter)
            ac.add_filtering(False, get_column_i(col, "to be filtered with"), val)

        if e.action.unique:
            ac.add_uniquing(get_column_i(e.action.unique, "to be put a single time"))

        # set output dialect
        # Taken from config.ini or flags. If differs from the current one, parser marked as processable.
        self.parser.settings["dialect"] = dialect = type('', (), {})()
        for k, v in self.parser.dialect.__dict__.copy().items():
            setattr(dialect, k, v)

        def change_dialect(s, s2):
            # delimiter_output, quote_char_output
            v = getattr(e.csv, s + "_output") or getattr(self.env.csv, s + "_output")
            if v and v != getattr(dialect, s2):
                v = v.replace(r"\t", "\t").replace("TAB", "\t").replace("tab", "\t")
                if len(v) != 1:
                    print(f"Output {s2} has to be 1 character long: {v}")
                    exit()
                setattr(dialect, s2, v)
                self.parser.is_processable = True

        change_dialect("delimiter", "delimiter")
        change_dialect("quote_char", "quotechar")
        self.parser.settings["header"] = self.parser.has_header
        if self.parser.has_header and e.csv.header_output is not None:
            # If current parser has header, we may cut it off
            # However, this is such a small change, we will not turning parser.is_processable on.
            self.parser.settings["header"] = e.csv.header_output

        if self.parser.is_processable and self.m.env.cli.yes:
            self.process()

        if e.sending.send and self.parser.is_analyzed and self.parser.is_split and not self.parser.is_processable:
            self.see_menu = False
            if e.sending.send is not True:
                self.send_menu(e.sending.send, send_now=True)
            else:
                self.send_menu(send_now=True)
        if e.sending.send_test:
            c = Path(e.sending.send_test[1]).read_text()
            Path(Config.get_cache_dir(), Config.get_env().sending.mail_template).write_text(c)
            Path(Config.get_cache_dir(), Config.get_env().sending.mail_template_abroad).write_text(c)
            self.send_menu(test_attachment=e.sending.send_test[0])

        if not self.see_menu:
            self.close()
        if is_daemon:  # if in daemon, everything important has been already sent to STDOUT
            exit()
        return ac

    def run_menu(self, ac: ActionController):
        # main menu
        start_debugger = False
        session = None
        while True:
            if session and hasattr(session, "process"):
                # session.prompt keybinding asked processing
                # (we cannot reprocess from keybinding due to the deadlock if an input had been encountered,
                # no clear way to call a prompt within another prompt)
                self.process()
            self.parser = self.wrapper.parser  # may be changed by reprocessing
            self.parser.informer.sout_info()

            if start_debugger:
                print("\nDebugging mode, you may want to see `self.parser` variable:")
                start_debugger = False
                Config.get_debugger().set_trace()

            menu = Menu(title="Main menu - how the file should be processed?")
            menu.add("Pick or delete columns", ac.choose_cols)
            menu.add("Add a column", ac.add_column)
            menu.add("Filter", ac.add_filter)
            menu.add("Split by a column", ac.add_splitting)
            menu.add("Change CSV dialect", ac.add_dialect)
            menu.add("Aggregate", ac.add_aggregation)
            menu.add("Merge", ac.add_merge)
            if self.parser.is_processable:
                menu.add("process", self.process, key="p", default=True)
            else:
                menu.add("process  (choose some actions)")
            if self.parser.is_analyzed and self.parser.is_split:
                if self.parser.is_processed:
                    menu.add("send...", self.send_menu, key="s", default=not self.parser.is_processable)
                else:
                    menu.add("send (process first)")
            else:
                menu.add("send (split first)")
            if self.parser.is_analyzed:
                menu.add("show all details", lambda: (self.parser.informer.sout_info(full=True), input()), key="d")
            else:
                menu.add("show all details (process first)")
            menu.add("redo...", self.redo_menu, key="r")
            menu.add("config...", self.config_menu, key="c")
            menu.add("exit", self.close, key="x")

            try:
                bindings = KeyBindings()
                session = PromptSession()

                def refresh():
                    # exiting the app makes the main menu redraw again
                    session.app.exit(session.layout.current_buffer.text or "refresh")

                @bindings.add('right')  # select column
                def _(_):
                    self.parser.move_selection(1)
                    refresh()

                @bindings.add('left')  # select column
                def _(_):
                    self.parser.move_selection(-1)
                    refresh()

                @bindings.add('c-right')  # control-right to move the column
                def _(_):
                    self.parser.move_selection(1, True)
                    refresh()
                    self.parser.is_processable = True

                @bindings.add('c-left')  # control-left to move the column
                def _(_):
                    self.parser.move_selection(-1, True)
                    refresh()
                    self.parser.is_processable = True

                @bindings.add('delete')  # enter to toggle selected field
                def _(_):
                    [f.toggle_chosen() for f in self.parser.fields if f.is_selected]
                    refresh()
                    self.parser.is_processable = True

                @bindings.add('escape', 'a')  # alt-a to aggregate
                def _(_):
                    for f in self.parser.fields:
                        if f.is_selected:
                            self.parser.settings["aggregate"] = AggregateAction(f, [(Aggregate.count, f)])
                            self.parser.is_processable = True
                            session.process = True
                            break
                    else:
                        # I cannot use a mere `input()` here, it would interfere with promtpt_toolkit and freeze
                        self.m.alert("No column selected to aggregate with.\nUse arrows to select a column first.")
                    refresh()

                # @bindings.add('escape', 'n')  # alt-n to rename header
                # def _(_):
                #     for f in self.parser.fields:
                #         if f.is_selected:
                #             break
                #     refresh()

                options = {'key_bindings': bindings,
                           "bottom_toolbar": HTML("Ctrl+<b>←/→</b> arrows for column manipulation,"
                                                  " <b>Delete</b> for exclusion,"
                                                  " <b>Alt+a</b> to aggregate count"),
                           "style": bottom_plain_style
                           }
                menu.sout(session, options)
            except Cancelled as e:
                print(e)
                pass
            except Debugged as e:
                start_debugger = True

    def send_menu(self, method="smtp", test_attachment=None, send_now=False):
        # choose method SMTP/OTRS
        # We prefer OTRS sending over SMTP because of the signing keys that an OTRS operator does not possess.
        if self.m.env.otrs.enabled and self.env.otrs.id:
            method = "otrs"
        elif self.m.env.otrs.enabled and not self.m.env.cli.yes:
            method = self.m.select({"Send by SMTP...": "smtp",
                                    "Send by OTRS...": "otrs"},
                                   "What sending method do we want to use?")
        if method == "otrs":
            sender = MailSenderOtrs(self.parser)
            sender.assure_tokens()
            self.wrapper.save()
        elif method == "smtp":
            sender = MailSenderSmtp(self.parser)
        else:
            raise RuntimeError("Unknown sending method: {method}")

        # sending dialog loop
        st = self.parser.stats
        limit = float("inf")
        def limitable(max_): return f"limited to: {limit}/{max_}" if limit < max_ else max_

        while True:
            # clear screen
            info = []

            # display info
            def display_recipients(abroad, text):
                draft = "abroad" if abroad else "local"
                c = st[draft]
                if sum(c) > 0:
                    info.append(f"{text}")
                    if c[0]:
                        info.append(f"Recipient list ({c[0]}/{sum(c)}): "
                                    + ", ".join([o.mail for o in Attachment.get_all(abroad, False, 5, True)]))
                    if c[1]:
                        info.append(f"Already sent ({c[1]}/{sum(c)}): "
                                    + ", ".join([o.mail for o in Attachment.get_all(abroad, True, 5, True)]))
                    info.append(f"Attachment: " + (", ".join(filter(None, (self.env.sending.attach_files and "split CSV file attached",
                                                                           self.env.sending.attach_paths_from_path_column and "files from the path column attached")))
                                                   or "nothing attached"))
                    info.append(f"\n{Contacts.mail_draft[draft].get_mail_preview()}\n")
                    return True
                return False

            seen_local = display_recipients(False, "  *** E-mail template ***")
            seen_abroad = display_recipients(True, "  *** Abroad template ***")

            if Config.is_testing():
                info.append(
                    f"\n\n\n*** TESTING MOD - mails will be sent to the address: {self.env.sending.testing_mail} ***"
                    f"\n (For turning off testing mode set `testing = False` in config.ini.)")
            info.append("*" * 50)
            sum_ = st['local'][0] + st['abroad'][0]
            everything_sent = False
            if sum_ < 1:
                everything_sent = True
                info.append("No e-mail to be sent.")
            method_s = "OTRS" if method == "otrs" else self.m.env.sending.smtp_host

            if test_attachment:
                option = "test"
            elif send_now:
                option = "1"
                send_now = False  # while-loop must not re-send
            else:
                clear()
                # NOTE convert to Mininterface.select when mnemonics is implemented
                menu = Menu("\n".join(info), callbacks=False, fullscreen=False, skippable=False)

                if seen_local or seen_abroad:
                    menu.add(f"Send all e-mails ({limitable(sum_)}) via {method_s}", key="1")
                if seen_local and seen_abroad:
                    menu.add(f"Send local e-mails ({limitable(st['local'][0])})", key="2")
                    menu.add(f"Send abroad e-mails ({limitable(st['abroad'][0])})", key="3")
                if len(menu.menu) == 0:
                    print("No e-mails in the set. Cannot send.")

                t = f" from {limit}" if limit < float("inf") else ""
                menu.add(f"Limit sending amount{t} to...", key="l")
                menu.add("Edit template...", key="e")
                menu.add("Choose recipients...", key="r")
                menu.add("Send test e-mail...", key="t", default=not everything_sent)
                menu.add("Print e-mails to a file...", key="p")
                menu.add(f"Attach files (toggle): {Config.get_env().sending.attach_files}", key="a")
                menu.add("Attach paths from path column (toggle):"
                         f" {Config.get_env().sending.attach_paths_from_path_column}", key="i")
                menu.add("Go back...", key="x", default=everything_sent)

                option = menu.sout()
                if option is None:
                    return

            # sending menu processing - all, abuse and abroad e-mails
            limit_csirtmails_when_all = limit - st['local'][0]
            if option in ("1", "2") and st['local'][0] > 0:
                print("Sending e-mails...")
                sender.send_list(Attachment.get_all(False, False, limit))
            if option in ("1", "3") and st['abroad'][0] > 0:
                # decrease the limit by the number of e-mails that was just send in basic list
                l = {"1": limit_csirtmails_when_all, "3": limit}[option]
                if l < 1:
                    print("Cannot send abroad e-mails due to limit.")
                else:
                    print("Sending to abroad e-mails...")
                    sender.send_list(Attachment.get_all(True, False, l))
            if option in ["1", "2", "3"]:
                if self.m.env.cli.yes:
                    return
                self.wrapper.save()  # save what message has been sent right now
                input("\n\nPress Enter to continue...")
                continue

            # other menu options
            if option == "e":
                local, abroad = st['local'][0], st['abroad'][0]
                if local:
                    Contacts.mail_draft["local"].edit_text()
                if abroad:
                    Contacts.mail_draft["abroad"].edit_text()
                if not (local or abroad):
                    print("Neither local nor abroad e-mails are to be sent, no editor was opened.")
            elif option == "l":
                limit = self.m.ask_number("How many e-mails should be send at once: ")
                if limit < 0:
                    limit = float("inf")
            elif option == "a":
                Config.get_env().sending.attach_files = not Config.get_env().sending.attach_files
            elif option == "i":
                Config.get_env().sending.attach_paths_from_path_column = not Config.get_env().sending.attach_paths_from_path_column
            elif option in ["test", "t", "r", "p"]:
                attachments = sorted(list(Attachment.get_all()), key=lambda x: x.mail.lower())
                if option == "p":
                    with NamedTemporaryFile(mode="w+") as f:
                        try:
                            print(
                                f"The messages are being temporarily generated to the file (stop by Ctrl+C): {f.name}")
                            for attachment in attachments:
                                print(".", end="")
                                sys.stdout.flush()
                                f.write(str(attachment.get_envelope()))
                            f.file.flush()
                            print("Done!")
                        except KeyboardInterrupt:
                            print("Interrupted!")
                        finally:
                            edit(Path(f.name), blocking=True)
                elif option == "test":
                    choices = [o for o in attachments if o.mail == test_attachment]
                    if len(choices) != 1:
                        print(f"Invalid testing attachment {test_attachment}")
                    else:
                        print(choices[0].get_envelope().preview())
                    return
                elif option == "t":
                    # Choose an attachment
                    try:
                        attachment = self.m.select({o.mail: o for o in attachments},
                                                   f"What attachment should serve as a test?")
                    except Cancelled:
                        continue
                    clear()

                    # Display generated attachment
                    print(attachment.get_envelope().preview())

                    # Define testing e-mail
                    t = self.m.env.sending.testing_mail
                    t = f" – type in or hit Enter to use {t}" if t else ""
                    try:
                        t = self.m.ask(
                            Fore.YELLOW + f"Testing e-mail address to be sent to{t} (Ctrl+C to go back): " + Fore.RESET).strip()
                    except KeyboardInterrupt:
                        continue
                    if not t:
                        t = self.m.env.sending.testing_mail
                    if not t:
                        input("No address written. Hit Enter...")
                        continue

                    # Send testing e-mail
                    old_testing, old_sent, attachment.sent = Config.get_env().sending.testing, attachment.sent, None
                    Config.get_env().sending.testing = True
                    Config.get_env().sending.testing_mail = t
                    sender.send_list([attachment])
                    Config.get_env().sending.testing = old_testing
                    input("\n\nTesting completed. Press Enter to continue...")
                    attachment.sent = old_sent
                elif option == "r":
                    # choose recipient list
                    choices = {(o.mail, o.get_draft_name() + ("" if validate_email(o.mail, check_dns=False,
                                check_smtp=False) else " (invalid)")): o for o in attachments}
                    default = [o.mail for o in attachments if not o.sent]
                    try:
                        tags = set(self.m.select(choices, "Toggle e-mails to be send", default=default))
                    except Cancelled:
                        continue
                    else:
                        for attachment in attachments:
                            attachment.sent = attachment not in tags
                        print("Changed!")
            elif option == "x":
                return

    def process(self):
        self.parser.run_analysis()
        self.wrapper.save()

    def config_menu(self):
        def start_debugger():
            raise Debugged

        self.m.select({"Edit configuration": lambda: edit("config", 3, restart_when_done=True, blocking=True),
                       "Edit default e-mail template": lambda: edit("template", blocking=True),
                       "Edit default abroad e-mail template": lambda: edit("template_abroad", blocking=True),
                       "Edit uwsgi configuration": lambda: edit("uwsgi"),
                       "Fetch whois for an IP": self.debug_ip,
                       "Start debugger": start_debugger},
                      title="Config menu")

    def debug_ip(self):
        ip = input("Debugging whois – get IP: ")
        if ip:
            from .whois import Whois
            self.parser.reset_whois(assure_init=True)
            whois = Whois(ip.strip())
            print(whois.analyze())
            print(whois.whois_response)
        input()

    def choose_settings(self):
        """ Remove some of the processing settings """
        actions = []  # description
        discard = []  # lambda to remove the setting
        st = self.parser.settings
        fields = self.parser.fields

        def add_list(labels):
            actions.extend(labels)
            discard.extend((st[type_].pop, i) for i, _ in enumerate(items))

        # Build processing settings list
        for type_, items in st.items():
            if not items and items != 0:
                continue
            if type_ == "split":
                actions.append(f"split by {fields[items]}")
                discard.append((st.pop, "split"))
            elif type_ == "add":
                add_list(f"add {f} (from {str(f.source_field)})" for f in items)
            elif type_ == "filter":
                add_list(f"filter {fields[f].name} {'' if include else '!'}= {val}" for include, f, val in items)
            elif type_ == "unique":
                add_list(f"unique {fields[f].name}" for f in items)
            elif type_ == "aggregate":
                actions.extend(f"{fn.__name__}({fields[col].name})" for fn, col in items[1])
                discard.extend((st[type_][1].pop, i) for i, _ in enumerate(items[1]))
                self.parser.aggregation.clear()  # remove possible aggregation results

        if not actions:
            input("No processing settings found. Hit Enter...")
            return

        # Build dialog
        values = self.m.select({action: i+1 for i, action in enumerate(actions)},
                               "What processing settings should be discarded?", multiple=True, skippable=False)

        # these processing settings should be removed
        # we reverse the list, we need to pop bigger indices first without shifting lower indices
        for v in values[::-1]:
            fn, v = discard[int(v) - 1]
            fn(v)
        if st["aggregate"] and not st["aggregate"][1]:
            # when removing an aggregation settings, we check if it was the last one to get rid of the setting altogether
            del st["aggregate"]

    def redo_menu(self):
        self.m.select({f"Delete some processing settings": self.choose_settings,
                       "Delete all processing settings": self.parser.reset_settings,
                       "Delete whois cache": self.parser.reset_whois,
                       "Resolve unknown abuse-mails": self.parser.resolve_unknown,
                       "Resolve invalid lines": self.parser.resolve_invalid,
                       "Resolve queued lines": self.parser.resolve_queued,
                       "Rework whole file again": self.wrapper.clear},
                      title="What should be reprocessed?")
        # NOTE that aggregation generators were deleted (jsonpickling) → aggregation count will reset when re-resolving
        # See comment in the Aggregation class, concerning generator serialization.

    def close(self):
        self.wrapper.save(last_chance=True)  # re-save cache file
        if not self.m.env.cli.yes:
            if not Config.is_quiet():
                # Build processing settings list
                o = []
                st = self.parser.settings
                fields = self.parser.fields

                # XX code does not return its custom part
                if col := st["split"]:
                    o.append(f"--split {fields[col]}")
                o.extend(f"--field {f},{str(f.source_field)}" for f in st["add"])
                o.extend(f"--{'include' if include else 'exclude'}-filter {fields[f].name},{val}"
                         for include, f, val in st["filter"])
                o.extend(f"--unique {fields[f].name}" for f in st["unique"])
                if col := st["aggregate"]:
                    o.append(f"--aggregate " + ",".join(f"{col.name},{fn.__name__}" for fn, col in col.actions)
                             + (f",{col.group_by}" if col.group_by else ""))
                if o:
                    print(f" Settings cached:\n convey {self.parser.source_file} " + " ".join(o) + "\n")

            print("Finished.")
        exit(0)

    # NOTE remove
    # def cleanup(self):
    #     """ Make `Controller.run()` calls independent.
    #     This method is called by ex: tests.
    #     """
    #     new_fields.clear()
    #     # Config.cache.clear()

    def get_autocompletion(self, parser):
        actions = [x for action in parser._actions for x in action.option_strings]

        a = ["#!/usr/bin/env bash",
             "# bash completion for convey",
             ""
             '_convey()',
             '{',
             '  local cur',
             '  local cmd',
             '',
             '  cur=${COMP_WORDS[$COMP_CWORD]}',
             '  prev="${COMP_WORDS[COMP_CWORD-1]}";',
             '  cmd=( ${COMP_WORDS[@]} )',
             '',
             '  if [[ "$prev" == -f ]] || [[ "$prev" == --field ]] ||' +
             '  [[ "$prev" == -fe ]] || [[ "$prev" == --field-excluded ]]; then',
             f'        COMPREPLY=( $( compgen -W "{" ".join(t.name for t in Types.get_computable_types())}"  -- "$cur" ) )',
             '        return 0',
             '    fi',
             '',
             '  if [[ "$prev" == -a ]] || [[ "$prev" == --aggregate ]]; then',
             '    param=(${cur//,/ })',
             f'        COMPREPLY=( $( compgen -W "{" ".join("${param[0]}," + s for s in aggregate_functions)}"  -- "$cur" ) )',
             '        return 0',
             '    fi',
             '',
             '  if [[ "$cur" == -* ]]; then',
             f'    COMPREPLY=( $( compgen -W "{" ".join(actions)}" -- $cur ) )',
             '    return 0',
             '  fi',
             '}',
             '',
             'complete -F _convey -o default convey']
        return "\n".join(a)

    def copy_into(self, dst: Any, src: Any) -> None:
        """
        Recursively copy from src dataclass to dst dataclass.
        """
        for f in fields(dst):
            val_src = getattr(src, f.name)
            val_dst = getattr(dst, f.name)

            if is_dataclass(val_src):
                self.copy_into(val_dst, val_src)
            else:
                setattr(dst, f.name, val_src)
