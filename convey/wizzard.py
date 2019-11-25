import logging
import re
from sre_constants import error

from prompt_toolkit import PromptSession, ANSI, HTML
from prompt_toolkit.application import get_app
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.shortcuts import clear
from prompt_toolkit.styles import Style
from prompt_toolkit.styles import merge_styles
from prompt_toolkit.styles.pygments import style_from_pygments_cls
from prompt_toolkit.validation import Validator, ValidationError
from pygments.lexer import RegexLexer, include
from pygments.lexers.python import Python3Lexer
from pygments.styles import get_style_by_name
from pygments.token import Token
from tabulate import tabulate

from convey import PickInput
from .config import Config, console_handler
from .dialogue import Cancelled
from .types import Type, Types


def yellow_no_end(s):
    return f"\033[0;41m{s}"


def yellow(s, error=False):
    s = f"\033[0;33m{s}\033[0m"
    if error:
        s += red("!")
    return s


def blue(s):
    return f"\033[0;36m{s}\033[0m"


def red(s):
    return f"\033[0;41m{s}\033[0m"


class RegularLexer(RegexLexer):
    tokens = {
        'root': [
            (r'\\^', Token.START_TEXT),
            (r'\$', Token.END_TEXT),
            (r'(\[\^)', Token.SQUARE_NEGATIVE, 'square-negative'),
            (r'(\[)', Token.SQUARE, 'square'),
            (r'\(', Token.ROUND, 'round'),
            (r'\{', Token.CURLY, 'curly'),
            include("grammar")
        ],
        'grammar': [
            (r'\\w', Token.W),
            (r'\\d', Token.D),
            (r'\.', Token.DOT),
            (r'\*', Token.ASTERISK),
            (r'\+', Token.PLUS),
            (r'\?', Token.QUESTION),
            (r'\//', Token.SLASH),
            (r'\|', Token.PIPE),
            (r'.', Token.TEXT),
        ],
        'round': [
            (r'\)', Token.ROUND, '#pop'),
            include("grammar"),
        ],
        'curly': [
            (r'\}', Token.CURLY, '#pop'),
            (r'.', Token.CURLY_TEXT),
        ],
        'square': [
            (r'\]', Token.SQUARE, '#pop'),
            (r'.', Token.SQUARE_TEXT),
        ],
        'square-negative': [
            (r'\]', Token.SQUARE_NEGATIVE, '#pop'),
            (r'.', Token.SQUARE_TEXT_NEGATIVE),
        ]
    }


# test_regex = "\w\d.*+?//| (abc)  [abc] [^abc] {abc}"

# reg_style = style_from_pygments_cls(get_style_by_name('colorful'))
reg_style = style_from_pygments_cls(get_style_by_name('friendly'))
reg_style = merge_styles([reg_style, Style.from_dict({
    'pygments.start_text': '#F00',
    'pygments.end_text': '#F00',
    'pygments.text': '#fff bg:#005',
    'pygments.w': '#000 bg:#00ffd7',
    'pygments.d': '#000 bg:#005fff',
    'pygments.dot': '#000 bg:#ffff00',
    'pygments.asterisk': '#000 bg:#ff5522',
    'pygments.plus': '#000 bg:#ff7755',
    'pygments.question': '#000 bg:#ff9977',
    'pygments.slash': '#f00 bg:#000',
    'pygments.pipe': '#0F0',
    'pygments.round': '#0F0',
    'pygments.curly': '#000 bg:#ffff55',
    'pygments.curly_text': '#000 bg:#ffff55',
    'pygments.square': '#fff bg:#0000ff',
    'pygments.square_text': '#fff bg:#0000ff',
    'pygments.square_negative': '#fff bg:#870000',
    'pygments.square_text_negative': '#fff bg:#870000',
})])
bottom_plain_style = Style.from_dict({
    'bottom-toolbar': 'noreverse',
})


def _code_method(e, x):
    """ simulate real code execution in the Identifier """
    l = locals()
    try:
        exec(compile(e, '', 'exec'), l)
    except:
        return ""
    x = l["x"]
    return x


def _reg_method(line, search, replace=None):
    """ simulate real reg ex matching in the Identifier """
    match = search.search(line)
    reg_s = ""

    if not match:
        return "", "", "", blue(line)
    groups = match.groups()
    if not groups:
        groups_preview = [match.group(0)]
    else:
        groups_preview = ["{0}: " + str(match.group(0))] + ["{" + str(i + 1) + "}: " + g for i, g in enumerate(groups)]

    if not replace:
        if not groups:
            reg_m = match.group(0)
        else:
            reg_m = match.group(1)
        reg_s = search.sub("", line)
    else:
        try:
            reg_m = replace.format(match.group(0), *[g for g in groups])
            # we convert "str{0}" → "\g<0>" (works better than conversion to a mere "\0" that may result to ambiguity
            try:
                replace_pattern = re.sub(r"{(\d+)}", r"\\g<\1>", replace)
                reg_s = search.sub(replace_pattern, line)
            except error:
                reg_s = "!"
        except IndexError:
            reg_m = ""
    span = match.span(0)
    return groups_preview, reg_m, reg_s, blue(line[0:span[0]]) + red(line[slice(*span)]) + blue(line[span[1]:])


class ReValidator(Validator):
    def validate(self, document):
        text = document.text
        try:
            re.compile(text)
        except re.error:
            for i in range(len(text)):
                try:
                    text = text[:-1]
                except re.error:
                    pass
                else:
                    break
            raise ValidationError(message='Cannot be used as a regexp.', cursor_position=len(text) - 1)


class TypeValidator(Validator):
    def validate(self, document):
        if document.text not in ["reg_m", "reg_s"]:
            raise ValidationError(message='Type reg_m or reg_s')


class Preview:

    def __init__(self, source_field, source_type: "Type", target_type: "Type" = None):
        self.source_field = source_field
        self.source_type = source_type
        self.target_type = target_type
        # common part of every preview
        self.samples = source_field.get_samples(supposed_type=source_type, target_type=target_type)

        # define key self.bindings
        self.session = self.reset_session()
        self.bindings = KeyBindings()

        # cancel on control-c (escape inaccessible, waits for another keystroke)
        @self.bindings.add('c-c')
        def _(_):
            get_app().exit(False)

        # exit on control+d (because the default exit command alt-enter seems unintuitive) (control+enter unacessible)
        @self.bindings.add('c-d')
        def _(_):
            get_app().exit(self.session.layout.current_buffer.text)

        # define styling
        self.style = merge_styles([reg_style, bottom_plain_style])

        # Init variables that may be used in methods
        self.get_toolbar_row = self.search = self.replace = self.phase = self.chosen_type =  None

    def standard_toolbar(self):
        """ define bottom preview toolbar """
        rows = []
        level = Config.verbosity  # temporarily suppress info messages like 'NMAPing...' that would break up the wizzard layout
        console_handler.setLevel(logging.WARNING)
        for line in self.samples:
            val = self.get_toolbar_row(self.session.layout.current_buffer.text, line)
            rows.append((f"\033[0;36m{line}\033[0m", f"\033[0;33m{val}\033[0m"))  # blue and yellow
        console_handler.setLevel(level)

        return ANSI('\nPreview\n' + tabulate(rows, headers=("original", "result"), tablefmt="github"))

    def code(self):
        """ code preview specific part """

        def get_toolbar_row_code(text, line):
            return _code_method(text, line)

        self.get_toolbar_row = get_toolbar_row_code

        def get_prompt():
            s = '<b>Ctrl+D</b>' if "\n" in self.session.layout.current_buffer.text else 'Ctrl+D'
            return HTML(f'Code <i>({s} to confirm)</i>: ')

        # prints the application
        text = self.reset_session().prompt(get_prompt, bottom_toolbar=self.standard_toolbar, style=self.style,
                                           lexer=PygmentsLexer(Python3Lexer), multiline=True, key_bindings=self.bindings)
        return text

    def pick_input(self, o: PickInput):
        """ code preview specific part """

        def get_toolbar_row_pick_input(text, line):
            try:
                val = o.get_lambda(text)(line)
            except Exception as e:
                val = str(e)
            return val

        self.get_toolbar_row = get_toolbar_row_pick_input

        def get_prompt():
            return HTML(o.description + ": ")

        # prints the application
        text = self.reset_session().prompt(get_prompt, bottom_toolbar=self.standard_toolbar, style=self.style,
                                           default=o.default or "", lexer=PygmentsLexer(Python3Lexer), key_bindings=self.bindings)
        if text is False:
            raise Cancelled
        return text

    def reg(self):
        """ regex preview specific part """
        # self.ask_search = True
        self.phase = None
        self.search = ""
        self.replace = ""
        self.target_type = [self.target_type] if self.target_type != Types.reg else [Types.reg_m, Types.reg_s]
        self.chosen_type = None

        # @self.bindings.add('escape', 'left')  # alt-left
        @self.bindings.add('c-i')  # tab to jump back
        def _(_):
            if self.phase > 1:
                clear()
                self.phase = "continue"
            self.session.app.exit(self.session.layout.current_buffer.text)

        if len(self.target_type) > 1:
            def toggle_type(default):
                if self.chosen_type is None:
                    self.chosen_type = default
                else:
                    self.chosen_type = Types.reg_m if self.chosen_type == Types.reg_s else Types.reg_s
                if self.phase == 3:
                    self.session.layout.current_buffer.text = str(self.chosen_type)

            @self.bindings.add('escape', 'left')  # cycle preferred method
            def _(_):
                toggle_type(Types.reg_s)

            @self.bindings.add('escape', 'right')  # cycle preferred method
            def _(_):
                toggle_type(Types.reg_m)

        # prints the application
        options = {"bottom_toolbar": self.reg_toolbar, "style": self.style,
                   "lexer": PygmentsLexer(RegularLexer), "multiline": False, "key_bindings": self.bindings}
        while True:
            # self.ask_search = False
            self.phase = 1
            self.search = self.reset_session().prompt('Regular match: ', **options, default=self.search,
                                                      validator=ReValidator())
            if self.search is False:
                raise Cancelled
            if self.phase == "continue":
                continue
            self.phase = 2
            self.replace = self.reset_session().prompt('Regular replace: ', **options, default=self.replace,
                                                       rprompt=HTML('hit <b>tab</b> to jump back'))
            if self.replace is False:
                raise Cancelled
            if self.phase == "continue":
                continue
            self.phase = 3
            if len(self.target_type) > 1:  # we have to choose the column
                if self.chosen_type is None:
                    # we are not using groups, match has no sense
                    self.chosen_type = Types.reg_s if "{" not in self.replace and self.replace else Types.reg_m
                type_ = self.reset_session().prompt('Do you prefer match or substitution? ', **options,
                                                    default=str(self.chosen_type),
                                                    rprompt=HTML('choose with <b>Alt+←/→</b>'), validator=TypeValidator())
                if self.phase == "continue":
                    continue
                if type_:
                    self.target_type = Types.reg_s if type_ == "reg_s" else Types.reg_m
                elif type_ is False:
                    raise Cancelled
                else:
                    self.target_type = self.chosen_type
            else:
                self.target_type = self.target_type[0]
            break
        return self.search, self.replace, self.target_type

    def reset_session(self):
        """ Calling
            self.session = PromptSession()
            self.session.prompt(validator=V)
            self.session.prompt(validator=None) → would still have previous validator

        """
        self.session = PromptSession()
        return self.session

    # define bottom preview toolbar
    def reg_toolbar(self):
        helper = ""
        rows = []
        match = []
        for line in self.samples:
            text = self.session.layout.current_buffer.text
            error = False  # prompt text is erroneous, probably not completed yet
            while True:
                row = []
                if self.phase == 1:  # first phase - searching for match string
                    contents = text
                    try:
                        search_re = re.compile(contents)
                    except re.error:
                        text = text[:-1]
                        error = True
                        continue
                    match, reg_m_preview, reg_s_preview, line = _reg_method(line, search_re, self.replace)
                    row.append("\n".join([yellow(m) for m in match]))  # colorize lines separately
                    if error:
                        row[-1] += red("!")
                    reg_m_preview = blue(self.highlight(reg_m_preview, Types.reg_m))
                    reg_s_preview = blue(self.highlight(reg_s_preview, Types.reg_s))
                    helper = r". - any char, \w - word, \d - digit, () - matching group"
                else:  # second phase - searching for replace string (and third phase just diplaying)
                    contents = self.search
                    search_re = re.compile(contents)
                    try:
                        match, reg_m_preview, reg_s_preview, line = _reg_method(line, search_re,
                                                                                text if self.phase == 2 else self.replace)
                    except ValueError:
                        text = text[:-1]
                        error = True
                        continue
                    # blue, blue, yellow
                    row.append("\n".join([blue(m) for m in match]))
                    reg_m_preview = yellow(self.highlight(reg_m_preview, Types.reg_m), error)
                    reg_s_preview = yellow(self.highlight(reg_s_preview, Types.reg_s), error)
                    helper = "Access matched parts with {0}, ex: string {1} string."
                if Types.reg_m in self.target_type:
                    row.append(reg_m_preview)
                if Types.reg_s in self.target_type:
                    if contents:
                        row.append(reg_s_preview)
                    else:
                        row.append("")
                row.insert(0, line)
                rows.append(row)
                break
        headers = ["original", "groups" if len(match) > 1 else "group {0}"]
        if Types.reg_m in self.target_type:
            headers.append(self.highlight("match", Types.reg_m))
        if Types.reg_s in self.target_type:
            headers.append(self.highlight("substitution", Types.reg_s))
            # 'grid' handles multiline rows well, 'github' handles them bad, despite the documentation
        return ANSI('\n\nPreview\n' + tabulate(rows, headers=headers, tablefmt="grid") + "\n\n" + helper)

    def highlight(self, s, current):
        if self.chosen_type is None:
            return s
        elif self.chosen_type == current:
            return f"\033[1m{s}\033[0m"
        else:
            return f"\033[38;5;7m{s}\033[0m"
