import re

from prompt_toolkit import PromptSession, ANSI, HTML
from prompt_toolkit.application import get_app
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.styles import Style
from prompt_toolkit.styles import merge_styles
from prompt_toolkit.styles.pygments import style_from_pygments_cls
from prompt_toolkit.validation import Validator, ValidationError
from pygments.lexer import RegexLexer, include
from pygments.lexers.python import Python3Lexer
from pygments.styles import get_style_by_name
from pygments.token import Token
from tabulate import tabulate


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


def _code_method(e, x):
    """ simulate real code execution in the Identifier """
    l = locals()
    try:
        exec(compile(e, '', 'exec'), l)
    except:
        return ""
    x = l["x"]
    return x


def _reg_method(s, search, replace=None):
    """ simulate real reg ex matching in the Identifier """
    match = search.search(s)

    if not match:
        return "", ""
    groups = match.groups()
    if not groups:
        preview = match.group(0)
    else:
        preview = "0: " + match.group(0) + "\n" + "\n".join([f"{i + 1}: {g}" for i, g in enumerate(groups)])

    # print(s, search, replace, match)
    # print(match.groups())
    if not replace:
        if not groups:
            result = match.group(0)
        else:
            result = match.group(1)
    else:
        try:
            result = replace.format(match.group(0), *[g for g in groups])
        except IndexError:
            result = ""
    return preview, result


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


class Preview:

    def __init__(self, source_field):
        self.source_field = source_field
        # common part of every preview
        self.samples = source_field.get_samples()

        # define key self.bindings
        self.session = PromptSession()
        self.bindings = KeyBindings()

        # cancel on control-c (escape inaccessible, waits for another keystroke)
        @self.bindings.add('c-c')
        def _(_):
            get_app().exit("")

        # define styling
        self.style = merge_styles([reg_style, Style.from_dict({
            'bottom-toolbar': 'noreverse',
        })])

    def code(self):
        """ code preview specific part """

        # exit on control+d (because the default exit command alt-enter seems unintuitive) (control+enter unacessible)
        @self.bindings.add('c-d')
        def _(_):
            get_app().exit(self.session.layout.current_buffer.text)

        # define bottom preview toolbar
        def get_toolbar():
            rows = []
            for line in self.samples:
                val = _code_method(self.session.layout.current_buffer.text, line)
                rows.append((f"\033[0;36m{line}\033[0m", f"\033[0;33m{val}\033[0m"))  # blue and yellow

            return ANSI('\nPreview\n' + tabulate(rows, headers=("original", "result"), tablefmt="github"))

        def get_prompt():
            s = '<b>Ctrl+D</b>' if "\n" in self.session.layout.current_buffer.text else 'Ctrl+D'
            return HTML(f'Code <i>({s} to confirm)</i>: ')

        # prints the application
        text = self.session.prompt(get_prompt, bottom_toolbar=get_toolbar, style=self.style,
                                   lexer=PygmentsLexer(Python3Lexer), multiline=True, key_bindings=self.bindings)
        return text

    def reg(self):
        """ regex preview specific part """
        self.ask_search = True
        self.phase = None
        self.search = ""
        self.replace = ""

        @self.bindings.add('c-i')  # tab to jump back
        def _(_):
            if self.phase == 2:
                self.ask_search = True
            get_app().exit(self.session.layout.current_buffer.text)

        # prints the application
        options = {"bottom_toolbar": self.get_toolbar_search, "style": self.style,
                   "lexer": PygmentsLexer(RegularLexer), "multiline": False, "key_bindings": self.bindings}
        while True:
            if self.ask_search:
                self.ask_search = False
                self.phase = 1
                self.search = self.session.prompt('Regular match: ', **options, default=self.search, validator=ReValidator())
                self.phase = 2
                self.replace = self.session.prompt('Regular replace: ', rprompt=HTML('hit <b>tab</b> to jump back'), **options,
                                                   default=self.replace)
            else:
                break
        return self.search, self.replace

    # define bottom preview toolbar
    def get_toolbar_search(self):
        second = third = helper = ""
        rows = []
        for line in self.samples:
            text = self.session.layout.current_buffer.text
            error = False  # prompt text is erroneous, probably not completed yet
            while True:
                if self.phase == 1:  # first phase - searching for match string
                    try:
                        search_re = re.compile(text)
                    except re.error:
                        text = text[:-1]
                        error = True
                        continue
                    match, result = _reg_method(line, search_re, self.replace)
                    # blue, yellow, blue
                    second = "\n".join([f"\033[0;33m{m}\033[0m" for m in match.split("\n")])  # colorize lines separately
                    if error:
                        second += "\033[0;41m!\033[0m"
                    third = f"\033[0;36m{result}\033[0m"
                    helper = ". - any char, \w - word, \d - digit, () - matching group"
                elif self.phase == 2:  # second phase - searching for replace string
                    search_re = re.compile(self.search)
                    try:
                        match, result = _reg_method(line, search_re, text)
                    except ValueError:
                        text = text[:-1]
                        error = True
                        continue
                    # blue, blue, yellow
                    second = "\n".join([f"\033[0;36m{m}\033[0m" for m in match.split("\n")])  # colorize lines separately
                    third = f"\033[0;33m{result}\033[0m"
                    if error:
                        third += "\033[0;41m!\033[0m"
                    helper = "Access matched parts with {0}, ex: string {1} string."
                rows.append((f"\033[0;36m{line}\033[0m", second, third))
                break

            # 'grid' handles multiline rows well, 'github' handles them bad, despite the documentation
        return ANSI('\n\nPreview\n' + tabulate(rows, headers=["original", "match", "result"], tablefmt="grid") + "\n\n" + helper)
