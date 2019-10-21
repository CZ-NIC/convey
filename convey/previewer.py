from prompt_toolkit import PromptSession, HTML, ANSI
from prompt_toolkit.application import get_app
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.styles import Style
from prompt_toolkit.styles import merge_styles
from prompt_toolkit.styles.pygments import style_from_pygments_cls
from pygments.lexer import RegexLexer, bygroups, include
from pygments.lexers.python import Python3Lexer
from pygments.styles import get_style_by_name
from pygments.token import Text, Keyword, Number, String
from tabulate import tabulate

Python3Lexer()


class RegularLexer(RegexLexer):
    tokens = {
        'root': [
            (r'\\^', String),
            (r'\$', String),
            (r'(\[)(\^?)', bygroups(Keyword, Number), 'square'),
            (r'\(', Keyword, 'round'),
            (r'\{', Keyword, 'curly'),
            include("grammar")
        ],
        'grammar': [
            (r'\\w', Number),
            (r'\\d', Number),
            (r'\.', String),
            (r'\*', String),
            (r'\+', String),
            (r'\?', String),
            (r'\//', String),
            (r'\|', String),
        ],
        'round': [
            (r'\)', Keyword, '#pop'),
            include("grammar"),
            (r'.', Text),
        ],
        'curly': [
            (r'\}', Keyword, '#pop'),
            (r'.', Text),
        ],
        'square': [
            (r'\]', Keyword, '#pop'),
            (r'.', Text),
        ]
    }


reg_style = style_from_pygments_cls(get_style_by_name('colorful'))


def _code_method(e, x):
    l = locals()
    try:
        exec(compile(e, '', 'exec'), l)
    except Exception as exception:
        return ""
    x = l["x"]
    return x




def code_preview(question, source_field: "Field"):
    samples = source_field.get_samples()

    # define key bindings
    session = PromptSession()
    bindings = KeyBindings()

    # cancel on control-c (escape inaccessible, waits for another keystroke)
    @bindings.add('c-c')
    def _(_):
        get_app().exit("")

    # exit on control+d (because the default exit command alt-enter seems unintuitive) (control+enter unacessible)
    @bindings.add('c-d')
    def _(_):
        get_app().exit(session.layout.current_buffer.text)

    # define bottom preview toolbar
    def get_toolbar():
        rows = []
        submittable = True
        for line in samples:
            val = _code_method(session.layout.current_buffer.text, line)
            rows.append((f"\033[0;36m{line}\033[0m", f"\033[0;33m{val}\033[0m"))  # blue and yellow
            if not val or val == line:
                submittable = False

        return ANSI('\nPreview\n' + tabulate(rows, headers=("original", "computed"), tablefmt="github"))

    # define styling
    style = merge_styles([reg_style, Style.from_dict({
        'bottom-toolbar': 'noreverse',
        # "pygments.keyword": '#2F2'
    })])

    def get_prompt():
        s = ' <i>(<b>Ctrl+D</b> to confirm)</i>' if "\n" in session.layout.current_buffer.text else ""
        return HTML(f'Code{s}: ')

    # prints the application
    print(question)
    text = session.prompt(get_prompt, bottom_toolbar=get_toolbar, style=style,
                          lexer=PygmentsLexer(Python3Lexer), multiline=True, key_bindings=bindings)
    return text
