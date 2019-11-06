#!/bin/bash
# This file is to be launched by program author when pushing new commit so we are not checking you have the dependencies.


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"  # this file dirname
convey --disable-external --show-uml 0 | dot -Tsvg -o $DIR/../docs/convey-methods.svg
HELPFILE=$DIR/../docs/convey-help-cmd-output.md
echo "\`\`\`" > $HELPFILE
convey --help >> $HELPFILE
echo "\`\`\`" >> $HELPFILE
