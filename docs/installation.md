# Installation and first run

## Prerequisites
If something is missing on your system, you may find help yourself with this command:
`sudo apt install python3-pip python3-dev python3-tk git xdg-utils whois dnsutils nmap curl build-essential libssl-dev libpcre3 libpcre3-dev && pip3 install setuptools wheel uwsgi ipython`

* `build-essential` is needed to build `uwsgi` and `envelope`
* `libpcre3 libpcre3-dev` needed to suppress uWSGI warning `!!! no internal routing support, rebuild with pcre support !!!`
* `libssl-dev` needed to be present before building `uwsgi` if you will need to use `--https`

## Launch as a package:

```bash
# (optional) setup virtual environment
python3 -m venv venv
. venv/bin/activate
(venv) $ ... # continue below

# install from PyPi
pip3 install convey  # without root use may want to use --user

# (optional) alternatively, you may want to install current master from GitHub
pip3 install git+https://github.com/CZ-NIC/convey.git

# launch
convey [filename or input text] # or try `python3 -m convey` if you're not having `.local/bin` in your executable path
```

Parameter `[filename or input text]` may be the path of the CSV source file or any text that should be parsed. Note that if the text consist of a single value, program prints out all the computable information and exits; I.E. inputting a base64 string will decode it.

## OR launch from a directory

```bash
# download from GitHub
git clone git@github.com:CZ-NIC/convey.git
cd convey
pip3 install -r requirements.txt  --user

# launch
./convey.py
```

## Bash completion

1. Run: `apt-get install bash-completion jq`
2. Copy: [extra/convey-autocompletion.bash](https://github.com/CZ-NIC/convey/blob/main/extra/convey-autocompletion.bash) to `/etc/bash_completion.d/`
3. Restart terminal

## Customisation

* Launch convey with [`--help`](convey-help-cmd-output.md) flag to see [further options](convey-help-cmd-output.md).
* The config file [`convey.yaml`](https://github.com/CZ-NIC/convey/blob/main/convey/defaults/convey.yaml) is automatically created in [user config folder](https://github.com/CZ-NIC/convey/blob/main/convey/defaults/convey.yaml). This file may be edited for further customisation. Access it with `convey --config`. Convey tries to open the file in the default GUI editor or in the terminal editor if GUI is not an option.

