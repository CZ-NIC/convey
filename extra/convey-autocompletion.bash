#!/usr/bin/env bash
# bash completion for convey
_convey()
{
  local cur
  local cmd

  cur=${COMP_WORDS[$COMP_CWORD]}
  prev="${COMP_WORDS[COMP_CWORD-1]}";
  cmd=( ${COMP_WORDS[@]} )

  if [[ "$prev" == -f ]] || [[ "$prev" == --field ]] ||  [[ "$prev" == -fe ]] || [[ "$prev" == --field-excluded ]]; then
        COMPREPLY=( $( compgen -W "HostnameTldExternal base64 charset cidr country_name date email first_method formatted_time hostname ip isotimestamp plaintext port quoted_printable second_method time tld unit url urlencode code external reg reg_m reg_s abusemail asn country csirt_contact incident_contact netname prefix a aaaa dmarc mx ns spf txt"  -- "$cur" ) )
        return 0
    fi

  if [[ "$prev" == -a ]] || [[ "$prev" == --aggregate ]]; then
    param=(${cur//,/ })
        COMPREPLY=( $( compgen -W "${param[0]},avg ${param[0]},sum ${param[0]},count ${param[0]},min ${param[0]},max ${param[0]},list ${param[0]},set"  -- "$cur" ) )
        return 0
    fi

  if [[ "$cur" == -* ]]; then
    COMPREPLY=( $( compgen -W "-h --help --file -i --input -o --output -S --single-query --single-detect -C --csv-processing --debug -v --verbose -q --quiet -y --yes -H --headless --compute-preview --csirt-incident --config --show-uml --get-autocompletion --version --threads -F --fresh -R --reprocess --server --daemon --delimiter --quote-char --header --no-header --delimiter-output --quote-char-output --header-output -d --delete -f --field -fe --field-excluded -t --type --split -s --sort -u --unique -ef --exclude-filter -if --include-filter -a --aggregate --whois --nmap --dig --web --disable-external --json --user-agent --multiple-hostname-ip --multiple-cidr-ip --web-timeout --whois-ttl --whois-delete --whois-delete-unknown --whois-reprocessable-unknown --whois-cache --send --send-test --jinja --attach-files --testing --subject --body --otrs_id --otrs_num --otrs_cookie --otrs_token" -- $cur ) )
    return 0
  fi
}

complete -F _convey -o default convey
