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
        COMPREPLY=( $( compgen -W "base64 charset cidr country_name date email formatted_time hostname ip isotimestamp plaintext port quoted_printable time tld unit url urlencode code external reg reg_m reg_s abusemail asn cc_contact country csirt_contact incident_contact netname prefix registrar_abusemail a aaaa dmarc mx ns spf txt csp form_names html http_status redirects text x_frame_options"  -- "$cur" ) )
        return 0
    fi

  if [[ "$prev" == -a ]] || [[ "$prev" == --aggregate ]]; then
    param=(${cur//,/ })
        COMPREPLY=( $( compgen -W "${param[0]},avg ${param[0]},sum ${param[0]},count ${param[0]},min ${param[0]},max ${param[0]},list ${param[0]},set"  -- "$cur" ) )
        return 0
    fi

  if [[ "$cur" == -* ]]; then
    COMPREPLY=( $( compgen -W "-h --help --file -i --input --output -S --single-query --single-detect -C --csv-processing --default-action --save-stdin-output -v --verbose -q --quiet -y --yes -H --headless --github-crash-submit --debug --crash-post-mortem --autoopen-editor --write-statistics --config --show-uml --get-autocompletion --version --threads -F --fresh -R --reprocess --server --daemon --daemonize --delimiter --quote-char --header --delimiter-output --quote-char-output --header-output -d --delete -f --field -fe --field-excluded -t --type --split -s --sort -u --unique -ef --exclude-filter -if --include-filter -a --aggregate --merge --whois --nmap --dig --web --json --user-agent --multiple-hostname-ip --multiple-cidr-ip --web-timeout --multiple-nmap-ports --single-query-ignored-fields --compute-preview --external-fields --whois.ttl --whois.delete --whois.delete-unknown --whois.reprocessable-unknown --whois.cache --whois.mirror --whois.local-country --whois.lacnic-quota-skip-lines --whois.lacnic-quota-resolve-immediately --send --send-test --jinja --attach-files --attach-paths-from-path-column --testing --testing-mail --subject --body --references --mail-template --mail-template-abroad --smtp-host --email-from-name --contacts-cc --contacts-abroad --otrs.enabled --otrs.id --otrs.cookie --otrs.token --otrs.host --otrs.baseuri --otrs.signkeyid --web.webservice-allow-unsafe-fields --web.user-agent --web.timeout" -- $cur ) )
    return 0
  fi
}

complete -F _convey -o default convey
