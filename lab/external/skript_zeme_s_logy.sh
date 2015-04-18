#/bin/sh

# Tento skript projde cely soubor IP s IP adresama a vytvori soubory ktere jsou pojmenovane podle country codu zemi a do techto souboru pripise vsechny IP adresy a logy ze souboru zdroj pro danou zemi.

cat IP |
while read line
do
COUNTRY=$(whois -h ripedb2.nic.cz -- $line | grep country |cut -d: -f2 | sed 's/^ *//;s/ *$//' )
#edvard: pridat zrejme case insensitive
pole=$(cat zdroj | grep "$line")
#echo "$line" "$pole" >> $COUNTRY ### EDVARD: tohle asi ma byt unkomentovany - a ten dalsi mozna zakomentovany!
echo "$pole" >> "${COUNTRY}"
done
