#/bin/sh

# Tento skript projde cely soubor IP s IP adresama a vypise IP adresu a e-maily do souboru contacts.
# Nejdriv hleda kontakt v radku % Abuse contact for, potom hleda abuse-mailbox a pokud nic nenajde hleda jakykoliv mail
# Obcas se objevy chyba, ale vse v poradku zpracuje 
# Pokud jsou v seznamu stejne e-maily, skript je seradi pod sebe

maily(){
	abuse_mail=$(whois -- $line | grep "\% Abuse contact for" | grep -E -o "\b[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+\b" || whois -- $line | grep abuse-mailbox | cut -d: -f2 | sed -e 's/^\s*//' -e 's/\s*$//' | sort -nr | uniq | tr '\n' ',' | sed -e 's/,$//' -e 's/,/\,/g') # Nahrazuji mezeru _ protoze kdyz tam dam rovnou , tak to zase nebere jako promenou
		if [ ! -z $abuse_mail ]; then
			abuse_mail=$(echo $abuse_mail | sed -e 's/_/\,/g')
			pole=$(cat zdroj | grep "$line")
			#echo $abuse_mail' '$line >> contacts_1
			echo $abuse_mail' '$pole >> contacts_1
		fi #Zapise mail, pokud se jedna o abuse e-maily

		if  [ -z $abuse_mail ]; then
			mail=$(whois -B -- $line | grep e-mail | cut -d: -f2 | sed -e 's/^\s*//' -e 's/\s*$//' | sort -nr | uniq | tr '\n' ',' | sed -e 's/,$//' -e 's/,/\,/g')
			pole=$(cat zdroj | grep "$line")
			#echo $mail' '$line >> contacts_1
			echo $mail' '$pole >> contacts_1
			pocet_mailu=$(($pocet_mailu+1))
			sleep 5
		fi #Zapise mail, pokud se jedna o jine e-maily
}

while read line; do
	maily 
done < IP

sort contacts_1 >> contacts_2 # Pouze srovnani souboru

while read kontakt_2 IP_adresa; do
	kontakt=$(echo $kontakt_2 | sed -e 's/,/\, /g') #Aby bylo mozne poslat maily, musi byt mezi nima carka a mezera
	echo IP':' "$IP_adresa\n"CONTACTS':' "$kontakt\n" >> contacts
	#echo IP':' "$pole\n"CONTACTS':' "$kontakt\n" >> contacts
done < contacts_2 #Stejne maily jsou serazeny pod sebe

rm contacts_1 contacts_2 #Odstraneni jiz nepotrebnych souboru
echo Konec programu \;-\)
echo Pocet IP adres ktery lezli pres B je\:"$pocet_mailu"

