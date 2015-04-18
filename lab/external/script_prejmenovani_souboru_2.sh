#/bin/sh
# csript ktery vytvori soubor contacts do ktereho zaise hodnoty:
# CONTACTS: email
# FILENAME: file
# a prejmenuje soubory ktery maji tvar e-mailu na soubory ve zkracenem tvaru
# priklad ripe@blue4.cz prejmenuje na blue4

# je potreba mit seznam vsech mailu v souboru maily


while read line; do
	echo 'CONTACTS: '$line >>contacts
	p=$(ls | grep $line |cut -d@ -f2 | cut -d. -f-1)
	echo "FILENAME: $p\n" >>contacts
	mv "$line" "$p"
	
done < maily
