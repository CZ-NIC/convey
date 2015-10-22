Spusťte convey.py a o nic víc se nestarejte. Když to nenajde dost knihoven, vyzve vás to k install.sh.

OTRS Convey -> tlumočník pro OTRS
Tlumočník pro OTRS.
 Syntaxe:
    ./convey.py [--id <OTRS ticket id>] [--num <OTRS ticket number>] [--cookie <OTRS cookie>] [--token <OTRS token>] [<filename>]
 Parametr [filename] je cesta ke zdrojovému souboru logů ve formátu CSV.
 Pokud [filename] není zadán, skript se na něj zeptá.
 Skript se jej pokusí parsovat a zjistit sloupec s IP a ASN.

 Místo sloupce IP lze užít sloupec s URL. V takovém případě skript z každé URL vytáhne doménu, přeloží ji na IP a přidá do CSV sloupec 'HOST_IP'. Pokud nalezne více IP, řádek s URL zduplikuje.

 Potřebné knihovny se nainstalují skriptem install.sh .
 -h, --help Nápověda