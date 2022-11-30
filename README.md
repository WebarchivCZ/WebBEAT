# WebBEAT

- backend program for checking live and extinct websites


## Prerequisities

- Sys - could be run on Win, IOS or any other env, Linux server is recommended
- Python 3.9+
- pip + dependencies listed in 
- service user is recommended - eg. 'webbeat'

## Installation of WebBEAT

- prepare path for this project
- clone this project and setup cron with desired intensity of checking - recommended eg. once for month

```
cd /opt/
git clone https://github.com/JanMeritus/WebBEAT.git
cd WebBEAT
python3 -m pip check    # check main dependencies status
python3 -m pip install  # install dependencies 
```

## Basic usage

- script run could be specified by several options detailed in help section

```
$ python3 WebBEAT.py --help
usage: WebBEAT.py [-h] [-e ENDPOINT] [-s SEEDS] [-p PAUSE] [-t TIMEOUTMARGIN] [-r MAXREDIRECTS] [--whois_c] [--no-whois]

optional arguments:
  -h, --help            show this help message and exit
  -e ENDPOINT, --Endpoint ENDPOINT
                        set API DB endpoint; -e {endpoint adress}/api/v2
  -s SEEDS, --Seeds SEEDS
                        set API seeds list; -s 'https://webarchiv.cz https://nkp.cz' OR dont specify and get it from seeds endpoint
  -p PAUSE, --Pause PAUSE
                        set Pause between seeds, def. for Whois 61 s.; -p 10
  -t TIMEOUTMARGIN, --TimeoutMargin TIMEOUTMARGIN
                        set Timeout Margin call constraint in live requests, def. 0.02;
  -r MAXREDIRECTS, --MaxRedirects MAXREDIRECTS
                        set Max Redirects constraint in live requests, def. 12;
  --whois_c             Activate WHOIS checking procedure, def. activated. Use as parameter; --whois_c
  --no-whois            Desactivate WHOIS checking procedure, def. activated. Use as parameter; --no-whois
```

## Operation
- endpoint for data export
-- endpoint DB for import of data is recommended, part of main repository https://github.com/WebarchivCZ/extinct-websites DB which supposes relational DB
-- could be also easily sent to custom noSQL DB endpoint, eg. MongoDB
- seed import
-- could by done via FS (eg. for tests)
-- recommended way is to import it from data endpoint as part of main project https://github.com/WebarchivCZ/extinct-websites, or any other json structured data provider '''{'data':[{'url':'seed'},{'url':'seed'}]}'''
- time schedule decision
-- it is recommended to run this script (for large amount of webs) once per month
- single web vs batch decision
-- for reason of specific implementation script send page data serially (specific implementation), however data model suppose batch approach
- whois decision 
-- decide if you want use whois module 
-- here implemented specifically for czech  CZ.NIC provider, for international just switch functionality of tweaked library - need to create bigger pauses - eg. 120 seconds
- create respective crontab

```
#crontab -e
# no-whois example
0 1 1 * *  python3 /opt/webbeat/WebBEAT.py -p 5 --no-whois  -e http://121.0.0.1/api/v2/ >> WebBEAT-date +\%Y\%m\%d\%H\%M\%S.log
# whois option example
0 1 1 * *  python3 /opt/webbeat/WebBEAT.py -p 120 --whois_c  -e http://121.0.0.1/api/v2/ >> WebBEAT-date +\%Y\%m\%d\%H\%M\%S.log

```

## Dedication

For Webarchive of the National Library of the Czech Republic

### Supported by

_Realizováno v rámci institucionálního výzkumu Národní knihovny České republiky financovaného Ministerstvem kultury ČR v rámci Dlouhodobého koncepčního rozvoje výzkumné organizace._
