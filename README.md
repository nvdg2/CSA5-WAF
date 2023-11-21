Tutorial used from: [jptosso](https://medium.com/@jptosso/oss-waf-stack-using-coraza-caddy-and-elastic-3a715dcbf2f2)

## Brute force aanval

## SQL injection

### Input van aanvaller

![](images/input_SQLi.png)

### Log van Web Application Firewall

![](images/error_SQLi.png)

Zoals u op de bovenstaande foto's kan zien, wordt de SQL injectieaanval geblokkeerd door de Web Application Firewall.

### Core regel met betrekking tot SQL injectie

```conf
SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx /\*!?|\*/|[';]--|--(?:[\s\v]|[^\-]*?-)|[^&\-]#.*?[\s\v]|;?\x00" \
    "id:942440,\
    phase:2,\
    block,\
    capture,\
    t:none,t:urlDecodeUni,\
    msg:'SQL Comment Sequence Detected',\
    logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',\
    tag:'application-multi',\
    tag:'language-multi',\
    tag:'platform-multi',\
    tag:'attack-sqli',\
    tag:'OWASP_CRS',\
    tag:'capec/1000/152/248/66',\
    tag:'PCI/6.5.2',\
    tag:'paranoia-level/2',\
    ver:'OWASP_CRS/4.0.0-rc2',\
    severity:'CRITICAL',\
    chain"
    SecRule MATCHED_VARS "!@rx ^ey[\-0-9A-Z_a-z]+\.ey[\-0-9A-Z_a-z]+\.[\-0-9A-Z_a-z]+$" \
        "t:none,\
        setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}',\
        setvar:'tx.sql_injection_score=+%{tx.critical_anomaly_score}'"

```

De volgende regel bevat een complexe reguliere expressie. 

```
SecRule MATCHED_VARS "!@rx ^ey[\-0-9A-Z_a-z]+\.ey[\-0-9A-Z_a-z]+\.[\-0-9A-Z_a-z]+$"
```

Er wordt een kritieke anomalie score aan het verzoek van de gebruiker gegeven indien zijn input voldoet aan de reguliere expressie.  Dit betekent namelijk dat de kans groot is dat de gebruiker een SQL-injectie uitvoert. In het bestand waar deze regel is gedefinieerd, worden enkel SQL injecties opgesomd die hierdoor worden gedetecteerd:

```text
# ‘ or 1=1#
# ‘ or 1=1-- -
# ‘ or 1=1/*
# ' or 1=1;\x00
# 1='1' or-- -
# ' /*!50000or*/1='1
# ' /*!or*/1='1
# 0/**/union/*!50000select*/table_name`foo`/**/
```

Zoals u ziet, zijn de eerste drie voorbeelden heel gelijkaardig aan de injectie die wij hebben uitgevoerd.



## Cross site scripting



## CSRF aanval

## Eender welke request die van buiten België komt

## Blokkeren van ‘repeat offenders’
