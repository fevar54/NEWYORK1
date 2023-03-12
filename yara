rule detect_phishing_campaign {
    meta:
        description = "Detects a phishing campaign targeting the Financier and insurance sector"
        author = "Fevar54"
        date = "2023-03-11"
    strings:
        $domain1 = "cryptoexchangenyse.com "
        $domain2 = "nysecryptoexchange.com "
        $domain3 = "nysecoinexchange.com "
    condition:
        domain in {$domain1 $domain2 $domain3} and
        all of them
