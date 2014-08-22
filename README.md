honeypot-smtp
=============

SMTP Honeypot

Features:
 * SMTP + SMTPS
 * Catch spammer, relayer

Dependencies:
 * Twisted
 * My site-packages(3) --> common-modules

Usage:
```bash
# Generate Config
python smtp.py -d config.xml
# Run
python smtp.py
```

TODO: 
 * Randomize Hash-Strings
 * Deliver E-Mails to Honeypot-POP3-account (interaction)
 * Implement correct StartTLS 
 * Do not accept all email-adresses, but many (second request per source-addr?)
 
Contribution welcome.

All rights reserved.
(c) 2014 by Alexander Bredo