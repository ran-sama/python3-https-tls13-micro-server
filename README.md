# python3-https-tls13-micro-server
Threaded Python 3 HTTPS + TLS 1.3 server w/ CryptCheck & SSL Labs 100% A+ rating.
```diff
!~ QuickStart ~!
```
[Click for setup instructions and guide](https://github.com/ran-sama/python-3-https-tls-1-3-micro-server?tab=readme-ov-file#setup-instructions-and-guide)
```diff
!~ QuickStart ~!
```
![alt text](https://raw.githubusercontent.com/ran-sama/python3_https_tls1_2_microserver/master/images/tls13_tls12_mixed_mode_new.png)
![alt text](https://raw.githubusercontent.com/ran-sama/python3_https_tls1_2_microserver/master/images/cryptcheck.png)
![alt text](https://raw.githubusercontent.com/ran-sama/python3_https_tls1_2_microserver/master/images/observatory_rating_new.png)

## (Optional step) SSL Labs rating of A+ and 100% score in every category

SSL Labs will mildly downgrade everyone using the single AES128 cipher in the TLS1.3 spec, however this is easy to avoid:
For convenience we could directly edit the OpenSSL 3.x.x config, but it is more elegant to work on a copy and avoid making a system wide change.
The copy can be easily used by any program with the help of environment variables limited to the services where we want to use the copy:
```
cp /etc/ssl/openssl.cnf /home/ran/pyopenssl.cnf
```
Before we dive deeper, allow me to illustrate how easy it is to define an environment variable for a single unit file:
```
sudo systemctl edit --force --full fox1.service
```
And adding the env var in the Service section:
```
[Service]
Environment="OPENSSL_CONF=/home/ran/pyopenssl.cnf"
```
To learn more about turning any Python program into a real service you can check: ![systemd-service-examples](https://github.com/ran-sama/systemd-service-examples)  
Returning to the actual changes in the config of the copied openssl config:
```
nano /home/ran/pyopenssl.cnf
```
Start by adding an extra line near the beginning to change:
```
[openssl_init]
# providers = provider_sect
```
into
```
[openssl_init]
ssl_conf = ssl_configuration
# providers = provider_sect
```

Afterward simply add this section to the end of the file:
```
[ssl_configuration]
system_default = tls_system_default

[tls_system_default]
# The command can be repeated with one instance setting a TLS bound and the other setting a DTLS bound
MinProtocol = TLSv1.2
MinProtocol = DTLSv1.2
# Sets the ciphersuite list for TLSv1.2
CipherString = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305
# Sets the available ciphersuites for TLSv1.3
Ciphersuites = TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
# KEX and KEM groups
Groups = secp521r1:secp384r1
```

This workaround is still required until either Python >3.13 or OpenSSL will fix the set_ciphers() function:
```
https://docs.python.org/3.13/library/ssl.html#tls-1-3
https://www.openssl.org/docs/man3.3/man5/config.html
https://www.openssl.org/docs/man3.3/man3/SSL_CONF_cmd.html
```

## Setup instructions and guide

The setup is straightforward and easy, as you only need certain directories and files to be present.

In the example we use:
```
/home/ran/.acmeweb/
/home/ran/.acme.sh/
/media/kingdian/server_pub/
```
And the servers:
```
port80_redirector_acme_ready.py
server-TLS1_3_ready.py
```
Feel free to just call them redirector.py and server.py for ease of use.
* Remember: You need superuser rights to bring up ports 80 and 443. 

In the beginning you probably will lack any form of certificates for your server to load into the openssl module of python.
Whilst in your home directory:
```
mkdir .acmeweb
```
We use this directory to do acme-challenges.
Also make appropriate changes to redirector.py:
```
MYSERV_ACMEWEBDIR = "/home/ran/.acmeweb"
```
For this we will bring up the redirector with python3 and make sure port 80 is forwarded in your WAN.
* Note: The redirector is only able to perform HTTP(301) redirects and answer GET and HEAD requests for the upcoming acme-challenge.

## Issuing a cert with acme.sh

For the letsencrypt acme-challenge to work you also need the DNS entry of example.com pointing to your servers IP.
Make yourself familiar with [acme.sh](https://github.com/acmesh-official/acme.sh) first and download it:

```
wget https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh
chmod +x acme.sh
```
We run a shell one-liner to issue a certificate request, make appropriate changes according to your MYSERV_ACMEWEBDIR:
```
./acme.sh --issue -d example.com --keylength ec-384 --accountkeylength 4096 -w /home/ran/.acmeweb --server letsencrypt --force
```
We want an EC-384 key, be able to authenticate us in future with a letsencrypt account key of 4096 bits and do the challenge in in the MYSERV_ACMEWEBDIR which you edited.

The acme.sh will inform you about the location where your key and fullchain files have been placed, like for the user "ran" it is:
```
/home/ran/.acme.sh/example.com_ecc/fullchain.cer
/home/ran/.acme.sh/example.com_ecc/example.com.key
```

Make appropriate changes to server.py since your username will differ, please ignore the commented line:
```
MYSERV_WORKDIR = "/media/kingdian/server_pub"
#MYSERV_CLIENTCRT = "/home/ran/keys/client.pem"
MYSERV_FULLCHAIN = "/home/ran/.acme.sh/example.com_ecc/fullchain.cer"
MYSERV_PRIVKEY = "/home/ran/.acme.sh/example.com_ecc/example.com.key"
```
* Note: Client certificates will prevent everyone from accessing your server, thus we leave them deactivated.

If all is configured correctly, bringing up server.py with python3 will make it serve all files located in MYSERV_WORKDIR using your private key and fullchain.

* Your future tasks: Set up an own cronjob to run every 90 days for auto-renewal of your certificates!

To help you with this I provide an example:
```
0 4 2 */2 * bash /home/ran/acme.sh --issue -d example.com --keylength ec-384 --accountkeylength 4096 -w /home/ran/.acmeweb/ --server letsencrypt --force 1>/home/ran/acme_status.log 2>/home/ran/acme_error.log && sudo reboot
```
Do notice a system reboot is forced at the end, if you don't want this you can just restart the python server itself.
Please use a different day and time! I'm sure Let's entcrypt can handle the load to their servers, but randomize it a bit.

Every 2nd odd month:
[https://crontab.guru/#0_4_2_*/2_*](https://crontab.guru/#0_4_2_*/2_*)

Every 2nd even month:
[https://crontab.guru/#0_4_2_2-12/2_*](https://crontab.guru/#0_4_2_2-12/2_*)

## Documentation

https://docs.python.org/3.14/library/ssl.html  
https://docs.python.org/3.14/library/socket.html  

## License
Licensed under the WTFPL license.
