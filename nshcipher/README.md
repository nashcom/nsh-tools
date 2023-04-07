


# nshcipher -- Small cipher check helper tool

This simple test tool demonstates how to use TLS/SSL ciphers with OpenSSL.  
It can be used to dump all supported ciphers and also to connect to a remote server to check which ciphers are supported.  
Server Name Indication (SNI) is used when connecting. SNI sends the reqested server in the handshake phase of the connection.  

## Syntax

If started without parameters all ciphers are listed.

When specifying a hostname the remote server is checked against the full cipher list starting with TLS 1.0 ciphers.  
The connection assumes port 443. You can specify a different port to connect to.

By default ECDSA and RSA signature algorithms are used. You may want to explictly specify only RSA ciphers via `-r` for servers supporting ECDSA and RSA keys at the same time like HCL Domino 12.0.x and higher with CertMgr enabled.


## Source Code

You may want to look into the source code how openssl specifies and lists ciphers.

- The number printed is the official cipher code used by applications like Domino and other applications.  
- The first name printed is the OpenSSL name often found in NGINX, Apache and other well known applications.
- The second name printed is the official cipher name often seen in network analysis tools like [SSL Labs](https://www.ssllabs.com/ssltest/) the extremely helpful [testssl.sh](https://github.com/drwetter/testssl.sh) script.



## Compile this application

This application is mainly intended for Linux and provides a Linux makefile.  
The main reason is that Linux provides an easy way to install OpenSSL development tools (openssl-devel) fitting your Linux version.  
It has been tested with OpenSSL 1.1.1 and OpenSSL 3.0.5. 


#Examples

The following tests have been performed against a Domino 12.0.2 server with a best practices cipher configuration.


## Example: ECDSA Cipher

ECDSA ciphers are the more modern ciphers, based on the better performing elliptic cuve algorithms.  
But those algorithms require ECDSA keys instead of RSA keys. 
Domino fully supports ECDSA keys sind version 12.0 leveaging the new CertMgr and TLS Cache. 
This even includes wildcard support and RSA and ECDSA keys in parallel.

This tool can also be used to test different key types.



```
./nshciphers notes.nashcom.de

Checking 60 ciphers...

------------------------------------------
C02C, TLSv1.2, ECDHE-ECDSA-AES256-GCM-SHA384 , TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
C02B, TLSv1.2, ECDHE-ECDSA-AES128-GCM-SHA256 , TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
------------------------------------------
OK: 2, Error, 44, Skipped: 14
```


## Example: RSA Cipher


```
nshciphers notes.nashcom.de -r

Checking 60 ciphers...

------------------------------------------
C030, TLSv1.2, ECDHE-RSA-AES256-GCM-SHA384   , TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
009F, TLSv1.2, DHE-RSA-AES256-GCM-SHA384     , TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
C02F, TLSv1.2, ECDHE-RSA-AES128-GCM-SHA256   , TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
009E, TLSv1.2, DHE-RSA-AES128-GCM-SHA256     , TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
C028, TLSv1.2, ECDHE-RSA-AES256-SHA384       , TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
006B, TLSv1.2, DHE-RSA-AES256-SHA256         , TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
C027, TLSv1.2, ECDHE-RSA-AES128-SHA256       , TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
0067, TLSv1.2, DHE-RSA-AES128-SHA256         , TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
------------------------------------------
OK: 8, Error, 38, Skipped: 14

```

## Example Cipher List supported by OpenSSL 3.0.x

```
./nshciphers
------------------------------------------
1302, TLSv1.3, TLS_AES_256_GCM_SHA384        , TLS_AES_256_GCM_SHA384,
1303, TLSv1.3, TLS_CHACHA20_POLY1305_SHA256  , TLS_CHACHA20_POLY1305_SHA256,
1301, TLSv1.3, TLS_AES_128_GCM_SHA256        , TLS_AES_128_GCM_SHA256,
C02C, TLSv1.2, ECDHE-ECDSA-AES256-GCM-SHA384 , TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
C030, TLSv1.2, ECDHE-RSA-AES256-GCM-SHA384   , TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
009F, TLSv1.2, DHE-RSA-AES256-GCM-SHA384     , TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
CCA9, TLSv1.2, ECDHE-ECDSA-CHACHA20-POLY1305 , TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
CCA8, TLSv1.2, ECDHE-RSA-CHACHA20-POLY1305   , TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
CCAA, TLSv1.2, DHE-RSA-CHACHA20-POLY1305     , TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
C02B, TLSv1.2, ECDHE-ECDSA-AES128-GCM-SHA256 , TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
C02F, TLSv1.2, ECDHE-RSA-AES128-GCM-SHA256   , TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
009E, TLSv1.2, DHE-RSA-AES128-GCM-SHA256     , TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
C024, TLSv1.2, ECDHE-ECDSA-AES256-SHA384     , TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
C028, TLSv1.2, ECDHE-RSA-AES256-SHA384       , TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
006B, TLSv1.2, DHE-RSA-AES256-SHA256         , TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
C023, TLSv1.2, ECDHE-ECDSA-AES128-SHA256     , TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
C027, TLSv1.2, ECDHE-RSA-AES128-SHA256       , TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
0067, TLSv1.2, DHE-RSA-AES128-SHA256         , TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
C00A, TLSv1.0, ECDHE-ECDSA-AES256-SHA        , TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
C014, TLSv1.0, ECDHE-RSA-AES256-SHA          , TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
0039, SSLv3  , DHE-RSA-AES256-SHA            , TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
C009, TLSv1.0, ECDHE-ECDSA-AES128-SHA        , TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
C013, TLSv1.0, ECDHE-RSA-AES128-SHA          , TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
0033, SSLv3  , DHE-RSA-AES128-SHA            , TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
00AD, TLSv1.2, RSA-PSK-AES256-GCM-SHA384     , TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
00AB, TLSv1.2, DHE-PSK-AES256-GCM-SHA384     , TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
CCAE, TLSv1.2, RSA-PSK-CHACHA20-POLY1305     , TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
CCAD, TLSv1.2, DHE-PSK-CHACHA20-POLY1305     , TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
CCAC, TLSv1.2, ECDHE-PSK-CHACHA20-POLY1305   , TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
009D, TLSv1.2, AES256-GCM-SHA384             , TLS_RSA_WITH_AES_256_GCM_SHA384,
00A9, TLSv1.2, PSK-AES256-GCM-SHA384         , TLS_PSK_WITH_AES_256_GCM_SHA384,
CCAB, TLSv1.2, PSK-CHACHA20-POLY1305         , TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
00AC, TLSv1.2, RSA-PSK-AES128-GCM-SHA256     , TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
00AA, TLSv1.2, DHE-PSK-AES128-GCM-SHA256     , TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
009C, TLSv1.2, AES128-GCM-SHA256             , TLS_RSA_WITH_AES_128_GCM_SHA256,
00A8, TLSv1.2, PSK-AES128-GCM-SHA256         , TLS_PSK_WITH_AES_128_GCM_SHA256,
003D, TLSv1.2, AES256-SHA256                 , TLS_RSA_WITH_AES_256_CBC_SHA256,
003C, TLSv1.2, AES128-SHA256                 , TLS_RSA_WITH_AES_128_CBC_SHA256,
C038, TLSv1.0, ECDHE-PSK-AES256-CBC-SHA384   , TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
C036, TLSv1.0, ECDHE-PSK-AES256-CBC-SHA      , TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
C021, SSLv3  , SRP-RSA-AES-256-CBC-SHA       , TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
C020, SSLv3  , SRP-AES-256-CBC-SHA           , TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
00B7, TLSv1.0, RSA-PSK-AES256-CBC-SHA384     , TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
00B3, TLSv1.0, DHE-PSK-AES256-CBC-SHA384     , TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
0095, SSLv3  , RSA-PSK-AES256-CBC-SHA        , TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
0091, SSLv3  , DHE-PSK-AES256-CBC-SHA        , TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
0035, SSLv3  , AES256-SHA                    , TLS_RSA_WITH_AES_256_CBC_SHA,
00AF, TLSv1.0, PSK-AES256-CBC-SHA384         , TLS_PSK_WITH_AES_256_CBC_SHA384,
008D, SSLv3  , PSK-AES256-CBC-SHA            , TLS_PSK_WITH_AES_256_CBC_SHA,
C037, TLSv1.0, ECDHE-PSK-AES128-CBC-SHA256   , TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
C035, TLSv1.0, ECDHE-PSK-AES128-CBC-SHA      , TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
C01E, SSLv3  , SRP-RSA-AES-128-CBC-SHA       , TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
C01D, SSLv3  , SRP-AES-128-CBC-SHA           , TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
00B6, TLSv1.0, RSA-PSK-AES128-CBC-SHA256     , TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
00B2, TLSv1.0, DHE-PSK-AES128-CBC-SHA256     , TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
0094, SSLv3  , RSA-PSK-AES128-CBC-SHA        , TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
0090, SSLv3  , DHE-PSK-AES128-CBC-SHA        , TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
002F, SSLv3  , AES128-SHA                    , TLS_RSA_WITH_AES_128_CBC_SHA,
00AE, TLSv1.0, PSK-AES128-CBC-SHA256         , TLS_PSK_WITH_AES_128_CBC_SHA256,
008C, SSLv3  , PSK-AES128-CBC-SHA            , TLS_PSK_WITH_AES_128_CBC_SHA,
------------------------------------------
Total: 60

```


