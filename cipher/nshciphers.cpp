
/*
    Copyright Nash!Com, Daniel Nashed 2019, 2020 - APACHE 2.0 see LICENSE
    Author: Daniel Nashed (Nash!Com)
    Licensed to the Apache Software Foundation (ASF) under one
    or more contributor license agreements.  See the NOTICE file
    distributed with this work for additional information
    regarding copyright ownership.  The ASF licenses this file
    to you under the Apache License, Version 2.0 (the
    "License"); you may not use this file except in compliance
    with the License.  You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
    Unless required by applicable law or agreed to in writing,
    software distributed under the License is distributed on an
    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
    KIND, either express or implied.  See the License for the
    specific language governing permissions and limitations
    under the License.

    --------------------------------------------------------------------------------

    Simple test and demo application for TLS/SSL cipher   

*/

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

void print_cipher (const SSL_CIPHER *pCipher)
{
    if (NULL == pCipher)
        return;

    printf("%04X, %-7s, %-30s, %s,\n",
           SSL_CIPHER_get_protocol_id (pCipher),
           SSL_CIPHER_get_version     (pCipher),
           SSL_CIPHER_get_name        (pCipher),
           SSL_CIPHER_standard_name   (pCipher));
}

int ListCiphers()
{
    SSL_CTX * pCtx = NULL;
    SSL *pSSL      = NULL;

    STACK_OF(SSL_CIPHER) * pCiphers = NULL;
    const SSL_CIPHER     *pCipher   = NULL;

    int CipherCount = 0;
    int i = 0;

    pCtx = SSL_CTX_new (TLS_client_method() );

    if (NULL == pCtx)
        goto Done;

    pSSL = SSL_new (pCtx);

    if (NULL == pSSL)
        goto Done;

    pCiphers = SSL_get_ciphers (pSSL);

    if (NULL == pCiphers)
        goto Done;

    printf ("------------------------------------------\n");

    CipherCount = sk_SSL_CIPHER_num (pCiphers);

    for (i = 0; i < CipherCount; i++) 
    {
        pCipher = sk_SSL_CIPHER_value(pCiphers, i);
        print_cipher (pCipher);
    }

    printf ("------------------------------------------\n");
    printf("Total: %d\n\n", CipherCount);

Done:

    if (pSSL)
    {
        SSL_free (pSSL);
        pSSL = NULL;
    }

    if (pCtx)
    {
        SSL_CTX_free (pCtx);
        pCtx = NULL;
    }

   return 0;
}

void LogError (const char *pszErrorText)
{
    printf ("Error: %s\n", pszErrorText);

}

int ConnectionCheck (const char *pszHost, const char *pszPort, const char *pszSignAlgs)
{
    int     ret       = 0;
    SSL     *pSSL     = NULL;
    SSL     *pListSSL = NULL;
    SSL_CTX *pCtx     = NULL;
    BIO     *pBio     = NULL;

    int CipherCount   = 0;
    int i             = 0;
    int CountSkipped  = 0;
    int CountOK       = 0;
    int CountError    = 0;

    STACK_OF(SSL_CIPHER) * pCiphers = NULL;

    const SSL_CIPHER *pCipher = NULL;
    const SSL_METHOD *pMethod = NULL;

    char szConnect[255] = {0};

    if ( (!pszHost) || (!*pszHost) )
    {
        LogError ("No hostname specified");
        goto Done;
    }

    snprintf (szConnect, sizeof (szConnect), "%s:%s", pszHost, (pszPort && *pszPort) ? pszPort: "443");

    pMethod = TLS_client_method();

    if (NULL == pMethod)
    {
        LogError ("Cannot client mode");
        goto Done;
    }

    pCtx = SSL_CTX_new (pMethod);

    if (NULL == pCtx)
    {
        LogError ("Cannot create new context");
        goto Done;
    }

    pListSSL = SSL_new (pCtx);

    if (NULL == pListSSL)
    {
        LogError ("Cannot get SSL connection");
        goto Done;
    }

    pCiphers = SSL_get_ciphers (pListSSL);

    if (NULL == pCiphers)
    {
        printf ("No client ciphers returned\n");
        goto Done;
    }

    CipherCount = sk_SSL_CIPHER_num (pCiphers);

    printf("\nChecking %d ciphers...\n\n", CipherCount);

    printf ("------------------------------------------\n");

    for (i = 0; i < CipherCount; i++) 
    {
        pCipher = sk_SSL_CIPHER_value (pCiphers, i);

        if (NULL == pCipher)
            continue;

        if (NULL == strstr (SSL_CIPHER_get_version (pCipher), "TLS"))
        {
            CountSkipped++;
            continue;
        }

        pBio = BIO_new_ssl_connect (pCtx);

        if (NULL == pBio)
        {
            LogError ("Cannot set new SSL connection");
            goto Done;
        }

        BIO_get_ssl (pBio, &pSSL);

        if (NULL == pSSL)
        {
            LogError ("Cannot get SSL connection");
            goto Done;
        }

        if (pszSignAlgs && *pszSignAlgs)
        {
            ret = SSL_set1_sigalgs_list (pSSL, pszSignAlgs);
        }

        SSL_set_cipher_list (pSSL, SSL_CIPHER_get_name (pCipher));

        BIO_set_conn_hostname (pBio, szConnect);
        SSL_set_tlsext_host_name (pSSL, pszHost); /* SNI */

        ret = SSL_do_handshake (pSSL);

        if (1 == ret)
        {
            print_cipher (pCipher);
            CountOK++;
        }
        else
        {
            CountError++;
        }

        if (pBio)
        {
            BIO_free_all (pBio);
            pBio = NULL;
        }

    } /* for */

    printf ("------------------------------------------\n");
    printf ("OK: %d, Err: %d, Skipped: %d\n\n", CountOK, CountError, CountSkipped);

Done:

    if (pListSSL)
    {
        SSL_free (pListSSL);
        pListSSL = NULL;
    }

    if (pBio)
    {
        BIO_free_all (pBio);
        pBio = NULL;
    }

    if (pCtx)
    {
        SSL_CTX_free (pCtx);
        pCtx = NULL;
    }

   return 0;
}


int main(int argc, char *argv[])
{
    int  ret      = 0;
    int  consumed = 1;
    char *pHost   = NULL;
    char *pPort   = NULL;

    char szSignAlgs[20] = {0};

    if (argc < 2)
    {
        ListCiphers();
        goto Done;
    }

    while (argc > consumed)
    {
        if ('-' == *argv[consumed])
        {
            switch (*(argv[consumed]+1))
            {
                case 'r':
                    snprintf (szSignAlgs, sizeof (szSignAlgs), "%s", "RSA+SHA256");
                    break;

                case 'e':
                    snprintf (szSignAlgs, sizeof (szSignAlgs), "%s", "ECDSA+SHA256");
                    break;

                 default:
                    printf ("Invalid parameter: '%s'\n\n", argv[consumed]);
                    goto Done;
                    break;

            } /* switch */
        }
        else if ( (*argv[consumed] >= '0') && (*argv[consumed] <= '9'))
        {
            pPort = argv[consumed];
        }
        else
        {
            pHost = argv[consumed];
        }

        consumed++;
    }

    ret = ConnectionCheck (pHost, pPort, szSignAlgs);

Done:
    return ret;
}

