
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

    Test application for TLS/SSL cipher configurations on client and server side.

*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

#define NSHCIPER_OPTION_ENABLE_TLS13 0x0001

#define MAX_BUFFER_SIZE 32000

int  g_ShutdownPending = 0;
char g_HostPort[1024]  = {0};

void LogError (const char *pszErrorText)
{
    printf ("\nError: %s\n\n", pszErrorText);
}
void printf_line()
{
    printf ("------------------------------------------\n");
}

void dump (const char *pszHeader, const char *pszValue)
{
    printf ("%s: [%s]\n", pszHeader, (NULL == pszValue) ? "NULL": pszValue);
}

void print_cipher (const SSL_CIPHER *pCipher, const SSL *pSSL, int format)
{
    if (NULL == pCipher)
        return;

    printf(format ? "%04X, %-7s, %-30s, %s\n" : "0x%04X, %s, %s, %s\n",
           SSL_CIPHER_get_protocol_id (pCipher),
           (NULL == pSSL) ? SSL_CIPHER_get_version (pCipher) : SSL_get_version (pSSL),
           SSL_CIPHER_get_name (pCipher),
           SSL_CIPHER_standard_name (pCipher));
}

int hex2bin (const char *pszStr)
{
    /* Helper function to convert string to hex */

    int num = 0;
    char c  = 0;
    const char *p = NULL;

    p = pszStr;
    num = 0;

    while (*p)
    {
        c = tolower (*p);

        if (c >= '0' && c <= '9')
        {
            num = num * 16 + (c - '0');
        }
        else if (c >= 'a' && c <= 'f')
        {
            num = num * 16 + (10 + c - 'a');
        }
        else
        {
            return num;
        }

        p++;
    }

    return num;
}


int ListMapCiphers (char *pszFilter, int CipherListMaxLen, char *retpszCipherList)
{
    /* List and/or map ciphers */

    SSL_CTX * pCtx = NULL;
    SSL *pSSL      = NULL;

    STACK_OF(SSL_CIPHER) * pCiphers = NULL;
    const SSL_CIPHER     *pCipher   = NULL;

    int count       = 0;
    int CipherCount = 0;
    int i           = 0;
    int len         = 0;
    int found       = 0;
    int HexID       = 0;
    int display     = 0;

    const char *pszCipher  = NULL;
    const char *pszName    = NULL;

    char *pszCipherList    = NULL;
    char szCipherStr[MAX_BUFFER_SIZE] = {0};

    if (retpszCipherList && CipherListMaxLen)
    {
        pszCipherList = retpszCipherList;
    }
    else
    {
        pszCipherList = szCipherStr;
        CipherListMaxLen = sizeof (szCipherStr);
        display = 1;
    }

    /* Ensure space for null terminator */
    CipherListMaxLen--;

    pCtx = SSL_CTX_new (TLS_client_method() );

    if (NULL == pCtx)
        goto Done;

    pSSL = SSL_new (pCtx);

    if (NULL == pSSL)
        goto Done;

    pCiphers = SSL_get_ciphers (pSSL);

    if (NULL == pCiphers)
        goto Done;

    if (display)
    {
        printf ("\n");
        printf_line();
    }

    CipherCount = sk_SSL_CIPHER_num (pCiphers);

    if (NULL == pszFilter)
    {
        for (i = 0; i < CipherCount; i++)
        {
            pCipher = sk_SSL_CIPHER_value (pCiphers, i);
            count++;

            if (display)
                print_cipher (pCipher, NULL, 1);
        }
    }
    else
    {
        pszCipher = strtok (pszFilter, ":");

        while (pszCipher)
        {
            found = 0;
            for (i = 0; i < CipherCount; i++)
            {
                pCipher = sk_SSL_CIPHER_value (pCiphers, i);

                if (NULL == pCipher)
                    continue;

                len = strlen (pszCipher);
                if (0 == len)
                    continue;

                if (len <= 4)
                {
                    HexID = hex2bin (pszCipher);
                    if (HexID == SSL_CIPHER_get_protocol_id (pCipher))
                        found = 1;
                }
                else
                {
                    if (0 == strcasecmp (pszCipher, SSL_CIPHER_get_name (pCipher)))
                        found = 1;
                    else if (0 == strcasecmp (pszCipher, SSL_CIPHER_standard_name (pCipher)))
                        found = 1;
                }

                if (found)
                {
                    if (display)
                        print_cipher (pCipher, NULL, 1);

                    pszName = SSL_CIPHER_get_name (pCipher);

                    if (NULL == strstr (pszCipherList, pszName))
                    {
                        if (*pszCipherList)
                            strncat (pszCipherList, ":", CipherListMaxLen);

                        strncat (pszCipherList, pszName, CipherListMaxLen);
                    }

                    break;
                }

            } /* for */

            if (found)
            {
                count++;
            }
            else
            {
                printf ("Not found: %s\n", pszCipher);
            }

            pszCipher = strtok (NULL, ":");

        } /* while */
    }

    if (display)
    {
        printf_line();
        printf("Total: %d\n\n", count);

        if (*pszCipherList)
        {
            printf ("\n");
            printf ("OpenSSL Cipher String\n");
            printf_line();
            printf ("%s\n\n", pszCipherList);
        }
    }

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

int WriteHttpHeader (BIO *pBio, int HttpStatus, char *pszHeader, int ContentLen)
{
    int ret = 0;
    char szFullHeader [4096] = {0};

    snprintf (szFullHeader, sizeof (szFullHeader),
        "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nConnection: close\r\n\r\n",
        HttpStatus,
        pszHeader,
        ContentLen);

    ret = BIO_puts (pBio, szFullHeader);

    return ret;
}


int ServerCheck (const char *pszHost,
                 const char *pszPort,
                 const char *pszPemCert,
                 const char *pszPemKey,
                       char *pszCipherList,
                       int  Options)
{
    int ret         = 0;
    int ErrSSL      = 0;
    int ContentLen  = 0;
    int CipherCount = 0;
    int i           = 0;
    int count       = 0;
    int verbose     = 0;
    int BufferLen   = 0;

    SSL     *pSSL       = NULL;
    SSL_CTX *pCtx       = NULL;
    BIO     *pBio       = NULL;
    BIO     *bbio       = NULL;
    BIO     *pBioSSL    = NULL;
    BIO     *pBioAccept = NULL;

    char szBuffer[MAX_BUFFER_SIZE]    = {0};
    char szCipherStr[MAX_BUFFER_SIZE] = {0};
    char szLine[1024]                 = {0};
    char szConnect[255]               = {0};
 
    STACK_OF(SSL_CIPHER) * pCiphers = NULL;

    const SSL_CIPHER *pCipher = NULL;
    const SSL_METHOD *pMethod = NULL;

    BufferLen = sizeof (szBuffer) -1;

    if (NULL == pszPemCert)
    {
        LogError ("No PEM server certificate specified");
        goto Done;
    }

    if (NULL == pszPemKey)
    {
        LogError ("No PEM server key specified");
        goto Done;
    }

    snprintf (szConnect, sizeof (szConnect), "%s:%s", pszHost ? pszHost: "", (pszPort && *pszPort) ? pszPort: "443");
    snprintf (g_HostPort, sizeof (g_HostPort), "%s", szConnect);

    pMethod = TLS_server_method();

    if (NULL == pMethod)
    {
        LogError ("Cannot set client mode");
        goto Done;
    }

    pCtx = SSL_CTX_new (pMethod);

    if (NULL == pCtx)
    {
        LogError ("Cannot create new context");
        goto Done;
    }

    if (Options & NSHCIPER_OPTION_ENABLE_TLS13)
    {
        /* Keep TLS V1.3 enabled */
    }
    else
    {
        SSL_CTX_set_options (pCtx, SSL_OP_NO_TLSv1_3);
    }

    ret = SSL_CTX_use_certificate_chain_file (pCtx, pszPemCert);
    if (1 != ret)
    {
        LogError ("Cannot read certificate");
        goto Done;
    }

    ret = SSL_CTX_use_PrivateKey_file (pCtx, pszPemKey, SSL_FILETYPE_PEM);

    if (1 != ret)
    {
        LogError ("Cannot read private key");
        goto Done;
    }

    ret = SSL_CTX_check_private_key (pCtx);

    if (1 != ret)
    {
        LogError ("Invalid private key");
        goto Done;
    }

    if (pszCipherList && *pszCipherList)
    {
        printf ("\nConfigured Ciphers:\n");
        ListMapCiphers (pszCipherList, sizeof (szCipherStr), szCipherStr);
        ret = SSL_CTX_set_cipher_list (pCtx, szCipherStr);

        ListMapCiphers (szCipherStr, 0, NULL);
    }

    /* New SSL BIO setup as server */
    pBioSSL = BIO_new_ssl (pCtx, 0);

    BIO_get_ssl (pBioSSL, &pSSL);

    if (NULL == pSSL)
    {
        LogError ("Cannot get SSL from BIO");
        goto Done;
    }

    SSL_set_accept_state (pSSL);

    pBioAccept = BIO_new_accept (szConnect);

    if (NULL == pBioAccept)
    {
        LogError ("Cannot set new SSL connection");
        goto Done;
    }

    bbio = BIO_new (BIO_f_buffer());
    pBioSSL = BIO_push (bbio, pBioSSL);

    BIO_set_accept_bios (pBioAccept, pBioSSL);

    /* Setup listener */
    ret = BIO_do_accept (pBioAccept);

    if (1 != ret)
    {
        LogError ("Failed setting up listener");
        goto Done;
    }

    printf ("\nListening on [%s] ...\n\n", g_HostPort);

    while (0 == g_ShutdownPending)
    {
        if (verbose)
            printf ("\nWaiting for connection...\n\n");

        ret = BIO_do_accept (pBioAccept);

        if (1 != ret)
        {
            LogError ("Failed accepting connection");
            goto Cleanup;
        }

        pBio = BIO_pop (pBioAccept);

        if (NULL == pBio)
        {
            LogError ("No BIO returned from TCP/IP accept");
            goto Cleanup;
        }

        BIO_get_ssl (pBio, &pSSL);

        if (NULL == pSSL)
        {
            LogError ("Cannot get SSL from accepted connection");
            goto Cleanup;
        }

        // dump ("Before Handshake Status", SSL_state_string_long (pSSL));

        ret = SSL_do_handshake (pSSL);

        // dump ("Handshake status", SSL_state_string_long (pSSL));

        if (g_ShutdownPending)
        {
            goto Done;
        }

        if (1 != ret)
        {
            if (verbose)
                LogError ("SSL handshake failure");

            goto Cleanup;
        }

        ErrSSL = SSL_get_error (pSSL, ret);

        if (SSL_ERROR_NONE != ErrSSL)
        {
            LogError ("Error returned from SSL Handshake");
            goto Cleanup;
        }

        pCipher = SSL_get_current_cipher (pSSL);
        printf ("\nConnected with cipher:\n");
        printf_line();
        print_cipher (pCipher, pSSL, 0);
        printf ("\n");

        if (pCipher)
        {
            snprintf (szBuffer,
                      BufferLen,
                      "\nConnected with cipher\n------------------------------------------\n%s, 0x%04X, %s, %s\n\n",
                      SSL_get_version (pSSL),
                      SSL_CIPHER_get_protocol_id (pCipher),
                      SSL_CIPHER_get_name        (pCipher),
                      SSL_CIPHER_standard_name   (pCipher));
        }
        else
        {
            snprintf (szBuffer, BufferLen, "No Cipher information available\n");
        }

        /* Show ciphers requested from client */
        pCiphers = SSL_get_client_ciphers (pSSL);

        if (NULL == pCiphers)
        {
            if (verbose)
                printf ("No client ciphers returned\n");
        }
        else
        {
            CipherCount = sk_SSL_CIPHER_num (pCiphers);

            printf ("\nCiphers requested by client: %d\n", CipherCount);
            printf_line ();

            snprintf (szLine,
                      sizeof (szLine),
                      "Ciphers requested by client: %d\n------------------------------------------\n",
                      CipherCount);

            strncat (szBuffer, szLine, BufferLen);
 
            for (i = 0; i < CipherCount; i++)
            {
                pCipher = sk_SSL_CIPHER_value (pCiphers, i);

                if (pCipher)
                {
                    print_cipher (pCipher, pSSL, 1);

                    snprintf (szLine,
                              sizeof (szLine), "%04X %s\n",
                              SSL_CIPHER_get_protocol_id (pCipher),
                              SSL_CIPHER_standard_name   (pCipher));

                    strncat (szBuffer, szLine, BufferLen);
                }
            } /* for */

            strncat (szBuffer, "\n", BufferLen);
        }

        ContentLen = strlen (szBuffer);
        WriteHttpHeader (pBio, 200, "OK", ContentLen);
        BIO_flush (pBio);

        ret = BIO_write (pBio, szBuffer, ContentLen);
        BIO_flush (pBio);

        /* If connection was properly established, try to cleanly shutdown the connection and wait up to one second */
        ret = SSL_shutdown (pSSL);

        if (ret < 0)
        {
            printf ("Cannot shutdown SSL Connection: %d\n", ret);
        }
        else
        {
            /* Wait up to one second for shutdown and check every 100 ms */
            count = 0;
            while (0 == ret)
            {
                usleep (100*1000);
                ret = SSL_shutdown (pSSL);
                count++;

                if (count >= 10)
                    break;
            }

            if (verbose)
                printf ("Shutdown(%d): %d\n", count, ret);
        }

Cleanup:

        if (pBio)
        {
            BIO_reset (pBio);
            BIO_free_all (pBio);
            pBio = NULL;
        }

    } /* while */

Done:

    if (pBioAccept)
    {
        BIO_free_all (pBioAccept);
        pBioAccept = NULL;
    }

    if (pCtx)
    {
        SSL_CTX_free (pCtx);
        pCtx = NULL;
    }

    g_ShutdownPending = 2;

    return 0;
}


int ConnectionCheck (const char *pszHost,
                     const char *pszPort,
                           char *pszCipherList,
                     const char *pszSignAlgs,
                           int  Options)
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

    char szConnect[255]               = {0};
    char szCipherStr[MAX_BUFFER_SIZE] = {0};

    if ( (!pszHost) || (!*pszHost) )
    {
        LogError ("No hostname specified");
        goto Done;
    }

    snprintf (szConnect, sizeof (szConnect), "%s:%s", pszHost, (pszPort && *pszPort) ? pszPort: "443");

    printf ("\nConnecting to [%s] ...\n\n", szConnect);

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

    if (Options & NSHCIPER_OPTION_ENABLE_TLS13)
    {
        /* Keep TLS V1.3 enabled */
    }
    else
    {
        SSL_CTX_set_options (pCtx, SSL_OP_NO_TLSv1_3);
    }

    /* Use specified cipher list if requested */

    if (pszCipherList && *pszCipherList)
    {
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

        if (pszCipherList && *pszCipherList)
        {
            ListMapCiphers (pszCipherList, sizeof (szCipherStr), szCipherStr);
            ret = SSL_set_cipher_list (pSSL, szCipherStr);

            if (1 != ret)
            {
                LogError ("Cannot set cipher list in SSL context");
                goto Done;
            }
        }


        BIO_set_conn_hostname (pBio, szConnect);
        SSL_set_tlsext_host_name (pSSL, pszHost); /* SNI */

        ret = SSL_do_handshake (pSSL);

        // usleep (1000);

        if (1 == ret)
        {
            pCipher = SSL_get_current_cipher (pSSL);
            printf ("\nConnected with cipher:\n");
            printf_line();
            print_cipher (pCipher, pSSL, 0);
            printf ("\n");
        }
        else
        {
            LogError ("Failed to connect with specified cipher list");
        }

        goto Done;
    }

    /* Else try all ciphers */

    pListSSL = SSL_new (pCtx);

    if (NULL == pListSSL)
    {
        LogError ("Cannot get SSL context");
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
    printf_line();

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

        if (strstr (SSL_CIPHER_get_version (pCipher), "TLSv1.3"))
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

        ret = SSL_set_cipher_list (pSSL, SSL_CIPHER_get_name (pCipher));

        if (1 != ret)
        {
            printf ("Cannot set cipher list in SSL context to [%s]\n", SSL_CIPHER_get_name (pCipher));
            // goto Done;
        }

        BIO_set_conn_hostname (pBio, szConnect);
        SSL_set_tlsext_host_name (pSSL, pszHost); /* SNI */

        ret = SSL_do_handshake (pSSL);

        if (1 == ret)
        {
            print_cipher (SSL_get_current_cipher (pSSL), pSSL, 1);
            CountOK++;
        }
        else
        {
            CountError++;
        }

        // usleep (1000);

        if (pBio)
        {
            BIO_free_all (pBio);
            pBio = NULL;
        }

    } /* for */

    printf_line();
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


void help (const char *pszProgram)
{
    printf ("\n");
    printf ("nshciphers\n");
    printf ("----------\n");
    printf ("%s\n", OpenSSL_version(OPENSSL_VERSION));
    printf ("(Build on: %s)\n\n", OPENSSL_VERSION_TEXT);

    printf ("Syntax: %s <hostname> [Options]\n\n", pszProgram);
    printf ("-port    <port number>\n");
    printf ("-cert    <PEM cert file>\n");
    printf ("-key     <PEM key file>\n");
    printf ("-cipher  <OpenSSL cipher list, colon separated>\n");
    printf ("-map     <Hex string with cipher IDs to map to OpenSSL cipher names, colon separated>\n");
    printf ("-s       Server mode\n");
    printf ("-tls13   Enable TLS v1.3\n");
    printf ("-r       Use RSA   signing algorithm (RSA+SHA256)\n");
    printf ("-e       Use ECDSA signing algorithm (ECDSA+SHA256)\n");
    printf ("\n");
    printf ("Without any parameter just list all known ciphers\n");

    printf ("\n");
}


void sig_handler (int signum)
{
    int ret   = 0;
    BIO *pBio = NULL;

    // printf ("\nSignal catched: %d\n", signum);

    g_ShutdownPending = 1;

    pBio = BIO_new_connect (g_HostPort);

    if (NULL == pBio)
    {
        LogError ("No BIO returned");
        goto Done;
    }

    ret = BIO_do_connect (pBio);

    if (ret != 1)
    {
        LogError ("Cannot connect to host");
        goto Done;
    }

Done:

    if (pBio)
    {
        BIO_free_all (pBio);
        pBio = NULL;
    }

    return;
}


int main(int argc, char *argv[])
{
    int  ret      = 0;
    int  consumed = 1;
    int  IsServer = 0;
    int  Options  = 0;

    char szSignAlgs[20] = {0};
    char szLocalhost[]  = "localhost";

    char *pszHost       = szLocalhost;
    char *pszPort       = NULL;
    char *pszCipherList = NULL;
    char *pszCert       = NULL;
    char *pszKey        = NULL;

    struct sigaction SignalAction = {0};

    /* Ignore broken pipes, which can happen when the remote side is not behaving well */
    SignalAction.sa_handler = SIG_IGN;
    ret = sigaction (SIGPIPE, &SignalAction, NULL);

    if (0 != ret)
    {
        LogError ("Cannot set signal action to ignore SIGPIPE");
    }

    /* Just list all known ciphers */
    if (argc < 2)
    {
        ListMapCiphers (NULL, 0, NULL);
        goto Done;
    }

    while (argc > consumed)
    {
        if ('-' == *argv[consumed])
        {
            if ( (0 == strcmp (argv[consumed], "-h"))    ||
                 (0 == strcmp (argv[consumed], "-?"))    ||
                 (0 == strcmp (argv[consumed], "-help")) ||
                 (0 == strcmp (argv[consumed], "--help")) )
            {
                help (argv[0]);
                return 0;
            }

            else if  (0 == strcmp (argv[consumed], "-map"))
            {
                consumed++;
                if (consumed >= argc)
                    goto InvalidSyntax;

                if (argv[consumed][0] == '-')
                    goto InvalidSyntax;

                ListMapCiphers (argv[consumed], 0, NULL);
                goto Done;
            }

            else if  (0 == strcmp (argv[consumed], "-cipher"))
            {
                consumed++;
                if (consumed >= argc)
                    goto InvalidSyntax;

                if (argv[consumed][0] == '-')
                    goto InvalidSyntax;

                pszCipherList = argv[consumed];
            }

            else if  (0 == strcmp (argv[consumed], "-port"))
            {
                consumed++;
                if (consumed >= argc)
                    goto InvalidSyntax;

                if (argv[consumed][0] == '-')
                    goto InvalidSyntax;

                pszPort = argv[consumed];
            }

            else if  (0 == strcmp (argv[consumed], "-cert"))
            {
                consumed++;
                if (consumed >= argc)
                    goto InvalidSyntax;

                if (argv[consumed][0] == '-')
                    goto InvalidSyntax;

                pszCert = argv[consumed];
            }

            else if  (0 == strcmp (argv[consumed], "-key"))
            {
                consumed++;
                if (consumed >= argc)
                    goto InvalidSyntax;

                if (argv[consumed][0] == '-')
                    goto InvalidSyntax;

                pszKey = argv[consumed];
            }

            else if  (0 == strcmp (argv[consumed], "-tls13"))
            {
                Options |= NSHCIPER_OPTION_ENABLE_TLS13;
            }

            else if  (0 == strcmp (argv[consumed], "-s"))
            {
                IsServer = 1;
            }

            else if  (0 == strcmp (argv[consumed], "-c"))
            {
                IsServer = 0;
            }

            else if  (0 == strcmp (argv[consumed], "-r"))
            {
                snprintf (szSignAlgs, sizeof (szSignAlgs), "%s", "RSA+SHA256");
            }

            else if  (0 == strcmp (argv[consumed], "-e"))
            {
                snprintf (szSignAlgs, sizeof (szSignAlgs), "%s", "ECDSA+SHA256");
            }
            else
            {
                goto InvalidSyntax;
            }
        }
        else
        {
            pszHost = argv[consumed];
        }

        consumed++;
    }

    if (IsServer)
    {
        /* Tap signals for shutdown */
        signal (SIGQUIT, sig_handler);
        signal (SIGINT,  sig_handler);
        signal (SIGTRAP, sig_handler);
        signal (SIGABRT, sig_handler);

        ret = ServerCheck (pszHost, pszPort, pszCert, pszKey, pszCipherList, Options);
    }
    else
    {
        ret = ConnectionCheck (pszHost, pszPort, pszCipherList, szSignAlgs, Options);
    }

Done:

    printf ("\nnshciphers: shutdown\n\n");

    return ret;

InvalidSyntax:

    LogError ("Invalid syntax");

    return ret;
}
