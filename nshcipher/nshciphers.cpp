
/*
    Copyright Nash!Com, Daniel Nashed 2023-2024 - APACHE 2.0 see LICENSE
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

#ifdef _WIN32
#include <windows.h>

#define strncasecmp _strnicmp
#define strcasecmp _stricmp

#else

#include <signal.h>
#include <unistd.h>

#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/ossl_typ.h>

#define NSHCIPHER_OPTION_ENABLE_TLS13 0x0001
#define NSHCIPHER_OPTION_USE_EDCSA    0x0002


#define NSHCIPHERS_VERSION "1.0.1"
#define COPYRIGHT "Copyright 2024, Nash!Com, Daniel Nashed"

#define MAX_BUFFER_SIZE 32000

int  g_LogLevel        = 0;
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

int IsNullStr (const char *pszStr)
{
    if (NULL == pszStr)
        return 1;

    if ('\0' == *pszStr)
        return 1;

    return 0;
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

int WriteHttpHeader (BIO *pBio, int HttpStatus, const char *pszHeader, int ContentLen)
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

int Create_RSA_Key (int wBits, EVP_PKEY **ppKey)
{
    int      ret  = 0;
    EVP_PKEY_CTX *pEvpKeyCtx = NULL;

    if (NULL == ppKey)
        goto Done;

    *ppKey = NULL;

    pEvpKeyCtx = EVP_PKEY_CTX_new_id (EVP_PKEY_RSA, NULL);

    if (NULL == pEvpKeyCtx)
    {
        LogError ("Cannot use EVP_PKEY_RSA");
    }

    ret = EVP_PKEY_keygen_init (pEvpKeyCtx);

    if (1 != ret)
    {
        LogError ("Cannot init keygen");
        goto Done;
    }

    ret = EVP_PKEY_CTX_set_rsa_keygen_bits (pEvpKeyCtx, wBits);

    if (1 != ret)
    {
        LogError ("Cannot set key len");
        goto Done;
    }

    ret = EVP_PKEY_keygen (pEvpKeyCtx, ppKey);

    if (1 != ret)
    {
        LogError ("Cannot create key");
        goto Done;
    }

Done:

    if (pEvpKeyCtx)
    {
        EVP_PKEY_CTX_free (pEvpKeyCtx);
        pEvpKeyCtx = NULL;
    }

    return ret;
}


int Create_ECDSA_Key (const char *pszCurveName, EVP_PKEY **ppKey)
{
    int ret = 0;

    if (NULL == pszCurveName)
        *ppKey = EVP_EC_gen("P-256");
    else
        *ppKey = EVP_EC_gen(pszCurveName);

    if (NULL == *ppKey)
    {
        LogError ("Cannot create ECDSA Key");
        goto Done;
    }

    ret = 1;
    printf ("\nCreated private ECDSA key!\n");

Done:

    return ret;
}


int GenerateSerialNumber (ASN1_INTEGER *pAsnInteger)
{
    #define NSH_SERIAL_RAND_BITS 127
    BIGNUM *pTempBigNum = NULL;
    int ret = 0;

    if (NULL == pAsnInteger)
        return 0;

    ASN1_INTEGER_set (pAsnInteger, 0);

    pTempBigNum = BN_new();

    if (NULL == pTempBigNum)
        goto Done;

    ret = BN_rand (pTempBigNum, NSH_SERIAL_RAND_BITS, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);

    if (1 != ret)
        goto Done;

    if (!BN_to_ASN1_INTEGER (pTempBigNum, pAsnInteger))
        ret = 0;

Done:

    if (pTempBigNum)
    {
        BN_free(pTempBigNum);
        pTempBigNum = NULL;
    }

    return ret;
}

int X509AddNameEntryText (X509_NAME *pX509Name, const char *pszName, const char *pszValue)
{
    int ret = 0;

    if ((NULL == pszName) || ('\0' == *pszName))
    {
        return 0;
    }

    if ((NULL == pszValue) || ('\0' == *pszValue))
    {
        return 0;
    }

    ret = X509_NAME_add_entry_by_txt (pX509Name, pszName, MBSTRING_ASC, (const unsigned char*) pszValue, -1, -1, 0);

    if (1 != ret)
    {
        LogError ("X509 - Cannot add extension");
    }

    return ret;
}

int add_ext (X509 *pCert, int nid, const char *value,  X509V3_CTX *pV3Ctx)
{
    X509_EXTENSION *pExt = NULL;
    int ret = 0;

    if (IsNullStr(value))
    {
        return 0;
    }

    pExt = X509V3_EXT_conf_nid (NULL, pV3Ctx, nid, value);

    if (NULL == pExt)
    {
        LogError ("Cannot create extension");
        printf ("Error adding extension: [%s]", value);
        goto Done;
    }

    ret = X509_add_ext (pCert, pExt, -1);

    if (1 != ret)
    {
        LogError  ("Cannot add extension");
    }

Done:

    if (pExt)
    {
        X509_EXTENSION_free (pExt);
        pExt = NULL;
    }

    return ret;
}


int CreateCertificate (EVP_PKEY *pKey,
                       const char *pszOrganization,
                       const char *pszCommonName,
                       const char *pszSAN,
                       int ExpirationDays,
                       X509 **ppCert)
{
    int ret = 0;
    X509_NAME    *pX509Name     = NULL;
    ASN1_INTEGER *pSerialAsnInt = NULL;
    ASN1_TIME    *pTime         = NULL;
    time_t       CurrentTime    = time (NULL);
    EVP_PKEY     *pPubKey       = NULL;
    X509         *pCert         = NULL;

    const EVP_MD *pEvpMD  = EVP_sha256();

    /* Create a new certificate */

    *ppCert = X509_new();

    /* Short could for access to certificate */
    pCert = *ppCert;

    if (NULL == pCert)
    {
        LogError ("Cannot allocate certificate");
        goto Done;
    }

    ret = X509_set_version (pCert, 2);

    if (1 != ret)
    {
        LogError ("Cannot set certificate version");
        goto Done;
    }

    pSerialAsnInt = ASN1_INTEGER_new();

    if (NULL == pSerialAsnInt)
    {
        LogError ("Cannot allocate serial number");
        goto Done;
    }

    GenerateSerialNumber (pSerialAsnInt);

    ret = X509_set_serialNumber (pCert, pSerialAsnInt);

    if (1 != ret)
    {
        LogError ("Cannot set serial number");
        goto Done;
    }

    ret = X509_set_pubkey (pCert, pKey);

    if (1 != ret)
    {
        LogError ("Cannot set public key in certificate");
        goto Done;
    }

    pX509Name = X509_NAME_new();

    if (NULL == pX509Name)
    {
        LogError ("Cannot allocate x509 name");
        goto Done;
    }

    if (!IsNullStr (pszOrganization))
        X509AddNameEntryText (pX509Name, "O", pszOrganization);

    if (!IsNullStr (pszCommonName))
       X509AddNameEntryText (pX509Name, "CN", pszCommonName);


    ret = X509_set_issuer_name (pCert, pX509Name);

    if (1 != ret)
    {
        LogError ("Cannot add Issuer Name to certificate");
        goto Done;
    }

    ret = X509_set_subject_name (pCert, pX509Name);

    if (1 != ret)
    {
        LogError ("Cannot set subject name for certificate");
        goto Done;
    }

    pTime = ASN1_TIME_adj (pTime, CurrentTime, -1, 0);

    if (NULL == pTime)
    {
        LogError ("Cannot calculate NotBefore time");
        goto Done;
    }

    ret = X509_set1_notBefore (pCert, pTime);

    if (1 != ret)
    {
        LogError ("Cannot set NotBefore for certificate");
        goto Done;
    }

    pTime = ASN1_TIME_adj (pTime, CurrentTime, ExpirationDays, 0);

    if (NULL == pTime)
    {
        LogError ("Cannot calculate NotAfter time");
        goto Done;
    }

    ret = X509_set1_notAfter (pCert, pTime);

    if (1 != ret)
    {
        LogError ("Cannot set NotAfter for certificate");
        goto Done;
    }

    /* Set SAN explicitly if specified */

    if (!IsNullStr (pszSAN))
        ret = add_ext (pCert, NID_subject_alt_name, pszSAN, NULL);

    ret = add_ext (pCert, NID_ext_key_usage, "clientAuth,serverAuth", NULL);
    ret = add_ext (pCert, NID_key_usage, "critical,digitalSignature,keyEncipherment", NULL);

    /* Set extensions context for Subject Key Identifier and Authority Key Identifier */

    ret = X509_sign (pCert, pKey, pEvpMD);

    if (ret < 1)
    {
        LogError ("Cannot sign certificate");
        goto Done;
    }

Done:

    if (pPubKey)
    {
        EVP_PKEY_free (pPubKey);
        pPubKey = NULL;
    }

    if (pTime)
    {
        ASN1_STRING_free (pTime);
        pTime = NULL;
    }

    if (pSerialAsnInt)
    {
        ASN1_INTEGER_free (pSerialAsnInt);
        pSerialAsnInt = NULL;
    }

    if (pX509Name)
    {
        X509_NAME_free (pX509Name);
        pX509Name = NULL;
    }

    return ret;
}


int SSLClientHelloCallback (SSL *pSSL, int *pAlert, void *pArg)
{
    int    ret  = 0;
    size_t len  = 0;
    size_t i    = 0;
    size_t CipherListSize = 0;
    size_t ExtensionCount = 0;

    const unsigned char *pExtension  = NULL;
    const unsigned char *pCipherList = NULL;
    int *pExtensions = NULL;

    printf ("--- Client Hello Callback ---\n");

    if (NULL == pSSL)
        return SSL_CLIENT_HELLO_ERROR;

    if (SSL_client_hello_isv2 (pSSL))
        printf ("Client Hello is V2\n");

    ret = SSL_client_hello_get1_extensions_present (pSSL, &pExtensions, &ExtensionCount);

    if (1 == ret)
    {
        printf ("Extensions(%lu): ", ExtensionCount);
    }

    for (i=0; i < ExtensionCount; i++)
    {
        ret = SSL_client_hello_get0_ext (pSSL, *(pExtensions+i), &pExtension, &len);

        if (1 == ret)
        {
            printf ("%u ", *(pExtensions+i));
        }
    }
    printf ("\n");

    if (pExtensions)
    {
        OPENSSL_free (pExtensions);
        pExtensions = NULL;
    }

    CipherListSize = SSL_client_hello_get0_ciphers (pSSL, &pCipherList);

    if (0 == CipherListSize)
    {
        printf ("Client provided no cipher list\n");
    }
    if (NULL == pCipherList)
    {
        printf ("Client provided NULL cipher list\n");
    }
    else
    {
        printf ("Client Cipher List(%ld): ", CipherListSize);
        for (size_t i=0; i<CipherListSize; i++)
        {
            if (1 == (i % 2))
                printf ("%02X ", *(pCipherList+i));
            else
                printf ("%02X", *(pCipherList+i));
        }

        printf ("\n");
    }

    printf ("\n");

    return SSL_CLIENT_HELLO_SUCCESS;
}


int SSLServerNameCallback (SSL *pSSL, int *pAlert, void *pArg)
{
    const char *pszServerName  = NULL;

    printf ("--- Server Name Callback ---\n");

    pszServerName = SSL_get_servername (pSSL, TLSEXT_NAMETYPE_host_name);

    if (NULL == pszServerName)
        printf ("No hostname requested by client\n");
    else
        printf ("Client requested hostname: [%s]\n", pszServerName);

    printf ("\n");

    return SSL_TLSEXT_ERR_OK;

}

int ServerCheck (const char *pszHost,
                 const char *pszPort,
                 const char *pszPemCert,
                 const char *pszPemKey,
                 const char *pszSAN,
                       char *pszCipherList,
                       int  Options)
{
    int ret         = 0;
    int ErrSSL      = 0;
    int ContentLen  = 0;
    int CipherCount = 0;
    int i           = 0;
    int BufferLen   = 0;

    SSL      *pSSL       = NULL;
    SSL_CTX  *pCtx       = NULL;
    BIO      *pBio       = NULL;
    BIO      *bbio       = NULL;
    BIO      *pBioSSL    = NULL;
    BIO      *pBioAccept = NULL;
    EVP_PKEY *pKey       = NULL;
    X509     *pCert      = NULL;

    char szBuffer[MAX_BUFFER_SIZE]    = {0};
    char szCipherStr[MAX_BUFFER_SIZE] = {0};
    char szLine[1024]                 = {0};
    char szConnect[255]               = {0};
    char szSAN[255]                   = {0};

    STACK_OF(SSL_CIPHER) * pCiphers = NULL;

    const SSL_CIPHER *pCipher = NULL;
    const SSL_METHOD *pMethod = NULL;

    BufferLen = sizeof (szBuffer) -1;

    snprintf (szConnect, sizeof (szConnect), "%s:%s", pszHost ? pszHost: "", (pszPort && *pszPort) ? pszPort: "443");

    /* Remember connection string for shutdown request */
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

    SSL_CTX_set_client_hello_cb (pCtx, SSLClientHelloCallback, NULL);
    SSL_CTX_set_tlsext_servername_callback (pCtx, SSLServerNameCallback);

    if (Options & NSHCIPHER_OPTION_ENABLE_TLS13)
    {
        /* Keep TLS V1.3 enabled */
    }
    else
    {
        SSL_CTX_set_options (pCtx, SSL_OP_NO_TLSv1_3);
    }

    if ( pszPemKey && *pszPemKey )
    {
        ret = SSL_CTX_use_PrivateKey_file (pCtx, pszPemKey, SSL_FILETYPE_PEM);

        if (1 != ret)
        {
            LogError ("Cannot read private key");
            goto Done;
        }
    }
    else
    {
        /* No private key specified, create one on the fly */

        if (Options & NSHCIPHER_OPTION_USE_EDCSA)
            ret = Create_ECDSA_Key ("P-256", &pKey);
        else
            ret = Create_RSA_Key (4096, &pKey);

        if ( (NULL == pKey) || (ret != 1) )
        {
           LogError ("No private key created");
           goto Done;
        }

        ret = SSL_CTX_use_PrivateKey (pCtx, pKey);

        if (1 != ret)
        {
            LogError ("Cannot read private key");
            goto Done;
        }
    }

    if ( pszPemCert && *pszPemCert )
    {
        ret = SSL_CTX_use_certificate_chain_file (pCtx, pszPemCert);
        if (1 != ret)
        {
            LogError ("Cannot read certificate");
            goto Done;
        }
    }
    else
    {
        if (NULL == pKey)
        {
            LogError ("No private key found to create certificate");
            goto Done;
        }

        snprintf (szSAN, sizeof (szSAN), "DNS:%s", IsNullStr (pszSAN) ? "localhost" : pszSAN);

        ret = CreateCertificate (pKey,
                     "NashCom",
                     "nshciphers",
                     szSAN,
                     365,
                     &pCert);

        if (ret < 1)
        {
            LogError ("Cannot create certificate");
            goto Done;
        }

        if (NULL == pCert)
        {
            LogError ("No on-the-fly certificate created");
            goto Done;
        }

        ret = SSL_CTX_use_certificate (pCtx, pCert);

        if (1 != ret)
        {
            LogError ("Cannot use on-the-fly certificate");
            goto Done;
        }
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
        if (g_LogLevel)
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

        if (g_LogLevel)
            dump ("Before Handshake Status", SSL_state_string_long (pSSL));

        ret = SSL_do_handshake (pSSL);

        if (g_LogLevel)
        {
            dump ("Handshake status", SSL_state_string_long (pSSL));

            /* Check SSL handshake status. Returns 1 if SSL session was not established */
            if (SSL_in_init (pSSL))
                printf ("SSL_in_init: %d\n", SSL_in_init (pSSL));
        }

        if (1 != ret)
        {
            if (g_LogLevel)
                LogError ("SSL handshake failure");

            /* Can't call SSL_shutdown, but ensure we are getting rid of the connection ASAP */
            SSL_set_quiet_shutdown (pSSL, 1);
            goto Cleanup;
        }

        ErrSSL = SSL_get_error (pSSL, ret);

        if (SSL_ERROR_NONE != ErrSSL)
        {
            LogError ("Error returned from SSL Handshake");

            /* Can't call SSL_shutdown, but ensure we are getting rid of the connection ASAP */
            SSL_set_quiet_shutdown (pSSL, 1);
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
            if (g_LogLevel)
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

#ifdef _WIN32
        Sleep (1);
#else
        usleep (10*1000);
#endif

        /* If connection was properly established, try to cleanly shutdown */
        ret = SSL_shutdown (pSSL);

        if (ret < 0)
        {
            printf ("Cannot shutdown SSL Connection: %d\n", ret);
        }
        else
        {
            /* Needs to be called twice */
            ret = SSL_shutdown (pSSL);

            if (g_LogLevel)
                printf ("Shutdown SSL: %d\n", ret);
        }

Cleanup:

        if (pSSL)
        {
            ret = SSL_clear (pSSL);
            if (1 != ret)
                LogError ("Cannot clear SSL");
        }

        if (pBio)
        {
            BIO_set_close (pBio, BIO_CLOSE);

#ifdef _WIN32
            Sleep (1);
#else
            usleep (1*1000);
#endif
            BIO_free_all (pBio);
            pBio = NULL;
        }

        if (g_ShutdownPending)
        {
            goto Done;
        }

        fflush (stdout);

    } /* while */

Done:

    if (pKey)
    {
        EVP_PKEY_free (pKey);
        pKey = NULL;
    }

    if (pCert)
    {
        X509_free (pCert);
        pCert = NULL;
    }

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
                     const char *pszHostSNI,
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

    if (Options & NSHCIPHER_OPTION_ENABLE_TLS13)
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

        /* Connection host name */
        BIO_set_conn_hostname (pBio, szConnect);

	/* SNI */
	if (pszHostSNI)
            SSL_set_tlsext_host_name (pSSL, pszHostSNI);
	else
            SSL_set_tlsext_host_name (pSSL, pszHost);

        ret = SSL_do_handshake (pSSL);

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

	/* Connected host */
        BIO_set_conn_hostname (pBio, szConnect);

        /* SNI */
        if (pszHostSNI)
            SSL_set_tlsext_host_name (pSSL, pszHostSNI);
        else
            SSL_set_tlsext_host_name (pSSL, pszHost);

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
    char szLine[255] = {0};
    char *p = NULL;

    printf ("\n");

    snprintf (szLine, sizeof (szLine), "nshciphers %s", NSHCIPHERS_VERSION);
    printf ("%s\n", szLine);

    p = szLine;
    while (*p) *p++ = '-';
    printf ("%s\n", szLine);

    printf ("%s\n", OpenSSL_version(OPENSSL_VERSION));
    printf ("(Build on: %s)\n\n", OPENSSL_VERSION_TEXT);

    printf ("Syntax: %s <hostname> [Options]\n\n", pszProgram);
    printf ("-sni      <SNI name> Specify a different SNI name than connecting host name\n");
    printf ("-port     <port number to listen/connect to>\n");
    printf ("-cert     <PEM cert file>\n");
    printf ("-key      <PEM key file>\n");
    printf ("-cipher   <OpenSSL cipher list, colon separated>\n");
    printf ("-san      <SAN name when creating self signed cert>\n");
    printf ("-map      <Hex string with cipher IDs to map to OpenSSL cipher names, colon separated>\n");
    printf ("-s        Run in server mode\n");
    printf ("-tls13    Enable TLS v1.3\n");
    printf ("-r        Use RSA   signing algorithm (RSA+SHA256)\n");
    printf ("-e        Use ECDSA signing algorithm (ECDSA+SHA256)\n");
    printf ("-v        Enable verbose logging\n");
    printf ("--version Print version and exit\n");
    printf ("\n");
    printf ("Without any parameter just list all known ciphers\n");

    printf ("\n");
}


void SignalShutdown ()
{
    int ret   = 0;
    BIO *pBio = NULL;

    printf ("Shutdown detected\n");

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


#ifdef _WIN32

BOOL WINAPI CtrlHandler (DWORD fdwCtrlType)
{
    BOOL bTerminate = FALSE;

    switch (fdwCtrlType)
    {
        case CTRL_C_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            bTerminate = TRUE;
            break;

    default:
        bTerminate = FALSE;
    }

    if (bTerminate)
    {
        SignalShutdown();
    }

    return bTerminate;
}

#else

void sig_handler (int signum)
{

    SignalShutdown();
    return;
}

#endif


void PrintVersion()
{
    fprintf (stderr, "\nNash!Com Cipher Test Tool %s\n", NSHCIPHERS_VERSION);
    fprintf (stderr, "%s\n", COPYRIGHT);
    fprintf (stderr, "%s\n", OpenSSL_version(OPENSSL_VERSION));
    fprintf (stderr, "(Build on: %s)\n", OPENSSL_VERSION_TEXT);
}


int main(int argc, char *argv[])
{
    int  ret      = 0;
    int  consumed = 1;
    int  IsServer = 0;
    int  Options  = 0;

    char szSignAlgs[20] = {0};
    char *pszHost       = NULL;
    char *pszHostSNI    = NULL;
    char *pszPort       = NULL;
    char *pszCipherList = NULL;
    char *pszCert       = NULL;
    char *pszKey        = NULL;
    char *pszSAN        = NULL;

#ifdef _WIN32
#else
    struct sigaction SignalAction = {{0}};

    /* Ignore broken pipes, which can happen when the remote side is not behaving well */
    SignalAction.sa_handler = SIG_IGN;
    ret = sigaction (SIGPIPE, &SignalAction, NULL);

    if (0 != ret)
    {
        LogError ("Cannot set signal action to ignore SIGPIPE");
    }

#endif

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
            if ( (0 == strcasecmp (argv[consumed], "-h"))    ||
                 (0 == strcasecmp (argv[consumed], "-?"))    ||
                 (0 == strcasecmp (argv[consumed], "-help")) ||
                 (0 == strcasecmp (argv[consumed], "--help")) )
            {
                help (argv[0]);
                return 0;
            }

            else if (0 == strcasecmp (argv[consumed], "--version"))
            {
                PrintVersion();
                return 0;
            }

            else if (0 == strcasecmp (argv[consumed], "-v"))
            {
                g_LogLevel = 1;
            }

            else if (0 == strcasecmp (argv[consumed], "-map"))
            {
                consumed++;
                if (consumed >= argc)
                    goto InvalidSyntax;

                if (argv[consumed][0] == '-')
                    goto InvalidSyntax;

                ListMapCiphers (argv[consumed], 0, NULL);
                goto Done;
            }

            else if (0 == strcasecmp (argv[consumed], "-cipher"))
            {
                consumed++;
                if (consumed >= argc)
                    goto InvalidSyntax;

                if (argv[consumed][0] == '-')
                    goto InvalidSyntax;

                pszCipherList = argv[consumed];
            }

            else if (0 == strcasecmp (argv[consumed], "-sni"))
            {
                consumed++;
                if (consumed >= argc)
                    goto InvalidSyntax;

                if (argv[consumed][0] == '-')
                    goto InvalidSyntax;

                pszHostSNI = argv[consumed];
            }

            else if (0 == strcasecmp (argv[consumed], "-port"))
            {
                consumed++;
                if (consumed >= argc)
                    goto InvalidSyntax;

                if (argv[consumed][0] == '-')
                    goto InvalidSyntax;

                pszPort = argv[consumed];
            }

            else if (0 == strcasecmp (argv[consumed], "-cert"))
            {
                consumed++;
                if (consumed >= argc)
                    goto InvalidSyntax;

                if (argv[consumed][0] == '-')
                    goto InvalidSyntax;

                pszCert = argv[consumed];
            }

            else if (0 == strcasecmp (argv[consumed], "-key"))
            {
                consumed++;
                if (consumed >= argc)
                    goto InvalidSyntax;

                if (argv[consumed][0] == '-')
                    goto InvalidSyntax;

                pszKey = argv[consumed];
            }

            else if (0 == strcasecmp (argv[consumed], "-san"))
            {
                consumed++;
                if (consumed >= argc)
                    goto InvalidSyntax;

                if (argv[consumed][0] == '-')
                    goto InvalidSyntax;

                pszSAN = argv[consumed];
            }

            else if (0 == strcasecmp (argv[consumed], "-tls13"))
            {
                Options |= NSHCIPHER_OPTION_ENABLE_TLS13;
            }

            else if (0 == strcasecmp (argv[consumed], "-ec"))
            {
                Options |= NSHCIPHER_OPTION_USE_EDCSA;
            }


            else if (0 == strcasecmp (argv[consumed], "-s"))
            {
                IsServer = 1;
            }

            else if (0 == strcasecmp (argv[consumed], "-c"))
            {
                IsServer = 0;
            }

            else if (0 == strcasecmp (argv[consumed], "-r"))
            {
                snprintf (szSignAlgs, sizeof (szSignAlgs), "%s", "RSA+SHA256");
            }

            else if (0 == strcasecmp (argv[consumed], "-e"))
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

#ifdef _WIN32
    if (FALSE == SetConsoleCtrlHandler (CtrlHandler, TRUE))
    {
        LogError ("Cannot register CtrlHandler");
    }
#else
        /* Tap signals for shutdown */
        signal (SIGQUIT, sig_handler);
        signal (SIGINT,  sig_handler);
        signal (SIGTRAP, sig_handler);
        signal (SIGABRT, sig_handler);
#endif

        ret = ServerCheck (pszHost, pszPort, pszCert, pszKey, pszSAN, pszCipherList, Options);
    }
    else
    {
        ret = ConnectionCheck (pszHost, pszHostSNI, pszPort, pszCipherList, szSignAlgs, Options);
    }

Done:

    printf ("\nnshciphers: shutdown\n\n");

    return ret;

InvalidSyntax:

    LogError ("Invalid syntax");

    return ret;
}

