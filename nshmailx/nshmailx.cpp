/*
###########################################################################
# NashCom SMTP mail test/send tool (nshmailx)                             #
# Version 1.0.0 20.07.2024                                                #
# (C) Copyright Daniel Nashed/NashCom 2024                                #
#                                                                         #
# This application can be used to troubleshoot and test SMTP connections. #
#                                                                         #
# The application is based on OpenSSL and also show how to                #
#                                                                         #
# - STARTTLS connections via OpenSSL                                      #
# - Send SMTP mail crafting the RFC821 and RFC822 part of a message       #
# - Lookup MX records and pick the one with the lowest priority           #
# - Create a simple MIME encoded mail with a base64 encoded attachment    #
#                                                                         #
# Licensed under the Apache License, Version 2.0 (the "License");         #
# you may not use this file except in compliance with the License.        #
# You may obtain a copy of the License at                                 #
#                                                                         #
#      http://www.apache.org/licenses/LICENSE-2.0                         #
#                                                                         #
# Unless required by applicable law or agreed to in writing, software     #
# distributed under the License is distributed on an "AS IS" BASIS,       #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.#
# See the License for the specific language governing permissions and     #
# limitations under the License.                                          #
#                                                                         #
#                                                                         #
###########################################################################
*/

/*
Change History

0.9.1 04.01.2024

Add from phrase support (e.g. "John Doe" <jd@acme.com>)

0.9.2 05.01.2024

Add basic support for LibreSSL on MacOS

0.9.3 07.01.2024

Basic bsd-mailx compatibility

0.9.4 07.01.2024

More mailx compatibility and basic -cc and -bcc support

0.9.5 08.01.2024

Dump key and certificate information via OpenSSL code

0.9.6 20.02.2024

- Dump received and verified chain with verbose output
- New -pem option to dump certificate/key PEM data

0.9.7 09.03.2024

- Print OpenSSL Error

0.9.8 15.03.2024

- Add support for specifying a OpenSSL cipher string

0.9.9 04.07.2024

- New -trace option

1.0.0 20.07.2024

- Change MX lookup code to work also on Alpine


1.0.1 31.07.2024

- Add configuration file (/etc/nshmailx.cfg)
- Add -silent mode (only log errors)
- Set default mailer to "nshmailx"

1.0.2 28.09.2024

- Add handshake debugging

1.0.4 01.10.2024

- Add -NoTLS13 option

1.0.5 02.10.2024

- Dump TLS/SSL version and correct cipher information

1.0.6 27.05.2025

- Add bsd-mail option -a
- Makefile changes and Alpine build support

1.0.7 01.06.2025

- Add allowed recipients settings cfg and documentation

*/



#define VERSION "1.0.7"
#define COPYRIGHT "Copyright 2024-2025, Nash!Com, Daniel Nashed"

/* C++ includes */
#include <regex>
#include <string>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <resolv.h>
#include <pwd.h>

#include <openssl/opensslv.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>

#ifdef LIBRESSL_VERSION_NUMBER
#else
#include <openssl/core_names.h>
#endif

#define MAX_BUFFER_LEN 65535
#define MAX_STR        1024

#define CRLF "\r\n"
#define CR   "\r"
#define LF   "\n"

/* Globals */

BIO     *g_pBio    = NULL;
SSL     *g_pSSL    = NULL;
SSL_CTX *g_pCtxSSL = NULL;

char g_ProgramName[] = "nshmailx";
char g_szConfigFile[] = "/etc/nshmailx.cfg";
char g_szBuffer[MAX_BUFFER_LEN+1] = {0};
char g_szErrorBuffer[4096] = {0};
int  g_Verbose = 0;
int  g_Trace   = 0;
int  g_DumpPEM = 0;

bool g_bUseTLS  = true;
bool g_bNoTLS13 = false;
bool g_bVerify  = false;
bool g_bECDSA   = false;
bool g_bUTF8    = true;
bool g_bSilent  = false;

char g_szMailer[MAX_STR]            = "nshmailx";
char g_szFrom[MAX_STR]              = {0};
char g_szFromName[MAX_STR]          = {0};
char g_szHostname[MAX_STR]          = {0};
char g_szSmtpServerAddress[MAX_STR] = {0};
char g_szCipherList[MAX_STR]        = {0};
char g_szAllowedRecptsRegx[MAX_STR] = {0};


void strdncpy (char *pszStr, const char *ct, size_t n)
{
    if (NULL == pszStr)
        return;

    if (n>0)
    {
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wstringop-truncation"
        strncpy (pszStr, ct, n-1);
        #pragma GCC diagnostic pop
        pszStr[n-1] = '\0';
    }
}


void LogWarning (const char *pszErrorText)
{
    if (NULL == pszErrorText)
        return;

    fprintf (stderr, "Warning: %s\n\n", pszErrorText);
}


void LogInvalidOption (const char *pszCommand, const char *pszOption)
{
    struct  tm TimeTM = {0};
    ssize_t ret_size  = 0;
    FILE    *fp       = NULL;
    pid_t   ppid      = getppid();
    time_t  tNow      = time (NULL);

    char    szProcess[2048] = {0};
    char    szBinary[2048]  = {0};
    char    szExe[2048]     = {0};
    char    szTime[100]     = {0};

    if (NULL == pszOption)
        return;

    fprintf (stderr, "Warning - Unknown option: [%s]\n", pszOption);

    ret_size = readlink ("/proc/self/exe", szExe, sizeof (szExe));

    if (0 == ret_size)
        *szExe = '\0';

    fp = fopen ("/tmp/nshmailx.log", "a");

    if (NULL == fp)
        return;

    snprintf (szProcess, sizeof (szProcess), "/proc/%d/exe", ppid);
    ret_size = readlink (szProcess, szBinary, sizeof (szBinary));

    if (0 == ret_size)
        *szBinary = '\0';

    localtime_r (&tNow, &TimeTM);
    strftime (szTime, sizeof (szTime)-1, "%Y-%m-%d %H:%M:%S %z", &TimeTM);

    fprintf (fp, "%s exe: %s, ppid: %d, ppbin: %s, unknown option: %s [%s]\n", szTime, szExe, ppid, szBinary, pszCommand, pszOption);

    fclose (fp);
    fp = NULL;
}


void LogError (const char *pszErrorText, const char *pszParam)
{
    if (NULL == pszErrorText)
        return;

    if (pszParam)
        fprintf (stderr, "Error: %s: %s\n\n", pszErrorText, pszParam);
    else
        fprintf (stderr, "Error: %s\n\n", pszErrorText);

    ERR_print_errors_fp (stderr);
}

void LogError (const char *pszErrorText)
{
    LogError (pszErrorText, NULL);
}


bool GetUser (uid_t uid, size_t MaxReturnBuffer, char *retpszBuffer)
{
    struct passwd *pPasswd = NULL;

    if (MaxReturnBuffer && retpszBuffer)
        *retpszBuffer = '\0';
    else
        return false;

    pPasswd = getpwuid (uid);

    if (NULL == pPasswd)
        return false;

    if (NULL == pPasswd->pw_name)
        return false;

    strdncpy (retpszBuffer, pPasswd->pw_name, MaxReturnBuffer);
    return true;
}


size_t GetLocalHostname (char *retpszHostname, size_t MaxBuffer)
{
    if (NULL == retpszHostname)
        return 0;

    if (0 == MaxBuffer)
        return 0;

    if (gethostname (retpszHostname, MaxBuffer-1))
    {
        *retpszHostname = '\0';
        return 0;
    }

    return strlen (retpszHostname);
}


void PrintVersion()
{
    fprintf (stderr, "\nNash!Com SMTP Mail Tool %s\n", VERSION);
    fprintf (stderr, "%s\n", COPYRIGHT);
    fprintf (stderr, "%s\n", OpenSSL_version(OPENSSL_VERSION));
    fprintf (stderr, "(Build on: %s)\n", OPENSSL_VERSION_TEXT);
}


void PrintHelpText (char *pszName)
{
    PrintVersion ();

    fprintf (stderr, "\nUsage: %s [Options]\n\n", pszName);

    fprintf (stderr, "-server <FQDN/IP>      SMTP server DNS name or IP (Can be a relay host. By default MX record of the recipient's domain is used)\n");
    fprintf (stderr, "-host <FQDN>           Hostname to send in EHLO (by default use server's hostname)\n");
    fprintf (stderr, "-from <email>          From address\n");
    fprintf (stderr, "-name <real name>      Name to add to the from address as a phrase\n");
    fprintf (stderr, "-to <email>            Send to recipient address\n");
    fprintf (stderr, "-cc <email>            Copy to recipient address\n");
    fprintf (stderr, "-bcc <email>           Blind copy to recipient address\n");
    fprintf (stderr, "-subject <text>        Subject of message\n");
    fprintf (stderr, "-body <text>           Body of message\n");
    fprintf (stderr, "-file <filepath>       File send as body (specify '-' to write stdin to the UTF-8 formatted body)\n");
    fprintf (stderr, "-att <filepath>        Attachment to send (specify '-' for attaching stdin to a file)\n");
    fprintf (stderr, "-attname <filename>    File name for file to attach\n");
    fprintf (stderr, "-mailer <name>         Mailer Name\n");
    fprintf (stderr, "-cipher <cipher list>  OpenSSL cipher list string (colon separated) used for a connection\n");
    fprintf (stderr, "-NoTLS                 Disable TLS/SSL\n");
    fprintf (stderr, "-NoTLS13               Disable TLS 1.3\n");
    fprintf (stderr, "-v                     Verbose logging (specify twice for more verbose logging)\n");
    fprintf (stderr, "-silent                Only log errors to stderr\n");
    fprintf (stderr, "-trace                 Show input and output with client/server tags)\n");
    fprintf (stderr, "-pem                   Dump pem data with cert/key info (specify twice for PEM of certificate chain)\n");

    fprintf (stderr, "\n");
    fprintf (stderr, "Note: Also supports Linux BSD mailx command line sending options\n");
    fprintf (stderr, "\n");
    fprintf (stderr, "Configuration file: %s\n", g_szConfigFile);
    fprintf (stderr, "\n");
    fprintf (stderr, "from=<addr>            Standard from address\n");
    fprintf (stderr, "fromname=<addr>        Standard from name\n");
    fprintf (stderr, "mailer=<str>           Mail agent\n");
    fprintf (stderr, "hostname=<std>         Override default hostname\n");
    fprintf (stderr, "serveraddress=<addr>   Set server address/relay host\n");
    fprintf (stderr, "cipherlist=<list>      OpenSSL cipher list string (colon separated) used for a connection\n");
    fprintf (stderr, "rcptallowed=<regex>    Regex expression to define allowed recipients\n");
    fprintf (stderr, "tls=0|1                Use TLS (enabled by default, can be disabled via tls=0\n");
    fprintf (stderr, "notls13=0|1            Disable TLS 1.3\n");
    fprintf (stderr, "verify=0|1             Verify certificate chain\n");
    fprintf (stderr, "ecdsa=0|1              Use ECDSA instead of RSA\n");
    fprintf (stderr, "utf8=0|1               Use UTF8\n");
    fprintf (stderr, "silent=0|1             Run silent. Only log errors to stderr\n");
    fprintf (stderr, "\n");
}


bool IsNullStr (const char *pszStr)
{
    if (NULL == pszStr)
        return 1;

    if ('\0' == *pszStr)
        return 1;

    return 0;
}


bool RecipientAllowed (const char *pszRecipient)
{
    if (IsNullStr (pszRecipient))
        return true; /* To avoid extra checks for empty recipients */

    if (IsNullStr (g_szAllowedRecptsRegx))
        return true;

    try
    {

        std::string recipient = pszRecipient;
        std::regex  pattern (g_szAllowedRecptsRegx);

        if (std::regex_match (recipient, pattern))
        {
            return true;
        }

    } catch (const std::regex_error& e)
    {
        fprintf(stderr, "Error: Failed to check recipient: %s\n", e.what());
        return false;
    }

    return false;
}


size_t GetFileSize (const char *pszFileName)
{
    int ret = 0;
    struct stat Filestat = {0};

    if (IsNullStr (pszFileName))
        return 0;

    ret = stat (pszFileName, &Filestat);

    if (ret)
        return 0;

    if (S_IFDIR & Filestat.st_mode)
        return 0;

    return Filestat.st_size;
}


int GetRandomString (const char *pszCharset, size_t len, char *retpszRandomString)
{
    const char    szDefaultCharset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    unsigned char *p = (unsigned char *) retpszRandomString;

    size_t MaxIndex = sizeof (szDefaultCharset)-1;
    size_t i = 0;

    if (len <=0)
        return 1;

    if (NULL == retpszRandomString)
        return 1;

    /* Room for null terminator */
    len--;

    if (pszCharset)
        MaxIndex = strlen (pszCharset);
    else
        pszCharset = szDefaultCharset;

    /* Generate random bytes and use them as a modulo index to generate chars from charset specified */
    RAND_bytes ((unsigned char *) retpszRandomString, len);

    for (i=0; i < len; i++)
    {
        *p = *(pszCharset+ (*p % MaxIndex));
        p++;
    }

    *p = '\0';

    return 0;
}


int GetTimeString (time_t *pTime, char *retpszTime, size_t MaxBuffer)
{
    struct tm TimeTM = {0};

    if (MaxBuffer && retpszTime)
        *retpszTime = '\0';
    else
        return 1;

    gmtime_r (pTime, &TimeTM);
    strftime (retpszTime, MaxBuffer, "%a, %d %b %Y %H:%M:%S %z", &TimeTM);

    return 0;
}


size_t RecvBuffer()
{
    int    ret       = 0;
    size_t readbytes = 0;

    if (g_pSSL)
    {
        ret = SSL_read_ex (g_pSSL, g_szBuffer, MAX_BUFFER_LEN, &readbytes);

        if (ret < 0)
            readbytes = 0;
    }
    else
    {
        ret = BIO_read (g_pBio, g_szBuffer, MAX_BUFFER_LEN);

        if (ret < 0)
            readbytes = 0;
        else
            readbytes = ret;
    }

    if (readbytes < 0)
        *g_szBuffer = '\0';
    else
        *(g_szBuffer+readbytes) = '\0';

    if (g_Verbose > 1)
        printf ("%s", g_szBuffer);

    return readbytes;
}


int GetReturnCode()
{
    int    rc   = 0;
    size_t len  = 0;
    char   *p   = g_szBuffer;
    char   *pMessage = NULL;

    len = RecvBuffer();

    if (len <= 0)
        return 500;

    if (g_Trace)
        printf ("S:%s", g_szBuffer);

    while (*p)
    {
        if (*p <= 32)
        {
            if (*p == ' ')
                pMessage = p+1;
            *p = '\0';
            break;
        }
        p++;
    }

    rc = atoi (g_szBuffer);

    if ( (rc >= 200) && (rc < 400) )
        return 0;

    if (pMessage)
    {
        p = pMessage;
        while (*p)
        {
            if (*p < 32)
            {
                *p = '\0';
                break;
            }
            p++;
        }

        strdncpy (g_szErrorBuffer, pMessage, sizeof (g_szErrorBuffer));
    }

    return rc;
}


int SendBuffer (const char *pszBuffer)
{
    int ret = 0;
    size_t  byteswritten = 0;

    if (NULL == pszBuffer)
        return 0;

    if (g_Trace)
        printf ("C:%s", pszBuffer);

    if (g_pSSL)
    {
        ret = SSL_write_ex (g_pSSL, pszBuffer, strlen (pszBuffer), &byteswritten);
    }
    else
    {
        ret = BIO_puts (g_pBio, pszBuffer);
    }

    return ret;
}


int CheckLocalAvailableCiphers()
{
    const char *pStr = NULL;
    int priority = 0;

    if (NULL == g_pSSL)
        return 0;

    if (g_Verbose > 1)
    {
        printf ("\nLocal available ciphers offered\n-------------------------------\n");
    }

    while (priority < 1000)
    {
        pStr = SSL_get_cipher_list (g_pSSL, priority);
        if (NULL == pStr)
            break;

        if (g_Verbose > 1)
            printf ("%s\n", pStr);

        priority++;
    }

    if (g_Verbose > 1)
    {
        printf ("\n");
    }

    return priority;
}


int CopyFromToBio (BIO *pBioIn, BIO *pBioOut)
{
    /* Returns 1 for success */

    int  writebytes = 0;
    int  readbytes  = 0;

    if (NULL == pBioIn)
        return 0;

    if (NULL == pBioOut)
        return 0;

    while (1)
    {
        readbytes = BIO_read (pBioIn, g_szBuffer, sizeof (g_szBuffer)-1);

        if (0 == readbytes)
            break;

        if (readbytes < 0)
            return readbytes;

        writebytes = BIO_write (pBioOut, g_szBuffer, readbytes);

        if (writebytes < 0)
            return writebytes;

    } /* while */

    return 1;
}


size_t GetMxRecord (const char *pszDomain, size_t MaxBuffer, char *retpszBuffer, int *retpPriority)
{
    unsigned char Buffer[32000]  = {0};
    char   Result[1024]          = {0};
    int    Priority              = 0;
    int    LowestPriority        = 0;
    int    ret                   = 0;

    ns_msg nsMsg  = {0};
    ns_rr  rr     = {{0}};

    size_t len    = 0;
    size_t count  = 0;
    size_t found  = 0;
    size_t i      = 0;

    if (MaxBuffer && retpszBuffer)
        *retpszBuffer = '\0';

    if (retpPriority)
        *retpPriority = 0;

    ret = res_init ();

    if (ret)
    {
        LogError ("error initializing resolver");
        goto Done;
    }

    len = res_query (pszDomain, ns_c_in, ns_t_mx, Buffer, sizeof(Buffer)-1);

    if (len <= 0)
    {
        LogError ("DNS did not return any MX");
        goto Done;
    }

    ret = ns_initparse (Buffer, len, &nsMsg);

    if (ret)
    {
        LogError ("Cannot init NS parser");
        goto Done;
    }

    count = ns_msg_count (nsMsg, ns_s_an);

    for (i=0; i<count; i++)
    {
        ret = ns_parserr (&nsMsg, ns_s_an, i, &rr);

        if (ret)
        {
            LogError ("Cannot parse NS result");
            goto Done;
        }

        Priority = ns_get16 (ns_rr_rdata (rr));

        dn_expand (ns_msg_base (nsMsg), ns_msg_base (nsMsg) + ns_msg_size (nsMsg), ns_rr_rdata (rr) + NS_INT16SZ, Result, sizeof(Result));

        if (g_Verbose)
            printf ("%02d MX: [%s]\n", Priority, Result);

        if ((0 == LowestPriority) || (Priority < LowestPriority))
        {
            if (MaxBuffer && retpszBuffer)
            {
                snprintf (retpszBuffer, MaxBuffer, "%s", Result);
            }

            if (retpPriority)
                *retpPriority = Priority;

            LowestPriority = Priority;
        }

        found++;

    } /* for */

Done:

    return found;
}


#ifdef LIBRESSL_VERSION_NUMBER

/* LibreSSL isn't the same as OpenSSL and would need more work to provide the same functionality.

   The recommended target environment on MacOS is statically linked OpenSSL.
   The basic functionality of nshmailx works on LibreSSL as well.
   But specific TLS/SSL session information is not checked on LibreSSL.
   The following is a basic routine to dump the Cipher at least.

 */


int LogChainInfos (SSL *pSSL)
{
    int   ret = 0;
    X509 *pCert = NULL;

    return ret;
}

int LogSSLInfos (SSL *pSSL)
{
    const char *pStr  = NULL;

    if (NULL == pSSL)
        goto Done;

    pStr = SSL_get_version (pSSL);
    if (pStr)
        printf("TLS version: %s\n", pStr);

    /* For some reason LibreSSL does always return TLSv1/SSLv3. But the connection is still a TLS V1.2 connection */
    pStr = SSL_get_cipher_version (pSSL);
    if (pStr)
       printf ("TLS Cipher Version: [%s]\n", pStr);

    pStr = SSL_get_cipher (pSSL);
    if (pStr)
        printf ("TLS Cipher Version: [%s]\n", pStr);


Done:
    return 0;
}

#else

int GetX509Names (X509 *pCert, int nid, int type, int RetBufferLen, char *pszRetBuffer)
{
    GENERAL_NAMES *pNames  = NULL;
    GENERAL_NAME  *pEntry  = NULL;
    unsigned char *pUtf8   = NULL;
    char          *pBuffer = pszRetBuffer;

    int LenUtf8  = 0;
    int LenSan   = 0;
    int CountSan = 0;
    int i        = 0;
    int count    = 0;

    if (NULL == pszRetBuffer)
        return 0;

    if (0 == RetBufferLen)
        return 0;

    *pszRetBuffer = '\0';

    if (!pCert)
        goto Done;

    pNames = (GENERAL_NAMES *) X509_get_ext_d2i (pCert, nid, NULL, NULL);

    if (NULL == pNames)
    {
        goto Done;
    }

    count = sk_GENERAL_NAME_num (pNames);

    if (0 == count)
        goto Done;

    for( i=0; i<count; ++i )
    {
        pEntry = sk_GENERAL_NAME_value (pNames, i);
        if (!pEntry)
        {
            continue;
        }

        if (type == pEntry->type)
        {
            LenUtf8  = 0;
            LenSan  = -1;
            pUtf8 = NULL;

            LenUtf8 = ASN1_STRING_to_UTF8 (&pUtf8, pEntry->d.dNSName);
            if (pUtf8)
               LenSan = (int) strlen((const char*)pUtf8);

            if (LenUtf8 != LenSan)
            {
                LogError ("ASN1_STRING as incorrect size");
                goto Done;
            }

            if (pUtf8 && LenUtf8 && LenSan && (LenUtf8 == LenSan))
            {
               if (pBuffer - pszRetBuffer + LenSan + 2 >= RetBufferLen)
               {
                   goto Done;
               }

               if (CountSan)
               {
                   *pBuffer++ = ',';
                   *pBuffer++ = ' ';
               }

               memcpy (pBuffer, pUtf8, LenSan);
               pBuffer += LenSan;
               *pBuffer = '\0'; /* always terminate buffer */

               CountSan++;
            }

            if (pUtf8)
            {
               OPENSSL_free (pUtf8);
               pUtf8 = NULL;
            }
        }
    } /* for */

Done:

    if (pNames)
        GENERAL_NAMES_free (pNames);

    if (pUtf8)
        OPENSSL_free (pUtf8);

    return CountSan;
}

#define X509_GET_NOT_BEFORE     1
#define X509_GET_NOT_AFTER      2

int AsnTimeGetDate (const ASN1_TIME *pTM, int wRetBufferLen, char *pszRetBuffer, struct tm *pretTM)
{
    struct tm tTime = {0};

    if (pszRetBuffer && wRetBufferLen)
        *pszRetBuffer = '\0';

    if (pretTM)
        memset (pretTM, 0, sizeof (struct tm));

    if (pTM)
    {
        if (0 == ASN1_TIME_to_tm (pTM, &tTime))
            goto Done;

        if (pretTM)
        {
            memcpy (pretTM, &tTime, sizeof (struct tm));
        }

        if (pszRetBuffer && wRetBufferLen)
        {
            snprintf (pszRetBuffer, wRetBufferLen, "%04u.%02u.%02u %02u:%02u:%02u",
                     tTime.tm_year+1900,
                     tTime.tm_mon+1,
                     tTime.tm_mday,
                     tTime.tm_hour,
                     tTime.tm_min,
                     tTime.tm_sec);
        }
    }

Done:
    return 0;
}


int X509GetDate (const X509 *pX509, int NameType, int wRetBufferLen, char *pszRetBuffer, struct tm *pretTM)
{
    ASN1_TIME   const *pTM = NULL;

    if (pszRetBuffer && wRetBufferLen)
        *pszRetBuffer = '\0';

    if (pretTM)
        memset (pretTM, 0, sizeof (struct tm));

    switch (NameType)
    {
        case X509_GET_NOT_BEFORE:
            pTM = X509_get0_notBefore (pX509);
            break;

        case X509_GET_NOT_AFTER:
            pTM = X509_get0_notAfter (pX509);
            break;

        default:
            return 0;
    } /* switch */

    AsnTimeGetDate (pTM, wRetBufferLen, pszRetBuffer, pretTM);

    return 0;
}


int LogKeyInfos (const char *pszHeader, EVP_PKEY *pKey, X509 *pCert, bool bDumpPEM)
{
    int ret     = 0;
    int KeyType = 0;
    int Bits    = 0;

    size_t len  = 0;
    char szBuffer [1024] = {0};

    if (NULL == pszHeader)
        return 0;

    /* If no key is specified, get public key from cert */
    if (NULL == pKey)
    {
        if (NULL == pCert)
            goto Done;

        pKey = X509_get0_pubkey (pCert); /* Don't free the key returned from this call! */

        if (NULL == pKey)
            goto Done;
    }

    KeyType = EVP_PKEY_base_id (pKey);

    if (0 == KeyType)
        goto Done;

    Bits = EVP_PKEY_bits (pKey);

    switch (KeyType)
    {
        case NID_ED25519:
            printf ("%s: Ed25519 %d bit\n", pszHeader, Bits);
            break;

        case NID_ED448:
            printf ("%s: Ed448 %d bit\n", pszHeader, Bits);
            break;

        case NID_X25519:
            printf ("%s: X25519 %d bit\n", pszHeader, Bits);
            break;

        case NID_X448:
            printf ("%s: X448 %d bit\n", pszHeader, Bits);
            break;

        case EVP_PKEY_RSA:
            printf ("%s: RSA %d bit\n", pszHeader, Bits);
            break;

        case EVP_PKEY_RSA_PSS:
            printf ("%s: RSA PSS %d bit\n", pszHeader, Bits);
            break;

        case EVP_PKEY_EC:

            ret = EVP_PKEY_get_utf8_string_param (pKey, OSSL_PKEY_PARAM_GROUP_NAME, szBuffer, sizeof (szBuffer), &len);

            if (ret)
                printf ("%s: ECDSA %s\n", pszHeader, szBuffer);
            break;

        default:
            printf ("%s: Unknown key type %d\n", pszHeader, KeyType);
            break;

    } /* switch */

    if (bDumpPEM)
    {
        printf ("\n");
        PEM_write_PUBKEY (stdout, pKey);
    }

    printf ("\n");

Done:
    return 0;
}


int LogCertInfos (const char *pszHeader, X509 *pCert, bool bDumpPEM)
{
    int ret = 0;
    const char *pStr  = NULL;
    char szBuffer [10240] = {0};

    if (NULL == pszHeader)
        return 0;

    printf ("--- %s ---\n", pszHeader);

    if (NULL == pCert)
        return 0;

    GetX509Names (pCert, NID_subject_alt_name, GEN_DNS, sizeof(szBuffer)-1, szBuffer);

    if (*szBuffer)
        printf ("SAN        : %s\n", szBuffer);

    pStr = X509_NAME_oneline (X509_get_subject_name (pCert), szBuffer, sizeof (szBuffer)-1);

    if (pStr)
        printf ("Subject    : %s\n", szBuffer);

    pStr = X509_NAME_oneline (X509_get_issuer_name (pCert), szBuffer, sizeof (szBuffer)-1);

    if (pStr)
        printf ("Issuer     : %s\n", szBuffer);

    X509GetDate (pCert, X509_GET_NOT_BEFORE, sizeof (szBuffer), szBuffer, NULL);

    if (*szBuffer)
        printf ("Not before : %s\n", szBuffer);

    X509GetDate (pCert, X509_GET_NOT_AFTER, sizeof (szBuffer),  szBuffer,  NULL);

    if (*szBuffer)
        printf ("Not after  : %s\n", szBuffer);

    /* Dump the leaf certificate */
    if (bDumpPEM)
    {
        printf ("\n");
        PEM_write_X509 (stdout, pCert);
    }

    printf ("\n");

    return ret;
}


int LogChain (const char *pszHeader, STACK_OF(X509) *pChain)
{
    int   ret   = 0;
    int   i     = 0;
    int   count = 0;
    X509 *pCert = NULL;

    char szBuffer [1024] = {0};

    if (NULL == pszHeader)
        return 0;

    if (NULL == pChain)
        return 0;

    count = sk_X509_num (pChain);

    if (g_Verbose < 1)
    {
        printf ("%s(%d)\n", pszHeader, count);
        return 0;
    }
 
    for (i=0; i<count; ++i)
    {
        snprintf (szBuffer, sizeof (szBuffer), "%s #%d", pszHeader, i);

        pCert = sk_X509_value (pChain, i);
        LogCertInfos (szBuffer, pCert, g_DumpPEM > 1 ? true : false);
    }

    return ret;
}

int LogChainInfos (SSL *pSSL)
{
    int   ret   = 0;
    STACK_OF(X509) *pChain;

    if (NULL == pSSL)
        return 0;

    pChain = SSL_get_peer_cert_chain (pSSL);
    LogChain ("Received Chain", pChain);

    pChain = SSL_get0_verified_chain (pSSL);
    LogChain ("Verified Chain", pChain);

    return ret;
}

int LogSSLInfos (SSL *pSSL)
{
    int ret = 0;
    const char *pStr  = NULL;
    EVP_PKEY   *pKey  = NULL;
    X509       *pCert = NULL;

    if (NULL == pSSL)
        goto Done;

    pStr = SSL_get_cipher_version (pSSL);
    if (pStr)
        printf ("TLS Version: [%s]\n", pStr);

    pStr = SSL_get_cipher (pSSL);
    if (pStr)
        printf ("TLS Cipher : [%s]\n", pStr);

    ret = SSL_get_peer_tmp_key (pSSL, &pKey);

    if (0 == ret)
        ret = SSL_get_tmp_key (pSSL, &pKey);

    if (pKey)
        LogKeyInfos ("Session Key", pKey, NULL, g_DumpPEM ? true : false);

    pCert = SSL_get1_peer_certificate (pSSL);

    if (NULL == pCert)
    {
        goto Done;
    }

    LogKeyInfos  ("Certificate", NULL, pCert, g_DumpPEM > 1 ? true : false);
    LogCertInfos ("Leaf Certificate", pCert, g_DumpPEM ? true : false);

    printf ("\n");

Done:

    if (pCert)
    {
        X509_free (pCert);
        pCert = NULL;
    }

    if (pKey)
    {
        EVP_PKEY_free (pKey);
        pKey = NULL;
    }

    return ret;
}


static int VerifyCallback (int wPreverify, X509_STORE_CTX *pStoreCtx)
{
    X509 *pCert = X509_STORE_CTX_get_current_cert (pStoreCtx);

    if (NULL == pCert)
    {
        printf ("Verify got no certificate\n");
        goto Done;
    }

    LogCertInfos ("Verify", pCert, (g_DumpPEM > 1) ? true : false);

    wPreverify = 1;

Done:

    return wPreverify;
 }


void ssl_info_callback (const SSL *pSSL, int where, int ret)
{
    const char *pszStr       = NULL;
    const char *pszAlertType = NULL;
    const char *pszAlertDesc = NULL;
    const char *pszStateStr  = NULL;
    const char szEmpty[]     = "";

    int w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT)
        pszStr = "SSL_connect";

    else if (w & SSL_ST_ACCEPT)
        pszStr = "SSL_accept";

    else
        pszStr = "undefined";

    if (where & SSL_CB_LOOP)
    {
        printf("%s: %s\n", pszStr, SSL_state_string_long (pSSL));
    }
    else if (where & SSL_CB_ALERT)
    {
        pszStr = (where & SSL_CB_READ) ? "read" : "write";

        pszAlertType = SSL_alert_type_string_long (ret);
        pszAlertDesc = SSL_alert_desc_string_long (ret);

        if (NULL == pszAlertType)
            pszAlertType = szEmpty;

        if (NULL == pszAlertDesc)
            pszAlertDesc = szEmpty;

        printf("SSL3 alert %s: %s: %s\n", pszStr, pszAlertType, pszAlertDesc);
    }
    else if (where & SSL_CB_EXIT)
    {

        pszStateStr = SSL_state_string_long (pSSL);

        if (NULL == pszStateStr)
            pszStateStr = szEmpty;

        if (ret == 0)
            printf("%s: failed in %s\n", pszStr, pszStateStr);

        else if (ret < 0)
            printf("%s: error in %s\n", pszStr, pszStateStr);
    }
}

#endif


int SendSmtpMessage (const char *pszHostname,
                     const char *pszMailer,
                     const char *pszSmtpServerAddress,
                     const char *pszFrom,
                     const char *pszFromName,
                     const char *pszSendTo,
                     const char *pszCopyTo,
                     const char *pszBlindCopyTo,
                     const char *pszSubject,
                     const char *pszBody,
                     const char *pszBodyFile,
                     const char *pszAttachmenFilePath,
                     const char *pszAttachmentName,
                     const char *pszCipherList,
                     bool bUseTLS,
                     bool bNoTLS13,
                     bool bVerify,
                     bool bECDSA,
                     bool bUTF8)
{
    int rc = 600;
    int CipherCount      = 0;
    int PriorityMX       = 0;

    char szConnect[80]   = {0};
    char szRandom[80]    = {0};
    char szTime[40]      = {0};
    char szBoundary[255] = {0};
    char szUser[40]      = {0};
    char szHostname[80]  = {0};
    char szFrom[255]     = {0};
    char szMX[2048]      = {0};
    char *pMem           = NULL;

    const char szLocalHost[] = "127.0.0.1";
    const char szDefaultAttachmenName[] = "message.txt";
    const char *pStr      = NULL;
    const char *pszDomain = NULL;

    BIO *pBioMem   = NULL;
    BIO *pBioB64   = NULL;
    BIO *pBioFile  = NULL;

    size_t MemSize = 0;
    size_t CountMX = 0;
    time_t tNow    = time (NULL);

    if (IsNullStr (pszHostname))
    {
        GetLocalHostname (szHostname, sizeof (szHostname));
        pszHostname = szHostname;
    }

    if  ((IsNullStr (pszSendTo)) && (IsNullStr (pszCopyTo)) && (IsNullStr (pszBlindCopyTo)))
    {
        LogError ("No recipient specified");
        goto Done;
    }

    if (IsNullStr (pszFrom))
    {
        GetUser (getuid(), sizeof (szUser), szUser);
        snprintf (szFrom, sizeof (szFrom), "%s@%s", szUser, pszHostname);
        pszFrom = szFrom;
    }

    /* Get SMTP server from first mail address */
    if (IsNullStr (pszSmtpServerAddress))
    {
        if (pszSendTo)
            pszDomain = strchr (pszSendTo, '@');
        else if (pszCopyTo)
            pszDomain = strchr (pszCopyTo, '@');
        else if (pszBlindCopyTo)
            pszDomain = strchr (pszBlindCopyTo, '@');

        if (pszDomain)
        {
            pszDomain++;
            CountMX = GetMxRecord (pszDomain, sizeof (szMX), szMX, &PriorityMX);

            if (CountMX)
            {
                pszSmtpServerAddress = szMX;

                if (!g_bSilent)
                    printf ("SMTP Server: [%s] (MX: %d)\n", szMX, PriorityMX);
            }
        }
        else
        {
            pszSmtpServerAddress = szLocalHost;
        }
    }

    if (IsNullStr (pszSmtpServerAddress))
    {
        LogError ("No SMTP server specified");
        goto Done;
    }

    if (!g_bSilent)
        printf ("Connecting to server ... %s\n", pszSmtpServerAddress);

    snprintf (szConnect, sizeof (szConnect),  "%s:25", pszSmtpServerAddress);

    g_pBio = BIO_new_connect (szConnect);

    if (NULL == g_pBio)
    {
        LogError ("Error creating new connection to server", szConnect);
        goto Done;
    }

    if (BIO_do_connect (g_pBio) <= 0)
    {
        LogError ("Error connecting to server", szConnect);
        goto Done;
    }

    if (!g_bSilent)
        printf ("Connection established\n");

    if((rc = GetReturnCode()))
        goto Quit;

    snprintf (g_szBuffer, sizeof (g_szBuffer), "EHLO %s%s", pszHostname, CRLF);
    SendBuffer (g_szBuffer);

    if((rc = GetReturnCode()))
       goto Quit;

    if (bUseTLS)
    {
        snprintf (g_szBuffer, sizeof (g_szBuffer), "STARTTLS%s", CRLF);
        SendBuffer (g_szBuffer);

        if((rc = GetReturnCode()))
            goto Quit;

        if (!g_bSilent)
            printf ("Starting TLS session ...\n");

        g_pCtxSSL = SSL_CTX_new (TLS_client_method());

        if (NULL == g_pCtxSSL)
        {
            LogError ("Cannot create SSL context");
            goto Quit;
        }

        if (bNoTLS13)
        {
            SSL_CTX_set_options (g_pCtxSSL, SSL_OP_NO_TLSv1_3);
        }

        if (pszCipherList && *pszCipherList)
        {
            SSL_CTX_set_cipher_list (g_pCtxSSL, pszCipherList);
        }

        g_pSSL = SSL_new (g_pCtxSSL);

        if (NULL == g_pSSL)
        {
            LogError ("No SSL connection allocated");
            goto Quit;
        }

        SSL_set_tlsext_host_name (g_pSSL, pszSmtpServerAddress);

#ifdef LIBRESSL_VERSION_NUMBER
        if (bECDSA)
            LogError ("ECDSA option currently not supported on LibreSSL");
#else
        if (bECDSA)
            SSL_set1_sigalgs_list (g_pSSL, "ECDSA+SHA256");

        if (bVerify)
        {
            SSL_set_verify (g_pSSL, SSL_VERIFY_PEER, VerifyCallback);
        }

        if (g_Verbose > 1)
        {
            SSL_CTX_set_info_callback (g_pCtxSSL, ssl_info_callback);
        }

#endif

        SSL_set_bio (g_pSSL, g_pBio, g_pBio);

        CipherCount = CheckLocalAvailableCiphers();

        if (!g_bSilent)
            printf ("Ciphers: %d\n", CipherCount);

        if (1 != SSL_connect (g_pSSL))
        {
            ERR_print_errors_fp (stderr);
            LogError ("Handshake failed");
            goto Quit;
        }

        if (!g_bSilent)
            printf ("Handshake Done\n\n");

        if (g_Verbose)
        {
            LogSSLInfos (g_pSSL);
            LogChainInfos (g_pSSL);
        }

        snprintf (g_szBuffer, sizeof (g_szBuffer), "EHLO %s%s", pszHostname, CRLF);
        SendBuffer (g_szBuffer);

        if((rc = GetReturnCode()))
            goto Quit;
    }

    if (pszFrom)
    {
        snprintf (g_szBuffer, sizeof (g_szBuffer), "MAIL FROM:<%s>%s", pszFrom, CRLF);
        SendBuffer (g_szBuffer);
    }

    if((rc = GetReturnCode()))
       goto Quit;

    if (pszSendTo)
    {
        snprintf (g_szBuffer, sizeof (g_szBuffer), "RCPT TO:<%s>%s", pszSendTo, CRLF);
        SendBuffer (g_szBuffer);
    }

    if (pszCopyTo)
    {
        snprintf (g_szBuffer, sizeof (g_szBuffer), "RCPT TO:<%s>%s", pszCopyTo, CRLF);
        SendBuffer (g_szBuffer);
    }

    if (pszBlindCopyTo)
    {
        snprintf (g_szBuffer, sizeof (g_szBuffer), "RCPT TO:<%s>%s", pszBlindCopyTo, CRLF);
        SendBuffer (g_szBuffer);
    }

    if((rc = GetReturnCode()))
       goto Quit;

    snprintf (g_szBuffer, sizeof (g_szBuffer), "DATA%s", CRLF);
    SendBuffer (g_szBuffer);

    if((rc = GetReturnCode()))
        goto Quit;

    GetTimeString (&tNow, szTime, sizeof (szTime));

    snprintf (g_szBuffer, sizeof (g_szBuffer), "Date: %s%s", szTime, CRLF);
    SendBuffer (g_szBuffer);

    if (pszSendTo)
    {
        snprintf (g_szBuffer, sizeof (g_szBuffer), "To: %s%s", pszSendTo, CRLF);
        SendBuffer (g_szBuffer);
    }

    if (pszCopyTo)
    {
        snprintf (g_szBuffer, sizeof (g_szBuffer), "CC: %s%s", pszCopyTo, CRLF);
        SendBuffer (g_szBuffer);
    }

    if (pszSubject)
    {
        snprintf (g_szBuffer, sizeof (g_szBuffer), "Subject: %s%s", pszSubject, CRLF);
        SendBuffer (g_szBuffer);
    }

    if (pszMailer)
    {
        snprintf (g_szBuffer, sizeof (g_szBuffer), "X-MAILER: %s%s", pszMailer, CRLF);
        SendBuffer (g_szBuffer);
    }

    snprintf (g_szBuffer, sizeof (g_szBuffer), "MIME-Version: 1.0%s", CRLF);
    SendBuffer (g_szBuffer);

    GetRandomString (NULL, 20, szRandom);

    if (pszHostname)
        snprintf (g_szBuffer, sizeof (g_szBuffer), "Message-ID: <%s@%s>%s", szRandom, pszHostname, CRLF);
    else
        snprintf (g_szBuffer, sizeof (g_szBuffer), "Message-ID: <%s>%s", szRandom, CRLF);

    SendBuffer (g_szBuffer);

    if (pszFrom)
    {
        if (IsNullStr (pszFromName))
            snprintf (g_szBuffer, sizeof (g_szBuffer), "From: %s%s", pszFrom, CRLF);
        else
            snprintf (g_szBuffer, sizeof (g_szBuffer), "From: \"%s\" <%s>%s", pszFromName, pszFrom, CRLF);

        SendBuffer (g_szBuffer);
    }

    GetRandomString (NULL, 40, szRandom);
    snprintf (szBoundary, sizeof (szBoundary), "%s", szRandom);

    snprintf (g_szBuffer, sizeof (g_szBuffer), "Content-Type: multipart/mixed; boundary=\"%s\"%s", szBoundary, CRLF);
    SendBuffer (g_szBuffer);

    snprintf (g_szBuffer, sizeof (g_szBuffer), "%s", CRLF);
    SendBuffer (g_szBuffer);

    snprintf (g_szBuffer, sizeof (g_szBuffer), "--%s%s", szBoundary, CRLF);
    SendBuffer (g_szBuffer);

    if (bUTF8 || (false == IsNullStr (pszBodyFile)))
    {
        pBioMem = BIO_new (BIO_s_mem());
        if (NULL == pBioMem)
        {
            LogError ("Cannot create memory BIO");
            goto Done;
        }

        pBioB64 = BIO_new (BIO_f_base64());

        if (NULL == pBioB64)
        {
            LogError ("Cannot create Base64 BIO");
            goto Done;
        }

        pBioMem = BIO_push (pBioB64, pBioMem);

        if (IsNullStr (pszBodyFile))
        {
            if (false == IsNullStr (pszBody))
                BIO_puts (pBioMem, pszBody);
        }
        else
        {
            if (0 == strcmp (pszBodyFile, "-"))
            {
                pBioFile = BIO_new_fp (stdin, BIO_NOCLOSE);
            }
            else
            {
                pBioFile = BIO_new_file (pszBodyFile, "rb");
            }

            if (NULL == pBioFile)
            {
                LogError ("Cannot read body file", pszBodyFile);
                goto Done;
            }

            CopyFromToBio (pBioFile, pBioMem);

            BIO_free_all (pBioFile);
            pBioFile = NULL;
        }

        BIO_flush (pBioMem);

        snprintf (g_szBuffer, sizeof (g_szBuffer), "Content-Transfer-Encoding: base64%s", CRLF);
        SendBuffer (g_szBuffer);

        snprintf (g_szBuffer, sizeof (g_szBuffer), "Content-Type: text/plain; charset=UTF-8%s", CRLF);
        SendBuffer (g_szBuffer);

        snprintf (g_szBuffer, sizeof (g_szBuffer), "Content-Disposition: inline%s", CRLF);
        SendBuffer (g_szBuffer);

        snprintf (g_szBuffer, sizeof (g_szBuffer), "%s", CRLF);
        SendBuffer (g_szBuffer);

        MemSize = BIO_get_mem_data (pBioMem, &pMem);

        if ((pMem) && (MemSize))
        {
            SendBuffer (pMem);
        }

        BIO_free_all (pBioMem);
        pBioMem = NULL;

        snprintf (g_szBuffer, sizeof (g_szBuffer), "%s", CRLF);
        SendBuffer (g_szBuffer);
    }
    else
    {
        snprintf (g_szBuffer, sizeof (g_szBuffer), "Content-Transfer-Encoding: 7bit%s", CRLF);
        SendBuffer (g_szBuffer);

        snprintf (g_szBuffer, sizeof (g_szBuffer), "Content-Type: text/plain; charset=us-ascii%s", CRLF);
        SendBuffer (g_szBuffer);

        snprintf (g_szBuffer, sizeof (g_szBuffer), "Content-Disposition: inline%s", CRLF);
        SendBuffer (g_szBuffer);

        if (false == IsNullStr (pszBody))
        {
            SendBuffer (pszBody);
        }
    }

    snprintf (g_szBuffer, sizeof (g_szBuffer), "%s", CRLF);
    SendBuffer (g_szBuffer);

    snprintf (g_szBuffer, sizeof (g_szBuffer), "%s", CRLF);
    SendBuffer (g_szBuffer);

    if (pszAttachmenFilePath)
    {
        snprintf (g_szBuffer, sizeof (g_szBuffer), "--%s%s", szBoundary, CRLF);
        SendBuffer (g_szBuffer);

        snprintf (g_szBuffer, sizeof (g_szBuffer), "Content-Type: application/octet-stream%s", CRLF);
        SendBuffer (g_szBuffer);

        if (IsNullStr (pszAttachmentName))
        {
            if (0 == strcmp (pszAttachmenFilePath, "-"))
            {
                pszAttachmentName = szDefaultAttachmenName;
            }
            else
            {
                /* Get attachment name from file path */
                pszAttachmentName = pszAttachmenFilePath;
                pStr = pszAttachmenFilePath;

                while (*pStr)
                {
                    if ('/' == *pStr)
                        pszAttachmentName = pStr+1;
                    pStr++;
                }
            }
        }

        snprintf (g_szBuffer, sizeof (g_szBuffer), "Content-Disposition: attachment; filename=\"%s\"%s", pszAttachmentName, CRLF);
        SendBuffer (g_szBuffer);

        snprintf (g_szBuffer, sizeof (g_szBuffer), "Content-Transfer-Encoding: base64%s", CRLF);
        SendBuffer (g_szBuffer);

        snprintf (g_szBuffer, sizeof (g_szBuffer), "%s", CRLF);
        SendBuffer (g_szBuffer);

        pBioMem = BIO_new (BIO_s_mem());
        if (NULL == pBioMem)
        {
            LogError ("Cannot create memory BIO\n");
            goto Done;
        }

        pBioB64 = BIO_new (BIO_f_base64());

        if (NULL == pBioB64)
        {
            LogError ("Cannot create Base64 BIO\n");
            goto Done;
        }

        pBioMem = BIO_push (pBioB64, pBioMem);

        if (0 == strcmp (pszAttachmenFilePath, "-"))
        {
            pBioFile = BIO_new_fp (stdin, BIO_NOCLOSE);
        }
        else
        {
            pBioFile = BIO_new_file (pszAttachmenFilePath, "rb");
        }

        if (NULL == pBioFile)
        {
           LogError ("Cannot read file: %s\n", pszAttachmenFilePath);
            goto Done;
        }

        CopyFromToBio (pBioFile, pBioMem);

        BIO_free_all (pBioFile);
        pBioFile = NULL;

        BIO_flush (pBioMem);
        MemSize = BIO_get_mem_data (pBioMem, &pMem);

        if ((pMem) && (MemSize))
        {
            SendBuffer (pMem);
        }

        BIO_free_all (pBioMem);
        pBioMem = NULL;

        snprintf (g_szBuffer, sizeof (g_szBuffer), "%s", CRLF);
        SendBuffer (g_szBuffer);
    }

    snprintf (g_szBuffer, sizeof (g_szBuffer), "--%s--%s", szBoundary, CRLF);
    SendBuffer (g_szBuffer);

    snprintf (g_szBuffer, sizeof (g_szBuffer), "%s.%s", CRLF, CRLF);
    SendBuffer (g_szBuffer);

    if((rc = GetReturnCode()))
        goto Quit;

Quit:

    snprintf (g_szBuffer, sizeof (g_szBuffer), "QUIT%s", CRLF);
    SendBuffer (g_szBuffer);

    if (!g_bSilent)
        printf ("Quit.\n");

Done:

    if (!g_bSilent)
        printf ("Done.\n");

    if (pBioMem)
    {
        BIO_free_all (pBioMem);
        pBioMem = NULL;
    }

    if (pBioFile)
    {
        BIO_free_all (pBioFile);
        pBioFile = NULL;
    }

    if (g_pBio)
    {
        BIO_free_all (g_pBio);
        g_pBio = NULL;
    }

    if (g_pCtxSSL)
    {
        SSL_CTX_free (g_pCtxSSL);
        g_pCtxSSL = NULL;
    }

    if (!g_bSilent)
        printf ("Cleanup Done.\n");

    return rc;
}


int GetParam (const char *pszParamName, const char *pszName, const char *pszValue, int BufferSize, char *retpszBuffer)
{
    if (IsNullStr (pszName))
        return 0;

    if (NULL == pszValue)
        return 0;

    if (NULL == retpszBuffer)
        return 0;

    if (0 == BufferSize)
        return 0;

    if (strcmp (pszParamName, pszName))
        return 0;

    strdncpy (retpszBuffer, pszValue, BufferSize);
    return 1;
}


int FileExists (const char *pszFilename)
{
    int ret = 0;
    struct stat Filestat = {0};

    if (IsNullStr (pszFilename))
        return 0;

    ret = stat (pszFilename, &Filestat);

    if (ret)
        return 0;

    if (S_IFDIR & Filestat.st_mode)
        return 2;
    else
        return 1;
}


int ReadConfig (const char *pszConfigFile)
{
    int  ret = 0;
    FILE *fp = NULL;
    char *p  = NULL;
    char *pszValue = NULL;
    char szBuffer[4096] = {0};
    char szNum[20] = {0};

    if (IsNullStr (pszConfigFile))
    {
        fprintf (stderr, "No configuration file specified\n");
        ret = -1;
        goto Done;
    }

    if (0 == FileExists (pszConfigFile))
    {
        fprintf (stderr, "Info: No configuration profile found: %s\n", pszConfigFile);
    }

    fp = fopen (pszConfigFile, "r");

    if (NULL == fp)
    {
        fprintf (stderr, "Cannot open configuration file: %s\n", pszConfigFile);
        ret= -1;
        goto Done;
    }

    while ( fgets (szBuffer, sizeof (szBuffer)-1, fp) )
    {
        /* Parse for '=' to get value */
        p = szBuffer;
        pszValue = NULL;
        while (*p)
        {
            if ('=' == *p)
            {
                if (NULL == pszValue)
                {
                    *p = '\0';
                    pszValue = p+1;
                }
            }
            else if (*p < 32)
            {
               *p = '\0';
                break;
            }

            p++;
        }

        if (!*szBuffer)
            continue;

        if ('#' == *szBuffer)
            continue;

        if (NULL == pszValue)
        {
            fprintf (stdout, "Warning - Invalid parameter: [%s]\n", szBuffer);
            ret++;
            continue;
        }

             if ( GetParam ("from",          szBuffer, pszValue, sizeof (g_szFrom),              g_szFrom));
        else if ( GetParam ("fromname",      szBuffer, pszValue, sizeof (g_szFromName),          g_szFromName));
        else if ( GetParam ("mailer",        szBuffer, pszValue, sizeof (g_szMailer),            g_szMailer));
        else if ( GetParam ("hostname",      szBuffer, pszValue, sizeof (g_szHostname),          g_szHostname));
        else if ( GetParam ("serveraddress", szBuffer, pszValue, sizeof (g_szSmtpServerAddress), g_szSmtpServerAddress));
        else if ( GetParam ("cipherlist",    szBuffer, pszValue, sizeof (g_szCipherList),        g_szCipherList));
        else if ( GetParam ("rcptallowed",   szBuffer, pszValue, sizeof (g_szAllowedRecptsRegx), g_szAllowedRecptsRegx));

        else if ( GetParam ("tls", szBuffer, pszValue, sizeof (szNum), szNum))
        {
            g_bUseTLS = atoi (szNum) ? true : false;
        }

        else if ( GetParam ("notls13", szBuffer, pszValue, sizeof (szNum), szNum))
        {
            g_bNoTLS13 = atoi (szNum) ? true : false;
        }

        else if ( GetParam ("verify", szBuffer, pszValue, sizeof (szNum), szNum))
        {
            g_bVerify = atoi (szNum) ? true : false;
        }

        else if ( GetParam ("ecdsa", szBuffer, pszValue, sizeof (szNum), szNum))
        {
            g_bECDSA = atoi (szNum) ? true : false;
        }

        else if ( GetParam ("utf8", szBuffer, pszValue, sizeof (szNum), szNum))
        {
            g_bUTF8 = atoi (szNum) ? true : false;
        }

        else if ( GetParam ("silent", szBuffer, pszValue, sizeof (szNum), szNum))
        {
            g_bSilent = atoi (szNum) ? true : false;
        }

        else
        {
             fprintf (stdout, "Warning - Invalid configuration parameter: [%s]\n", szBuffer);
             ret++;
        }

    } /* while */

Done:

    if (fp)
    {
        fclose (fp);
        fp = NULL;
    }

    return ret;
}



int main (int argc, const char *argv[])
{
    int rc  = 0;
    int ret = 1;
    int consumed = 1;

    const char *pszSendTo            = NULL;
    const char *pszCopyTo            = NULL;
    const char *pszBlindCopyTo       = NULL;
    const char *pszSubject           = NULL;
    const char *pszBody              = NULL;
    const char *pszBodyFile          = NULL;
    const char *pszAttachmenFilePath = NULL;
    const char *pszAttachmenName     = NULL;

    /* Set defaults from config overwritten by command line parameters */
    const char *pszFrom              = g_szFrom;
    const char *pszMailer            = g_szMailer;
    const char *pszFromName          = g_szFromName;
    const char *pszHostname          = g_szHostname;
    const char *pszSmtpServerAddress = g_szSmtpServerAddress;
    const char *pszCipherList        = g_szCipherList;

    bool bUseTLS  = true;
    bool bNoTLS13 = false;
    bool bVerify  = false;
    bool bECDSA   = false;
    bool bUTF8    = true;

    size_t FileSize = 0;

    /* Read optional config file if present */
    ret = ReadConfig (g_szConfigFile);

    /* Set defaults from config overwritten by command line parameters */

    bUseTLS  = g_bUseTLS;
    bNoTLS13 = g_bNoTLS13;
    bVerify  = g_bVerify;
    bECDSA   = g_bECDSA;
    bUTF8    = g_bUTF8;

    while (argc > consumed)
    {
        if  ( (0 == strcasecmp (argv[consumed], "-help")) ||
              (0 == strcasecmp (argv[consumed], "-h")) ||
              (0 == strcasecmp (argv[consumed], "-?")) )
        {
            PrintHelpText(g_ProgramName);
            goto Done;
        }

        else if  ( (0 == strcasecmp (argv[consumed], "-version")) ||
                   (0 == strcasecmp (argv[consumed], "--version")) ||
                   (0 == strcasecmp (argv[consumed], "-ver")) )
        {
            PrintVersion();
            ret = 0;
            goto Done;
        }

        else if (0 == strcasecmp (argv[consumed], "-notls"))
        {
            bUseTLS = false;
        }

        else if (0 == strcasecmp (argv[consumed], "-notls13"))
        {
            bNoTLS13 = true;
        }

        else if (0 == strcasecmp (argv[consumed], "-ec"))
        {
            bECDSA = true;
        }

        else if (0 == strcasecmp (argv[consumed], "-verify"))
        {
            bVerify = true;
        }

        else if (0 == strcasecmp (argv[consumed], "-silent"))
        {
            g_bSilent = true;
        }

        else if (0 == strcasecmp (argv[consumed], "-nosilent"))
        {
            g_bSilent = false;
        }

        else if (0 == strcasecmp (argv[consumed], "-v"))
        {
            g_Verbose++;
        }

        else if (0 == strcasecmp (argv[consumed], "-trace"))
        {
            g_Trace++;
        }

        else if (0 == strcasecmp (argv[consumed], "-pem"))
        {
            g_DumpPEM++;
        }

        else if (0 == strcasecmp (argv[consumed], "-host"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszHostname = argv[consumed];
        }

        else if (0 == strcasecmp (argv[consumed], "-server"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszSmtpServerAddress = argv[consumed];
        }

        else if ( (0 == strcasecmp (argv[consumed], "-from")) ||
                  (0 == strcasecmp (argv[consumed], "-r")) )
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszFrom = argv[consumed];
        }

        else if (0 == strcasecmp (argv[consumed], "-name"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszFromName = argv[consumed];
        }

        else if (0 == strcasecmp (argv[consumed], "-to"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszSendTo = argv[consumed];
        }

        else if ( (0 == strcasecmp (argv[consumed], "-cc")) ||
                  (0 == strcasecmp (argv[consumed], "-c")) )
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszCopyTo = argv[consumed];
        }

        else if ( (0 == strcasecmp (argv[consumed], "-bcc")) ||
                  (0 == strcasecmp (argv[consumed], "-b")) )
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszBlindCopyTo = argv[consumed];
        }


        else if ( (0 == strcasecmp (argv[consumed], "-subject")) ||
                  (0 == strcasecmp (argv[consumed], "-s")) )
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszSubject = argv[consumed];
        }

        else if (0 == strcasecmp (argv[consumed], "-body"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszBody = argv[consumed];
        }

        else if (0 == strcasecmp (argv[consumed], "-mailer"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszMailer = argv[consumed];
        }

        else if (0 == strcasecmp (argv[consumed], "-file"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;

            if (0 == strcmp (argv[consumed], "-"));
            else if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszBodyFile = argv[consumed];
        }

        else if ((0 == strcasecmp (argv[consumed], "-att")) ||
                 (0 == strcasecmp (argv[consumed], "-a")) )
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;

            if (0 == strcmp (argv[consumed], "-"));
            else if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszAttachmenFilePath = argv[consumed];
        }

        else if (0 == strcasecmp (argv[consumed], "-attname"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszAttachmenName = argv[consumed];
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

        else if (0 == strcasecmp (argv[consumed], "--"))
        {
            /* Ignored parameter */
        }

        else
        {
            if ('-' == *argv[consumed])
            {
                if (strstr (argv[0], "nshmailx"))
                    goto InvalidSyntax;

                /* Trace mailx and other symbolic link invocations */
                LogInvalidOption (argv[0], argv[consumed]);
            }
            else
            {
                pszSendTo = argv[consumed];
            }
        }

        consumed++;
    } /* while */

    if  ((IsNullStr (pszSendTo)) && (IsNullStr (pszCopyTo)) && (IsNullStr (pszBlindCopyTo)))
    {
        LogError ("No recipient specified");
        goto Done;
    }


    if (!RecipientAllowed (pszSendTo))
    {
        LogError ("Recipient not allowed");
        goto Done;
    }

    if (!RecipientAllowed (pszCopyTo))
    {
        LogError ("CopyTo recipient not allowed");
        goto Done;
    }

    if (!RecipientAllowed (pszBlindCopyTo))
    {
        LogError ("BlindCopyTo recipient not allowed");
        goto Done;
    }

    if (IsNullStr (pszFrom))
        LogWarning ("No FROM address specified");

    if (IsNullStr (pszSubject))
        LogWarning ("No Subject specified");

    if (false == IsNullStr (pszAttachmenFilePath))
    {
        if (0 == strcmp (pszAttachmenFilePath, "-"))
        {
            /* stdin needs not check */
        }
        else
        {
            FileSize = GetFileSize (pszAttachmenFilePath);

            if (0 == FileSize)
            {
                LogError ("Cannot open attachment file", pszAttachmenFilePath);
                goto Done;
            }

            if (FileSize > 1024 * 1024 * 1024) /* Max 1 GB */
            {
                LogError ("Attachment too large to send", pszAttachmenFilePath);
                goto Done;
            }
        }
    }

    if (false == IsNullStr (pszBodyFile))
    {
        if (0 == strcmp (pszBodyFile, "-"))
        {
            /* stdin needs not check */
        }
        else
        {
            FileSize = GetFileSize (pszBodyFile);

            if (0 == FileSize)
            {
                LogError ("Cannot open body file", pszBodyFile);
                goto Done;
            }

            if (FileSize > 50 * 1024 * 1024)
            {
                LogError ("Body file too large to send", pszBodyFile);
                goto Done;
            }
        }
    }

    rc = SendSmtpMessage (pszHostname,
                          pszMailer,
                          pszSmtpServerAddress,
                          pszFrom,
                          pszFromName,
                          pszSendTo,
                          pszCopyTo,
                          pszBlindCopyTo,
                          pszSubject,
                          pszBody,
                          pszBodyFile,
                          pszAttachmenFilePath,
                          pszAttachmenName,
                          pszCipherList,
                          bUseTLS,
                          bNoTLS13,
                          bVerify,
                          bECDSA,
                          bUTF8);

    if (0 == rc)
        ret = 0;
    else
        fprintf (stderr, "ERROR: Failed to send Message. Status: %d, Error: [%s]\n", rc, g_szErrorBuffer);

Done:

    return ret;

InvalidSyntax:

    LogError ("\nInvalid Syntax!");
    PrintHelpText (g_ProgramName);

    return ret;
}

