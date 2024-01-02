
/*
###########################################################################
# NashCom SMTP mail test/send tool (nshmailx)                             #
# Version 0.9.0 02.01.2024                                                #
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <resolv.h>
#include <pwd.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define VERSION "0.9.0"

#define MAX_BUFFER_LEN 65535

#define CRLF "\r\n"
#define CR   "\r"
#define LF   "\n"

/* Globals */

BIO     *g_pBio    = NULL;
SSL     *g_pSSL    = NULL;
SSL_CTX *g_pCtxSSL = NULL;

char g_ProgramName[] = "nshmailx";
char g_szBuffer[MAX_BUFFER_LEN+1] = {0};
char g_szErrorBuffer[4096] = {0};
int  g_Verbose = 0;


void strdncpy (char *pszStr, const char *ct, size_t n)
{
    if (NULL == pszStr)
        return;

    if (n>0)
    {
        strncpy (pszStr, ct, n-1);
        pszStr[n-1] = '\0';
    }
}


void LogWarning (const char *pszErrorText)
{
    if (NULL == pszErrorText)
        return;

    fprintf (stderr, "Warning: %s\n\n", pszErrorText);
}


void LogError (const char *pszErrorText, const char *pszParam)
{
    if (NULL == pszErrorText)
        return;

    if (pszParam)
        fprintf (stderr, "Error: %s: %s\n\n", pszErrorText, pszParam);
    else
        fprintf (stderr, "Error: %s\n\n", pszErrorText);
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
    fprintf (stderr, "\nSMTP Test Tool %s\n", VERSION);
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
    fprintf (stderr, "-to <email>            Recipient address\n");
    fprintf (stderr, "-subject <text>        Subject of message\n");
    fprintf (stderr, "-body <text>           Body of message\n");
    fprintf (stderr, "-file <filepath>       File send as body (specify '-' to write stdin to the UTF-8 formatted body)\n");
    fprintf (stderr, "-att <filepath>        Attachment to send (specify '-' for attaching stdin to a file)\n");
    fprintf (stderr, "-attname <filename>    File name for file to attach\n");
    fprintf (stderr, "-mailer <name>         Mailer Name\n");
    fprintf (stderr, "-NoTLS                 Disable TLS/SSL\n");
    fprintf (stderr, "-v                     Verbose logging\n");
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
    int     ret       = 0;
    size_t  readbytes = 0;

    if (g_pSSL)
    {
        ret = SSL_read_ex (g_pSSL, g_szBuffer, MAX_BUFFER_LEN, &readbytes);

        if (ret < 0)
            readbytes = ret;
    }
    else
    {
        readbytes = BIO_read (g_pBio, g_szBuffer, MAX_BUFFER_LEN);
    }

    if (readbytes < 0)
        *g_szBuffer = '\0';
    else
        *(g_szBuffer+readbytes) = '\0';

    if (g_Verbose)
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


int CheckCiphers()
{
    const char *pStr = NULL;
    int priority = 0;

    if (NULL == g_pSSL)
        return 0;

    while (priority < 1000)
    {
        pStr = SSL_get_cipher_list (g_pSSL, priority);
        if (NULL == pStr)
            break;

        if (g_Verbose > 1)
            printf ("%s\n", pStr);

        priority++;
    }

    return priority;
}


int CopyFromToBio (BIO *pBioIn, BIO *pBioOut)
{
    /* Returns 1 for success */

    int    ret    = 0;
    size_t writebytes = 0;
    size_t readbytes  = 0;

    if (NULL == pBioIn)
        return 0;

    if (NULL == pBioOut)
        return 0;

    while (1)
    {
        ret = BIO_read_ex (pBioIn, g_szBuffer, sizeof (g_szBuffer)-1, &readbytes);

        if (1 != ret)
        {
            break;
        }

        if (0 == readbytes)
            break;

        ret = BIO_write_ex (pBioOut, g_szBuffer, readbytes, &writebytes);

    } /* while */

    ret = 1;

    return ret;
}


size_t GetMxRecord (const char *pszDomain, size_t MaxBuffer, char *retpszBuffer, int *retpPriority)
{
    unsigned char Buffer[32000]  = {0};
    char   Result[1024]          = {0};
    int    Priority              = 0;
    int    LowestPriority        = 0;
    struct __res_state ResState  = {0};
    ns_msg nsMsg = {0};
    ns_rr  rr    = {0};
    
    int  ret      = 0;
    int  res_init = 0;

    size_t len    = 0;
    size_t count  = 0;
    size_t found  = 0;
    size_t i      = 0;

    if (MaxBuffer && retpszBuffer)
        *retpszBuffer = '\0';

    if (retpPriority)
        *retpPriority = 0;

    ret = res_ninit (&ResState);

    if (ret)
    {
        LogError ("error initializing resolver");
        goto Done;
    }

    res_init = 1;

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

    if (res_init)
        res_nclose (&ResState);

    return found;
}


int SendSmtpMessage (const char *pszHostname,
                     const char *pszMailer,
                     const char *pszSmtpServerAddress,
                     const char *pszFrom,
                     const char *pszSendTo,
                     const char *pszSubject,
                     const char *pszBody,
                     const char *pszBodyFile,
                     const char *pszAttachmenFilePath,
                     const char *pszAttachmentName,
                     bool bUseTLS,
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
    time_t tNow = time (NULL);

    const SSL_CIPHER *pSSLCipher = NULL;

    if (IsNullStr (pszHostname))
    {
        GetLocalHostname (szHostname, sizeof (szHostname));
        pszHostname = szHostname;
    }

    if (IsNullStr (pszSendTo))
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

    if (NULL == pszSmtpServerAddress)
    {
        pszDomain = strchr (pszSendTo, '@');

        if (pszDomain)
        {
            pszDomain++;
            CountMX = GetMxRecord (pszDomain, sizeof (szMX), szMX, &PriorityMX);

            if (CountMX)
            {
                printf ("SMTP Server: [%s] (MX: %d)\n", szMX, PriorityMX);
                pszSmtpServerAddress = szMX;
            }
        }
        else
        {
            pszSmtpServerAddress = szLocalHost;
        }
    }

    if (NULL == pszSmtpServerAddress)
    {
        LogError ("No SMTP server specified");
        goto Done;
    }

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

    printf ("Connection established ...\n");

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

        printf ("Starting TLS session ...\n");

        g_pCtxSSL = SSL_CTX_new (TLS_client_method());

        if (NULL == g_pCtxSSL)
        {
            LogError ("Cannot create SSL context");
            goto Quit;
        }

        g_pSSL = SSL_new (g_pCtxSSL);

        if (NULL == g_pSSL)
        {
            LogError ("No SSL connection allocated");
            goto Quit;
        }

        SSL_set_tlsext_host_name (g_pSSL, pszSmtpServerAddress);

        if (bECDSA)
            SSL_set1_sigalgs_list (g_pSSL, "ECDSA+SHA256");

        SSL_set_bio (g_pSSL, g_pBio, g_pBio);

        CipherCount = CheckCiphers ();

        printf ("Ciphers: %d\n", CipherCount);

        if (1 != SSL_connect (g_pSSL))
        {
            ERR_print_errors_fp (stderr);
            LogError ("Handshake failed");
            goto Quit;
        }

        printf ("Handshake Done\n");

        pSSLCipher = SSL_get_current_cipher (g_pSSL);

        if (pSSLCipher)
        {
            pStr = SSL_CIPHER_get_version (pSSLCipher);
            if (pStr)
                printf ("TLS Version: [%s]\n", pStr);

            pStr = SSL_CIPHER_get_name (pSSLCipher);
            if (pStr)
                printf ("TLS Cipher: [%s]\n", pStr);
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
        snprintf (g_szBuffer, sizeof (g_szBuffer), "From: %s%s", pszFrom, CRLF);
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

        if (NULL == pszAttachmentName)
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
            printf ("Cannot create memory BIO\n");
            goto Done;
        }

        pBioB64 = BIO_new (BIO_f_base64());

        if (NULL == pBioB64)
        {
            printf ("Cannot create Base64 BIO\n");
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
            printf ("Cannot read file: %s\n", pszAttachmenFilePath);
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

    printf ("Quit.\n");

    snprintf (g_szBuffer, sizeof (g_szBuffer), "QUIT%s", CRLF);
    SendBuffer (g_szBuffer);

Done:

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

    printf ("Cleanup Done.\n");

    return rc;
}


int main (int argc, const char *argv[])
{
    int rc  = 0;
    int ret = 1;
    int consumed = 1;

    const char szMailer[]            = "";
    const char szFrom[]              = "";
    const char szSendTo[]            = "";
    const char szSubject[]           = "";
    const char szBody[]              = "";

    const char *pszFrom              = szFrom;
    const char *pszSendTo            = szSendTo;
    const char *pszSubject           = szSubject;
    const char *pszBody              = szBody;
    const char *pszMailer            = szMailer;
    const char *pszHostname          = NULL;
    const char *pszBodyFile          = NULL;
    const char *pszSmtpServerAddress = NULL;
    const char *pszAttachmenFilePath = NULL;
    const char *pszAttachmenName     = NULL;

    bool bUseTLS = true;
    bool bECDSA  = false;
    bool bUTF8   = true;

    size_t FileSize = 0;

    while (argc > consumed)
    {
        if  ( (0 == strcasecmp (argv[consumed], "-help")) || (0 == strcasecmp (argv[consumed], "-h")) || (0 == strcasecmp (argv[consumed], "-?")) )
        {
            PrintHelpText(g_ProgramName);
            goto Done;
        }

        else if  ( (0 == strcasecmp (argv[consumed], "-version")) || (0 == strcasecmp (argv[consumed], "--version")) || (0 == strcasecmp (argv[consumed], "-ver")) )
        {
            PrintVersion();
            goto Done;
        }

        else if  (0 == strcasecmp (argv[consumed], "-notls"))
        {
            bUseTLS = false;
        }

        else if  (0 == strcasecmp (argv[consumed], "-ec"))
        {
            bECDSA = true;
        }

        else if  (0 == strcasecmp (argv[consumed], "-v"))
        {
            g_Verbose++;
        }

        else if  (0 == strcasecmp (argv[consumed], "-host"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszHostname = argv[consumed];
        }

        else if  (0 == strcasecmp (argv[consumed], "-server"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszSmtpServerAddress = argv[consumed];
        }

        else if  (0 == strcasecmp (argv[consumed], "-from"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszFrom = argv[consumed];
        }

        else if  (0 == strcasecmp (argv[consumed], "-to"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszSendTo = argv[consumed];
        }

        else if  (0 == strcasecmp (argv[consumed], "-subject"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszSubject = argv[consumed];
        }

        else if  (0 == strcasecmp (argv[consumed], "-body"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszBody = argv[consumed];
        }

        else if  (0 == strcasecmp (argv[consumed], "-mailer"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszMailer = argv[consumed];
        }

        else if  (0 == strcasecmp (argv[consumed], "-file"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;

            if (0 == strcmp (argv[consumed], "-"));
            else if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszBodyFile = argv[consumed];
        }

        else if  (0 == strcasecmp (argv[consumed], "-att"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;

            if (0 == strcmp (argv[consumed], "-"));
            else if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszAttachmenFilePath = argv[consumed];
        }

        else if  (0 == strcasecmp (argv[consumed], "-attname"))
        {
            consumed++;
            if (consumed >= argc)
                goto InvalidSyntax;
            if (argv[consumed][0] == '-')
                goto InvalidSyntax;

            pszAttachmenName = argv[consumed];
        }
        else
        {
            goto InvalidSyntax;
        }

        consumed++;
    } /* while */

    if (IsNullStr (pszSendTo))
    {
        LogError ("No recipient specified");
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

            if (FileSize > 50 * 1024 * 1024)
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
                          pszFrom, pszSendTo,
                          pszSubject,
                          pszBody,
                          pszBodyFile,
                          pszAttachmenFilePath,
                          pszAttachmenName,
                          bUseTLS,
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
