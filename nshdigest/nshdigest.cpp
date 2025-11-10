
/* nshdigest.cpp: Test programm for SHA checksums via OpenSSL */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

size_t nsh_get_ostimer()
{
#ifdef _WIN32
    return (GetTickCount());

#else
    struct timeval t;
    struct timezone tp;

    gettimeofday (&t,&tp);
    return((t.tv_sec*1000)+(t.tv_usec/1000));

#endif
}

void PrintErrorOpenSSL (const char *pszErrorText)
{
    if (pszErrorText)
        fprintf (stderr, "Error: %s\n", pszErrorText);

    ERR_print_errors_fp (stderr);
}

size_t FileDigest (const char *pszEvpTypeMD, const EVP_MD *pEvpTypeMD, const char *pszInputFile, unsigned int MaxLen, char *retpszHash)
{
    size_t BytesRead   = 0;
    size_t BytesTotal  = 0;
    size_t MbSec       = 0;
    char   *p          = NULL;
    FILE   *fpInput    = NULL;

    EVP_MD_CTX *pMDCtx  = NULL;
    unsigned int md_len = 0;
    unsigned int i      = 0;
    unsigned char MdValue[EVP_MAX_MD_SIZE+1] = {0};
    unsigned char szBuffer [256000] = {0};

    size_t BeginTicks = 0;
    size_t EndTicks   = 0;
    size_t DiffTicks  = 0;

    if (NULL == retpszHash)
        return 0;

    *retpszHash = '\0';

    if (NULL == pszEvpTypeMD)
        return 0;

    if (NULL == pEvpTypeMD)
        return 0;

    if (NULL == pszInputFile)
        return 0;

    fpInput = fopen (pszInputFile, "rb");

    if (NULL == fpInput)
    {
        fprintf (stderr, "Cannot open file: %s\n", pszInputFile);
        goto Done;
    }

    BeginTicks = nsh_get_ostimer();

    pMDCtx = EVP_MD_CTX_new();

    if (!EVP_DigestInit_ex2 (pMDCtx, pEvpTypeMD, NULL))
    {
        PrintErrorOpenSSL ("Cannot init digest");
        goto Done;
    }

    while ((BytesRead = fread (szBuffer, 1, sizeof (szBuffer), fpInput)))
    {
        if (!EVP_DigestUpdate (pMDCtx, szBuffer, BytesRead))
        {
            PrintErrorOpenSSL ("Cannot update digest");
            goto Done;
        }

        BytesTotal += BytesRead;
    } /* while */

    if (!EVP_DigestFinal_ex (pMDCtx, MdValue, &md_len))
    {
        PrintErrorOpenSSL ("Cannot finalize digest");
        goto Done;
    }

    if (MaxLen < (md_len*2+1))
    {
        fprintf (stderr, "Buffer size: %u, Required size: %u\n", MaxLen, md_len*2+1);
        return 0;
    }

    p = retpszHash;

    for (i=0; i<md_len; i++)
    {
        snprintf (p, MaxLen, "%02x", MdValue[i]);
        p += 2;
    }

    EndTicks = nsh_get_ostimer();

    DiffTicks = EndTicks - BeginTicks;

    if (0 == DiffTicks)
        DiffTicks = 1;

    if (DiffTicks)
    {
        MbSec = (1000 * BytesTotal / DiffTicks) / 1048576;
        printf ("%6s, %4zu MB/sec, %6zu ms, Hash: %s\n", pszEvpTypeMD, MbSec, DiffTicks, retpszHash);
    }

Done:

    if (pMDCtx)
    {
        EVP_MD_CTX_free (pMDCtx);
        pMDCtx = NULL;
    }

    if (fpInput)
    {
        fclose (fpInput);
        fpInput = NULL;
    }

    return BytesTotal;
}

size_t TestDigest (const char* pszFileName)
{
    size_t FileSize = 0;
    char szHash[256] = {0};

    FileSize = FileDigest ("MD5",    EVP_md5(),    pszFileName, sizeof (szHash), szHash);
    FileSize = FileDigest ("SHA1",   EVP_sha1(),   pszFileName, sizeof (szHash), szHash);
    FileSize = FileDigest ("SHA256", EVP_sha256(), pszFileName, sizeof (szHash), szHash);
    FileSize = FileDigest ("SHA384", EVP_sha384(), pszFileName, sizeof (szHash), szHash);
    FileSize = FileDigest ("SHA512", EVP_sha512(), pszFileName, sizeof (szHash), szHash);

    return FileSize;
}

int main (int argc, char* argv[])
{
    if (argc < 2)
    {
        printf ("Usage: %s <file> \n", argv[0]);
        return 1;
    }

    if (TestDigest (argv[1]))
        return 0;
    else
        return 1;
}

