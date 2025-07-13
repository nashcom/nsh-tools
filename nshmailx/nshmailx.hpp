
#ifndef NSHMAILX_HEADER_HPP
#define NSHMAILX_HEADER_HPP


#define NSHMAILX_OPTIONS_NO_TLS            0x0001
#define NSHMAILX_OPTIONS_NO_TLS13          0x0002
#define NSHMAILX_OPTIONS_VERIFY            0x0004
#define NSHMAILX_OPTIONS_USE_ECDSA         0x0008
#define NSHMAILX_OPTIONS_NO_UTF8           0x0010


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
                     const char *pszAttachmentBuffer,
                     const char *pszCipherList,
                     int  Port,
                     size_t Options);


#endif
