
#ifndef TESTING_HEADER_HPP
#define TESTING_HEADER_HPP

char* GenerateLoremBuffer (size_t TargetLen);

int SendTestMessages(const char *pszHostname,
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
		     size_t Options,
                     size_t TestMessageCount,
                     size_t TestBodySize,
                     size_t TestAttSize);


#endif
