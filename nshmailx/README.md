
# nshmail -- Simple SMTP mail send tool


This application can be used to troubleshoot and test SMTP connections.  
The application is based on OpenSSL and also show how to

- STARTTLS connections via OpenSSL
- Send SMTP mail crafting the RFC821 and RFC822 part of a message
- Lookup MX records and pick the one with the lowest priority value
- Create a simple MIME encoded mail with a base64 encoded attachment


## Syntax


```
nshmailx 0.9.0
----------------
Usage: nshmailx [Options]

-server <FQDN/IP>      SMTP server DNS name or IP (Can be a relay host. By default MX record of the recipient's domain is used)
-host <FQDN>           Hostname to send in EHLO (by default use server's hostname)
-from <email>          From address
-to <email>            Recipient address
-subject <text>        Subject of message
-body <text>           Body of message
-file <filepath>       File send as body (specify '-' to write stdin to the UTF-8 formatted body)
-att <filepath>        Attachment to send (specify '-' for attaching stdin to a file)
-attname <filename>    File name for file to attach
-mailer <name>         Mailer Name
-NoTLS                 Disable TLS/SSL
-v                     Verbose logging
```

## Command Line Examples

### Send a simple mail

Mail with subject and body from command-line

```
./nshmailx -to nsh@acme.com -from nsh@acme.com -subject "Hello World ..." -body "This is a simple body text"
```

Mail with body from file /etc/os-release

```
./nshmailx -to nsh@acme.com -from nsh@acme.com -subject "Hello World ..." -file /etc/os-release
```


### Send a mail with stdin data attached to the mail

In this example the output of tar is packed into a file and named "notesdata.taz"

```
tar -cz /local/notesdata/*.ntf | ./nshmailx -to nsh@acme.com -from nsh@acme.com -subject "Notes Templates" -att - -attname notesdata.taz
```

## Compile this application

This application is mainly intended for Linux and provides a Linux makefile.  
The main reason is that Linux provides an easy way to install OpenSSL development tools (openssl-devel) fitting your Linux version.  
It has been tested with OpenSSL 3.0.x

Once the compiler and the OpenSSL development package is installed just run `make`.

