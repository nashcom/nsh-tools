
# Tutorial: Compile and Link C/C++ applications with OpenSSL on Linux and MacOS

To compile and link C/C++ applications with OpenSSL, you need a build environment.
Different Linux distributions require different packets to be installed.
This tutorial shows how to build OpenSSL applications on different platforms.
The easiest way to install multiple Linux instance is to use a container on Docker or Podman.

The following short writeup should help you to get started.
This doesn't mean you have to use a container in your environment.
But this is a good way to try out different environments.


# Prepare your development environment for C/C++ development with OpenSSL

The first step is always to install the C/C++ compiler.
For Linux this is always gcc/gcc++/g++. The name of the package might vary by distribution.
Also the name of the OpenSSL development environment might vary.

The development environment would bring the headers and libs to run with.
But this will result in a dynamically linked binary, which has OpenSSL dependencies.
This tutorial also shows you how to clone from GitHub and compile OpenSSL from scratch to get a more current version which also provides static link libs.


## Linking with OpenSSL statically

Linking OpenSSL statically can be specially interesting if you want to provide the resulting tool to be used on a different machine -- which might have an older OpenSSL version installed.
Relying on the OpenSSL version installed or shipping with the dynamically link libs cause challenges.

- If you leverage OpenSSL shipping with the platform the OpenSSL version might not fit
- Providing the files as separate `*.so` files will require the lib search part to find the right versions and not use the one shipping with Linux
- Statically linking also ensures nobody could sneak in a different version of OpenSSL

But on the other side it puts the burden of maintaining the OpenSSL version on the person compiling the application.

The application used in this tutorial is **nshmailx**. It comes with a makefile which will automatically detect what is available.
If you have the static link versions of OpenSSL available, it will link statically.
Else it uses the OpenSSL version installed on Linux and dynamically link.

OpenSSL is an essential component of each Linux distribution and each distribution is responsible for maintaining the OpenSSL version shipped.
Not all of them are using the latest version.
Compiling your own OpenSSL version brings you in full control and give you the option to fully control the OpenSSL version your application uses.


## MacOS OpenSSL or LibreSSL

The makefile of **nshmailx** also supports MacOS with two different options.

The default SSL implementation on MacOS is LibreSSL.

LibreSSL isn't the same as OpenSSL and it has been forked from OpenSSL quite a while ago.
For complex applications you can't expect them to work 1:1 without changes on LibreSSL.

**nshmailx** is a simple application, which uses basic OpenSSL API, which mostly also works on LibreSSL.
So it is a good candidate to show how to build with LibreSSL and OpenSSL.

The LibreSSL development environment also needs to be installed.
So cloning OpenSSL locally and building it on your Mac to statically link OpenSSL with your application, isn't a much bigger step.

This also allows you to use the full range of OpenSSL APIs and is potentially easier to maintain.
Still **nshmailx** supports both environments as a good tutorial how to implement a makefile which works in different environments.
And also to get hands on experience with LibreSSL vs. OpenSSL.


# Preparing a C/C++ development environment

The following section describes shortly different environments and the steps to take.
I have been using a container based approach to allow to switch between different Linux distributions and show the different steps to take in each distribution.

Docker/Podman containers are a good way to quickly setup and test a different distribution.
But the same steps will work on a native installed Linux instance.


## Ubuntu 22.04 LTS in a container

Ubuntu is one of the most common environments and it comes with it's own packet manager.
So instead of `yum` the Debian packet manager `apt` is used.
Some packages are named differently, which might be a bit confusing.

```
docker run -it --rm ubuntu

apt -y update
apt -y install git gcc++ make openssl libssl-dev
```


## CentOS Stream 9 in a container

CentOS Stream is a common used environment by many customers.
It is a free of charge Linux, which uses the `yum/dnf` stack for installing software.
This is very comparable to **Redhat** clones like **AlmaLinux** or **RockyLinux**.

```
docker run -it --rm quay.io/centos/centos:stream9

yum -y update
yum -y install git g++ make openssl openssl-devel perl

```


## Redhat UBI 9 Minimal in a container

Probably the best platform to build on is vanilla Redhat Enterprise Linux.
The Redhat UBI platform is the free Redhat Enterprise based platform.
It comes with different flavors of container images.
The full image provides a full yum/dnf stack.
The smaller minimum image also works well for development environments and has much less packet dependencies.
But it comes with a different packet manager **microdnf** which is very similar to operate then **yum/dnf**.

```
docker run -it --rm registry.access.redhat.com/ubi9/ubi-minimal

microdnf -y update
microdnf -y install git g++ make openssl openssl-devel perl
```


## MacOS

On MacOS there are two different options.
Either install the **libressl-devel** development environment using **Brew** or in my case **MacPorts**.
Or directly compile your own version of OpenSSL.

To compile applications you need a MacOS development environment.
Refer to the Apple Developer documentation for details.
Once you have it installed, a the steps are actually the same then on a Linux distribution.

Install LibreSSL development environment

```
port install libressl-devel
```


# Build OpenSSL 3.2.0 release

There are basically two options to compile and link applications:

- Use dynamically linked libs from the installed Linux OpenSSL development environment matching the Linux distribution's OpenSSL version
- Get statically link libraries to link OpenSSL directly into your application

If you just want to dynamically link, compiling OpenSSL from scratch can be skipped.
The makefile of **nshmailx** can consume either the dynamically link libs or the static libs as described before.

OpenSSL is available directly on GitHub, which is the place most Open Source software is maintained today.
There are multiple ways to consume a GutHub project. You could download and extract a tar. 
But if you are connected to the Internet directly, using the **git** client is the most natural way to work with GitHub projects.

The command used is **clone**, which creates a local instance of a project.
This could be just to consume the project or to make changes and commit them back to the project.


## Build steps

- Create a new local directory to clone all your repositories.
  I am always using `/local/github` for consistency on Linux.
  On MacOS you might want to use `github` under your home folder

- Clone the OpenSSL GitHub repository

- Switch to the tag which represents the released version you choose like OpenSSL 3.2.0 in this example

- Basic OpenSSL project configuration, which will define the makefile

- Finally compile the project

```
mkdir -p /local/github
cd /local/github

git clone https://github.com/openssl/openssl.git
cd openssl

git checkout openssl-3.2.0
./config
make
```


## Result of compile command

The result is a local new copy of OpenSSL, which is not installed on your Linux machine as the main OpenSSL version.
There is an optional `make install` step to install OpenSSL. But for development purposes the local OpenSSL version is exactly what is needed.
The makefile of **nshmailx** will detect and use the static link libs and include directory from building an application.


# Compiling nshmailx

Once everything is in place, the last test is to clone, compile and link the the actual application

```
cd /local/github
git clone https://github.com/nashcom/nsh-tools.git
cd nsh-tools/nshmailx
make
```


## Checking a resulting binary

The resulting binary will be in general a dynamically build binary.
This is the recommended way of building binaries. You could also completely statically like the binary.
But this would bundle all run-time environments into the application.

In this example only the OpenSSL run-time is statically linked.
You can checkout the result with the following commands.


### Linux

In this example the build platform was Ubuntu 22.04 LTS on an ARM machine.

```
ldd nshmailx

nshmailx

        linux-vdso.so.1 (0x0000ffffaeff6000)
        libresolv.so.2 => /lib/aarch64-linux-gnu/libresolv.so.2 (0x0000ffffaea20000)
        libc.so.6 => /lib/aarch64-linux-gnu/libc.so.6 (0x0000ffffae870000)
        /lib/ld-linux-aarch64.so.1 (0x0000ffffaefbd000)
```

### MacOS

```
otool -L nshmailx

nshmailx:
        /usr/lib/libresolv.9.dylib (compatibility version 1.0.0, current version 1.0.0)
        /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1336.61.1)
```


### Run the binary to check OpenSSL version used

**nshmailx** shows it compile and run-time OpenSSL version.
It's good practice to show the information when querying the application version.
OpenSSL provides API calls to provide this information.

In case the application would be build dynamically, the OpenSSL run-time and build version could differ.

```
./nshmailx --version

SMTP Test Tool 0.9.2
OpenSSL 3.2.0 23 Nov 2023
(Build on: OpenSSL 3.2.0 23 Nov 2023)
```
