
# nshshutdown - NashCom Shutdown Helper

Shutdown helper for cleanly shutting down services when Windows is shutdown or rebooted.

## Background

When stopping Windows service manually, the Windows service control manager (SCM) waits sufficient time to always shutdown Domino cleanly.
But a Windows shutdown or reboot does not wait sufficient time for service termination.
This is critical because it would kill running applications without giving them the time to shutdown cleanly.

For more detail about the background behinds this behavior refer to Microsoft documentation [Service Control Handler Function](https://learn.microsoft.com/en-us/windows/win32/services/service-control-handler-function)
The summary is that a service would need to register and handle for `SERVICE_CONTROL_PRESHUTDOWN` events in addition to a service shutdown event to get notified ahead of shutdown/reboot.

Windows gives services a very short shutdown of a couple of seconds without this special implementation of new functionality added in Windows 2008/Vista the a service can't extend the shutdown delay properly.
There is an unreliable setting which can extend the time a bit by setting the `WaitToKillServiceTimeout` registry value. But even if working this would at most limit you to 125 seconds if you are lucky.

## Solution

Implement a service which supports Windows Pre-Shutdown events and let this service stop services cleanly.

- Register for re-shutdown events
- On a reboot or shutdown stop configured services before reporting back the pre-shutdown operations have been performed
- Wait for a maximum of 10 minutes and terminates as soon all configured services are stopped


## Compile this application

Compile using Visual Studio `nmake`
Also works with MigWin compiler via `gcc nshshutdown.cpp -o nshshutdown.exe`


## How to install

- Copy `nshshutdown.exe` to `C:\Windows`
- Invoke `nshshutdown.exe install`
- Configure your services to stop on Windows reboot/shutdown in `C:\Windows\nshshutdown.cfg`  
  Tip: Invoke `nshshutdown.exe cfg` to edit config file in Notepad

```
copy nshshutdown.exe  C:\Windows
nshshutdown.exe install
nshshutdown.exe cfg
```

## Short documentation

```

nshshutdown 0.9.0 - NashCom Shutdown Helper
Shutdown helper for cleanly shutting down services when Windows is shutdown or rebooted

status       Prints status of services
reboot       Initiates server reboot
shutdown     Initiates server shutdown
peshutdown   Invokes pre-shutdown operations manually
install      Installs program as a service
uninstall    Installs program service
start        Starts this service
stops        Stops this service
restart      Restarts this service

Specify Windows service name to pre-shutdown in service configuration file

Config file  : C:\Windows\nshshutdown.cfg
Log file     : C:\nshshutdown-service.log
Timeout(sec) : 600
```


## Implementation details

Implementing this functionality brings up a couple of interesting challenges, which are not well documented.
The following might be helpful if you implement your own service.

- It only works with registering and extended service control manager via [RegisterServiceCtrlHandlerEx()](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-registerservicectrlhandlerexa). Else the service is not called for pre-shutdown
- Use [LPHANDLER_FUNCTION_EX](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nc-winsvc-lphandler_function_ex) instead of the standard service handle.
- The service needs to properly handle the `SERVICE_CONTROL_PRESHUTDOWN` event

Once the event is received, the service stops services which are not pre-shutdown aware
In addition to accepting pre-shutdown you have to regularly tell Windows you are still shutting down via e.g. 
`ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 30*1000)` every couple of seconds seconds ( I am using 10 seconds).

