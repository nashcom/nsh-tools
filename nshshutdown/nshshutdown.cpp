#include <windows.h>
#include <time.h>
#include <stdio.h>

#define MAX_ERROR_TEXT           4096
#define MAX_SHUTDOWN_SERVICES     100

#define SERVICE_OPERATION_STATUS    0
#define SERVICE_OPERATION_STOP      1
#define SERVICE_OPERATION_START     2

#ifndef sizeofstring
#define sizeofstring(x) (sizeof(x) - 1)
#endif

#define MAX(A, B) ((A) > (B) ? (A) : (B))
#define MIN(A, B) ((A) < (B) ? (A) : (B))

// Global variables
SERVICE_STATUS g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = nullptr;
HANDLE g_ServiceStopEvent = nullptr;

char g_szVersion[] = "0.9.1";
char g_szServiceName[]         = "nshshutdown";
char g_szServiceDisplayName[]  = "NashCom Shutdown Helper";
char g_szServiceDirectory[]    = "C:";
char g_szServiceDescription[]  = "Shutdown helper for cleanly shutting down services when Windows is shutdown or rebooted";
char g_szConfigFile[]          = "C:\\Windows\\nshshutdown.cfg";
char g_szServiceReboot[]       = "Nash!Com Service Reboot";
char g_szServiceShutdown[]     = "Nash!Com Service Shutdown";

char g_szLogFilename[4096] = {0};
char g_szShutdownServiceNames[MAX_SHUTDOWN_SERVICES+1][MAX_PATH+1] = {0};

char g_ConfigSectionTag[]   = "[Config]";
char g_ServicesSectionTag[] = "[Services]";

char g_CfgLogFileTag[] = "logfile=";
char g_CfgTimeoutTag[] = "timeout=";

DWORD g_dwShutdownServiceStatus[MAX_SHUTDOWN_SERVICES+1] = {0};

BOOL   g_bPreShutdownPending = FALSE;
BOOL   g_bInteractiveMode    = FALSE;
DWORD  g_dwGraceTime         = 600; // Maximum 10 minutes
size_t g_CountShutdownServiceNames = 0;

// Function prototypes

void WINAPI ServiceMain(DWORD argc, LPTSTR *argv);

void ReportServiceStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint);
void InstallService();
void UninstallService();
void StartService();
void LogMessage(const char* pszMessage);
void TraceWinErrorMessage(const char* pszMessage);
bool IsNullStr(const char* pszStr);
void PrintWindowsError(const char* pszMessage);
void WriteDefaultConfigFile();
BOOL WaitForServiceToStop (const char *pszServiceName, DWORD dwTimeoutSeconds);
BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
BOOL ServiceCommand(const char* pszService, DWORD Operation, DWORD dwWaitSeconds, DWORD *retpdwServiceStatus);
BOOL ChangeCurrentServiceConfig(const char* pszService, DWORD dwPreshutdownTimeout);
BOOL DumpFile(const char *pszFilename);
BOOL ClearLog();
DWORD StartServices(DWORD dwSeconds);

size_t ReadConfig();
size_t ReadShutdownServiceNames(const char* pszServiceName, const char* pszFilename);
size_t ShutdownCheckServices(DWORD dwOperation, DWORD dwSeconds, BOOL bVerbose);
size_t StartShutdownRegisteredServices(DWORD dwSeconds);

void PrintHeader(const char *pszMessage)
{
    size_t len = 0;
    char  szDashes[MAX_ERROR_TEXT+1] = {0};

    if (NULL == pszMessage)
        return;

    printf ("\n%s\n", pszMessage);

    len = MIN (strlen (pszMessage), MAX_ERROR_TEXT);

    memset (szDashes, '-', len);
    printf ("%s\n\n", szDashes);
}

void PrintConfig()
{
    char szMessage[MAX_ERROR_TEXT+1] = {0};

    snprintf(szMessage, sizeofstring(szMessage), "%s - Configuration", g_szServiceName);
    PrintHeader (szMessage);

    printf ("Config file  : %s\n", g_szConfigFile);
    printf ("Log file     : %s\n", g_szLogFilename);
    printf ("Timeout(sec) : %u\n", g_dwGraceTime);
    printf ("\n");
}

void CheckStatus()
{
    BOOL   bSuccess       = FALSE;
    DWORD  dwServiceState = 0;

    bSuccess = ServiceCommand(g_szServiceName, SERVICE_OPERATION_STATUS, 0, &dwServiceState);
    printf ("\n");

    if (FALSE == bSuccess)
        printf ("[%s] service is not installed\n", g_szServiceName);
    else if (SERVICE_STOPPED == dwServiceState)
        printf ("[%s] service is stopped\n", g_szServiceName);
    else if (SERVICE_RUNNING == dwServiceState)
        printf ("[%s] service is running\n", g_szServiceName);
    else
        printf ("[%s] service is unknown\n", g_szServiceName);

    printf ("\n");

    PrintHeader ("Windows Services");

    ReadShutdownServiceNames(NULL, g_szConfigFile);
    printf ("\nServices running: %zu\n\n", ShutdownCheckServices (SERVICE_OPERATION_STATUS, 0, TRUE));
}

void PrintHelp()
{
    printf ("\n%s V%s - %s\n%s\n\n", g_szServiceName, g_szVersion, g_szServiceDisplayName, g_szServiceDescription);

    printf ("status       Prints status of services and configuration\n");
    printf ("version      Prints version and exits\n");
    printf ("start        Starts this service\n");
    printf ("stop         Stops this service\n");
    printf ("restart      Restarts this service\n");
    printf ("install      Installs program as a Windows service\n");
    printf ("uninstall    Uninstalls Windows service\n");
    printf ("peshutdown   Invokes pre-shutdown operations manually\n");
    printf ("startall     Start all pre-shutdown configured services\n");
    printf ("reboot       Initiates server reboot\n");
    printf ("shutdown     Initiates server shutdown\n");
    printf ("\n");
    printf ("cfg          Opens configuration in notepad\n");
    printf ("log          Dump log file\n");
    printf ("clear        Clear logfile\n");

    printf ("\n");
    printf ("Specify Windows service name to pre-shutdown in config file section %s\n", g_ServicesSectionTag);
    printf ("\n");

    PrintConfig();
}

void NotepadConfigFile()
{
    char szCommand[MAX_PATH+1] = {0};

    printf ("\nPlease edit the config file opened in Notepad!\n\n");
    snprintf(szCommand, sizeofstring(szCommand), "notepad \"%s\"", g_szConfigFile);
    system (szCommand);
    PrintConfig();
    CheckStatus();
}


int main(int argc, char *argv[])
{
    BOOL  bSuccess       = FALSE;
    DWORD dwServiceState = 0;
    DWORD dwGraceTime    = g_dwGraceTime;

    snprintf(g_szLogFilename, sizeof(g_szLogFilename), "%s%s%s%s", g_szServiceDirectory, "\\", g_szServiceName, "-service.log");

    ReadConfig();

    if (argc > 1)
    {
        if (strcmp(argv[1], "install") == 0)
        {
            InstallService();
            WriteDefaultConfigFile();
            StartService();
        }

        else if (strcmp(argv[1], "cfg") == 0)
        {
            NotepadConfigFile();
        }

        else if (strcmp(argv[1], "log") == 0)
        {
            DumpFile(g_szLogFilename);
        }

        else if (strcmp(argv[1], "clear") == 0)
        {
            ClearLog();
        }

        else if (strcmp(argv[1], "uninstall") == 0)
        {
            UninstallService();
        }

        else if (strcmp(argv[1], "start") == 0)
        {
            StartService();
        }

        else if (strcmp(argv[1], "stop") == 0)
        {
            ServiceCommand(g_szServiceName, SERVICE_OPERATION_STOP, 30, NULL);
        }

        else if (strcmp(argv[1], "restart") == 0)
        {
            ServiceCommand(g_szServiceName, SERVICE_OPERATION_STOP, 30, NULL);
            StartService();
        }

        else if (strcmp(argv[1], "abort") == 0)
        {
            SetPrivilege(SE_SHUTDOWN_NAME, TRUE);
            bSuccess = AbortSystemShutdown(NULL);

            if (bSuccess)
            {
                printf ("Shutdown aborted");
            }
            else
            {
                PrintWindowsError ("Cannot abort shutdown");
            }
        }

        else if (strcmp(argv[1], "reboot") == 0)
        {
            if (argc > 2)
            {
                dwGraceTime = atoi (argv[2]);
            }

            SetPrivilege(SE_SHUTDOWN_NAME, TRUE);
            bSuccess = InitiateSystemShutdownEx(NULL, g_szServiceReboot, dwGraceTime, TRUE, TRUE, SHTDN_REASON_MINOR_INSTALLATION);

            if (bSuccess)
            {
                printf ("Shutdown initiated");
            }
            else
            {
                PrintWindowsError ("Cannot initiate shutdown");
            }
        }

        else if (strcmp(argv[1], "shutdown") == 0)
        {
            if (argc > 2)
            {
                dwGraceTime = atoi (argv[2]);
            }

            SetPrivilege(SE_SHUTDOWN_NAME, TRUE);
            bSuccess = InitiateSystemShutdownEx(NULL, g_szServiceShutdown, dwGraceTime, TRUE, FALSE, SHTDN_REASON_MINOR_INSTALLATION);

            if (bSuccess)
            {
                printf ("Shutdown initiated");
            }
            else
            {
                PrintWindowsError ("Cannot initiate shutdown");
            }
        }

        else if (strcmp(argv[1], "preshutdown") == 0)
        {
            g_bInteractiveMode = TRUE;

            if (argc > 2)
            {
                dwGraceTime = atoi (argv[2]);
            }

            WaitForServiceToStop (NULL, dwGraceTime);
        }

        else if (strcmp(argv[1], "startall") == 0)
        {
            g_bInteractiveMode = TRUE;

            StartServices(60);
        }

        else if (strcmp(argv[1], "status") == 0)
        {
            g_bInteractiveMode = TRUE;
            CheckStatus();
        }

        else if ((strcmp(argv[1], "help") == 0) || (strcmp(argv[1], "-?") == 0))
        {
            PrintHelp();
        }

        else if ((strcmp(argv[1], "version") == 0) || (strcmp(argv[1], "-version") == 0))
        {
            printf ("%s\n", g_szVersion);
            return 0;
        }

        else
        {
            printf("Invalid argument: %s - Try 'help' command\n", argv[1]);
            return 1;
        }
    }
    else
    {
        // Make sure the shutdown Grace period is set
        ChangeCurrentServiceConfig (g_szServiceName, g_dwGraceTime*1000);

        SERVICE_TABLE_ENTRY ServiceTable[] =
        {
            {(LPSTR)g_szServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
            {nullptr, nullptr}
        };

        if (!StartServiceCtrlDispatcher(ServiceTable))
        {
            TraceWinErrorMessage("StartServiceCtrlDispatcher failed");
        }
    }

    return 0;
}



DWORD StartServices(DWORD dwSeconds)
{
    DWORD dwServiceCount    = 0;
    DWORD dwServicesRunning = 0;

    dwServiceCount    = ReadShutdownServiceNames(NULL, g_szConfigFile);
    dwServicesRunning = StartShutdownRegisteredServices (dwSeconds);

    return dwServicesRunning;
}

BOOL WaitForServiceToStop (const char *pszServiceName, DWORD dwTimeoutSeconds)
{
    DWORD dwSeconds = 0;
    DWORD dwServicesRunning = 0;
    DWORD dwServiceCount    = 0;
    char szMessage[MAX_ERROR_TEXT+1] = {0};

    dwServiceCount = ReadShutdownServiceNames(pszServiceName, g_szConfigFile);

    snprintf(szMessage, sizeofstring(szMessage), "Services registered for shutdown: %u", dwServiceCount);
    LogMessage(szMessage);

    if (0 == dwServiceCount)
    {
        LogMessage("No pre-shutdown registered service is running");
        return TRUE;
    }

    dwServicesRunning = ShutdownCheckServices (SERVICE_OPERATION_STOP, dwSeconds, FALSE);

    if (0 == dwServicesRunning)
    {
        LogMessage("All pre-shutdown registered services stopped");
        return TRUE;
    }

    snprintf(szMessage, sizeofstring(szMessage), "Waiting for %u seconds to stop %u service%s", dwTimeoutSeconds, dwServicesRunning, 1 == dwServicesRunning ? "" : "s");
    LogMessage(szMessage);

    while (dwSeconds < dwTimeoutSeconds)
    {
        Sleep (1000);
        dwSeconds++;

        dwServicesRunning = ShutdownCheckServices (SERVICE_OPERATION_STATUS, dwSeconds, FALSE);

        if (0 == dwServicesRunning)
        {
            LogMessage("All pre-shutdown registered services shutdown");
            return TRUE;
        }

        if (0 == (dwSeconds %10))
        {
            snprintf(szMessage, sizeofstring(szMessage), "Waited for %u seconds (services still running: %u)", dwSeconds, dwServicesRunning);
            LogMessage(szMessage);

            if (g_bPreShutdownPending)
            {
                // Signal we are still waiting for services to stop
                ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 30*1000);
            }
        }
    }

    snprintf(szMessage, sizeofstring(szMessage), "Successfully waited for %u seconds", dwTimeoutSeconds);
    LogMessage(szMessage);

    return TRUE;
}


DWORD WINAPI ServiceControlHandler(DWORD dwCtrlCode, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext)
{
    switch (dwCtrlCode)
    {
        case SERVICE_CONTROL_STOP:
            LogMessage("SERVICE_CONTROL_STOP received");
            ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 30*1000);
            SetEvent(g_ServiceStopEvent);
            break;

        case SERVICE_CONTROL_PRESHUTDOWN:
        {
            LogMessage("SERVICE_CONTROL_PRESHUTDOWN received");

            g_bPreShutdownPending = TRUE;
            WaitForServiceToStop (NULL, g_dwGraceTime);
            ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 30*1000);
            SetEvent(g_ServiceStopEvent);
            break;
        }
        default:
            break;
    }

    return 0;
}


void WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{

    if (argc)
    {
    }

    if (argv)
    {
    }

    /* Note: Extended handler is required for SERVICE_ACCEPT_PRESHUTDOWN */
    g_StatusHandle = RegisterServiceCtrlHandlerEx(g_szServiceName, ServiceControlHandler, NULL);

    if (!g_StatusHandle)
    {
        TraceWinErrorMessage ("Cannot register service handler");
        return;
    }

    // Set the service status to start pending
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PRESHUTDOWN;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;

    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    // Create an event to signal service stop
    g_ServiceStopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!g_ServiceStopEvent)
    {
        ReportServiceStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    // Set the service status to running
    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

    // Service loop: wait for the stop event
    while (WaitForSingleObject(g_ServiceStopEvent, INFINITE) != WAIT_OBJECT_0)
    {
        // Handle events or work here
    }

    // Perform cleanup
    CloseHandle(g_ServiceStopEvent);

    // Set the service status to stopped
    ReportServiceStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

void ReportServiceStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint)
{
    static DWORD dwCheckPoint = 1;

    g_ServiceStatus.dwCurrentState = dwCurrentState;
    g_ServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
    g_ServiceStatus.dwWaitHint = dwWaitHint;

    if (dwCurrentState == SERVICE_RUNNING || dwCurrentState == SERVICE_STOPPED)
    {
        g_ServiceStatus.dwCheckPoint = 0;
    }
    else
    {
        g_ServiceStatus.dwCheckPoint = dwCheckPoint++;
    }

    if (!SetServiceStatus(g_StatusHandle, &g_ServiceStatus))
    {
        TraceWinErrorMessage("SetServiceStatus failed");
    }
}

void InstallService()
{
    TCHAR szUnquotedPath[MAX_PATH + 1] = {0};
    TCHAR szPath[MAX_PATH + 1]         = {0};

    SERVICE_DESCRIPTION description = { g_szServiceDescription };

    /* Use native function to register service. The current process has no process handle to pass and function needs no interface */
    if (0 == GetModuleFileName(NULL, szUnquotedPath, sizeofstring(szUnquotedPath)))
    {
        PrintWindowsError("Cannot get file name for binary");
        return;
    }

    snprintf(szPath, sizeofstring(szPath), "\"%s\"", szUnquotedPath);

    SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scManager)
    {
        PrintWindowsError("OpenSCManager failed");
        return;
    }

    SC_HANDLE scService = CreateService(
        scManager,
        g_szServiceName,
        g_szServiceDisplayName,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        szPath,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr
    );

    if (!scService)
    {
        PrintWindowsError("CreateService failed");
        CloseServiceHandle(scManager);
        return;
    }

    ChangeServiceConfig2(scService, SERVICE_CONFIG_DESCRIPTION, &description);
    ChangeCurrentServiceConfig (g_szServiceName, g_dwGraceTime*1000);

    printf("Service installed successfully: %s\n", szPath);
    LogMessage ("Service installed");

    CloseServiceHandle(scService);
    CloseServiceHandle(scManager);
}

void UninstallService()
{
    SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scManager)
    {
        PrintWindowsError("OpenSCManager failed");
        return;
    }

    SC_HANDLE scService = OpenService(scManager, g_szServiceName, SERVICE_STOP | DELETE);
    if (!scService)
    {
        PrintWindowsError("OpenService failed");
        CloseServiceHandle(scManager);
        return;
    }

    if (!DeleteService(scService))
    {
        PrintWindowsError("DeleteService failed");
    }
    else
    {
        printf("Service uninstalled successfully.\n");
        LogMessage ("Service uninstalled");
    }

    CloseServiceHandle(scService);
    CloseServiceHandle(scManager);
}

void StartService()
{
    SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager)
    {
        PrintWindowsError("OpenSCManager failed");
        return;
    }

    SC_HANDLE scService = OpenService(scManager, g_szServiceName, SERVICE_START);
    if (!scService)
    {
        PrintWindowsError("OpenService failed");
        CloseServiceHandle(scManager);
        return;
    }

    if (!StartService(scService, 0, nullptr))
    {
        PrintWindowsError("StartService failed");
    }
    else
    {
        printf("Service started successfully.\n");
        LogMessage ("Service started");
    }

    CloseServiceHandle(scService);
    CloseServiceHandle(scManager);
}


void LogMessage(const char* pszMessage)
{
    time_t timer     = {0};
    FILE*  fp = NULL;
    struct tm* pTmInfo = NULL;
    char   szBuffer[4096] = {0};

    if (NULL == pszMessage)
        return;

    if (g_bInteractiveMode)
    {
        printf ("%s\n", pszMessage);
        return;
    }

    fp = fopen(g_szLogFilename, "a");

    if (NULL == fp)
    {
        goto Done;
    }

    timer = time(NULL);
    pTmInfo = localtime(&timer);

    if (pTmInfo)
        strftime(szBuffer, sizeof(szBuffer), "%Y.%m.%d %H:%M:%S", pTmInfo);

    fprintf(fp, "[%08x] %s: %s\n", GetCurrentProcessId(), szBuffer, pszMessage);
    fflush(fp);

Done:

    if (fp)
    {
        fclose(fp);
        fp = NULL;
    }
}


void TraceWinErrorMessage(const char* pszMessage)
{
    DWORD dwWinError = GetLastError();
    char szWinError[MAX_ERROR_TEXT+1]       = {0};
    char szErrorMessage[MAX_ERROR_TEXT*2+1] = {0};

    if (0 == FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwWinError, 0, szWinError, sizeofstring(szWinError), NULL))
        *szWinError = '\0';

    if (IsNullStr (pszMessage))
    {
        snprintf(szErrorMessage, sizeofstring(szErrorMessage), "WindowsError: %s", szWinError);
    }
    else
    {
        snprintf(szErrorMessage, sizeofstring(szErrorMessage), "%s: %s", pszMessage, szWinError);
    }

    LogMessage(szErrorMessage);
}

void PrintWindowsError(const char* pszMessage)
{
    DWORD dwWinError = GetLastError();
    char szWinError[MAX_ERROR_TEXT+1] = {0};

    if (0 == FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, dwWinError, 0, szWinError, sizeof(szWinError)-1, NULL))
        *szWinError = '\0';

    if (IsNullStr (pszMessage))
    {
        printf("WindowsError: %s", szWinError);
    }
    else
    {
        printf("%s: %s", pszMessage, szWinError);
    }
}


bool IsNullStr(const char* pszStr)
{
    if (NULL == pszStr)
        return true;

    if ('\0' == *pszStr)
        return true;

    return false;
}


// Helper function to enable or disable a privilege on the current process token
BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    // Open the process token with required access rights
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        PrintWindowsError ("Cannot adjust token");
        return FALSE;
    }

    // Lookup the LUID for the privilege
    if (!LookupPrivilegeValue(nullptr, lpszPrivilege, &luid))
    {
        PrintWindowsError ("Cannot lookup privilege value");
        CloseHandle(hToken);
        return FALSE;
    }

    // Set up the TOKEN_PRIVILEGES structure
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

    // Adjust the token's privileges
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
    {
        PrintWindowsError ("Cannot AdjustTokenPrivileges");
        CloseHandle(hToken);
        return FALSE;
    }

    return TRUE;
}


BOOL ServiceCommand(const char* pszService, DWORD dwOperation, DWORD dwWaitSeconds, DWORD *retpdwServiceStatus)
{
    DWORD dwBufSize       = 0;
    DWORD dwBufNeed       = 0;
    DWORD dwDesiredState  = 0;
    BOOL  bResult         = FALSE;
    BOOL  bServiceRunning = FALSE;
    BOOL  bStatus         = FALSE;
    char  szStatus[1024]  = {0};

    SC_HANDLE hSCM      = NULL;
    SC_HANDLE hService  = NULL;

    SERVICE_STATUS_PROCESS   ServiceStatusProcess = { 0 };
    LPQUERY_SERVICE_CONFIGA  pServiceConfig = NULL;
    LPSERVICE_STATUS_PROCESS pServiceStatus = NULL;

    if (retpdwServiceStatus)
        *retpdwServiceStatus = 0;

    if (IsNullStr(pszService))
        return FALSE;

    hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (NULL == hSCM)
    {
        PrintWindowsError("Cannot open Service Manager");
        goto Done;
    }

    hService = OpenService(hSCM, pszService, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START);
    if (NULL == hService)
    {
        // PrintWindowsError("Cannot open service");
        goto Done;
    }

    bResult = QueryServiceConfig(hService, NULL, 0, &dwBufNeed);

    /* Only check if a buffer size was returned. The function weirdly still returns the buffer is too small (ERROR_INSUFFICIENT_BUFFER) when querying for buffer size needed */
    if (dwBufNeed == 0)
    {
        PrintWindowsError("Cannot query windows service");
        goto Done;
    }

    dwBufSize = dwBufNeed + 0x10;
    pServiceConfig = (LPQUERY_SERVICE_CONFIGA)calloc(1, dwBufSize + 1);

    bResult = QueryServiceConfig(hService, pServiceConfig, dwBufSize, &dwBufNeed);
    if (!bResult)
    {
        PrintWindowsError("Cannot query service config");
        goto Done;
    }

    bResult = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)pServiceStatus, 0, &dwBufNeed);

    /* Only check if a buffer size was returned. The function weirdly still returns the buffer is too small (ERROR_INSUFFICIENT_BUFFER) when querying for buffer size needed */
    if (dwBufNeed == 0)
    {
        PrintWindowsError("Cannot query service status");
        goto Done;
    }

    dwBufSize = dwBufNeed + 0x10;
    pServiceStatus = (LPSERVICE_STATUS_PROCESS)calloc(1, dwBufSize + 1);

    bResult = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)pServiceStatus, dwBufSize, &dwBufNeed);
    if (!bResult)
    {
        PrintWindowsError("Cannot query service status");
        goto Done;
    }

    if (retpdwServiceStatus)
        *retpdwServiceStatus = pServiceStatus->dwCurrentState;

    /* Check for service status */
    if (SERVICE_OPERATION_STATUS == dwOperation)
    {
        bStatus = TRUE;

        switch (pServiceStatus->dwCurrentState)
        {
        case SERVICE_STOPPED:
            snprintf(szStatus, sizeofstring(szStatus), "stopped");
            bServiceRunning = FALSE;
            break;

        case SERVICE_RUNNING:
            snprintf(szStatus, sizeofstring(szStatus), "running");
            bServiceRunning = TRUE;
            break;

        case SERVICE_START_PENDING:
            snprintf(szStatus, sizeofstring(szStatus), "start_pending");
            bServiceRunning = TRUE;
            break;

        case SERVICE_STOP_PENDING:
            snprintf(szStatus, sizeofstring(szStatus), "stop_pending");
            bServiceRunning = TRUE;
            break;

        case SERVICE_CONTINUE_PENDING:
            snprintf(szStatus, sizeofstring(szStatus), "continue_pending");
            bServiceRunning = TRUE;
            break;

        case SERVICE_PAUSE_PENDING:
            snprintf(szStatus, sizeofstring(szStatus), "pause_pending");
            bServiceRunning = TRUE;
            break;

        case SERVICE_PAUSED:
            snprintf(szStatus, sizeofstring(szStatus), "pause");
            bServiceRunning = TRUE;
            break;

        default:
            snprintf(szStatus, sizeofstring(szStatus), "status: %u", pServiceStatus->dwCurrentState);
            bServiceRunning = TRUE;
            break;

        } /* switch */

        goto Done;
    }
    else if (SERVICE_OPERATION_START == dwOperation)
    {
        switch (pServiceStatus->dwCurrentState)
        {
        case SERVICE_RUNNING:
            printf("Service already running: [%s]\n", pszService);
            bStatus = TRUE;
            goto Done;

        case SERVICE_START_PENDING:
            printf("Service start is pending: [%s]\n", pszService);
            dwDesiredState = SERVICE_RUNNING;
            goto WaitForStatus;

        } /* switch */

        dwDesiredState = SERVICE_RUNNING;

        bResult = StartService(hService, 0, NULL);

        printf("Starting Service [%s]\n", pszService);
        if (!bResult)
        {
            PrintWindowsError("Cannot initiate start of service");
            goto Done;
        }
    }

    else if (SERVICE_OPERATION_STOP == dwOperation)
    {
        switch (pServiceStatus->dwCurrentState)
        {
        case SERVICE_STOPPED:
            printf("Service already stopped: [%s]\n", pszService);
            bStatus = TRUE;
            goto Done;

        case SERVICE_STOP_PENDING:
            printf("Service stop is pending: [%s]\n", pszService);
            dwDesiredState = SERVICE_STOPPED;
            goto WaitForStatus;

        } /* switch */

        dwDesiredState = SERVICE_STOPPED;

        bResult = ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ServiceStatusProcess);
        if (!bResult)
        {
            PrintWindowsError("Cannot initiate service shutdown");
            goto Done;
        }

        printf("Stopping Service [%s]\n", pszService);
    }
    else
    {
        PrintWindowsError ("Invalid Service operation");
        goto Done;
    }

WaitForStatus:

    /* Don't wait for status if no interval specified */
    if (0 == dwWaitSeconds)
    {
        bStatus = TRUE;
        goto Done;
    }

    bStatus = FALSE;

    while (dwDesiredState != pServiceStatus->dwCurrentState)
    {
        if (dwWaitSeconds <= 0)
        {
            PrintWindowsError ("Shutdown wait time reached -- Can't wait any more");
            goto Done;
        }

        Sleep(1000);

        bResult = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)pServiceStatus, dwBufSize, &dwBufNeed);
        if (!bResult)
        {
            PrintWindowsError("Cannot query service status");
            goto Done;
        }

        dwWaitSeconds--;
    } /* while */

    bStatus = TRUE;

Done:

    if (pServiceStatus)
    {
        free(pServiceStatus);
        pServiceStatus = NULL;
    }

    if (pServiceConfig)
    {
        free(pServiceConfig);
        pServiceConfig = NULL;
    }

    if (hService)
    {
        CloseServiceHandle(hService);
        hService = NULL;
    }

    if (hSCM)
    {
        CloseServiceHandle(hSCM);
        hSCM = NULL;
    }

    return bStatus;
}


BOOL ChangeCurrentServiceConfig(const char* pszService, DWORD dwPreshutdownTimeout)
{
    SC_HANDLE   hSCM     = NULL;
    SC_HANDLE   hService = NULL;
    BOOL        bSuccess = FALSE;
    DWORD       dwBytesNeeded = 0;

    char szMessage[MAX_ERROR_TEXT] = {0};
    SERVICE_PRESHUTDOWN_INFO ServicePreshutdownInfo = {0};

    if (IsNullStr(pszService))
        return false;

    hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (NULL == hSCM)
    {
        PrintWindowsError("Cannot open Service Manager");
        goto Done;
    }

    hService = OpenService(hSCM, pszService, SERVICE_ALL_ACCESS);
    if (NULL == hService)
    {
        PrintWindowsError("Cannot open service");
        goto Done;
    }

    /* Ensure the service has at least the specified pre shutdown timeout configured */

    bSuccess = QueryServiceConfig2 (hService, SERVICE_CONFIG_PRESHUTDOWN_INFO, (LPBYTE) &ServicePreshutdownInfo, (DWORD) sizeof (ServicePreshutdownInfo), &dwBytesNeeded);

    if (bSuccess && (ServicePreshutdownInfo.dwPreshutdownTimeout >= dwPreshutdownTimeout))
    {
        /* Timeout already sufficient */
    }
    else
    {
        ServicePreshutdownInfo.dwPreshutdownTimeout = dwPreshutdownTimeout;

        bSuccess = ChangeServiceConfig2 (hService, SERVICE_CONFIG_PRESHUTDOWN_INFO, &ServicePreshutdownInfo);

        if (bSuccess)
        {
            snprintf(szMessage, sizeofstring(szMessage), "Changed Windows service pre-shutdown timeout to %u seconds", ServicePreshutdownInfo.dwPreshutdownTimeout / 1000);
            LogMessage(szMessage);
        }
        else
        {
            TraceWinErrorMessage ("Cannot change Windows service configuration to a higher pre-shutdown timeout");
        }
    }

Done:

    if (hService)
    {
        CloseServiceHandle(hService);
        hService = NULL;
    }

    if (hSCM)
    {
        CloseServiceHandle(hSCM);
        hSCM = NULL;
    }

    return bSuccess;
}


BOOL ClearLog()
{
    FILE*  fp = NULL;

    fp = fopen(g_szLogFilename, "r");

    if (NULL == fp)
    {
        return FALSE;
    }

    fclose(fp);
    fp = NULL;

    remove (g_szLogFilename);

    LogMessage ("Log file cleared");

    return TRUE;
}

void WriteDefaultConfigFile()
{
    FILE*  fp = NULL;

    /* Check if config file already exists */
    fp = fopen(g_szConfigFile, "r");

    if (fp)
    {
        goto Done;
    }

    fp = fopen(g_szConfigFile, "w");

    if (NULL == fp)
    {
        goto Done;
    }

    fprintf(fp, "%s\n\n", g_ConfigSectionTag);
    fprintf(fp, "%s\n\n", g_ServicesSectionTag);
    fflush(fp);

Done:

    if (fp)
    {
        fclose(fp);
        fp = NULL;
    }
}

BOOL DumpFile(const char *pszFilename)
{
    char   szBuffer[4096] = {0};

    FILE*  fp  = NULL;
    size_t len = 0;

    if (IsNullStr(pszFilename))
        return FALSE;

    PrintHeader(pszFilename);

    fp = fopen(pszFilename, "r");

    if (NULL == fp)
    {
        printf ("\nLog File not found: %s\n\n", pszFilename);
        return FALSE;
    }

    while (fgets(szBuffer, sizeofstring(szBuffer), fp))
    {
        printf ("%s", szBuffer);
    } // while

Done:

    if (fp)
    {
        fclose(fp);
        fp = NULL;
    }

    return TRUE;
}


size_t GetParam (const char *pszBuffer, const char *pszTag, size_t RetParamSize, char *retpszParam)
{
    const char *pszConfig = NULL;

    if (IsNullStr(pszBuffer))
        return 0;

    if (IsNullStr(pszTag))
        return 0;

    if (0 == RetParamSize)
        return 0;

    if (NULL == retpszParam)
        return 0;

    pszConfig = strstr (pszBuffer, pszTag);

    if (pszConfig != pszBuffer)
        return 0;

    snprintf (retpszParam, RetParamSize, "%s", pszBuffer + strlen (pszTag));

    return strlen (retpszParam);
}


size_t ReadConfig()
{
    BOOL   bSuccess = FALSE;
    char   szBuffer[4096] = {0};
    char   szMessage[MAX_ERROR_TEXT] = {0};
    char   szParam[1024] = {0};
    FILE*  fp  = NULL;
    size_t len = 0;
    size_t CountInvalidParam = 0;

    BOOL bConfigSection  = FALSE;
    BOOL bServiceSection = FALSE;

    if (IsNullStr(g_szConfigFile))
        goto Done;

    fp = fopen(g_szConfigFile, "r");

    if (NULL == fp)
        goto Done;

    while (fgets(szBuffer, sizeofstring(szBuffer), fp))
    {
        len = strlen (szBuffer);

        if ('\n' == szBuffer[len-1])
        {
            len--;
            szBuffer[len] = '\0';
        }

        if (len <= 0)
            continue;

        if ('#' == *szBuffer)
        {
        }
        else if (0 == strcmp(szBuffer,g_ServicesSectionTag))
        {
            bServiceSection = TRUE;
            bConfigSection  = FALSE;
        }
        else if (0 == strcmp(szBuffer,g_ConfigSectionTag))
        {
            bServiceSection = FALSE;
            bConfigSection  = TRUE;
        }
        else if ('[' == *szBuffer)
        {
            snprintf(szMessage, sizeofstring(szMessage), "Invalid section: %s", szBuffer);
            LogMessage(szMessage);
            CountInvalidParam++;
        }
        else if (bConfigSection)
        {
            if (GetParam (szBuffer, g_CfgLogFileTag, sizeofstring (g_szLogFilename), g_szLogFilename))
            {
            }
            else if (GetParam (szBuffer,g_CfgTimeoutTag, sizeofstring (szParam), szParam))
            {
                g_dwGraceTime =  atoi (szParam);
            }
            else
            {
                printf ("Invalid Config: %s\n", szBuffer);
            }
        }
    } // while

Done:

    if (fp)
    {
        fclose(fp);
        fp = NULL;
    }

    return CountInvalidParam;
}

size_t ReadShutdownServiceNames(const char *pszServiceName, const char* pszFilename)
{
    char   szBuffer[4096] = {0};
    char   szMessage[MAX_ERROR_TEXT] = {0};
    FILE*  fp  = NULL;
    size_t len = 0;

    BOOL bConfigSection  = FALSE;
    BOOL bServiceSection = FALSE;

    g_CountShutdownServiceNames = 0;

    if (FALSE == IsNullStr(pszServiceName))
    {
        snprintf (g_szShutdownServiceNames[g_CountShutdownServiceNames], sizeofstring(g_szShutdownServiceNames[g_CountShutdownServiceNames]), "%s", pszServiceName);
        g_dwShutdownServiceStatus[g_CountShutdownServiceNames] = 0;
        g_CountShutdownServiceNames++;
    }

    if (IsNullStr(pszFilename))
        goto Done;

    fp = fopen(pszFilename, "r");

    if (NULL == fp)
        goto Done;

    while (fgets(szBuffer, sizeofstring(szBuffer), fp))
    {
        len = strlen (szBuffer);

        if ('\n' == szBuffer[len-1])
        {
            len--;
            szBuffer[len] = '\0';
        }

        if (len <= 0)
            continue;

        if ('#' == *szBuffer)
        {
        }
        else if (0 == strcmp(szBuffer,g_ServicesSectionTag))
        {
            bServiceSection = TRUE;
            bConfigSection  = FALSE;
        }
        else if (0 == strcmp(szBuffer,g_ConfigSectionTag))
        {
            bServiceSection = FALSE;
            bConfigSection  = TRUE;
        }
        else if ('[' == *szBuffer)
        {
            snprintf(szMessage, sizeofstring(szMessage), "Invalid section: %s", szBuffer);
            LogMessage(szMessage);
            goto Done;
        }
        else if (bServiceSection)
        {
            if (g_CountShutdownServiceNames >= MAX_SHUTDOWN_SERVICES)
            {
                LogMessage ("Maximum number of pre-shutdown service exceeded!");
                goto Done;
            }

            snprintf (g_szShutdownServiceNames[g_CountShutdownServiceNames], sizeofstring (g_szShutdownServiceNames[g_CountShutdownServiceNames]), "%s", szBuffer);
            g_CountShutdownServiceNames++;
        }
    } // while

Done:

    if (fp)
    {
        fclose(fp);
        fp = NULL;
    }

    return g_CountShutdownServiceNames;
}

BOOL IsServiceRunning(DWORD dwServiceState)
{

    if (0 == dwServiceState)
        return FALSE;

    if (SERVICE_STOPPED == dwServiceState)
        return FALSE;

    return TRUE;
}

size_t ShutdownCheckServices(DWORD dwOperation, DWORD dwSeconds, BOOL bVerbose)
{
    size_t count          = 0;
    size_t idx            = 0;
    BOOL   bSuccess       = FALSE;
    DWORD  dwServiceState = 0;
    char   szMessage[MAX_ERROR_TEXT+1] = {0};

    memset (&g_dwShutdownServiceStatus, sizeof(g_dwShutdownServiceStatus), 0);

    for (idx=0; idx < g_CountShutdownServiceNames; idx++)
    {
        bSuccess = ServiceCommand(g_szShutdownServiceNames[idx], dwOperation, 0, &dwServiceState);

        if (g_dwShutdownServiceStatus[idx] != dwServiceState)
        {
            g_dwShutdownServiceStatus[idx] = dwServiceState;

            if ((SERVICE_STOPPED == dwServiceState) && (dwSeconds))
            {
                snprintf(szMessage, sizeofstring(szMessage), "Services shutdown [%s] after %u seconds", g_szShutdownServiceNames[idx], dwSeconds);
                LogMessage(szMessage);
            }
        }

        if (bVerbose)
            printf ("[%s] %s\n", IsServiceRunning(dwServiceState) ? "X" : " ", g_szShutdownServiceNames[idx]);

        if (SERVICE_STOPPED != dwServiceState)
            count++;
    }

    return count;
}


size_t StartShutdownRegisteredServices(DWORD dwSeconds)
{
    size_t count          = 0;
    size_t idx            = 0;
    BOOL   bSuccess       = FALSE;
    DWORD  dwServiceState = 0;

    memset (&g_dwShutdownServiceStatus, sizeof(g_dwShutdownServiceStatus), 0);

    for (idx=0; idx < g_CountShutdownServiceNames; idx++)
    {
        bSuccess = ServiceCommand(g_szShutdownServiceNames[idx], SERVICE_OPERATION_START, dwSeconds, &dwServiceState);

        if (SERVICE_RUNNING == dwServiceState)
            count++;
    }

    return count;
}
