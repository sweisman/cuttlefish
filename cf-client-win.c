/*
 * Cuttlefish Windows Client
 * Copyright (C) Scott Weisman
*/

// below hard-coded defines are used in one or more includes and not defined in MINGW includes
#define _WIN32_WINNT                       0x0501
#define JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 0x00002000

#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <io.h>
#include <process.h>
#include <winsock2.h>

#if defined(CF_CYASSL)
// WolfSSL, formerly CYASSL
#include <cyassl/openssl/ssl.h>
#else
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define CF_CLIENT_WIN
#define MAX_BUFFER_SIZE                    1024
#define SSL_CHECK                          if (ssl_io_result < 1) break
#define CLOSE_HANDLE(h)                    if (h) (CloseHandle(h), ((h) = NULL))
#define TOLOWER(x)                         ((x >= 'A') && (x <= 'Z') ? (x | 0x20) : x)

typedef struct
{
    uint32_t            id;
    char                payload[MAX_BUFFER_SIZE]; // command line or file name
    unsigned int        send_count;
    unsigned int        receive_count;
    unsigned char       terminate;
    unsigned char       disconnect;

    // CONNECT
    SOCKET              socket;

    // EXEC
    HANDLE              hEvent;
    HANDLE              hThread;
    unsigned int        thread_id;
    PROCESS_INFORMATION procinfo;
    HANDLE              stdout_read, stdin_write;

    // FILE
    char                mode;
    FILE                *fp;
} s_cf_socket;

SOCKET server_socket;
HANDLE mutex_ssl_io = NULL, mutex_log = NULL, job_obj = NULL;
time_t packet_send_time = 0, packet_read_time = 0;
char cf_path[MAX_BUFFER_SIZE] = "";
SSL        *ssl = NULL;
SSL_CTX    *ssl_ctx = NULL;
SSL_METHOD *ssl_method = NULL;
int        ssl_io_result = 1, timeout = 0;

int send_buffer(int socket, const char *buf, int len);

#include "common.h"
#include "XGetopt.h"

void event_loop(void);
int event_handle(void);
unsigned __stdcall cf_connect(LPVOID arg);
unsigned __stdcall cf_exec(LPVOID arg);
unsigned __stdcall cf_file_read(LPVOID arg);
SOCKET connect_socket(const char *host, const int port);
int ssl_end(int retval);
int ssl_begin(const char *servercert, const char *clientkey);
int ssl_handshake(SOCKET sd);
int ssl_pending(int delay);
int ssl_write(const void *buf, int len);
int ssl_read(void *buf, int len);
int log_ssl_error(int retval);
int do_select(fd_set *read_list, fd_set *write_list, long usec, char *msg);
void disconnect_check(void);
void disconnect(s_cf_socket *cf_socket);
void cf_token_replace(char* str);
void str_token_replace(char *str, char *token_str, char *replace_str);
int log_socket_error(s_cf_socket *cf_socket, DWORD error, char *msg);

int main(int argc, char *argv[])
{
    char server_host[MAX_BUFFER_SIZE] = "";
    char server_cert[MAX_BUFFER_SIZE * 4] = "";
    char client_cert[MAX_BUFFER_SIZE * 4] = "";
    int server_port = 0;
    int opt;

    while ((opt = getopt(argc, argv, "p:l:u:w:s:c:")) != EOF)
    {
        switch (opt)
        {
            case 'u':
                strncpy(server_host, optarg, MAX_BUFFER_SIZE);
                break;
            case 'p':
                server_port = atoi(optarg);
                break;
            case 'w':
                strncpy(cf_path, optarg, MAX_BUFFER_SIZE);
                break;
            case 'l':
                strncpy(log_file, optarg, MAX_BUFFER_SIZE);
                break;
            case 's':
                // assumes -w already parsed
                if (cf_path[0] && strlen(optarg) < MAX_BUFFER_SIZE)
                    sprintf(server_cert, "%s\\%s", cf_path, optarg);
                break;
            case 'c':
                // assumes -w already parsed
                if (cf_path[0] && strlen(optarg) < MAX_BUFFER_SIZE)
                    sprintf(client_cert, "%s\\%s", cf_path, optarg);
                break;
        }
    }

    print_log("MAIN: ENTER");

    if (!server_host[0])
    {
        print_log("MAIN: server host missing; exiting");
        return -1;
    }
    else if (!server_port)
    {
        print_log("MAIN: server port missing; exiting");
        return -1;
    }
    else if (!server_cert[0])
    {
        print_log("MAIN: server cert missing; exiting");
        return -1;
    }
    else if (!client_cert[0])
    {
        print_log("MAIN: client cert missing; exiting");
        return -1;
    }

    if ((job_obj = CreateJobObject(NULL, NULL)))
    {
        // configure all child processes associated with the job to terminate with the parent
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
        clear(&jeli, sizeof(jeli));
        jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(job_obj, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli)))
        {
            print_log("MAIN: could not set job object info; exiting");
            return -1;
        }
    }
    else
    {
        print_log("MAIN: could not create job object; exiting");
        return -1;
    }

    WSADATA wsa_data;
    int result;

    srand((unsigned int) time(NULL));
    mutex_log = CreateMutex(NULL, FALSE, NULL);
    mutex_ssl_io = CreateMutex(NULL, FALSE, NULL);

    print_log("MAIN: ENTER EVENT LOOP");

    do
    {
        if ((result = WSAStartup(MAKEWORD(1, 1), &wsa_data)))
        {
            print_log("MAIN: WSAStartup() error %d", result);
            break;
        }

        if (ssl_begin(server_cert, client_cert))
            break;

        if ((server_socket = connect_socket(server_host, server_port)) == INVALID_SOCKET)
            break;

        if (ssl_handshake(server_socket))
            break;

        ssl_io_result = 1;
        packet_send_time = time(NULL);
        packet_read_time = time(NULL);
        memset(cf_socket_list, 0, sizeof(cf_socket_list));

        event_loop();

    } while (0);

    print_log("MAIN: EXIT EVENT LOOP");

// xxx move shutdown code to atexit() function
    ssl_end(-10000);
    if (server_socket != INVALID_SOCKET)
        close_socket(server_socket);
    WSACleanup();

    CLOSE_HANDLE(mutex_log);
    CLOSE_HANDLE(mutex_ssl_io);

    print_log("MAIN: EXIT");

    return 0;
}

void event_loop(void)
{
    int result, select_count;
    unsigned char buffer[MAX_PACKET_SIZE];

    print_log("EVENT LOOP: ENTER");

    for (;;)
    {
        SSL_CHECK;
        disconnect_check();

        if ((select_count = ssl_pending(10000)) > 0)
        {
            do
            {
                print_log("EVENT LOOP: READ FROM SERVER");

                result = ssl_read(buffer, MAX_PACKET_SIZE);

                if (result < 0)
                {
                    print_log("EVENT LOOP NULL READ");
                }
                else if (!result)
                {
                    print_log("EVENT LOOP ERROR: SSL READ %d", result);
                    break;
                }
                else
                {
                    if (!queue_put(buffer, result))
                        break;

                    if (!event_handle())
                        break;
                }

                SSL_CHECK;
                disconnect_check();
            } while (SSL_pending(ssl));
        }
        else if (select_count < 0)
        {
// xxx error
            print_log("EVENT LOOP SSL_PENDING ERROR: %d", select_count);
            break;
        }

        SSL_CHECK;

        while (event_handle())
        {
            SSL_CHECK;
            disconnect_check();
        }

        SSL_CHECK;

        if (time(NULL) - packet_send_time >= 25)
        {
            if (send_packet(0, CF_PACKET_PING, NULL, 0))
            {
                print_log("EVENT LOOP ERROR: BAD PING SEND");
                timeout = 1;
                break;
            }

            cf_socket_dump();
        }

        if (time(NULL) - packet_read_time >= 35)
        {
            print_log("EVENT LOOP ERROR: ACTIVITY TIMEOUT");
            timeout = 1;
            cf_socket_dump();
            break;
        }
    }

    print_log("EVENT LOOP: EXIT");
}

int event_handle(void)
{
    s_cf_packet *cf_packet = queue_get();
    s_cf_socket *cf_socket;
    struct _stat stat_buf;
    //~ int payload_len;
    char *file_op;
    //~ char *ext;
    int file_path_err = 0;
    int i = 0;

    if (!cf_packet)
        return 0;

    char *payload = (char *) PACKET_PAYLOAD(cf_packet);

    print_log("EVENT HANDLE START: id=%d, type=%d, len=%d", cf_packet->id, cf_packet->type, cf_packet->len);

    packet_read_time = time(NULL);

    switch(cf_packet->type)
    {
        case CF_PACKET_PING:
            // ignore - no response or error logging
            break;

        case CF_PACKET_CONNECT:
            print_log("EVENT HANDLE CONNECT: '%s'", (cf_packet + 1));

            if ((cf_socket = cf_socket_new(cf_packet->id)))
            {
                char *connect_addr = (char *) (cf_packet + 1);
                char *connect_port = strchr(connect_addr, ':');

                if (!connect_port)
                {
                    print_log("    EVENT HANDLE ERROR: NO PORT");
                    disconnect(cf_socket);
                    break;
                }

                *(connect_port++) = '\0'; // separate address from port
                int port = atoi(connect_port);
                if (port <= 0 || port > 65535)
                {
                    print_log("    EVENT HANDLE ERROR: BAD PORT");
                    disconnect(cf_socket);
                    break;
                }

                cf_socket->socket = connect_socket(connect_addr, port);
                print_log("EVENT HANDLE CONNECT SOCKET: %d", cf_socket->socket);

                if (cf_socket->socket == INVALID_SOCKET)
                {
                    print_log("    EVENT HANDLE ERROR: BAD SOCKET");
                    disconnect(cf_socket);
                    break;
                }

                cf_socket->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
                if (!(cf_socket->hThread = (HANDLE) _beginthreadex(NULL, 0, cf_connect, (LPVOID) cf_socket, 0, &cf_socket->thread_id)))
                {
                    print_log("    EVENT HANDLE ERROR: _beginthreadex error %d", errno);
                    disconnect(cf_socket);
                    break;
                }
            }
            else
                print_log("    EVENT HANDLE ERROR: NO FREE SOCKET id=%d", cf_packet->id);
            break;

        case CF_PACKET_EXEC:
            if ((cf_socket = cf_socket_new(cf_packet->id)))
            {
                strncpy(cf_socket->payload, payload, MAX_BUFFER_SIZE);
                cf_socket->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
                if (!(cf_socket->hThread = (HANDLE) _beginthreadex(NULL, 0, cf_exec, (LPVOID) cf_socket, 0, &cf_socket->thread_id)))
                {
                    // assume fatal error always disconnect
                    print_log("    EVENT HANDLE ERROR: _beginthreadex error %d", errno);
                    disconnect(cf_socket);
                    break;
                }
            }
            else
                print_log("    EVENT HANDLE ERROR: NO FREE SOCKET id=%d", cf_packet->id);
            break;

        case CF_PACKET_FILE:
            if (!_stat(payload, &stat_buf))
            {
                // file exists - for file sending only
                print_log("    EVENT HANDLE FILE READ");
                file_op = "rb";
            }
            else
            {
                // no file - for file receiving only
                print_log("    EVENT HANDLE FILE WRITE");
                file_op = "wb";
            }

            if ((cf_socket = cf_socket_new(cf_packet->id)))
            {
                strncpy(cf_socket->payload, payload, MAX_BUFFER_SIZE);
                cf_token_replace(cf_socket->payload);

                print_log("    EVENT HANDLE TYPE: FILE payload={%s}", cf_socket->payload);

                // xxx change to use open(), or OpenFile() or whatever API is not buffered, then use ReadFile and WriteFile

                if (file_op[0] == 'r' && (cf_socket->fp = fopen(cf_socket->payload, file_op)))
                {
                    print_log("    EVENT HANDLE TYPE: FILE GET id=%d", cf_socket->id);

                    cf_socket->mode = 'r';
                    cf_socket->hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
                    if (!(cf_socket->hThread = (HANDLE) _beginthreadex(NULL, 0, cf_file_read, (LPVOID) cf_socket, 0, &cf_socket->thread_id)))
                    {
                        // assume fatal error always disconnect
                        print_log("    EVENT HANDLE ERROR: _beginthreadex %d", errno);
                        disconnect(cf_socket);
                        break;
                    }
                }
                else if (file_op[0] == 'w' && (cf_socket->fp = fopen(cf_socket->payload, file_op)))
                {
                    print_log("    EVENT HANDLE TYPE: FILE PUT id=%d", cf_socket->id);
                    cf_socket->mode = 'w';
                }
                else
                {
                    // assume fatal error always disconnect
                    print_log("    EVENT HANDLE FILE FATAL ERROR: fopen %d", errno);
                    disconnect(cf_socket);
                    break;
                }
            }
            else
                print_log("    EVENT HANDLE ERROR: NO FREE SOCKET id=%d", cf_packet->id);
            break;

        case CF_PACKET_DATA:
            if ((cf_socket = cf_socket_find(cf_packet->id)))
            {
                cf_socket->receive_count += cf_packet->len;

                if (cf_socket->socket)
                {
                    print_log("    EVENT HANDLE TYPE: DATA PUT id=%d", cf_socket->id);
                    if (send_buffer(cf_socket->socket, payload, cf_packet->len))
                    {
                        // assume fatal error always disconnect
                        print_log("    EVENT SEND BUFFER ERROR: id=%d", cf_packet->id);
                        disconnect(cf_socket);
                        break;
                    }
                }
                else if (cf_socket->mode == 'w')
                {
                    // FILE
                    print_log("    EVENT HANDLE TYPE: DATA PUT FILE id=%d", cf_socket->id);
                    fwrite(payload, 1, cf_packet->len, cf_socket->fp);
// xxx check result
                }
                else if (cf_socket->stdin_write)
                {
                    // EXEC
                    DWORD result;
                    print_log("    EVENT HANDLE TYPE: DATA PUT EXEC id=%d", cf_socket->id);
                    WriteFile(cf_socket->stdin_write, payload, cf_packet->len, &result, NULL);
// xxx check result
                }
                else
                    print_log("    EVENT HANDLE DATA PUT ERROR: UNKNOWN TYPE id=%d", cf_socket->id);
            }
            else
                print_log("    EVENT HANDLE DATA PUT ERROR: UNKNOWN ID id=%d", cf_packet->id);
            break;

        case CF_PACKET_DISCONNECT:
            if ((cf_socket = cf_socket_find(cf_packet->id)))
            {
                if (cf_socket->hThread)
                {
                    print_log("    EVENT HANDLE DISCONNECT: SET EVENT id=%d", cf_socket->id);

                    cf_socket->terminate = 1;

                    if (!SetEvent(cf_socket->hEvent))
                        log_socket_error(cf_socket, GetLastError(), "DISCONNECT SetEvent");

// CLOSE_HANDLE(cf_socket->stdout_read);
                }
                else
                    cf_socket->disconnect = 1;
            }
            else
                print_log("    EVENT HANDLE DISCONNECT ERROR: UNKNOWN ID id=%d", cf_packet->id);
            break;

        case CF_PACKET_LOG:
            // enable/disable logging
            if (cf_packet->len && *((char *) PACKET_PAYLOAD(cf_packet)) != '0')
                strcpy(log_file, ".\\cf-debug.log");
            else
                log_file[0] = 0;
            break;

        default:
            print_log("    EVENT HANDLE WHOOPS ERROR: UKNOWN TYPE id=%d type=%d", cf_packet->id, cf_packet->type);
            break;
    }

    print_log("EVENT HANDLE END id=%d", cf_packet->id);

    return 1;
}

unsigned __stdcall cf_connect(LPVOID arg)
{
    s_cf_socket *cf_socket = (s_cf_socket *) arg;
    char buffer[MAX_BUFFER_SIZE];
    int total_sent = 0;
    int read_len = 0;
    int select_count, result;
    fd_set fd_list;

    print_log("CONNECT ENTER id=%d, payload={%s}", cf_socket->id, cf_socket->payload);

    for (;;)
    {
// xxx set up fd_list before dp_select with cf_socket->socket
        FD_ZERO(&fd_list);
        FD_SET(cf_socket->socket, &fd_list);

        if (!cf_socket->id || cf_socket->terminate || cf_socket->disconnect || !cf_socket->socket)
        {
            print_log("    CONNECT EXIT: TERMINATE SIGNAL RECEIVED id=%d", cf_socket->id);
            break;
        }
        else if ((select_count = do_select(&fd_list, NULL, 10000, "local read wait")) < 0)
        {
            print_log("    CONNECT EXIT: SELECT ERROR id=%d", cf_socket->id);
            break;
        }
        else if (select_count)
        {
            print_log("CONNECT READ: START id=%d", cf_socket->id);

            if ((result = recv(cf_socket->socket, (char *) buffer, MAX_BUFFER_SIZE, 0)) <= 0)
            {
                cf_socket->disconnect = 1;

                if (result < 0)
                {
                    int error = WSAGetLastError(); // call here instead of in print_log to be 100% certain it is called first
                    print_log("CONNECT READ ERROR: recv id=%d, error=%d", cf_socket->id, error);
                    break;
                }
            }
            else
            {
                if (ssl_pending(-1))
                {
                    print_log("CONNECT READ ERROR: ssl_pending id=%d", cf_socket->id);
                    break;
                }
                else if (send_packet(cf_socket->id, CF_PACKET_DATA, buffer, result))
                {
                    print_log("CONNECT READ ERROR: READ LOCAL SEND id=%d", cf_socket->id);
                    break;
                }
                else
                    cf_socket->send_count += read_len;
            }

            print_log("CONNECT READ: END id=%d", cf_socket->id);
        }

        SSL_CHECK;
        disconnect_check();
    }

    print_log("CONNECT EXIT id=%d, sent=%d", cf_socket->id, total_sent);

    cf_socket->terminate == 1 ?
        (cf_socket->terminate = 2) :
        (cf_socket->disconnect = 1);

    return 0;
}

// Creating a Child Process with Redirected Input and Output
// http://msdn.microsoft.com/en-us/library/ms682499
// http://support.microsoft.com/kb/315939

unsigned __stdcall cf_exec(LPVOID arg)
{
    s_cf_socket *cf_socket = (s_cf_socket *) arg;
    STARTUPINFO sInfo;
    PROCESS_INFORMATION pInfo;
    SECURITY_ATTRIBUTES secat;
    HANDLE stdin_read, stdout_write, stderr_write, stderr_read;
    DWORD exit_code;

    memset(&sInfo, 0, sizeof(STARTUPINFO));
    memset(&pInfo, 0, sizeof(PROCESS_INFORMATION));

    secat.nLength = sizeof(SECURITY_ATTRIBUTES);
    secat.bInheritHandle = TRUE;
    secat.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&stdin_read, &cf_socket->stdin_write, &secat, 0) && log_socket_error(cf_socket, GetLastError(), "EXEC PIPE1"))
        return 1;

    if (!CreatePipe(&cf_socket->stdout_read, &stdout_write, &secat, 0) && log_socket_error(cf_socket, GetLastError(), "EXEC PIPE2"))
    {
        CLOSE_HANDLE(cf_socket->stdout_read);
        CLOSE_HANDLE(stdout_write);
        return 1;
    }

    if (!CreatePipe(&stderr_read, &stderr_write, &secat, 0) &&  log_socket_error(cf_socket, GetLastError(), "EXEC PIPE3"))
    {
        CLOSE_HANDLE(cf_socket->stdout_read);
        CLOSE_HANDLE(stdout_write);
        CLOSE_HANDLE(cf_socket->stdin_write);
        CLOSE_HANDLE(stdin_read);
        return 1;
    }

    sInfo.cb = sizeof(sInfo);
    sInfo.dwFlags = STARTF_USESTDHANDLES;
    sInfo.hStdInput = stdin_read;
    sInfo.hStdOutput = stdout_write;
    sInfo.hStdError = stderr_write;

    cf_token_replace(cf_socket->payload);

    print_log("EXEC ENTER id=%d, payload={%s}", cf_socket->id, cf_socket->payload);

    do
    {
        if (!CreateProcess(NULL, cf_socket->payload, NULL, NULL, TRUE, CREATE_DEFAULT_ERROR_MODE | HIGH_PRIORITY_CLASS, NULL, NULL, &sInfo, &cf_socket->procinfo))
        {
            log_socket_error(cf_socket, GetLastError(), "EXEC CreateProcess");
            if (cf_socket->procinfo.hProcess && GetExitCodeProcess(cf_socket->procinfo.hProcess, &exit_code))
                print_log("EXEC ERROR: CreateProcess (%s) ExitCode: %d", cf_socket->payload, exit_code);
            break;
        }

        if (!AssignProcessToJobObject(job_obj, cf_socket->procinfo.hProcess))
        {
            log_socket_error(cf_socket, GetLastError(), "EXEC AssignProcessToJobObject");
            break;
        }

        CLOSE_HANDLE(stdin_read);
        CLOSE_HANDLE(stdout_write);
        CLOSE_HANDLE(stderr_read);
        CLOSE_HANDLE(stderr_write);

        // xxx check errors on SetNamedPipeHandleState below!
        DWORD pipe_mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        if (!SetNamedPipeHandleState(cf_socket->stdout_read, &pipe_mode, NULL, NULL))
            log_socket_error(cf_socket, GetLastError(), "EXEC SetNamedPipeHandleState");

        char buffer[MAX_BUFFER_SIZE];
        DWORD kill = 1;

        for (;;)
        {
            SleepEx(10, TRUE);

            DWORD read_count, read_len;
            int result = 0;

            SSL_CHECK;

            if (!PeekNamedPipe(cf_socket->stdout_read, NULL, 0, NULL, &read_count, NULL))
                if (log_socket_error(cf_socket, GetLastError(), "EXEC PEEK"))
                    break;

            if (read_count)
            {
                print_log("        EXEC PEEK DATA id=%d %d", cf_socket->id, read_count);

                while (read_count > 0)
                {
                    if (ReadFile(cf_socket->stdout_read, buffer, read_count < sizeof(buffer) ? read_count : sizeof(buffer), &read_len, NULL))
                    {
                        print_log("        EXEC READ DATA id=%d %d", cf_socket->id, read_len);
                        read_count -= read_len;
                        if (read_len > 0)
                        {
                            if (ssl_pending(-1))
                            {
                                print_log("EXEC READ ERROR: ssl_pending id=%d", cf_socket->id);
                                break;
                            }
                            else if ((result = send_packet(cf_socket->id, CF_PACKET_DATA, buffer, read_len)))
                            {
                                print_log("        EXEC ERROR BAD SEND PACKET id=%d", cf_socket->id);
                                log_socket_error(cf_socket, GetLastError(), "EXEC READ");
                                break;
                            }
                            else
                                cf_socket->send_count += read_len;
                        }
                    }
                    else
                    {
                        result = -1;
                        break;
                    }
                }

                if (result < 0)
                    break;
            }

            // xxx read stderr and send as log packets

            if (cf_socket->terminate == 1)
            {
                print_log("        EXEC EXIT: TERMINATE 2 SIGNAL RECEIVED id=%d", cf_socket->id);
                break;
            }

            if (WaitForSingleObject(cf_socket->hEvent, 0) == WAIT_OBJECT_0)
            {
                print_log("        EXEC EXIT: TERMINATE 1 SIGNAL RECEIVED id=%d", cf_socket->id);
                break;
            }

            if (GetExitCodeProcess(cf_socket->procinfo.hProcess, &exit_code))
            {
                if (exit_code != STILL_ACTIVE)
                {
                    kill = 0;
                    print_log("        EXEC: EXIT 1 id=%d %d", cf_socket->id, exit_code);
                    break;
                }

                if (WaitForSingleObject(cf_socket->procinfo.hProcess, 0) == WAIT_OBJECT_0)
                {
                    kill = 0;
                    print_log("        EXEC: EXIT 2 id=%d %d", cf_socket->id, exit_code);
                    break;
                }
            }
            else if (log_socket_error(cf_socket, GetLastError(), "EXEC GET EXIT CODE"))
                break;
        }

        print_log("    EXEC LOOP END id=%d", cf_socket->id);

        if (kill)
        {
            print_log("    EXEC KILL START id=%d", cf_socket->id);

            if (TerminateProcess(cf_socket->procinfo.hProcess, 0))
            {
                print_log("    EXEC WAIT START id=%d", cf_socket->id);
                WaitForSingleObject(cf_socket->procinfo.hProcess, INFINITE);
                print_log("    EXEC WAIT END id=%d", cf_socket->id);
            }
            else
                log_socket_error(cf_socket, GetLastError(), "EXEC TerminateProcess");

            print_log("    EXEC KILL END id=%d", cf_socket->id);
        }

        CLOSE_HANDLE(cf_socket->procinfo.hProcess);
        CLOSE_HANDLE(cf_socket->procinfo.hThread);
    } while (0);

    CLOSE_HANDLE(stdin_read);
    CLOSE_HANDLE(cf_socket->stdin_write);
    CLOSE_HANDLE(cf_socket->stdout_read);
    CLOSE_HANDLE(stdout_write);
    CLOSE_HANDLE(stderr_read);
    CLOSE_HANDLE(stderr_write);

    cf_socket->terminate == 1 ?
        (cf_socket->terminate = 2) :
        (cf_socket->disconnect = 1);

    print_log("EXEC EXIT id=%d", cf_socket->id);

    return 0;
}

unsigned __stdcall cf_file_read(LPVOID arg)
{
    s_cf_socket *cf_socket = (s_cf_socket *) arg;
    char buffer[MAX_BUFFER_SIZE];
    int read_len = 0;

    print_log("FILE ENTER id=%d, payload={%s}", cf_socket->id, cf_socket->payload);

    for (;;)
    {
        print_log("    FILE LOOP START id=%d", cf_socket->id);

        SSL_CHECK;

        if (cf_socket->terminate == 1)
        {
            print_log("    FILE READ EXIT: TERMINATE SIGNAL RECEIVED id=%d", cf_socket->id);
            break;
        }
        else if (!(read_len = fread(buffer, 1, MAX_BUFFER_SIZE, cf_socket->fp)))
        {
            print_log("    FILE READ: EOF id=%d", cf_socket->id);
            break;
        }
        else if (ssl_pending(-1))
        {
            print_log("FILE READ ERROR: ssl_pending id=%d", cf_socket->id);
            break;
        }
        else if (send_packet(cf_socket->id, CF_PACKET_DATA, buffer, read_len))
        {
            print_log("        FILE READ ERROR BAD SEND PACKET id=%d", cf_socket->id);
            break;
        }
        else
            cf_socket->send_count += read_len;
    }

    print_log("FILE EXIT id=%d sent=%d", cf_socket->id, cf_socket->send_count);

    cf_socket->terminate == 1 ?
        (cf_socket->terminate = 2)
        :
        (cf_socket->disconnect = 1);

    return 0;
}

int send_buffer(int socket, const char *buf, int len)
{
    int total_sent = 0;
    int n = 0;

    if (len < 0)
        len = strlen(buf);

    while (len > 0)
    {
        if (socket > 0)
        {
            if ((n = send(socket, buf + total_sent, len, 0)) < 0)
            {
                errno ?
                    print_log("failed to send_buffer data on socket id:%d, len=%d, errno=%d, errstr=%s", socket, len, errno, strerror(errno))
                    :
                    print_log("failed to send_buffer data on socket id:%d, len=%d", socket, len);
                return -2;
            }
        }
        else if ((n = ssl_write(buf + total_sent, len)) < 1)
        {
            print_log("SEND BUFFER SSL ERROR -4 len=%d", len);
            return -11;
        }

        total_sent += n;
        len -= n;
    }

    return 0;
}

void disconnect_check(void)
{
    for (uint32_t i = 0; i <= cf_socket_idx; i++)
        if (cf_socket_list[i])
            if (cf_socket_list[i]->terminate == 2 || cf_socket_list[i]->disconnect || !cf_socket_list[i]->id)
                disconnect(cf_socket_list[i]);
}

void disconnect(s_cf_socket *cf_socket)
{
    print_log("DISCONNECT id=%d", cf_socket->id);

    if (!cf_socket->id)
        print_log("DISCONNECT ERROR: STRAY SOCKET id=%d", cf_socket->id);
    else if (!cf_socket->terminate && !timeout)
    {
        print_log("DISCONNECT SEND TERMINATE id=%d", cf_socket->id);
        if (send_packet(cf_socket->id, CF_PACKET_DISCONNECT, NULL, 0))
            print_log("DISCONNECT SEND BUFFER ERROR id=%d", cf_socket->id);
    }

    cf_socket_free(cf_socket);
}

void cf_token_replace(char* str)
{
    char SYSTEM32[MAX_BUFFER_SIZE] = "";
    char WINDOWS[MAX_BUFFER_SIZE] = "";

    GetSystemDirectory(SYSTEM32, MAX_BUFFER_SIZE);
    GetWindowsDirectory(WINDOWS, MAX_BUFFER_SIZE);

    str_token_replace(str, "%CFPATH%", cf_path);
    str_token_replace(str, "%SYSTEM32%", SYSTEM32);
    str_token_replace(str, "%WINDOWS%", WINDOWS);
}

void str_token_replace(char *str, char *token_str, char *replace_str)
{
    int token_len, replace_len;
    char *p, *q, *pp;
    int token_count = 0;

    q = str;
    while ((q = strstr(q, token_str)))
    {
        token_count++;
        q++;
    }

    if (!token_count)
        return;

    token_len = strlen(token_str);
    replace_len = strlen(replace_str);

    char *tmp = (char *) malloc(strlen(str) + (token_count * (replace_len - token_len)) + 1);

    if (!tmp)
        return;

    char *qq = tmp;
    q = str;

    while ((p = strstr(q, token_str)) != NULL)
    {
        pp = qq + (p - q);
        memcpy(qq, q, p - q);
        memcpy(pp, replace_str, replace_len);
        q = p + token_len;
        qq = pp + replace_len;
    }

    memcpy(qq, q, strlen(str) - (q - str));

    *((qq + strlen(str)) - (q - str)) = '\0';

    strncpy(str, tmp, MAX_BUFFER_SIZE);
    free(tmp);
}

SOCKET connect_socket(const char *host, const int port)
{
    unsigned long address = inet_addr(host);

    if (address == INADDR_NONE)
    {
        // host isn't a dotted IP, so resolve it through DNS
        struct hostent *pHE = gethostbyname(host);
        if (!pHE)
            return INVALID_SOCKET;

        address = *((u_long *) pHE->h_addr_list[0]);
    }

    print_log("CONNECT: START");

    SOCKET sd = socket(AF_INET, SOCK_STREAM, 0);

    if (sd != INVALID_SOCKET)
    {
        BOOL opt = 1;
        int result = setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, (char *) &opt, sizeof(BOOL));
        if (result == SOCKET_ERROR)
        {
            int error = WSAGetLastError(); // call here instead of in print_log to be 100% certain it is called first
            print_log("CONNECT: SETSOCKOPT ERROR %d", error);
        }

        struct sockaddr_in sinRemote;
        sinRemote.sin_family = AF_INET;
        sinRemote.sin_addr.s_addr = address;
        sinRemote.sin_port = htons(port);

        if (connect(sd, (struct sockaddr *) &sinRemote, sizeof(struct sockaddr_in)) == SOCKET_ERROR)
        {
            int error = WSAGetLastError(); // call here instead of in print_log to be 100% certain it is called first
            print_log("CONNECT: ERROR %d", error);
            close_socket(sd);
            return INVALID_SOCKET;
        }
    }
    else
        print_log("CONNECT: SOCKET ERROR");

    return sd;
}

int ssl_end(int retval)
{
    print_log("SSL_END: 1 %d", retval);

    log_ssl_error(retval);

    print_log("SSL_END: 2");

    if (ssl)
    {
        print_log("SSL_END: 3");
        SSL_free(ssl);
        ssl = NULL;
    }

    if (ssl_ctx)
    {
        print_log("SSL_END: 4");
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = NULL;
    }

    print_log("SSL_END: 5");

    return retval;
}

int ssl_begin(const char *server_cert, const char *client_cert)
{
    // SSL preliminaries. We keep the certificate and key with the context.

    ssl = NULL;

    SSL_library_init();
    SSL_load_error_strings();

    if (!ssl_method)
    {
        ssl_method = (SSL_METHOD *) SSLv23_client_method();
        if (!ssl_method)
            return ssl_end(-1);
    }

    if (!(ssl_ctx = SSL_CTX_new(ssl_method)))
        return ssl_end(-2);

    // commented out because retry is handled by service
    // SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY)
    // SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

    if (SSL_CTX_use_certificate_file(ssl_ctx, client_cert, SSL_FILETYPE_PEM) < 1)
        return ssl_end(-3);

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, client_cert, SSL_FILETYPE_PEM) < 1)
        return ssl_end(-4);

    if (!SSL_CTX_check_private_key(ssl_ctx))
        return ssl_end(-5);

    if (!SSL_CTX_load_verify_locations(ssl_ctx, server_cert, NULL))
        return ssl_end(-6);

    return 0;
}

int ssl_handshake(SOCKET sd)
{
    int result = 0;

    if (!(ssl = SSL_new(ssl_ctx)))
        return ssl_end(-7);

    SSL_set_connect_state(ssl);

    if (SSL_set_fd(ssl, sd) < 1)
        return ssl_end(-8);

    if (SSL_connect(ssl) < 1)
        return ssl_end(-9);

    print_log("SSL CONNECT CYPHER: %s", SSL_get_cipher(ssl));

    X509 *server_cert = SSL_get_peer_certificate(ssl);

    if (!server_cert)
        result = -10;

    if (server_cert)
        X509_free(server_cert);

    if (result < 0)
        return ssl_end(result);

    return result;
}

int ssl_pending(int delay)
{
    if (SSL_pending(ssl))
        return 1;

    fd_set fd_list;
    int loop = 0, result;

    if (delay < 0)
    {
        loop = 10;
        delay = 0;
    }

    do
    {
        FD_ZERO(&fd_list);
        FD_SET(server_socket, &fd_list);

        if ((result = do_select(&fd_list, NULL, delay, "io check")) <= 0)
            return result;

        if (loop)
        {
            Sleep(100);
            loop--;
        }
    } while (loop > 0 && result > 0);

    return result;
}

int ssl_write(const void *buf, int len)
{
    if (ssl_io_result > 0)
    {
        int io_loop = 0;

        for (;;)
        {
            print_log("SSL WRITE START loop=%d, len=%d", io_loop, len);
            if (WaitForSingleObject(mutex_ssl_io, INFINITE) != WAIT_OBJECT_0)
            {
                print_log("SSL WRITE MUTEX ERROR");
                return -3;
            }

            int result = SSL_write(ssl, buf, len);
            int error = SSL_get_error(ssl, result);
            int winsock_error = 0;

// xxx if result != len
            switch (error)
            {
                case SSL_ERROR_WANT_WRITE:
                    print_log("SSL_ERROR_WANT_WRITE during SSL_write %d", io_loop);
                    log_ssl_error(result);
                    io_loop++;
                    break;
                case SSL_ERROR_WANT_READ:
                    print_log("SSL_ERROR_WANT_READ during SSL_write %d", io_loop);
                    log_ssl_error(result);
                    io_loop++;
                    break;
                case SSL_ERROR_WANT_CONNECT:
                case SSL_ERROR_WANT_ACCEPT:
                case SSL_ERROR_WANT_X509_LOOKUP:
                case SSL_ERROR_ZERO_RETURN:
                case SSL_ERROR_SYSCALL:
                case SSL_ERROR_SSL:
                    if (error == SSL_ERROR_SYSCALL)
                        winsock_error = WSAGetLastError();
                    print_log("SSL_write error %d winsock_error %d loop %d", error, winsock_error, io_loop);
                    log_ssl_error(result);
                    if (result == -1 && error == SSL_ERROR_SYSCALL && !winsock_error)
                    {
                        // xxx retry
                        print_log("ssl_write null error retry");
                        io_loop++;
                    }
                    else
                    {
                        ssl_io_result = 0;
                        io_loop = 0;
                    }
                    break;
                case SSL_ERROR_NONE:
                    packet_send_time = time(NULL);
                    ssl_io_result = (result == len ? result : 0);
                    io_loop = 0;
                    break;
                default:
                    print_log("SSL_write unknown error %d %d", error, io_loop);
                    ssl_io_result = 0;
                    io_loop = 0;
                    break;
            }

            ReleaseMutex(mutex_ssl_io);

            if (!io_loop)
                break;
            else if (io_loop > 10)
            {
                print_log("ssl_write too many retries");
                ssl_io_result = 0;
                break;
            }

            Sleep(io_loop * 3);
        }
    }

    return ssl_io_result;
}

int ssl_read(void *buf, int len)
{
    if (ssl_io_result > 0)
    {
        int io_loop = 0;

        for (;;)
        {
            print_log("START SSL READ loop=%d", io_loop);
            int result = SSL_read(ssl, buf, len);
            int error = SSL_get_error(ssl, result);
            int winsock_error = 0;

            switch (error)
            {
                case SSL_ERROR_WANT_WRITE:
                    print_log("SSL_ERROR_WANT_WRITE during SSL_read %d", io_loop);
                    log_ssl_error(result);
                    io_loop++;
                    break;
                case SSL_ERROR_WANT_READ:
                    print_log("SSL_ERROR_WANT_READ during SSL_read %d", io_loop);
                    log_ssl_error(result);
                    io_loop++;
                    break;
                case SSL_ERROR_WANT_CONNECT:
                case SSL_ERROR_WANT_ACCEPT:
                case SSL_ERROR_WANT_X509_LOOKUP:
                case SSL_ERROR_ZERO_RETURN:
                case SSL_ERROR_SYSCALL:
                case SSL_ERROR_SSL:
                    if (error == SSL_ERROR_SYSCALL)
                        winsock_error = WSAGetLastError();
                    print_log("SSL_read error %d winsock_error %d loop %d", error, winsock_error, io_loop);
                    log_ssl_error(result);
                    if (result == -1 && error == SSL_ERROR_SYSCALL && !winsock_error)
                    {
                        // xxx retry
                        print_log("ssl_read null error return");
                        io_loop = 0;
                        return -1;
                    }
                    else
                    {
                        io_loop = 0;
                        ssl_io_result = 0;
                    }
                    break;
                case SSL_ERROR_NONE:
                    io_loop = 0;
                    ssl_io_result = result;
                    break;
                default:
                    print_log("SSL_read unknown error %d %d", error, io_loop);
                    ssl_io_result = 0;
                    io_loop = 0;
                    break;
            }

            if (!io_loop)
                break;
            else if (io_loop > 20)
            {
                print_log("ssl_read too many retries");
                ssl_io_result = 0;
                break;
            }

            Sleep(io_loop);
        }
    }

    return ssl_io_result;
}

int do_select(fd_set *read_list, fd_set *write_list, long usec, char *msg)
{
    struct timeval tv = {0, usec};

    int result = select(0, read_list, write_list, NULL, &tv);

    if (result < 0)
    {
        ssl_io_result = -1002; // set a fake error code to punt
        errno ?
            print_log("SELECT ERROR %s result=%d, errno=%d, errstr=%s", msg, result, errno, strerror(errno))
            :
            print_log("SELECT ERROR %s result=%d", msg, result);
    }

    return result;
}

int log_ssl_error(int retval)
{
    unsigned long error;
    char buffer[MAX_BUFFER_SIZE] = "";
    int count = 0;

    if (retval > 0)
        return retval;

    if (!ERR_peek_error())
        return retval;

    while ((error = ERR_get_error()))
    {
        count++;
        ERR_error_string_n(error, buffer, MAX_BUFFER_SIZE);
        print_log("ERROR SSL1 %d: %s", error, buffer);
    }

    if (!count && ((error = SSL_get_error(ssl, retval)) != SSL_ERROR_NONE))
        print_log("ERROR SSL2 %d", error);

    if (!count && !error)
        print_log("ERROR SSL3");

    return retval;
}

int log_socket_error(s_cf_socket *cf_socket, DWORD error, char *msg)
{
    if (error)
    {
        char buffer[256];
        FormatMessage(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM, cf_socket->procinfo.hProcess, error, 0, buffer, sizeof(buffer), NULL) ?
            print_log("ERROR %s %d: '%s' id=%d", msg, error, buffer, cf_socket->id)
            :
            print_log("ERROR %s %d: id=%d", msg, error, cf_socket->id);
    }

    return error;
}
