/*
 * CuttleFish Server
 * Copyright (C) Scott Weisman
 *
 * this program is meant to be invoked by stunnel
 * traffic is via stdio; control is through a uds file
 */

#define CF_SERVER
#define MAX_BUFFER_SIZE            1024
#define LPVOID                     void *
#define SET_HIGH_FD(check, high)   ((high) = ((((check) + 1) > (high)) ? ((check) + 1) : (high)))
#define SELECT_START(list, high)   (high) = 0; FD_ZERO(list)
#define SELECT_ADD(list, fd, high) FD_SET((fd), (list)); SET_HIGH_FD((fd), (high))

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

typedef struct
{
    uint32_t     id;
    int8_t       type;
    int          accept_socket;
    int          listen_socket;
    char         payload[MAX_BUFFER_SIZE];
    unsigned int send_count;
    unsigned int receive_count;
    uint16_t     local_port;
    uint16_t     remote_port;
} s_cf_socket;

char        client_name[MAX_BUFFER_SIZE] = "";
const char  *VERSION = "v4.0";
char        control_path[MAX_BUFFER_SIZE] = "";
int         control_listen, tunnel_in, tunnel_out;
time_t      packet_read_time, packet_send_time;

int send_buffer(int socket, const char *buf, int len);

#include "common.h"

int event_handle(fd_set *p_fd_list);
int event_handle_control(int control_accept, char *buf);
void event_handle_local_accept(s_cf_socket *cf_socket);
void event_handle_local_data(s_cf_socket *cf_socket);
int do_select(int high_fd, fd_set *read_list, int usec, char *msg);
void set_pid(const char *control_path);
int bind_port(s_cf_socket *cf_socket);
int bind_uds(const char *control_path);
char *get_arg(const char *buf, const int n, const int terminate);

int main(int argc, char *argv[])
{
    int opt, result;
    char *env = getenv("SSL_CLIENT_DN"); // also available SSL_CLIENT_I_DN
    if (!env)
        return -1;
    char *cn = strstr(env, "/CN=");
    if (!cn && !(cn = strstr(env, " CN=")))
        return -2;

    # this assumes that CN is at end of SSL_CLIENT_DN; better to look for CN=\w+
    strncpy(client_name, &cn[4], MAX_BUFFER_SIZE);
    char *client_name_check = strchr(client_name, '/');
    if (client_name_check)
        *client_name_check = 0;

    while ((opt = getopt(argc, argv, "p:l:")) != -1)
    {
        if (optarg)
        {
            switch (opt)
            {
                case 'p':
                    // path for uds control files eg "/usr/var/stunnel/pipes"
                    strncpy(control_path, optarg, MAX_BUFFER_SIZE);
                    if (control_path[strlen(control_path) - 1] != '/')
                        strncat(control_path, "/", MAX_BUFFER_SIZE);
                    break;

                case 'l':
                    // log dir eg "/var/log/stunnel"
                    strncpy(log_file, optarg, MAX_BUFFER_SIZE);
                    strncat(log_file, "/cf-", MAX_BUFFER_SIZE);
                    strncat(log_file, client_name, MAX_BUFFER_SIZE);
                    strncat(log_file, ".log", MAX_BUFFER_SIZE);
                    break;
            }
        }
    }

    if (!control_path[0])
    {
        print_log("main: pipe dir missing; exiting");
        return -3;
    }

    strncat(control_path, client_name, MAX_BUFFER_SIZE);

    result = remove(control_path);

    if (result < 0 && errno != ENOENT)
    {
        print_log("main: can't remove socket error %d; exiting", result);
        return -4;
    }

    umask(0);

    setvbuf(stdin, (char *) NULL, _IONBF, 0);
    setvbuf(stdout, (char *) NULL, _IONBF, 0);

    tunnel_in = fileno(stdin);
    tunnel_out = fileno(stdout);

    control_listen = bind_uds(control_path);

    if (control_listen < 0)
    {
        print_log("main: client %s already connected; exiting", client_name);
        return -5;
    }
    else if (!control_listen)
    {
        print_log("main: can't bind client %s; exiting", client_name);
        return -6;
    }

    set_pid(control_path);

    print_log("main: cf-server launched for client '%s'", client_name);
    print_log("main: all sanity checks passed; entering event loop");

    clear(cf_socket_list, sizeof(cf_socket_list));

    packet_send_time = time(NULL);
    packet_read_time = time(NULL);

    for (;;)
    {
        s_cf_socket *cf_socket;
        int          check_socket;
        int          high_fd;
        fd_set       fd_list;

        SELECT_START(&fd_list, high_fd);
// xxx add semaphore for exec commands. do not listen for any commands while an exec is in flight
// xxx either that or when an exec is running, wait for a first response packet before accepting other commands
// xxx or simply delay any other commands for a fixed length of time
        SELECT_ADD(&fd_list, control_listen, high_fd);
        SELECT_ADD(&fd_list, tunnel_in, high_fd);
        for (uint32_t pos = 0; pos <= cf_socket_idx; pos++)
            if ((cf_socket = cf_socket_list[pos]) && ((check_socket = cf_socket->accept_socket) || (check_socket = cf_socket->listen_socket)))
            {
                SELECT_ADD(&fd_list, check_socket, high_fd);
            }

        int select_count = do_select(high_fd, &fd_list, 100000, "wait all");

        if (select_count > 0)
        {
            if (event_handle(&fd_list) < 0)
            {
                // xxx error
                print_log("ERROR 1");
                break;
            }
        }
        else if (!select_count)
        {
// xxx reduce semaphore count by 1 until 0
        }
        else
        {
            // xxx error
            print_log("ERROR 2");
            break;
        }

        if ((time(NULL) - packet_read_time) > 35)
        {
            // xxx 35 sec timeout hard-coded
            print_log("main: network timeout (%d seconds); exiting", time(NULL) - packet_read_time);
            break;
        }

        if ((time(NULL) - packet_send_time) > 25)
            send_packet(0, CF_PACKET_PING, NULL, 0); // send keepalive packet every 25 secs - xxx hard-coded
    }

    print_log("main: event loop terminated; cleaning up");

// xxx move shutdown code to atexit() function
    for (unsigned int pos = 0; pos <= cf_socket_idx; pos++)
        if (cf_socket_list[pos])
            cf_socket_free(cf_socket_list[pos]);

    unlink(control_path);
    remove(control_path);

    return 0;
}

int event_handle(fd_set *p_fd_list)
{
    int                result;
    uint32_t           pos;
    s_cf_socket       *cf_socket;
    char               buf[MAX_PACKET_SIZE];

    clear(buf, sizeof(buf));

    print_log("event_handle: start");

    ///////////////////////////////////////////////////////////////////////
    // data from local ports
    ///////////////////////////////////////////////////////////////////////

    for (pos = 0; pos <= cf_socket_idx; pos++)
        if ((cf_socket = cf_socket_list[pos]))
        {
            if (cf_socket->listen_socket && FD_ISSET(cf_socket->listen_socket, p_fd_list))
                event_handle_local_accept(cf_socket);
            else if (cf_socket->accept_socket && FD_ISSET(cf_socket->accept_socket, p_fd_list))
                event_handle_local_data(cf_socket);
        }

    ///////////////////////////////////////////////////////////////////////
    // data from remote client
    ///////////////////////////////////////////////////////////////////////

    if (FD_ISSET(tunnel_in, p_fd_list))
    {
        print_log("event_handle: client data received");

        for (;;)
        {
// xxx is this select() even needed? always wait for a complete packet to be received
            int          high_fd;
            fd_set       fd_list;

            SELECT_START(&fd_list, high_fd);
            SELECT_ADD(&fd_list, tunnel_in, high_fd);
            if (do_select(high_fd, &fd_list, 10000, "wait tunnel") <= 0)
                break;

            if ((result = read(tunnel_in, buf, sizeof(buf))) <= 0)
            {
                // tunnel is closed, exit
                print_log("event_handle: exit; read result=%d, errno=%d", result, errno);
                return errno || result < 0 ? -1 : 0;
            }

            if (!queue_put(buf, result))
            {
                print_log("event_handle: queue_put error");
                break;
            }

            if (queue_check())
                break;

            // a whole packet was not received, retry once to see if the next read will complete it
            print_log("event_handle: incomplete or bad packet");
        }
    }

    s_cf_packet *cf_packet;
    int          queue_loop_exit = 0;

    while (!queue_loop_exit && (cf_packet = queue_get()))
    {
        print_log("event_handle: client data id=%d, type=%d, len=%d", cf_packet->id, cf_packet->type, cf_packet->len);

        packet_read_time = time(NULL);

        s_cf_socket *cf_socket;

        switch (cf_packet->type)
        {
            case CF_PACKET_DISCONNECT:
                print_log("event_handle: client-side disconnect");
// xxx end semaphore if exec socket
                if ((cf_socket = cf_socket_find(cf_packet->id)))
                    cf_socket_free(cf_socket);
                else
                    print_log("event_handle: client-side packet with bad id");
                break;
            case CF_PACKET_DATA:
                print_log("event_handle: client-side data");
// xxx end semaphore if exec socket
                if ((cf_socket = cf_socket_find(cf_packet->id)))
                {
                    if (cf_socket->accept_socket)
                    {
                        cf_socket->receive_count += cf_packet->len;
                        send_buffer(cf_socket->accept_socket, (const char *) PACKET_PAYLOAD(cf_packet), cf_packet->len);
                    }
                    else
                    {
// xxx if accept_socket not set yet, then put packet back on queue
// if !queue_check() then set break_while_loop = 1;
// queue_put(cf_socket, PACKET_SIZE(cf_socket));
// if break_while_loop then break out of loop to avoid processing the packet over and over
// xxx problem if this messes up packet order for the stream; solution will be to redesign packet queue
                        print_log("event_handle: no accept_socket for client-side data");
                        queue_put(cf_socket, PACKET_SIZE(cf_packet));
                        queue_loop_exit = 1;
                    }
                }
                else
                    print_log("event_handle: client-side packet with bad id");
                break;
            case CF_PACKET_PING:
                print_log("event_handle: client-side ping");
                break;
            case CF_PACKET_MESSAGE:
                print_log("event_handle: client-side message");
                // xxx print_log("%.32s", PACKET_PAYLOAD(cf_packet));
                break;
            default:
                print_log("event_handle: client data ERROR UKNOWN OR INVALID TYPE id=%d type=%d", cf_packet->id, cf_packet->type);
                break;
        }

        print_log("event_handle: client data end");
    }

    ///////////////////////////////////////////////////////////////////////
    // data from control socket
    ///////////////////////////////////////////////////////////////////////

    if (FD_ISSET(control_listen, p_fd_list))
    {
        print_log("event_handle: control_listen data received");

        struct sockaddr_un accept_addr;
        socklen_t sockaddr_un_len = sizeof(struct sockaddr_un);
        int control_accept = accept(control_listen, (struct sockaddr *) &accept_addr, &sockaddr_un_len);

        if (control_accept > 0)
        {
            do
            {
                if ((result = read(control_accept, buf, sizeof(buf))) <= 0)
                {
                    errno ?
                        print_log("event_handle: request socket read error %d = %s", errno, strerror(errno)) :
                        print_log("event_handle: request socket has no data; closing");
                    break;
                }

                buf[result] = 0;
                if (buf[result - 1] < 33)
                    buf[result - 1] = 0;

                print_log("event_handle control_accept data: %d '%s'", result, buf);

                if (event_handle_control(control_accept, buf))
                    return -2;

                print_log("event_handle: request processed");
            } while (0);

            print_log("event_handle: closing control_accept socket");
            close(control_accept);
        }
        else
            print_log("event_handle: accept error %d", errno);
    }

    return 0;
}

int event_handle_control(int control_accept, char *buf)
{
    char         msg[MAX_BUFFER_SIZE];
    s_cf_socket *cf_socket;
    char        *arg = strchr(buf, ' ') + 1;

    if (buf[0] == 'C' && buf[1] == 'O')
    {
        // CONNECT local_port host remote_port

        print_log("event_handle_control: CONNECT command received '%s'", arg);

        if ((cf_socket = cf_socket_new()))
        {
// xxx check arg != NULL
            cf_socket->local_port = atoi(get_arg(arg, 0, 1));
            strncpy(cf_socket->payload, get_arg(arg, 1, 1), MAX_BUFFER_SIZE);
            cf_socket->remote_port = atoi(get_arg(arg, 2, 1));
// xxx check payload and local_port and remote_port

            if (!cf_socket->remote_port || bind_port(cf_socket))
            {
                send_buffer(control_accept, "CONNECT FAIL\n", -1);
                cf_socket_free(cf_socket);
            }
            else
            {
                sprintf(msg, "CONNECT SUCCESS %d\n", cf_socket->local_port);
                send_buffer(control_accept, msg, -1);
            }
        }
        else
        {
            // xxx error
            print_log("ERROR 4");
        }
    }
    else if (buf[0] == 'E')
    {
        // EXEC local_port command

        print_log("event_handle_control: EXEC command received '%s'", arg);

        if ((cf_socket = cf_socket_new()))
        {
// xxx check arg != NULL
            cf_socket->type = CF_SOCKET_EXEC;
            cf_socket->local_port = atoi(get_arg(arg, 0, 1));
            strncpy(cf_socket->payload, get_arg(arg, 1, 0), MAX_BUFFER_SIZE);
// xxx check payload and local_port

            if (bind_port(cf_socket))
            {
                send_buffer(control_accept, "EXEC FAIL\n", -1);
                cf_socket_free(cf_socket);
            }
            else
            {
                sprintf(msg, "EXEC SUCCESS %d\n", cf_socket->local_port);
                send_buffer(control_accept, msg, -1);
            }

            // send exec packet here not below because we always want to run the program
            // xxx this is a potential race condition because we could get back data from the exec
            // xxx before the local side connects to the listening socket
// xxx set exec semaphore here
        }
        else
        {
            // xxx error
            print_log("ERROR 5");
        }
    }
    else if (buf[0] == 'F')
    {
        // FILE local_port file_name

        print_log("event_handle_control: FILE command received '%s'", arg);

        if ((cf_socket = cf_socket_new()))
        {
// xxx check arg != NULL
            cf_socket->type = CF_SOCKET_FILE;
            cf_socket->local_port = atoi(get_arg(arg, 0, 1));
            strncpy(cf_socket->payload, get_arg(arg, 1, 0), MAX_BUFFER_SIZE);
// xxx check payload and local_port

            if (bind_port(cf_socket))
            {
                send_buffer(control_accept, "FILE FAIL\n", -1);
                cf_socket_free(cf_socket);
            }
            else
            {
                sprintf(msg, "FILE SUCCESS %d\n", cf_socket->local_port);
                send_buffer(control_accept, msg, -1);
            }
        }
        else
        {
            // xxx error
            print_log("ERROR 6");
        }
    }
    else if (buf[0] == 'C' && buf[1] == 'L')
    {
        print_log("event_handle_control: CLOSE command received");
        send_buffer(control_accept, "CLOSING\n", -1);
        return -1;
    }
    else if (buf[0] == 'P')
    {
        print_log("event_handle_control: PING command received");
        send_packet(0, CF_PACKET_PING, NULL, 0);
    }
    else if (buf[0] == 'L' && buf[0] == 'I')
    {
        print_log("event_handle_control: LIST command received");

        for (uint32_t pos = 0; pos <= cf_socket_idx; pos++)
            if ((cf_socket = cf_socket_list[pos]))
            {
                sprintf(msg, "ID=%d\tLOCAL_PORT=%d\tREMOTE_PORT=%d\tTYPE=%s\tSTATUS=%s\tPAYLOAD=\"%s\"\n",
                        cf_socket->id,
                        cf_socket->local_port,
                        cf_socket->remote_port,
                        (cf_socket->remote_port ? "socket" : "command"),
                        (cf_socket->accept_socket ? "active" : "waiting"),
                        cf_socket->payload);
                send_buffer(control_accept, msg, -1);
            }
    }
    else if (buf[0] == 'L' && buf[0] == 'O')
    {
        print_log("event_handle_control: LOG command received");
        char payload[MAX_BUFFER_SIZE];
        strncpy(payload, get_arg(arg, 0, 1), MAX_BUFFER_SIZE);
        send_packet(0, CF_PACKET_LOG, (void *) payload, strlen(payload) + 1);
    }
    else if (buf[0] == 'S')
    {
        print_log("event_handle_control: STATUS command received");
        sprintf(msg, "LAST_PING=T-%dsec\n", (int) (time(NULL) - packet_read_time));
        send_buffer(control_accept, msg, -1);
    }

    return 0;
}

void event_handle_local_accept(s_cf_socket *cf_socket)
{
    struct sockaddr_in accept_addr;
    socklen_t sockaddr_in_len = sizeof(struct sockaddr_in);

    print_log("event_handle_local_accept: listen socket %d", cf_socket->listen_socket);

    if ((cf_socket->accept_socket = accept(cf_socket->listen_socket, (struct sockaddr *) &accept_addr, &sockaddr_in_len)) < 0)
        print_log("event_handle_local_accept: failed for accept()");
    else
    {
        print_log("event_handle_local_accept: accept %d from listen socket", cf_socket->accept_socket);
        print_log("event_handle_local_accept: setting upstream tunnel for accept socket %d", cf_socket->accept_socket);

        switch (cf_socket->type)
        {
            case CF_SOCKET_PING:
                // ping has no listen socket; do nothing here
                // xxx in fact, this is an error
                break;
            case CF_SOCKET_EXEC:
                send_packet(cf_socket->id, CF_PACKET_EXEC, (void *) cf_socket->payload, strlen(cf_socket->payload) + 1);
                break;
            case CF_SOCKET_FILE:
                send_packet(cf_socket->id, CF_PACKET_FILE, (void *) cf_socket->payload, strlen(cf_socket->payload) + 1);
                break;
            default:
                if (cf_socket->remote_port)
                {
                    char payload[MAX_BUFFER_SIZE];
                    send_packet(cf_socket->id, CF_PACKET_CONNECT, (void *) payload, sprintf(payload, "%s:%d", cf_socket->payload, cf_socket->remote_port) + 1);
                }
                break;
        }
    }

    // we only accept one socket so close listen socket now
    close(cf_socket->listen_socket);
    cf_socket->listen_socket = 0;
}

void event_handle_local_data(s_cf_socket *cf_socket)
{
    char         buf[MAX_BUFFER_SIZE];
    int          result, count = 0;

    print_log("event_handle_local_data: accept socket %d", cf_socket->accept_socket);

    for (;;)
    {
        if ((result = read(cf_socket->accept_socket, buf, sizeof(buf))) <= 0)
        {
            print_log("event_handle_local_data: server-side socket disconnect");
            send_packet(cf_socket->id, CF_PACKET_DISCONNECT, NULL, 0);
            cf_socket_free(cf_socket);
            break;
        }
        else
        {
            print_log("event_handle_local_data: server-side data received %d", result);
            cf_socket->send_count += result;
            send_packet(cf_socket->id, CF_PACKET_DATA, buf, result);
        }

        if (++count > 4)
            break;

        int          high_fd;
        fd_set       fd_list;
        SELECT_START(&fd_list, high_fd);
        SELECT_ADD(&fd_list, cf_socket->accept_socket, high_fd);
        if (do_select(high_fd, &fd_list, 10000, "wait local data") <= 0)
            break;
    }
}

int send_buffer(int socket, const char *buf, int len)
{
    int total_sent = 0;

    if (len < 0)
        len = strlen(buf);

    if (!socket)
    {
        print_log("send_buffer: bad socket descriptor");
        return -1;
    }
    else if (socket < 0)
        socket = tunnel_out; // send to tunnel

    while (len > 0)
    {
// xxx reset send time
        int n = write(socket, buf + total_sent, len);

        if (n < 0)
        {
            errno ?
                print_log("send_buffer: failed to send_buffer data on socket id=%d, errno=%d, errstr=%s", socket ? socket : -1, errno, strerror(errno)) :
                print_log("send_buffer: failed to send_buffer data on socket id=%d", socket ? socket : -1);
            return -1;
        }
        else if (!n)
            print_log("send_buffer: no data written on socket id=%d, requested=%d", socket ? socket : -1, len);
        else if (socket == tunnel_out)
            packet_send_time = time(NULL); // reset the send timeout

        total_sent += n;
        len -= n;
    }

    return 0;
}

void set_pid(const char *control_path)
{
    char pid_path[MAX_BUFFER_SIZE] = "";
    strncpy(pid_path, control_path, MAX_BUFFER_SIZE);
    strncat(pid_path, ".pid", MAX_BUFFER_SIZE);
    FILE *pid_fd = fopen(pid_path, "w");
    fprintf(pid_fd, "%d", getpid());
    fflush(pid_fd);
    fclose(pid_fd);
}

int bind_uds(const char *control_path)
{
    struct sockaddr_un addr;
    clear(&addr, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, control_path);
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);

    if (sock < 0)
    {
        print_log("bind_uds: socket failed");
        return sock;
    }
    else if (bind(sock, (struct sockaddr *) &addr, sizeof(addr.sun_family) + strlen(addr.sun_path)))
    {
        print_log("bind_uds: failed binding to path: %s", control_path);
        close(sock);
        return 0;
    }
    else if (listen(sock, 16))
    {
        print_log("bind_uds: listen failed: %d", errno);
        close(sock);
        return 0;
    }

    struct stat stat_data;
    if (stat(control_path, &stat_data))
    {
        print_log("bind_uds: %s doesn't exist %d", control_path, errno);
        close(sock);
        return 0;
    }

    return sock;
}

int bind_port(s_cf_socket *cf_socket)
{
    struct sockaddr    addr_result;
    struct sockaddr_in addr_in;
    int                result;
    const int          on = 1;
    uint               addr_len = sizeof(addr_result);

    print_log("bind_port %d", cf_socket->local_port);

    clear(&addr_in, sizeof(struct sockaddr_in));

    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = INADDR_ANY;
    addr_in.sin_port = htons(cf_socket->local_port);

    if ((cf_socket->listen_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        print_log("bind_port %d failed for socket()", cf_socket->local_port);
        return -1;
    }

    if (bind(cf_socket->listen_socket, (struct sockaddr *) &addr_in, sizeof(addr_in)) < 0)
    {
        print_log("bind_port %d failed for bind()", cf_socket->local_port);
        close(cf_socket->listen_socket);
        return -2;
    }

    if (!cf_socket->local_port)
    {
        getsockname(cf_socket->listen_socket, &addr_result, &addr_len);
        cf_socket->local_port = ntohs(((struct sockaddr_in *) &addr_result)->sin_port);
    }

    if (setsockopt(cf_socket->listen_socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int)) < 0)
    {
        print_log("bind_port %d failed for setsockopt()", cf_socket->local_port);
        close(cf_socket->listen_socket);
        return -3;
    }

    if ((result = listen(cf_socket->listen_socket, 2)))
    {
        print_log("bind_port %d failed for listen()", cf_socket->local_port);
        close(cf_socket->listen_socket);
        return -4;
    }

    print_log("bind_port local_port=%d remote_port=%d payload={%s}", cf_socket->local_port, cf_socket->remote_port, cf_socket->payload);

    return 0;
}

char *get_arg(const char *buf, const int n, const int terminate)
{
    static char arg[MAX_BUFFER_SIZE];
    char *result = arg;

    strncpy(arg, buf, MAX_BUFFER_SIZE);

    for (int i = 0; i < n; i++)
        result = strchr(result, ' ') + 1;

    if (terminate)
    {
        char *end = strchr(result, ' ');
        if (end)
            *end = 0;
    }

    print_log("arg %d '%s'", n, result);

    return result;
}

int do_select(int high_fd, fd_set *read_list, int usec, char *msg)
{
    struct timeval tv = {0, usec};
    int result = select(high_fd, read_list, NULL, NULL, &tv);

    if (result < 0)
    {
        errno ?
            print_log("do_select: ERROR %s result=%d, errno=%d, errstr=%s", msg, result, errno, strerror(errno)) :
            print_log("do_select: ERROR %s result=%d", msg, result);
    }

    return result;
}

/*
 * xxx modify to work with http://www.fehcom.de/ipnet/ucspi-ssl.html or http://smarden.org/ipsvd/ or http://homepage.ntlworld.com/jonathan.deboynepollard/Softwares/nosh/ or netcat instead of stunnel
 */
