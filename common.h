/*
 * CuttleFish Server and Client Common Include
 * Copyright (C) 2005-2023 Scott Weisman
 * Scott Weisman (sweisman@pobox.com)
 */

typedef struct
{
    int8_t              type;
    uint32_t            id;
    int16_t             len;
} s_cf_packet;

#define with(...)                  for (__VA_ARGS__, *_wth_ = (void *) 1; _wth_; _wth_ = NULL)

#define MAX_PACKET_SIZE            (MAX_BUFFER_SIZE + sizeof(s_cf_packet))
#define QUEUE_BUFFER_SIZE          (MAX_PACKET_SIZE * 64)

#define clear(buf, len)            memset((buf), 0, (len))
#define allot(len)                 memset((malloc(len)), 0, (len))
#define PACKET_PAYLOAD(x)          ((LPVOID) ((x) + 1))
#define PACKET_SIZE(x)             ((unsigned int) (sizeof(s_cf_packet) + (x)->len))

#define CF_PACKET_PING              1
#define CF_PACKET_CONNECT           2
#define CF_PACKET_DISCONNECT        3
#define CF_PACKET_DATA              4
#define CF_PACKET_EXEC              5
// #define CF_PACKET_COMPRESSED_DATA   6 xxx not used
#define CF_PACKET_FILE              7
#define CF_PACKET_MESSAGE           8
#define CF_PACKET_LOG               9
#define CF_PACKET_TYPE_MIN          1
#define CF_PACKET_TYPE_MAX          9

#define CF_SOCKET_EXEC             -1
#define CF_SOCKET_FILE             -2
#define CF_SOCKET_PING             -3

#define CF_SOCKET_MAX               (FD_SETSIZE - 2) // FD_SETSIZE - 1 (for stdin) - 1 (for control socket)

const char  *packet_type[] = {"error0", "PING", "CONNECT", "DISCONNECT", "DATA", "EXEC", "error1", "FILE", "MESSAGE", "LOG"};
char         log_file[MAX_BUFFER_SIZE] = "";
uint32_t     cf_socket_idx = 0;
s_cf_socket *cf_socket_list[CF_SOCKET_MAX];

void print_log(const char *fmt, ...)
{
    static char time_out[MAX_BUFFER_SIZE];
    va_list     argp;

    if (!log_file[0])
        return;

#if defined(CF_CLIENT_WIN)
    if (WaitForSingleObject(mutex_log, INFINITE) != WAIT_OBJECT_0)
        return;
#endif

    time_t log_time = time(NULL);
    strncpy(time_out, asctime(localtime(&log_time)), MAX_BUFFER_SIZE);
    time_out[strlen(time_out) - 1] = 0;

    FILE *fd = fopen(log_file, "a");

#if defined(CF_CLIENT_WIN)
    fprintf(fd, "[%s] ", time_out);
#elif defined(CF_SERVER)
    fprintf(fd, "[%s: %s] ", client_name, time_out);
#endif

    va_start(argp, fmt);
    vfprintf(fd, fmt, argp);
    va_end(argp);
    fprintf(fd, "\n");

    fflush(fd);
    fclose(fd);

#if defined(CF_CLIENT_WIN)
    ReleaseMutex(mutex_log);
#endif
}

#if defined(CF_CLIENT_WIN)
int close_socket(SOCKET sd)
{
    print_log("CLOSE_SOCKET 1");
    shutdown(sd, SD_SEND);
    print_log("CLOSE_SOCKET 2");
    if (closesocket(sd) == SOCKET_ERROR)
        return 0;
    return 1;
}
#endif

int send_packet(uint32_t id, int8_t type, LPVOID data, int len)
{
    s_cf_packet packet;
    int result;

    packet.id = id;
    packet.type = type;
    packet.len = len;

    type == 1 ?
        print_log("send_packet: PING") :
        print_log("send_packet: id=%d, type=%s, data_len=%d, packet_len=%d", id, packet_type[type], len, PACKET_SIZE(&packet));

    if (len && data)
    {
        unsigned char tmp[sizeof(s_cf_packet) + MAX_BUFFER_SIZE];
        memcpy(tmp, &packet, sizeof(s_cf_packet));
        memcpy(&tmp[sizeof(s_cf_packet)], data, len);
        result = send_buffer(-1, (const char *) tmp, PACKET_SIZE(&packet));
    }
    else
        result = send_buffer(-1, (const char *) &packet, sizeof(s_cf_packet));

    if (result)
        print_log("send_packet: SEND BUFFER ERROR -3 id=%d, type=%s, len=%d", id, packet_type[type], len);

    return result;
}

void cf_socket_dump(void)
{
    s_cf_socket *cf_socket;

    for (uint32_t i = 0; i <= cf_socket_idx; i++)
#if defined(CF_CLIENT_WIN)
        if ((cf_socket = cf_socket_list[i]))
            print_log("SOCKET DUMP idx=%d, id=%d, send=%d, receive=%d, term=%d, dis=%d", i, cf_socket->id, cf_socket->send_count, cf_socket->receive_count, cf_socket->terminate, cf_socket->disconnect);
#elif defined(CF_SERVER)
        if ((cf_socket = cf_socket_list[i]))
            print_log("SOCKET DUMP idx=%d, id=%d, send=%d, receive=%d", i, cf_socket->id, cf_socket->send_count, cf_socket->receive_count);
#endif
}

s_cf_socket *cf_socket_find(uint32_t id)
{
    for (uint32_t i = 0; i <= cf_socket_idx; i++)
        if (cf_socket_list[i] && (cf_socket_list[i]->id == id))
            return cf_socket_list[i];

    cf_socket_dump();

    return NULL;
}

void cf_socket_free(s_cf_socket *cf_socket)
{
    if (!cf_socket)
        return;

    print_log("SOCKET FREE CHECK: id=%d, send=%d, receive=%d", cf_socket->id, cf_socket->send_count, cf_socket->receive_count);

    for (uint32_t i = 0; i <= cf_socket_idx; i++)
        if (cf_socket == cf_socket_list[i])
        {
            print_log("SOCKET FREE START");

#if defined(CF_CLIENT_WIN)
            if (cf_socket->socket)
                close_socket(cf_socket->socket);

            if (cf_socket->fp)
                fclose(cf_socket->fp);

            if (cf_socket->hThread)
            {
// can't just wait! must first:
// cf_socket->terminate = 1;
                print_log("CLOSE THREAD A");
                WaitForSingleObject(cf_socket->hThread, INFINITE);
                print_log("CLOSE THREAD B");
                CLOSE_HANDLE(cf_socket->hThread);
                print_log("CLOSE THREAD C");
                CLOSE_HANDLE(cf_socket->hEvent);
                print_log("CLOSE THREAD D");
            }
#elif defined(CF_SERVER)
            if (cf_socket->accept_socket > 0)
                close(cf_socket->accept_socket);
            if (cf_socket->listen_socket > 0)
                close(cf_socket->listen_socket);
#endif

            clear(cf_socket, sizeof(s_cf_socket));
            free(cf_socket);
            cf_socket_list[i] = NULL;

            print_log("SOCKET FREE END");
        }
}

s_cf_socket *cf_socket_new(
#if defined(CF_CLIENT_WIN)
    uint32_t id
#elif defined(CF_SERVER)
    void
#endif
)
{
#if defined(CF_SERVER)
    static uint32_t id = 0;
#elif defined(CF_CLIENT_WIN)
    // xxx this stupid check is here because cf-server currently reuses ids!
    s_cf_socket *cf_socket = cf_socket_find(id);

    if (cf_socket)
    {
        print_log("SOCKET NEW ERROR id=%d", cf_socket->id);
        cf_socket_free(cf_socket);
    }
#endif

    for (uint32_t i = 0; i < CF_SOCKET_MAX; i++)
        if (!cf_socket_list[i])
        {
            if (cf_socket_idx < i)
                cf_socket_idx = i;

            cf_socket_list[i] = (s_cf_socket *) allot(sizeof(s_cf_socket));

            if (cf_socket_list[i])
            {
#if defined(CF_CLIENT_WIN)
                cf_socket_list[i]->id = id;
#elif defined(CF_SERVER)
                cf_socket_list[i]->id = ++id;
#endif
                print_log("SOCKET NEW id=%d, idx=%d, idx_max=%d", cf_socket_list[i]->id, i, cf_socket_idx);
                return cf_socket_list[i];
            }

            return NULL;
        }

    return NULL;
}

static unsigned char queue_buffer[QUEUE_BUFFER_SIZE];
static unsigned int  queue_pos = 0;
static unsigned char packet_buf[sizeof(s_cf_packet) + MAX_BUFFER_SIZE];

void queue_clear(void)
{
    queue_pos = 0;
}

int queue_put(LPVOID in_buf, int in_size)
{
    if (in_size > 0)
    {
        print_log("QUEUE PUT ENTER len=%d, start_pos=%d", in_size, queue_pos);
        memcpy(&queue_buffer[queue_pos], in_buf, in_size);
        queue_pos += in_size;
        print_log("QUEUE PUT EXIT end_pos=%d", queue_pos);

        if (queue_pos >= sizeof(s_cf_packet))
        {
            s_cf_packet          *in_packet = (s_cf_packet *) queue_buffer;
            print_log("QUEUE PUT PACKET id=%d, type=%d, packet_size=%d, payload_size=%d", in_packet->id, in_packet->type, PACKET_SIZE(in_packet), in_packet->len);
        }
    }

    if (queue_pos > QUEUE_BUFFER_SIZE - 2048)
    {
        print_log("QUEUE PUT BLOCKED");
        return 0;
    }

    return 1;
}

int queue_check(void)
{
    s_cf_packet          *in_packet = (s_cf_packet *) queue_buffer;

    if (queue_pos >= PACKET_SIZE(in_packet))
    {
        if ((in_packet->type >= CF_PACKET_TYPE_MIN) && (in_packet->type <= CF_PACKET_TYPE_MAX))
            return 1;

        print_log("CHECK BAD PACKET");
        queue_pos = 0;
    }

    return 0;
}

s_cf_packet *queue_get(void)
{
    if (!queue_check())
        return NULL;

    s_cf_packet          *in_packet = (s_cf_packet *) queue_buffer;
    s_cf_packet          *out_packet = (s_cf_packet *) packet_buf;

    memcpy(packet_buf, queue_buffer, PACKET_SIZE(in_packet));

    print_log("QUEUE GET PACKET id=%d, type=%s, packet_size=%d, payload_size=%d", out_packet->id, packet_type[out_packet->type], PACKET_SIZE(out_packet), out_packet->len);

    if (queue_pos > PACKET_SIZE(in_packet))
    {
        unsigned int move_count = queue_pos - PACKET_SIZE(in_packet);
        memmove(queue_buffer, &queue_buffer[PACKET_SIZE(in_packet)], move_count);
        print_log("QUEUE MOVE old_pos=%d, new_pos=%d", queue_pos, move_count);
        queue_pos = move_count;
    }
    else
        queue_pos = 0;

    return out_packet;
}
