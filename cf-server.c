/* Cuttlefish server. Copyright (C) Scott Weisman. */
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <getopt.h>
#include "common.h"
#include "miniz.c"

typedef struct {
    uint32_t id,credit,allowance;
    int listener,fd,type,remote_done,input_done,compress,started;
    unsigned port;
    uint64_t sent,received,progress;
    char path[108],request[CF_MAX_PAYLOAD];
    cf_buffer output;
} stream;
typedef struct {
    int fd,ready,close_server;
    size_t used;
    uint64_t progress;
    char input[CF_MAX_PAYLOAD+1];
    cf_buffer output;
} controller;
typedef struct { uint32_t id; char text[CF_MAX_PAYLOAD]; } outcome;
static stream streams[CF_MAX_STREAMS];
static controller controls[16];
static outcome results[CF_MAX_STREAMS];
static unsigned result_pos;
static uint32_t next_id;
static size_t budget;
static cf_buffer tunnel_output;
static cf_decoder decoder;
static int v2=1,unflagged,listener=-1,lock_fd=-1,dir_fd=-1,owns_path;
static volatile sig_atomic_t stopping;
static char control_path[108],pid_path[128],log_path[1024],data_dir[108];
static struct stat owned;
static uint64_t last_read,last_write;

static uint64_t now_ms(void)
{ struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t); return (uint64_t)t.tv_sec*1000+t.tv_nsec/1000000; }
static void signal_stop(int sig) { (void)sig; stopping=1; }
static int nonblock(int fd)
{ int f=fcntl(fd,F_GETFL); return f>=0 && fcntl(fd,F_SETFL,f|O_NONBLOCK)>=0 && fcntl(fd,F_SETFD,FD_CLOEXEC)>=0; }
static int packet(unsigned type,uint32_t id,const void *data,size_t n)
{
    cf_packet p; unsigned char wire[CF_MAX_PAYLOAD+16]; size_t count;
    if(n>CF_MAX_PAYLOAD) return 0;
    p.type=type; p.id=id; p.len=(unsigned)n; if(n) memcpy(p.data,data,n);
    if(!cf_packet_valid(&p,v2,unflagged)) return 0;
    count=cf_encode(wire,&p,v2);
    if(!cf_buffer_add(&tunnel_output,wire,count,CF_STREAM_LIMIT,&budget)) { stopping=1; return 0; }
    return 1;
}
static void remember(uint32_t id,const char *text)
{
    for(unsigned i=0;i<CF_MAX_STREAMS;i++) if(results[i].id==id) { cf_copy(results[i].text,sizeof(results[i].text),text); return; }
    outcome *o=&results[result_pos++%CF_MAX_STREAMS]; o->id=id; cf_copy(o->text,sizeof(o->text),text);
}
static stream *find_stream(uint32_t id)
{ for(unsigned i=0;i<CF_MAX_STREAMS;i++) if(streams[i].id==id) return &streams[i]; return NULL; }
static void release_stream(stream *s)
{
    if(s->listener>=0) close(s->listener);
    if(s->fd>=0) close(s->fd);
    if(*s->path) unlink(s->path);
    cf_buffer_free(&s->output,&budget); memset(s,0,sizeof(*s)); s->listener=s->fd=-1;
}
static void cancel_stream(stream *s,const char *why)
{ remember(s->id,why); packet(v2?CF_CANCEL:CF_DISCONNECT,s->id,NULL,0); release_stream(s); }
static int uds(const char *path)
{
    struct sockaddr_un a; int fd;
    memset(&a,0,sizeof(a)); a.sun_family=AF_UNIX;
    if(!cf_copy(a.sun_path,sizeof(a.sun_path),path)) return -1;
    fd=socket(AF_UNIX,SOCK_STREAM,0); if(fd<0) return -1;
    if(!nonblock(fd)||bind(fd,(struct sockaddr *)&a,sizeof(a))||chmod(path,0600)||listen(fd,16)) { close(fd); return -1; }
    return fd;
}
static int operation_listener(stream *s)
{
    if(v2) {
        int n=snprintf(s->path,sizeof(s->path),"%s/%u",data_dir,s->id);
        if(n<0 || (size_t)n>=sizeof(s->path)) return 0;
        s->listener=uds(s->path);
    } else {
        struct sockaddr_in a; socklen_t n=sizeof(a);
        memset(&a,0,sizeof(a)); a.sin_family=AF_INET;
        a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=htons((uint16_t)s->port);
        s->listener=socket(AF_INET,SOCK_STREAM,0);
        if(s->listener<0||!nonblock(s->listener)||bind(s->listener,(struct sockaddr *)&a,sizeof(a))||listen(s->listener,1)||getsockname(s->listener,(struct sockaddr *)&a,&n)) return 0;
        s->port=ntohs(a.sin_port);
    }
    return s->listener>=0;
}
static int begin_stream(stream *s)
{
    unsigned char b[CF_MAX_PAYLOAD]; size_t n=strlen(s->request)+1,off=unflagged?0:1;
    if(n+off>sizeof(b)) return 0;
    b[0]=(unsigned char)s->compress; memcpy(b+off,s->request,n);
    s->started=1; return packet((unsigned)s->type,s->id,b,n+off);
}
static void reply(controller *c,const char *text)
{ if(!cf_buffer_add(&c->output,text,strlen(text),128*1024,&budget)) c->ready=1; }
static void command(controller *c)
{
    char *rest=c->input,*verb=cf_word(&rest),msg[1400]; uint64_t port; unsigned type=0;
    c->ready=1;
    if(!strcmp(verb,"STATUS") && !*rest) {
        snprintf(msg,sizeof(msg),"LAST_PING=T-%llusec PROTOCOL=%s\n",(unsigned long long)((now_ms()-last_read)/1000),v2?"v2":"legacy"); reply(c,msg); return;
    }
    if(!strcmp(verb,"CLOSE") && !*rest) { reply(c,"CLOSING\n"); c->close_server=1; return; }
    if(!strcmp(verb,"PING") && !*rest) { packet(CF_PING,0,NULL,0); reply(c,"PING SENT\n"); return; }
    if(!strcmp(verb,"LIST") && !*rest) {
        for(unsigned i=0;i<CF_MAX_STREAMS;i++) if(streams[i].id) {
            stream *s=&streams[i];
            snprintf(msg,sizeof(msg),"ID=%u\tLOCAL_PORT=%u\tSTATUS=%s\tPAYLOAD=\"%s\"\n",s->id,s->port,s->fd>=0?"active":"waiting",s->request); reply(c,msg);
        }
        return;
    }
    if(!strcmp(verb,"RESULT") && v2) {
        uint64_t id; if(!cf_number(rest,&id)||!id||id>UINT32_MAX) goto invalid;
        for(unsigned i=0;i<CF_MAX_STREAMS;i++) if(results[i].id==id) { reply(c,results[i].text); reply(c,"\n"); return; }
        reply(c,find_stream((uint32_t)id)?"PENDING\n":"ERROR UNKNOWN ID\n"); return;
    }
    if(!strcmp(verb,"CANCEL") && v2) {
        uint64_t id; stream *s; if(!cf_number(rest,&id)||!id||id>UINT32_MAX) goto invalid;
        s=find_stream((uint32_t)id); if(s) cancel_stream(s,"ERROR CANCELLED");
        reply(c,s?"OK CANCELLED\n":"ERROR UNKNOWN ID\n"); return;
    }
    if(!strcmp(verb,"LOG") && (!strcmp(rest,"0")||!strcmp(rest,"1"))) { packet(CF_LOG,0,rest,2); reply(c,"LOG SENT\n"); return; }
    if(!strcmp(verb,"EXEC")) type=CF_EXEC;
    else if(!strcmp(verb,"CONNECT")) type=CF_CONNECT;
    else if(!strcmp(verb,"FILE") && !v2) type=CF_FILE;
    else if(!strcmp(verb,"GET") && v2) type=CF_GET;
    else if(!strcmp(verb,"PUT") && v2) type=CF_PUT;
    if(!type||!cf_number(cf_word(&rest),&port)||port>65535||(v2&&port)) goto invalid;
    int compress=0;
    if(!strncmp(rest,"--compress ",11)) { if(unflagged) goto invalid; compress=1; rest+=11; }
    if(!*rest) goto invalid;
    if(type==CF_CONNECT) {
        char *host=cf_word(&rest),*p=cf_word(&rest); uint64_t remote;
        if(!*host||strchr(host,':')||*rest||!cf_number(p,&remote)||!remote||remote>65535) goto invalid;
        if(snprintf(msg,sizeof(msg),"%s:%u",host,(unsigned)remote)>=(int)CF_MAX_PAYLOAD-2) goto invalid;
        rest=msg;
    }
    if(strlen(rest)+1+(unflagged?0:1)>CF_MAX_PAYLOAD) goto invalid;
    stream *s=NULL;
    for(unsigned i=0;i<CF_MAX_STREAMS;i++) if(!streams[i].id) { s=&streams[i]; break; }
    if(!s) { reply(c,"ERROR OPERATION LIMIT\n"); return; }
    do { next_id++; } while(!next_id||find_stream(next_id));
    memset(s,0,sizeof(*s)); s->id=next_id; s->fd=s->listener=-1;
    s->type=(int)type; s->port=(unsigned)port; s->compress=compress;
    s->credit=s->allowance=CF_WINDOW; s->progress=now_ms(); cf_copy(s->request,sizeof(s->request),rest);
    if(!operation_listener(s)) { release_stream(s); reply(c,"ERROR LISTENER\n"); return; }
    if(v2) snprintf(msg,sizeof(msg),"%s SUCCESS %u %s\n",verb,s->id,s->path);
    else snprintf(msg,sizeof(msg),"%s SUCCESS %u\n",verb,s->port);
    reply(c,msg);
    if(type!=CF_CONNECT && !begin_stream(s)) cancel_stream(s,"ERROR REQUEST");
    return;
invalid: reply(c,"ERROR INVALID COMMAND\n");
}
static int handle_packet(cf_packet *p)
{
    stream *s=find_stream(p->id); const unsigned char *data=p->data; size_t n=p->len;
    unsigned char expanded[CF_MAX_PAYLOAD]; last_read=now_ms();
    if(p->type==CF_PING||p->type==CF_MESSAGE) return 1;
    if(p->type!=CF_DATA&&p->type!=CF_COMPRESSED&&p->type!=CF_DISCONNECT&&p->type!=CF_RESULT&&p->type!=CF_CREDIT&&p->type!=CF_CANCEL) return 0;
    if(!s) return 1;
    if(p->type==CF_CREDIT) { uint32_t credit=cf_u32(data); if(credit>CF_WINDOW-s->credit) return 0; s->credit+=credit; return 1; }
    if(p->type==CF_RESULT) { remember(p->id,(const char *)data); return 1; }
    if(p->type==CF_CANCEL) { remember(p->id,"ERROR REMOTE CANCELLED"); release_stream(s); return 1; }
    if(p->type==CF_DISCONNECT) { s->remote_done=1; return 1; }
    if(s->remote_done) return 0;
    if(p->type==CF_COMPRESSED) {
        mz_ulong size=sizeof(expanded);
        if(unflagged||mz_uncompress(expanded,&size,data,(mz_ulong)n)!=MZ_OK||!size) return 0;
        data=expanded; n=size;
    }
    if(v2) { if(n>s->allowance) return 0; s->allowance-=(uint32_t)n; }
    if(!cf_buffer_add(&s->output,data,n,CF_STREAM_LIMIT,&budget)) { cancel_stream(s,"ERROR OUTPUT LIMIT"); return 1; }
    s->received+=n; return 1;
}
static void close_control(controller *c)
{
    if(c->fd>=0) {
        /* Drain already-sent excess input so a rejected overlong command does
         * not turn its error reply into a reset. Never wait for more input. */
        char discard[4096];
        for(unsigned i=0;i<16;i++) if(read(c->fd,discard,sizeof(discard))<=0) break;
        close(c->fd);
    }
    cf_buffer_free(&c->output,&budget); memset(c,0,sizeof(*c)); c->fd=-1;
}
static void cleanup(void)
{
    for(unsigned i=0;i<CF_MAX_STREAMS;i++) if(streams[i].id) release_stream(&streams[i]);
    for(unsigned i=0;i<16;i++) close_control(&controls[i]);
    cf_buffer_free(&tunnel_output,&budget); if(listener>=0) close(listener);
    struct stat current;
    if(owns_path&&!lstat(control_path,&current)&&current.st_dev==owned.st_dev&&current.st_ino==owned.st_ino) unlink(control_path);
    if(owns_path) unlink(pid_path);
    if(*data_dir) rmdir(data_dir);
    if(lock_fd>=0) close(lock_fd); /* Keep the lock inode: waiters can hold it. */
    if(dir_fd>=0) close(dir_fd);
}
static int setup(const char *directory)
{
    struct stat st; char name[65],lock_path[128]; const char *dn=getenv("SSL_CLIENT_DN"),*cn; size_t n;
    if(!dn) return 0;
    cn=strstr(dn,"/CN="); if(!cn) cn=strstr(dn," CN="); if(!cn) return 0;
    cn+=4; n=strcspn(cn,"/,"); if(!n||n>=sizeof(name)) return 0;
    for(size_t i=0;i<n;i++) if(!isalnum((unsigned char)cn[i])&&cn[i]!='_'&&cn[i]!='-'&&cn[i]!='.') return 0;
    memcpy(name,cn,n); name[n]=0; if(!strcmp(name,".")||!strcmp(name,"..")) return 0;
    dir_fd=open(directory,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(dir_fd<0||fstat(dir_fd,&st)||st.st_uid!=geteuid()||(st.st_mode&0077)||fchdir(dir_fd)) return 0;
    cf_copy(control_path,sizeof(control_path),name); snprintf(lock_path,sizeof(lock_path),"%s.lock",name);
    lock_fd=open(lock_path,O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC,0600);
    if(lock_fd<0||fstat(lock_fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||st.st_nlink!=1||(st.st_mode&0077)||flock(lock_fd,LOCK_EX|LOCK_NB)) return 0;
    if(!lstat(control_path,&st)) { if(!S_ISSOCK(st.st_mode)||st.st_uid!=geteuid()||unlink(control_path)) return 0; }
    else if(errno!=ENOENT) return 0;
    listener=uds(control_path); if(listener<0||lstat(control_path,&owned)) return 0; owns_path=1;
    snprintf(pid_path,sizeof(pid_path),"%s.pid",name);
    int fd=open(pid_path,O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600); if(fd<0) return 0;
    char pid[32]; int size=snprintf(pid,sizeof(pid),"%ld\n",(long)getpid());
    int ok=write(fd,pid,(size_t)size)==size; close(fd); if(!ok) return 0;
    if(v2) {
        char absolute[4096];
        if(!getcwd(absolute,sizeof(absolute))||strpbrk(absolute,"\r\n")||
           snprintf(data_dir,sizeof(data_dir),"%s/.cf-XXXXXX",absolute)>=(int)sizeof(data_dir)-12||!mkdtemp(data_dir)) { data_dir[0]=0; return 0; }
    }
    return nonblock(0)&&nonblock(1);
}
int main(int argc,char **argv)
{
    const char *directory=NULL,*logdir=NULL; int opt;
    static const struct option options[]={{"protocol",required_argument,NULL,'P'},{NULL,0,NULL,0}};
    for(unsigned i=0;i<16;i++) controls[i].fd=-1;
    for(unsigned i=0;i<CF_MAX_STREAMS;i++) streams[i].fd=streams[i].listener=-1;
    while((opt=getopt_long(argc,argv,"p:l:zP:",options,NULL))!=-1) {
        if(opt=='p') directory=optarg;
        else if(opt=='l') logdir=optarg;
        else if(opt=='z') unflagged=1;
        else if(opt=='P'&&(!strcmp(optarg,"legacy")||!strcmp(optarg,"v2"))) v2=!strcmp(optarg,"v2");
        else return 2;
    }
    if(!directory||(unflagged&&v2)) { fprintf(stderr,"use -p PRIVATE_DIR --protocol v2|legacy [-z]\n"); return 2; }
    if(logdir&&snprintf(log_path,sizeof(log_path),"%s/cf-server.log",logdir)>=(int)sizeof(log_path)) return 2;
    umask(0077); atexit(cleanup); signal(SIGPIPE,SIG_IGN); signal(SIGTERM,signal_stop); signal(SIGINT,signal_stop);
    if(!setup(directory)) { fprintf(stderr,"cuttlefish: unsafe configuration, duplicate session, or socket setup failure\n"); return 2; }
    last_read=last_write=now_ms();
    while(!stopping) {
        struct pollfd fds[3+16+CF_MAX_STREAMS]; unsigned count=3; int ci[16],si[CF_MAX_STREAMS];
        fds[0]=(struct pollfd){0,POLLIN,0}; fds[1]=(struct pollfd){1,tunnel_output.len?POLLOUT:0,0}; fds[2]=(struct pollfd){listener,POLLIN,0};
        for(unsigned i=0;i<16;i++) { ci[i]=-1; controller *c=&controls[i]; if(c->fd>=0) { ci[i]=(int)count; fds[count++]=(struct pollfd){c->fd,c->ready?POLLOUT:POLLIN,0}; } }
        for(unsigned i=0;i<CF_MAX_STREAMS;i++) {
            si[i]=-1; stream *s=&streams[i]; if(!s->id) continue;
            short events=s->listener>=0?POLLIN:0;
            if(s->fd>=0) {
                if(!s->input_done&&!s->remote_done&&(!v2||s->credit)&&tunnel_output.len<CF_STREAM_LIMIT/2) events|=POLLIN;
                if(s->output.len) events|=POLLOUT;
            }
            si[i]=(int)count; fds[count++]=(struct pollfd){s->fd>=0?s->fd:s->listener,events,0};
        }
        int ready=poll(fds,count,100); if(ready<0) { if(errno==EINTR) continue; break; }
        if(fds[0].revents&(POLLIN|POLLHUP|POLLERR)) {
            unsigned char b[8192]; ssize_t n=read(0,b,sizeof(b)); if(!n) break;
            if(n<0&&errno!=EAGAIN&&errno!=EINTR) break;
            if(n>0&&!cf_feed(&decoder,b,(size_t)n)) break;
            cf_packet p; int decoded;
            while((decoded=cf_decode(&decoder,&p,v2,unflagged))>0) if(!handle_packet(&p)) { stopping=1; break; }
            if(decoded<0) break;
        }
        if(fds[1].revents&(POLLERR|POLLHUP)) break;
        if(fds[1].revents&POLLOUT) {
            ssize_t n=write(1,tunnel_output.data+tunnel_output.start,tunnel_output.len);
            if(n>0) { cf_buffer_take(&tunnel_output,(size_t)n); last_write=now_ms(); }
            else if(n<0&&errno!=EAGAIN&&errno!=EINTR) break;
        }
        if(fds[2].revents&POLLIN) {
            int fd=accept(listener,NULL,NULL); controller *slot=NULL;
            for(unsigned i=0;i<16;i++) if(controls[i].fd<0) { slot=&controls[i]; break; }
            if(fd>=0) { struct ucred cred; socklen_t size=sizeof(cred);
                if(!slot||!nonblock(fd)||getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&cred,&size)||cred.uid!=geteuid()) close(fd);
                else { slot->fd=fd; slot->progress=now_ms(); }
            }
        }
        for(unsigned i=0;i<16;i++) {
            controller *c=&controls[i]; if(c->fd<0) continue;
            short events=ci[i]<0?0:fds[ci[i]].revents;
            if(!c->ready&&(events&(POLLIN|POLLHUP))) {
                ssize_t n=read(c->fd,c->input+c->used,CF_MAX_PAYLOAD-c->used);
                if(n>0) {
                    if(memchr(c->input+c->used,0,(size_t)n)) { reply(c,"ERROR INVALID COMMAND\n"); c->ready=1; }
                    c->used+=(size_t)n; c->input[c->used]=0; c->progress=now_ms(); char *end=strchr(c->input,'\n');
                    if(!c->ready&&end) { *end=0; if(end>c->input&&end[-1]=='\r') end[-1]=0; command(c); }
                    else if(!c->ready&&c->used==CF_MAX_PAYLOAD) { reply(c,"ERROR COMMAND TOO LONG\n"); c->ready=1; }
                } else if(!n) { if(c->used) command(c); else close_control(c); }
                else if(errno!=EAGAIN&&errno!=EINTR) close_control(c);
            }
            if(c->fd>=0&&!c->ready&&c->used&&c->input[c->used-1]==' '&&
               (!strcmp(c->input,"STATUS ")||!strcmp(c->input,"LIST ")||!strcmp(c->input,"CLOSE ")||!strcmp(c->input,"PING "))) command(c);
            /* Historical Perl requests have no record delimiter beyond a final
             * space. Keep a bounded compatibility grace period only in legacy
             * mode. Updated helpers always send newline-delimited requests. */
            if(!v2&&c->fd>=0&&!c->ready&&c->used&&c->input[c->used-1]==' '&&now_ms()-c->progress>=100) {
                while(c->used&&c->input[c->used-1]==' ') c->input[--c->used]=0;
                command(c);
            }
            if(c->fd>=0&&c->ready) {
                if(c->output.len&&(events&POLLOUT)) {
                    ssize_t n=write(c->fd,c->output.data+c->output.start,c->output.len);
                    if(n>0) { cf_buffer_take(&c->output,(size_t)n); c->progress=now_ms(); }
                    else if(n<0&&errno!=EAGAIN&&errno!=EINTR) { close_control(c); continue; }
                }
                if(!c->output.len) { if(c->close_server) stopping=1; close_control(c); }
            }
            if(c->fd>=0&&now_ms()-c->progress>CF_TIMEOUT*1000) close_control(c);
        }
        for(unsigned i=0;i<CF_MAX_STREAMS;i++) {
            stream *s=&streams[i]; if(!s->id) continue;
            int current_fd=s->fd>=0?s->fd:s->listener;
            short events=si[i]<0||fds[si[i]].fd!=current_fd?0:fds[si[i]].revents;
            if(s->listener>=0&&(events&POLLIN)) {
                int fd=accept(s->listener,NULL,NULL);
                if(fd>=0) {
                    if(!nonblock(fd)) close(fd);
                    else { s->fd=fd; close(s->listener); s->listener=-1; s->progress=now_ms();
                        if(!s->started&&!begin_stream(s)) { cancel_stream(s,"ERROR START"); continue; }
                    }
                }
            } else if(s->fd>=0) {
                if(events&POLLOUT) {
                    ssize_t n=write(s->fd,s->output.data+s->output.start,s->output.len);
                    if(n>0) {
                        cf_buffer_take(&s->output,(size_t)n); s->progress=now_ms();
                        if(v2) { unsigned char credit[4]; cf_put32(credit,(uint32_t)n); s->allowance+=(uint32_t)n; packet(CF_CREDIT,s->id,credit,4); }
                    } else if(n<0&&errno!=EAGAIN&&errno!=EINTR) { cancel_stream(s,"ERROR CONSUMER"); continue; }
                }
                if(!s->input_done&&!s->remote_done&&(events&(POLLIN|POLLHUP))) {
                    unsigned char b[CF_MAX_PAYLOAD],compressed[CF_MAX_PAYLOAD+32];
                    size_t limit=v2&&s->credit<sizeof(b)?s->credit:sizeof(b);
                    if(limit&&tunnel_output.len<CF_STREAM_LIMIT/2) {
                        ssize_t n=read(s->fd,b,limit);
                        if(n>0) {
                            mz_ulong size=sizeof(compressed);
                            if(s->compress&&mz_compress2(compressed,&size,b,(mz_ulong)n,MZ_DEFAULT_COMPRESSION)==MZ_OK&&size<(mz_ulong)n) packet(CF_COMPRESSED,s->id,compressed,size);
                            else packet(CF_DATA,s->id,b,(size_t)n);
                            s->sent+=(uint64_t)n; s->progress=now_ms(); if(v2) s->credit-=(uint32_t)n;
                        } else if(!n) {
                            s->input_done=1; packet(v2?CF_FINISH:CF_DISCONNECT,s->id,NULL,0);
                            if(!v2) { release_stream(s); continue; }
                        } else if(errno!=EAGAIN&&errno!=EINTR) { cancel_stream(s,"ERROR INPUT"); continue; }
                    }
                }
            }
            if(s->id&&s->input_done&&(events&POLLHUP)) { cancel_stream(s,"ERROR LOCAL CLOSED"); continue; }
            if(s->remote_done&&s->fd>=0&&!s->output.len) { release_stream(s); continue; }
            if(now_ms()-s->progress>CF_TIMEOUT*1000) cancel_stream(s,"ERROR TIMEOUT");
        }
        if(now_ms()-last_read>35000||(tunnel_output.len&&now_ms()-last_write>30000)) break;
        if(now_ms()-last_write>25000&&!tunnel_output.len) packet(CF_PING,0,NULL,0);
    }
    if(*log_path) { FILE *f=fopen(log_path,"a"); if(f) { fputs("session ended\n",f); fclose(f); } }
    return 0;
}
