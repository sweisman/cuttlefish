/* Shared Windows client runtime. Copyright (C) Scott Weisman. */
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include <ctype.h>
#include "common.h"
#if defined(CF_CYASSL)
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/pem.h>
#include <wolfssl/openssl/evp.h>
#else
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#endif
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
#undef MICROSOFT_WINDOWS_WINBASE_H_DEFINE_INTERLOCKED_CPLUSPLUS_OVERLOADS
#include "miniz.c"
#pragma GCC diagnostic pop

typedef struct {
    uint32_t id,credit,allowance,consumed;
    int type,compress;
    volatile LONG cancel,finished,done;
    HANDLE thread;
    DWORD progress;
    cf_buffer input,output;
    char request[CF_MAX_PAYLOAD],result[256];
    HANDLE guards[256]; unsigned guard_count;
} cf_stream;
static cf_stream *streams[CF_MAX_STREAMS];
static CRITICAL_SECTION buffers;
static size_t budget;
static int v2=1,unflagged;
static int log_enabled=1;
static char cf_path[CF_MAX_PAYLOAD],log_path[CF_MAX_PAYLOAD];
static char roots[16][CF_MAX_PAYLOAD];
static unsigned root_count;
static SOCKET tunnel=INVALID_SOCKET;
static SSL_CTX *tls_context;
static SSL *tls;
static X509 *pinned_certificate;
static cf_decoder decoder;
static cf_buffer wire_queue;
static DWORD last_read,last_write;

static DWORD ticks(void) { return GetTickCount(); }
static int elapsed(DWORD then,unsigned seconds) { return (DWORD)(ticks()-then)>seconds*1000u; }
static void log_error(const char *message)
{ FILE *f; if(log_enabled&&*log_path && (f=fopen(log_path,"a"))) { fprintf(f,"%s (Windows error %lu)\n",message,(unsigned long)GetLastError()); fclose(f); } }
static int cancelled(cf_stream *s) { return InterlockedCompareExchange(&s->cancel,0,0)!=0; }
static int finished(cf_stream *s) { return InterlockedCompareExchange(&s->finished,0,0)!=0; }
static void touch(cf_stream *s) { EnterCriticalSection(&buffers); s->progress=ticks(); LeaveCriticalSection(&buffers); }
static int expired(cf_stream *s)
{ int result; EnterCriticalSection(&buffers); result=elapsed(s->progress,CF_TIMEOUT); LeaveCriticalSection(&buffers); return result; }
static void fail(cf_stream *s,const char *why) { cf_copy(s->result,sizeof(s->result),why); }
static void handle_close(HANDLE *h) { if(*h && *h!=INVALID_HANDLE_VALUE) CloseHandle(*h); *h=NULL; }
static int expand_path(char *dst,size_t cap,const char *src)
{
    char windows[CF_MAX_PAYLOAD],system[CF_MAX_PAYLOAD]; size_t used=0;
    if(!GetWindowsDirectoryA(windows,sizeof(windows))||!GetSystemDirectoryA(system,sizeof(system))) return 0;
    while(*src) {
        const char *replacement=NULL; size_t skip=0,n;
        if(!strncmp(src,"%CFPATH%",8)) { replacement=cf_path; skip=8; }
        else if(!strncmp(src,"%WINDOWS%",9)) { replacement=windows; skip=9; }
        else if(!strncmp(src,"%SYSTEM32%",10)) { replacement=system; skip=10; }
        if(replacement) { n=strlen(replacement); if(n>=cap-used) return 0; memcpy(dst+used,replacement,n); used+=n; src+=skip; }
        else { if(used+1>=cap) return 0; dst[used++]=*src++; }
    }
    dst[used]=0; return 1;
}
static int absolute_path(const char *src,char *dst)
{
    char expanded[CF_MAX_PAYLOAD]; DWORD n;
    if(!expand_path(expanded,sizeof(expanded),src)) return 0;
    for(char *p=expanded;*p;p++) if(*p=='/') *p='\\';
    n=GetFullPathNameA(expanded,CF_MAX_PAYLOAD,dst,NULL);
    if(!n||n>=CF_MAX_PAYLOAD||!isalpha((unsigned char)dst[0])||dst[1]!=':'||dst[2]!='\\'||strchr(dst+2,':')) return 0;
    /* Reject Win32 aliases, wildcards, ADS and ambiguous trailing dot/space components. */
    const char *component=dst+3;
    for(const char *p=component;;p++) if(!*p||*p=='\\') {
        size_t len=(size_t)(p-component);
        if(!len && *p) return 0;
        if(len && (component[len-1]=='.'||component[len-1]==' ')) return 0;
        char base[16]; size_t b=0;
        while(b<len&&component[b]!='.'&&b<sizeof(base)-1) { base[b]=(char)toupper((unsigned char)component[b]); b++; }
        base[b]=0;
        if(!strcmp(base,"CON")||!strcmp(base,"PRN")||!strcmp(base,"AUX")||!strcmp(base,"NUL")||
           (b==4&&(!strncmp(base,"COM",3)||!strncmp(base,"LPT",3))&&base[3]>='1'&&base[3]<='9')) return 0;
        if(!*p) break;
        component=p+1;
    }
    for(const char *p=dst;*p;p++) if((unsigned char)*p<32||strchr("*?\"<>|",*p)) return 0;
    return 1;
}
static int permitted_path(const char *path)
{
#ifdef CF_APRO
    for(unsigned i=0;i<root_count;i++) { size_t n=strlen(roots[i]);
        if(!_strnicmp(path,roots[i],n)&&(path[n]==0||path[n]=='\\')) return 1;
    }
    return 0;
#else
    (void)path; return 1;
#endif
}
/* Hold directory handles without FILE_SHARE_DELETE until operation completion.
 * This prevents ancestor substitution after reparse checks. */
static int guard_path(cf_stream *s,const char *path,int include_final)
{
    char part[CF_MAX_PAYLOAD]; size_t len=strlen(path);
    if(!cf_copy(part,sizeof(part),path)) return 0;
    for(size_t i=3;i<=len;i++) if(part[i]=='\\'||(!part[i]&&include_final)) {
        char save=part[i]; part[i]=0;
        HANDLE h=CreateFileA(part,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,
                             FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,NULL);
        part[i]=save; BY_HANDLE_FILE_INFORMATION info;
        if(h==INVALID_HANDLE_VALUE) return 0;
        if(!GetFileInformationByHandle(h,&info)||(info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT)||s->guard_count==256) { CloseHandle(h); return 0; }
        s->guards[s->guard_count++]=h;
    }
    return 1;
}
static int safe_file(cf_stream *s,const char *src,char *dst,int existing)
{ return absolute_path(src,dst)&&permitted_path(dst)&&guard_path(s,dst,existing); }
static int upload_extension(const char *path)
{
#ifdef CF_APRO
    const char *ext=strrchr(path,'.');
    static const char *allowed[]={".txt",".pdf",".csv",".gif",".png",".jpg",".jpeg",".tif",".tiff"};
    if(!ext) return 0;
    for(unsigned i=0;i<sizeof(allowed)/sizeof(allowed[0]);i++) if(!_stricmp(ext,allowed[i])) return 1;
    return 0;
#else
    (void)path; return 1;
#endif
}
static int worker_send(cf_stream *s,const void *data,size_t n)
{
    while(!cancelled(s)&&!expired(s)) {
        int ok; EnterCriticalSection(&buffers);
        ok=s->input.len+s->output.len+n<=CF_STREAM_LIMIT && cf_buffer_add(&s->output,data,n,CF_STREAM_LIMIT,&budget);
        LeaveCriticalSection(&buffers);
        if(ok) return 1;
        Sleep(10);
    }
    return 0;
}
/* Copy input; caller acknowledges only bytes actually written to its sink. */
static size_t worker_peek(cf_stream *s,unsigned char *data,size_t cap)
{
    size_t n; EnterCriticalSection(&buffers); n=s->input.len<cap?s->input.len:cap;
    if(n) memcpy(data,s->input.data+s->input.start,n);
    LeaveCriticalSection(&buffers); return n;
}
static void worker_consume(cf_stream *s,size_t n)
{
    EnterCriticalSection(&buffers); cf_buffer_take(&s->input,n); s->consumed+=(uint32_t)n; s->progress=ticks(); LeaveCriticalSection(&buffers);
}
static SOCKET connect_host(const char *host,const char *port,cf_stream *s)
{
    struct addrinfo hints,*addresses=NULL,*a; SOCKET fd=INVALID_SOCKET; DWORD start=ticks();
    memset(&hints,0,sizeof(hints)); hints.ai_socktype=SOCK_STREAM; hints.ai_family=AF_UNSPEC;
    if(getaddrinfo(host,port,&hints,&addresses)) return INVALID_SOCKET;
    for(a=addresses;a&&!elapsed(start,CF_TIMEOUT)&&(!s||!cancelled(s));a=a->ai_next) {
        fd=socket(a->ai_family,a->ai_socktype,a->ai_protocol); if(fd==INVALID_SOCKET) continue;
        u_long on=1; if(ioctlsocket(fd,FIONBIO,&on)) { closesocket(fd); fd=INVALID_SOCKET; continue; }
        int result=connect(fd,a->ai_addr,(int)a->ai_addrlen);
        if(!result) break;
        if(WSAGetLastError()==WSAEWOULDBLOCK) {
            while(!elapsed(start,CF_TIMEOUT)&&(!s||!cancelled(s))) {
                fd_set wr,err; struct timeval tv={0,10000}; FD_ZERO(&wr); FD_ZERO(&err); FD_SET(fd,&wr); FD_SET(fd,&err);
                if(select(0,NULL,&wr,&err,&tv)>0) {
                    int error=0,n=sizeof(error);
                    if(!getsockopt(fd,SOL_SOCKET,SO_ERROR,(char *)&error,&n)&&!error) result=0;
                    break;
                }
            }
        }
        if(!result) break;
        closesocket(fd); fd=INVALID_SOCKET;
    }
    freeaddrinfo(addresses); return fd;
}
static void run_connect(cf_stream *s)
{
    char *port=strrchr(s->request,':'); uint64_t number; SOCKET fd;
    if(!port) return;
    *port++=0; if(!cf_number(port,&number)||!number||number>65535) return;
    fd=connect_host(s->request,port,s); if(fd==INVALID_SOCKET) return;
    int shut=0; unsigned char data[CF_MAX_PAYLOAD];
    while(!cancelled(s)&&!expired(s)) {
        size_t n=worker_peek(s,data,sizeof(data));
        if(n) { int sent=send(fd,(const char *)data,(int)n,0);
            if(sent>0) worker_consume(s,(size_t)sent);
            else if(sent==0||WSAGetLastError()!=WSAEWOULDBLOCK) break;
        } else if(finished(s)&&!shut) { shutdown(fd,SD_SEND); shut=1; }
        int got=recv(fd,(char *)data,sizeof(data),0);
        if(got>0) { if(!worker_send(s,data,(size_t)got)) break; touch(s); }
        else if(!got) { fail(s,"OK"); break; }
        else if(WSAGetLastError()!=WSAEWOULDBLOCK) break;
        Sleep(5);
    }
    closesocket(fd);
}
static void run_file(cf_stream *s)
{
    char path[CF_MAX_PAYLOAD],temp[CF_MAX_PAYLOAD]="",*source=s->request;
    unsigned char expected[32],digest[32],data[CF_MAX_PAYLOAD]; uint64_t wanted=0,total=0;
    HANDLE file=INVALID_HANDLE_VALUE; EVP_MD_CTX *hash=NULL; int upload=s->type==CF_PUT,complete=0,temp_owned=0;
    if(upload) {
        char *size=cf_word(&source),*hex=cf_word(&source);
        if(!cf_number(size,&wanted)||strlen(hex)!=64||!*source) { fail(s,"ERROR PUT METADATA"); return; }
        for(unsigned i=0;i<32;i++) { char pair[3]={hex[i*2],hex[i*2+1],0};
            if(!isxdigit((unsigned char)pair[0])||!isxdigit((unsigned char)pair[1])) return;
            expected[i]=(unsigned char)strtoul(pair,NULL,16);
        }
    }
    if(!safe_file(s,source,path,0)) { fail(s,"ERROR PATH DENIED"); return; }
    if(s->type==CF_FILE) {
        DWORD attributes=GetFileAttributesA(path);
        if(attributes==INVALID_FILE_ATTRIBUTES) {
            if(GetLastError()!=ERROR_FILE_NOT_FOUND) return;
            upload=1;
        }
    }
    if(!upload) {
        file=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT,NULL);
        BY_HANDLE_FILE_INFORMATION info;
        if(file==INVALID_HANDLE_VALUE||!GetFileInformationByHandle(file,&info)||
           (info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))) goto done;
        while(!cancelled(s)&&!expired(s)) {
            if(s->type==CF_FILE&&finished(s)) goto done;
            DWORD n=0;
            if(!ReadFile(file,data,sizeof(data),&n,NULL)) goto done;
            if(!n) { complete=1; break; }
            if(!worker_send(s,data,n)) goto done;
        }
    } else {
        if(!upload_extension(path)) { fail(s,"ERROR EXTENSION DENIED"); goto done; }
        if(GetFileAttributesA(path)!=INVALID_FILE_ATTRIBUTES||GetLastError()!=ERROR_FILE_NOT_FOUND) { fail(s,"ERROR DESTINATION EXISTS"); goto done; }
        if(v2) {
            for(unsigned attempt=0;attempt<32;attempt++) {
                int n=snprintf(temp,sizeof(temp),"%s.cf-%lu-%u-%u.tmp",path,(unsigned long)GetCurrentProcessId(),s->id,attempt);
                if(n<0||(size_t)n>=sizeof(temp)) goto done;
                file=CreateFileA(temp,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
                if(file!=INVALID_HANDLE_VALUE) { temp_owned=1; break; }
                if(GetLastError()!=ERROR_FILE_EXISTS) goto done;
            }
            if(file==INVALID_HANDLE_VALUE) { temp[0]=0; goto done; }
            hash=EVP_MD_CTX_new();
            if(!hash||EVP_DigestInit_ex(hash,EVP_sha256(),NULL)!=1) goto done;
        } else file=CreateFileA(path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
        if(file==INVALID_HANDLE_VALUE) goto done;
        while(!cancelled(s)&&!expired(s)) {
            size_t n=worker_peek(s,data,sizeof(data));
            if(n) {
                DWORD written=0;
                if(v2 && (total>wanted||n>wanted-total)) { fail(s,"ERROR SIZE MISMATCH"); goto done; }
                if(!WriteFile(file,data,(DWORD)n,&written,NULL)||!written) goto done;
                if(hash&&EVP_DigestUpdate(hash,data,written)!=1) goto done;
                total+=written; worker_consume(s,written);
            } else if(finished(s)) { complete=1; break; }
            else Sleep(10);
        }
        if(!complete) goto done;
        if(v2) {
            unsigned len=0;
            if(total!=wanted||EVP_DigestFinal_ex(hash,digest,&len)!=1||len!=32||memcmp(digest,expected,32)) { complete=0; fail(s,"ERROR SIZE OR DIGEST MISMATCH"); goto done; }
        }
        if(!FlushFileBuffers(file)) { complete=0; goto done; }
        CloseHandle(file); file=INVALID_HANDLE_VALUE;
        if(v2 && (cancelled(s)||!MoveFileExA(temp,path,MOVEFILE_WRITE_THROUGH))) { complete=0; fail(s,"ERROR PUBLISH"); goto done; }
        temp[0]=0;
    }
done:
    if(file!=INVALID_HANDLE_VALUE) CloseHandle(file);
    if(hash) EVP_MD_CTX_free(hash);
    if(temp_owned&&*temp) DeleteFileA(temp);
    if(complete) fail(s,"OK");
}

#ifdef CF_APRO
/* Deliberately small shell-free grammar. Quotes group arguments; shell syntax
 * and expansion never survive validation. Tool binaries come from -w. */
static int split_command(char *text,char **args,int cap)
{
    char *read=text,*write=text; int count=0;
    for(char *p=text;*p;p++) if((unsigned char)*p<32||strchr("&|<>^%!();",*p)) return -1;
    while(*read) {
        while(*read==' ') read++;
        if(!*read) break;
        if(count==cap) return -1;
        args[count++]=write; int quoted=0;
        while(*read && (quoted||*read!=' ')) {
            if(*read=='"') { quoted=!quoted; read++; }
            else *write++=*read++;
        }
        if(quoted) return -1;
        while(*read==' ') read++;
        *write++=0;
    }
    return count;
}
static int quote_args(char *out,size_t cap,char **args,int count)
{
    size_t used=0;
    for(int i=0;i<count;i++) {
        if(used+3>=cap) return 0;
        if(i) out[used++]=' ';
        out[used++]='"'; size_t n=strlen(args[i]);
        if(n>=cap-used-2) return 0;
        memcpy(out+used,args[i],n); used+=n;
        /* Escape trailing backslashes before the closing quote. */
        while(n && args[i][--n]=='\\') { if(used+2>=cap) return 0; out[used++]='\\'; }
        out[used++]='"';
    }
    out[used]=0; return 1;
}
static int apro_executable(cf_stream *s,const char *name,char *path)
{
    char candidate[CF_MAX_PAYLOAD];
    if(!absolute_path(name,candidate)) return 0;
    const char *base=strrchr(candidate,'\\');
    if(!base) return 0;
    if(!strchr(base,'.')) {
        size_t n=strlen(candidate);
        if(n+4>=sizeof(candidate)) return 0;
        memcpy(candidate+n,".exe",5);
    }
    return safe_file(s,candidate,path,1);
}
static int apro_net_use(char **args,int n)
{
    if(n<2||_stricmp(args[1],"use")) return 0;
    if(n==2) return 1;
    int position=2;
    if(!strcmp(args[position],"*") || (strlen(args[position])==2&&isalpha((unsigned char)args[position][0])&&args[position][1]==':')) position++;
    if(position<n && !strncmp(args[position],"\\\\",2)) {
        const char *host=args[position]+2,*share=strchr(host,'\\');
        if(!share||share==host||!share[1]||strstr(host,"..")) return 0;
        position++;
        if(position<n&&args[position][0]!='/') position++; /* password, passed directly */
    }
    for(;position<n;position++) {
        if(!_stricmp(args[position],"/delete")||!_stricmp(args[position],"/y")||
           !_stricmp(args[position],"/persistent:yes")||!_stricmp(args[position],"/persistent:no")) continue;
        if(!_strnicmp(args[position],"/user:",6)&&args[position][6]) continue;
        return 0;
    }
    return 1;
}
static int apro_path_argument(cf_stream *s,char **argument,char *storage,const char *working,int existing)
{
    const char *value=strchr(*argument,'=');
    size_t prefix=value?(size_t)(value+1-*argument):0;
    value=*argument+prefix;
    char source[CF_MAX_PAYLOAD],resolved[CF_MAX_PAYLOAD];
    if(isalpha((unsigned char)value[0])&&value[1]==':') {
        if(!cf_copy(source,sizeof(source),value)) return 0;
    } else if(snprintf(source,sizeof(source),"%s\\%s",working,value)>=(int)sizeof(source)) return 0;
    if(!safe_file(s,source,resolved,existing)||prefix+strlen(resolved)>=CF_MAX_PAYLOAD) return 0;
    memcpy(storage,*argument,prefix); strcpy(storage+prefix,resolved); *argument=storage; return 1;
}
static int apro_command(cf_stream *s,char *application,char *command,size_t cap,char *working)
{
    char expanded[CF_MAX_PAYLOAD],*args[64],system[CF_MAX_PAYLOAD],path[CF_MAX_PAYLOAD];
    char canonical[64][CF_MAX_PAYLOAD];
    if(!expand_path(expanded,sizeof(expanded),s->request)) return 0;
    int n=split_command(expanded,args,64); if(n<1) return 0;
    if(!GetSystemDirectoryA(system,sizeof(system))) return 0;
    int shell=!_stricmp(args[0],"cmd")||!_stricmp(args[0],"cmd.exe");
    if(shell) {
        if(n<4||_stricmp(args[1],"/c")) return 0;
        if(!_stricmp(args[2],"echo")) {
            /* Fixed interpreter, no user-controlled executable lookup. */
        } else if(!_stricmp(args[2],"dir")) {
            int paths=0;
            for(int i=3;i<n;i++) {
                if(args[i][0]=='/') {
                    if(_stricmp(args[i],"/b")&&_stricmp(args[i],"/s")&&_stricmp(args[i],"/a")&&
                       _stricmp(args[i],"/ad")&&_stricmp(args[i],"/a-d")&&_stricmp(args[i],"/n")&&_stricmp(args[i],"/-c")) return 0;
                } else { if(++paths>1||!apro_path_argument(s,&args[i],canonical[i],working,1)) return 0; }
            }
            if(paths!=1) return 0;
        } else if(!_stricmp(args[2],"start")) {
            /* Translate the documented start form to direct execution. */
            if(n<10||*args[3]||_strnicmp(args[4],"/d",2)||_stricmp(args[5],"/wait")||_stricmp(args[6],"/high")||
               !safe_file(s,args[4]+2,working,1)||!apro_executable(s,args[7],application)) return 0;
            const char *base=strrchr(application,'\\');
            if(!base||(_stricmp(base+1,"formview")&&_stricmp(base+1,"formview.exe"))) return 0;
            for(int i=8;i<n;i++) {
                char *value=strchr(args[i],'='); value=value?value+1:args[i];
                if(strpbrk(value,":\\/.")) if(!apro_path_argument(s,&args[i],canonical[i],working,0)) return 0;
            }
            args[7]=application; return quote_args(command,cap,args+7,n-7);
        } else return 0;
        if(snprintf(application,CF_MAX_PAYLOAD,"%s\\cmd.exe",system)>=(int)CF_MAX_PAYLOAD) return 0;
        /* /d disables registry AutoRun. Quote arguments individually after /c. */
        char tail[CF_MAX_PAYLOAD*2];
        if(!quote_args(tail,sizeof(tail),args+2,n-2)) return 0;
        return snprintf(command,cap,"\"%s\" /d /s /c \"%s\"",application,tail)<(int)cap;
    }
    const char *tool=args[0];
    if(!_stricmp(tool,"whoami")) { if(n!=1) return 0; }
    else if(!_stricmp(tool,"net")) {
        if(!apro_net_use(args,n)) return 0;
    } else if(!_stricmp(tool,"md5sum")||!_stricmp(tool,"zzip1")) {
        if(n!=2||!apro_path_argument(s,&args[1],canonical[1],working,1)) return 0;
    } else if(!_stricmp(tool,"oddie1")||!_stricmp(tool,"zpxdump")) {
        if(n<2) return 0;
        if(!safe_file(s,roots[0],working,1)) return 0;
        for(int i=1;i<n;i++) {
            char *value=strchr(args[i],'='); value=value?value+1:args[i];
            if(strpbrk(value,":\\/.")) if(!apro_path_argument(s,&args[i],canonical[i],working,0)) return 0;
        }
    } else {
        if(!apro_executable(s,tool,application)) return 0;
        const char *base=strrchr(application,'\\');
        if(!base||(_stricmp(base+1,"formview")&&_stricmp(base+1,"formview.exe"))) return 0;
        if(!cf_copy(path,sizeof(path),application)) return 0;
        *strrchr(path,'\\')=0;
        if(!safe_file(s,path,working,1)) return 0;
        for(int i=1;i<n;i++) {
            char *value=strchr(args[i],'='); value=value?value+1:args[i];
            if(strpbrk(value,":\\/.")) if(!apro_path_argument(s,&args[i],canonical[i],working,0)) return 0;
        }
        args[0]=application; return quote_args(command,cap,args,n);
    }
    const char *directory=(!_stricmp(tool,"net")||!_stricmp(tool,"whoami"))?system:cf_path;
    if(snprintf(application,CF_MAX_PAYLOAD,"%s\\%s.exe",directory,tool)>=(int)CF_MAX_PAYLOAD) return 0;
    if(!guard_path(s,application,1)) return 0;
    args[0]=application; return quote_args(command,cap,args,n);
}
#endif
static void run_exec(cf_stream *s)
{
    HANDLE input=NULL,input_child=NULL,out=NULL,out_child=NULL,err=NULL,err_child=NULL,operation_job=NULL;
    STARTUPINFOEXA startup; PROCESS_INFORMATION process; SECURITY_ATTRIBUTES sa={sizeof(sa),NULL,TRUE};
    OVERLAPPED pending; int writing=0,started=0; unsigned char input_data[CF_MAX_PAYLOAD],data[CF_MAX_PAYLOAD];
    char command[CF_MAX_PAYLOAD*4],application[CF_MAX_PAYLOAD]="",pipe_name[128],working[CF_MAX_PAYLOAD];
    SIZE_T attrs=0;
    memset(&startup,0,sizeof(startup)); memset(&process,0,sizeof(process)); memset(&pending,0,sizeof(pending));
    cf_copy(working,sizeof(working),cf_path);
#ifdef CF_APRO
    if(!apro_command(s,application,command,sizeof(command),working)) { fail(s,"ERROR COMMAND DENIED"); return; }
#else
    if(!expand_path(command,sizeof(command),s->request)) return;
#endif
    snprintf(pipe_name,sizeof(pipe_name),"\\\\.\\pipe\\cuttlefish-%lu-%u",(unsigned long)GetCurrentProcessId(),s->id);
    input=CreateNamedPipeA(pipe_name,PIPE_ACCESS_OUTBOUND|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
                          PIPE_TYPE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,4096,4096,0,NULL);
    if(input==INVALID_HANDLE_VALUE) { input=NULL; goto done; }
    input_child=CreateFileA(pipe_name,GENERIC_READ,0,&sa,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(input_child==INVALID_HANDLE_VALUE) { input_child=NULL; goto done; }
    if(!CreatePipe(&out,&out_child,&sa,4096)||!CreatePipe(&err,&err_child,&sa,4096)||
       !SetHandleInformation(out,HANDLE_FLAG_INHERIT,0)||!SetHandleInformation(err,HANDLE_FLAG_INHERIT,0)) goto done;
    pending.hEvent=CreateEvent(NULL,TRUE,FALSE,NULL); if(!pending.hEvent) goto done;
    InitializeProcThreadAttributeList(NULL,1,0,&attrs);
    startup.lpAttributeList=(LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attrs); if(!startup.lpAttributeList) goto done;
    if(!InitializeProcThreadAttributeList(startup.lpAttributeList,1,0,&attrs)) { free(startup.lpAttributeList); startup.lpAttributeList=NULL; goto done; }
    HANDLE inherited[3]={input_child,out_child,err_child};
    if(!UpdateProcThreadAttribute(startup.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),NULL,NULL)) goto done;
    startup.StartupInfo.cb=sizeof(startup); startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput=input_child; startup.StartupInfo.hStdOutput=out_child; startup.StartupInfo.hStdError=err_child;
    operation_job=CreateJobObject(NULL,NULL); if(!operation_job) goto done;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits; memset(&limits,0,sizeof(limits)); limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if(!SetInformationJobObject(operation_job,JobObjectExtendedLimitInformation,&limits,sizeof(limits))) goto done;
    if(!CreateProcessA(*application?application:NULL,command,NULL,NULL,TRUE,
                       CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT|CREATE_NO_WINDOW,NULL,working,&startup.StartupInfo,&process)) goto done;
    started=1;
    if(!AssignProcessToJobObject(operation_job,process.hProcess)||ResumeThread(process.hThread)==(DWORD)-1) goto done;
    handle_close(&input_child); handle_close(&out_child); handle_close(&err_child);
    while(!cancelled(s)&&!expired(s)) {
        DWORD written=0;
        if(writing) {
            if(GetOverlappedResult(input,&pending,&written,FALSE)) { if(!written) goto done; worker_consume(s,written); writing=0; }
            else if(GetLastError()!=ERROR_IO_INCOMPLETE) goto done;
        }
        if(input&&!writing) {
            size_t n=worker_peek(s,input_data,sizeof(input_data));
            if(n) {
                ResetEvent(pending.hEvent);
                if(WriteFile(input,input_data,(DWORD)n,&written,&pending)) { if(!written) goto done; worker_consume(s,written); }
                else if(GetLastError()==ERROR_IO_PENDING) writing=1;
                else goto done;
            } else if(finished(s)) handle_close(&input);
        }
        int any=0;
        for(unsigned channel=0;channel<2;channel++) {
            HANDLE h=channel?err:out; DWORD available=0;
            if(PeekNamedPipe(h,NULL,0,NULL,&available,NULL)&&available) {
                DWORD n=0; if(available>sizeof(data)) available=sizeof(data);
                if(!ReadFile(h,data,available,&n,NULL)) goto done;
                any=1;
                if(!channel&&n&&!worker_send(s,data,n)) goto done;
                touch(s); /* stderr is drained and intentionally discarded. */
            }
        }
        if(WaitForSingleObject(process.hProcess,0)==WAIT_OBJECT_0&&!any) {
            DWORD code=1; GetExitCodeProcess(process.hProcess,&code);
            snprintf(s->result,sizeof(s->result),code?"ERROR EXIT %lu":"OK EXIT %lu",(unsigned long)code); break;
        }
        Sleep(5);
    }
done:
    if(started&&WaitForSingleObject(process.hProcess,0)!=WAIT_OBJECT_0) TerminateProcess(process.hProcess,1);
    handle_close(&operation_job);
    if(writing&&input) { CancelIoEx(input,&pending); WaitForSingleObject(pending.hEvent,5000); }
    handle_close(&input); handle_close(&input_child); handle_close(&out); handle_close(&out_child);
    handle_close(&err); handle_close(&err_child); handle_close(&pending.hEvent);
    handle_close(&process.hProcess); handle_close(&process.hThread);
    if(startup.lpAttributeList) { DeleteProcThreadAttributeList(startup.lpAttributeList); free(startup.lpAttributeList); }
}
static unsigned __stdcall worker(void *arg)
{
    cf_stream *s=(cf_stream *)arg; fail(s,"ERROR OPERATION FAILED");
    if(s->type==CF_CONNECT) run_connect(s);
    else if(s->type==CF_EXEC) run_exec(s);
    else run_file(s);
    for(unsigned i=0;i<s->guard_count;i++) CloseHandle(s->guards[i]);
    if(cancelled(s)) fail(s,"ERROR CANCELLED");
    InterlockedExchange(&s->done,1); return 0;
}
static int packet(unsigned type,uint32_t id,const void *data,size_t n)
{
    cf_packet p; unsigned char wire[CF_MAX_PAYLOAD+16];
    if(n>CF_MAX_PAYLOAD) return 0;
    p.type=type; p.id=id; p.len=(unsigned)n; if(n) memcpy(p.data,data,n);
    if(!cf_packet_valid(&p,v2,unflagged)) return 0;
    size_t len=cf_encode(wire,&p,v2); int ok;
    EnterCriticalSection(&buffers); ok=cf_buffer_add(&wire_queue,wire,len,CF_STREAM_LIMIT,&budget); LeaveCriticalSection(&buffers); return ok;
}
static int reject(uint32_t id,const char *why)
{ return (!v2||packet(CF_RESULT,id,why,strlen(why)+1))&&packet(CF_DISCONNECT,id,NULL,0); }
static int handle_packet(cf_packet *p)
{
    cf_stream *s=NULL; unsigned slot=CF_MAX_STREAMS; last_read=ticks();
    for(unsigned i=0;i<CF_MAX_STREAMS;i++) { if(streams[i]&&streams[i]->id==p->id) s=streams[i]; if(!streams[i]) slot=i; }
    if(p->type==CF_PING) return 1;
    if(p->type==CF_LOG) {
#ifndef CF_APRO
        log_enabled=p->data[0]=='1'; /* Destination remains configuration-only. */
#endif
        return 1;
    }
    if(p->type==CF_CONNECT||p->type==CF_EXEC||p->type==CF_FILE||p->type==CF_GET||p->type==CF_PUT) {
        if(s) return 0;
        if(v2&&p->type==CF_FILE) return 0;
#ifdef CF_APRO
        if(p->type==CF_CONNECT) return reject(p->id,"ERROR CONNECT DENIED");
#endif
        if(slot==CF_MAX_STREAMS) return reject(p->id,"ERROR OPERATION LIMIT");
        s=(cf_stream *)calloc(1,sizeof(*s)); if(!s) return reject(p->id,"ERROR MEMORY");
        s->id=p->id; s->type=(int)p->type; s->credit=s->allowance=CF_WINDOW; s->progress=ticks();
        unsigned off=unflagged?0:1; s->compress=off?p->data[0]:0;
        cf_copy(s->request,sizeof(s->request),(char *)p->data+off);
        s->thread=(HANDLE)_beginthreadex(NULL,0,worker,s,0,NULL);
        if(!s->thread) { free(s); return reject(p->id,"ERROR THREAD"); }
        streams[slot]=s; return 1;
    }
    if(p->type!=CF_DATA&&p->type!=CF_COMPRESSED&&p->type!=CF_DISCONNECT&&p->type!=CF_FINISH&&p->type!=CF_CREDIT&&p->type!=CF_CANCEL) return 0;
    if(!s) return 1;
    if(p->type==CF_CREDIT) { uint32_t credit=cf_u32(p->data); if(credit>CF_WINDOW-s->credit) return 0; s->credit+=credit; return 1; }
    if(p->type==CF_FINISH || (!v2&&p->type==CF_DISCONNECT&&s->type==CF_FILE)) { InterlockedExchange(&s->finished,1); return 1; }
    if(p->type==CF_DISCONNECT||p->type==CF_CANCEL) { InterlockedExchange(&s->cancel,1); CancelSynchronousIo(s->thread); return 1; }
    if(finished(s)) return 0;
    if(InterlockedCompareExchange(&s->done,0,0)||cancelled(s)) return 1;
    unsigned char expanded[CF_MAX_PAYLOAD]; const unsigned char *data=p->data; size_t n=p->len;
    if(p->type==CF_COMPRESSED) {
        mz_ulong size=sizeof(expanded); if(unflagged||mz_uncompress(expanded,&size,data,(mz_ulong)n)!=MZ_OK||!size) return 0;
        data=expanded; n=size;
    }
    if(v2) { if(n>s->allowance) return 0; s->allowance-=(uint32_t)n; }
    EnterCriticalSection(&buffers);
    int ok=s->input.len+s->output.len+n<=CF_STREAM_LIMIT&&cf_buffer_add(&s->input,data,n,CF_STREAM_LIMIT,&budget);
    LeaveCriticalSection(&buffers);
    if(!ok) { InterlockedExchange(&s->cancel,1); CancelSynchronousIo(s->thread); }
    return 1;
}
/* Only this owner accesses SSL, the stream registry, or thread handles. */
static int pump_streams(void)
{
    for(unsigned i=0;i<CF_MAX_STREAMS;i++) {
        cf_stream *s=streams[i]; if(!s) continue;
        if(expired(s)) { InterlockedExchange(&s->cancel,1); CancelSynchronousIo(s->thread); }
        /* Observe worker completion before inspecting output. A worker may
         * otherwise enqueue its final bytes between the empty and done checks. */
        int done=InterlockedCompareExchange(&s->done,0,0)!=0;
        unsigned char data[CF_MAX_PAYLOAD],compressed[CF_MAX_PAYLOAD+32]; size_t n; uint32_t credit;
        EnterCriticalSection(&buffers);
        credit=s->consumed; s->consumed=0;
        n=s->output.len<sizeof(data)?s->output.len:sizeof(data);
        if(v2&&n>s->credit) n=s->credit;
        if(wire_queue.len>CF_STREAM_LIMIT/2) n=0;
        if(cancelled(s)) { cf_buffer_free(&s->output,&budget); n=0; }
        if(n) { memcpy(data,s->output.data+s->output.start,n); cf_buffer_take(&s->output,n); s->progress=ticks(); }
        int empty=s->output.len==0;
        LeaveCriticalSection(&buffers);
        if(v2&&credit) { unsigned char b[4]; cf_put32(b,credit); s->allowance+=credit; if(!packet(CF_CREDIT,s->id,b,4)) return 0; }
        if(n) {
            mz_ulong size=sizeof(compressed); int ok;
            if(s->compress&&mz_compress2(compressed,&size,data,(mz_ulong)n,MZ_DEFAULT_COMPRESSION)==MZ_OK&&size<n) ok=packet(CF_COMPRESSED,s->id,compressed,size);
            else ok=packet(CF_DATA,s->id,data,n);
            if(!ok) return 0;
            if(v2) s->credit-=(uint32_t)n;
        }
        if(done&&empty&&WaitForSingleObject(s->thread,0)==WAIT_OBJECT_0) {
            if(!reject(s->id,cancelled(s)?"ERROR CANCELLED":s->result)) return 0;
            CloseHandle(s->thread); EnterCriticalSection(&buffers);
            cf_buffer_free(&s->input,&budget); cf_buffer_free(&s->output,&budget);
            LeaveCriticalSection(&buffers); free(s); streams[i]=NULL;
        }
    }
    return 1;
}
static int setup_tls(const char *server_cert,const char *client_cert)
{
    SSL_library_init(); SSL_load_error_strings();
    tls_context=SSL_CTX_new(TLS_client_method()); if(!tls_context) return 0;
    if(!SSL_CTX_set_min_proto_version(tls_context,TLS1_2_VERSION)) return 0;
    SSL_CTX_set_verify(tls_context,SSL_VERIFY_PEER,NULL);
    if(SSL_CTX_load_verify_locations(tls_context,server_cert,NULL)!=1||
       SSL_CTX_use_certificate_file(tls_context,client_cert,SSL_FILETYPE_PEM)!=1||
       SSL_CTX_use_PrivateKey_file(tls_context,client_cert,SSL_FILETYPE_PEM)!=1||!SSL_CTX_check_private_key(tls_context)) return 0;
    BIO *file=BIO_new_file(server_cert,"r"); if(!file) return 0;
    pinned_certificate=PEM_read_bio_X509(file,NULL,NULL,NULL); BIO_free(file);
    return pinned_certificate!=NULL;
}
static int handshake(void)
{
    tls=SSL_new(tls_context); if(!tls||SSL_set_fd(tls,(int)tunnel)!=1) return 0;
    DWORD start=ticks();
    while(!elapsed(start,CF_TIMEOUT)) {
        int n=SSL_connect(tls); if(n==1) {
            X509 *peer=SSL_get_peer_certificate(tls);
            int ok=peer&&SSL_get_verify_result(tls)==X509_V_OK&&X509_cmp(peer,pinned_certificate)==0;
            if(peer) X509_free(peer);
            return ok;
        }
        int error=SSL_get_error(tls,n);
        if(error!=SSL_ERROR_WANT_READ&&error!=SSL_ERROR_WANT_WRITE) return 0;
        Sleep(10);
    }
    return 0;
}
static int event_loop(void)
{
    unsigned char pending[CF_MAX_PAYLOAD+16]; size_t pending_len=0;
    last_read=last_write=ticks();
    for(;;) {
        if(!pump_streams()) return 0;
        /* Keep identical address and length across SSL_write WANT retries. */
        if(!pending_len) {
            EnterCriticalSection(&buffers);
            pending_len=wire_queue.len<sizeof(pending)?wire_queue.len:sizeof(pending);
            if(pending_len) { memcpy(pending,wire_queue.data+wire_queue.start,pending_len); cf_buffer_take(&wire_queue,pending_len); }
            LeaveCriticalSection(&buffers);
        }
        if(pending_len) {
            int n=SSL_write(tls,pending,(int)pending_len);
            if(n>0) { if((size_t)n!=pending_len) return 0; pending_len=0; last_write=ticks(); }
            else { int error=SSL_get_error(tls,n); if(error!=SSL_ERROR_WANT_READ&&error!=SSL_ERROR_WANT_WRITE) return 0; }
        }
        unsigned char input[8192]; int n=SSL_read(tls,input,sizeof(input));
        if(n>0) {
            if(!cf_feed(&decoder,input,(size_t)n)) return 0;
            cf_packet p; int result;
            while((result=cf_decode(&decoder,&p,v2,unflagged))>0) if(!handle_packet(&p)) return 0;
            if(result<0) return 0;
        } else { int error=SSL_get_error(tls,n); if(error!=SSL_ERROR_WANT_READ&&error!=SSL_ERROR_WANT_WRITE) return 0; }
        if(elapsed(last_read,35)||(pending_len&&elapsed(last_write,30))) return 0;
        if(elapsed(last_write,25)&&!pending_len&&!wire_queue.len) if(!packet(CF_PING,0,NULL,0)) return 0;
        Sleep(5);
    }
}
static void cleanup(void)
{
    for(unsigned i=0;i<CF_MAX_STREAMS;i++) if(streams[i]) { InterlockedExchange(&streams[i]->cancel,1); CancelSynchronousIo(streams[i]->thread); }
    for(unsigned i=0;i<CF_MAX_STREAMS;i++) if(streams[i]) {
        cf_stream *s=streams[i];
        /* No shared state is freed under a live worker. OS cleanup is the last
         * resort for an uninterruptible third-party filesystem/DNS provider. */
        if(WaitForSingleObject(s->thread,5000)!=WAIT_OBJECT_0) ExitProcess(2);
        CloseHandle(s->thread);
        EnterCriticalSection(&buffers);
        cf_buffer_free(&s->input,&budget); cf_buffer_free(&s->output,&budget);
        LeaveCriticalSection(&buffers);
        free(s);
    }
    cf_buffer_free(&wire_queue,&budget);
    if(tls) SSL_free(tls);
    if(tls_context) SSL_CTX_free(tls_context);
    if(pinned_certificate) X509_free(pinned_certificate);
    if(tunnel!=INVALID_SOCKET) closesocket(tunnel);
    WSACleanup(); DeleteCriticalSection(&buffers);
}
int main(int argc,char **argv)
{
    const char *host=NULL,*port=NULL,*server_arg=NULL,*client_arg=NULL;
    char server_cert[CF_MAX_PAYLOAD],client_cert[CF_MAX_PAYLOAD]; uint64_t number;
    if(!GetCurrentDirectoryA(sizeof(cf_path),cf_path)) return 2;
    for(int i=1;i<argc;i++) {
        const char *option=argv[i];
        if(!strcmp(option,"-z")) { unflagged=1; continue; }
        if(++i==argc) return 2;
        const char *value=argv[i];
        if(!strcmp(option,"-u")) host=value;
        else if(!strcmp(option,"-p")) port=value;
        else if(!strcmp(option,"-s")) server_arg=value;
        else if(!strcmp(option,"-c")) client_arg=value;
        else if(!strcmp(option,"-w")) { if(!cf_copy(cf_path,sizeof(cf_path),value)) return 2; }
        else if(!strcmp(option,"-l")) { if(!cf_copy(log_path,sizeof(log_path),value)) return 2; }
        else if(!strcmp(option,"--protocol")||!strcmp(option,"-P")) {
            if(strcmp(value,"v2")&&strcmp(value,"legacy")) return 2;
            v2=!strcmp(value,"v2");
        } else if(!strcmp(option,"--root")) {
            if(root_count==16||!cf_copy(roots[root_count++],CF_MAX_PAYLOAD,value)) return 2;
        } else return 2;
    }
    if(!host||!port||!cf_number(port,&number)||!number||number>65535||!server_arg||!client_arg||(v2&&unflagged)) return 2;
    if(!SetCurrentDirectoryA(cf_path)||!GetCurrentDirectoryA(sizeof(cf_path),cf_path)||
       !absolute_path(server_arg,server_cert)||!absolute_path(client_arg,client_cert)) return 2;
    if(!root_count) { const char *defaults[]={"C:\\apro","C:\\ezagent","C:\\eappw","C:\\aprosql"};
        for(unsigned i=0;i<4;i++) cf_copy(roots[root_count++],CF_MAX_PAYLOAD,defaults[i]);
    }
    for(unsigned i=0;i<root_count;i++) {
        char root[CF_MAX_PAYLOAD]; if(!absolute_path(roots[i],root)) return 2;
        size_t n=strlen(root); while(n>3&&root[n-1]=='\\') root[--n]=0;
        cf_copy(roots[i],CF_MAX_PAYLOAD,root);
    }
    InitializeCriticalSection(&buffers); WSADATA data;
    if(WSAStartup(MAKEWORD(2,2),&data)) { DeleteCriticalSection(&buffers); return 2; }
    atexit(cleanup);
    if(!setup_tls(server_cert,client_cert)) { log_error("TLS configuration rejected"); return 2; }
    tunnel=connect_host(host,port,NULL);
    if(tunnel==INVALID_SOCKET||!handshake()) { log_error("TLS peer rejected or unreachable"); return 2; }
    event_loop(); return 0;
}
