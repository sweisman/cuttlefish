/* Cuttlefish protocol and bounded buffers. Copyright (C) Scott Weisman. */
#ifndef CF_COMMON_H
#define CF_COMMON_H
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#define CF_MAX_PAYLOAD 1024u
#define CF_MAX_STREAMS 64u
#define CF_STREAM_LIMIT (256u*1024u)
#define CF_SESSION_LIMIT (8u*1024u*1024u)
#define CF_WINDOW (64u*1024u)
#define CF_TIMEOUT 30u
#define CF_QUEUE_SIZE (64u*(CF_MAX_PAYLOAD+16u))
enum { CF_PING=1, CF_CONNECT, CF_DISCONNECT, CF_DATA, CF_EXEC, CF_COMPRESSED,
       CF_FILE, CF_MESSAGE, CF_LOG, CF_GET, CF_PUT, CF_FINISH, CF_RESULT, CF_CREDIT, CF_CANCEL };
typedef struct { int8_t type; uint32_t id; int16_t len; } cf_legacy_header;
typedef char cf_legacy_layout[(sizeof(cf_legacy_header)==12 && offsetof(cf_legacy_header,id)==4 && offsetof(cf_legacy_header,len)==8)?1:-1];
typedef struct { unsigned type,len; uint32_t id; unsigned char data[CF_MAX_PAYLOAD]; } cf_packet;
typedef struct { unsigned char data[CF_QUEUE_SIZE]; size_t len; int failed; } cf_decoder;
typedef struct { unsigned char *data; size_t start,len,cap; } cf_buffer;
static inline uint32_t cf_u32(const unsigned char *p)
{ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static inline void cf_put32(unsigned char *p,uint32_t n)
{ p[0]=(unsigned char)(n>>24); p[1]=(unsigned char)(n>>16); p[2]=(unsigned char)(n>>8); p[3]=(unsigned char)n; }
static inline int cf_copy(char *dst,size_t cap,const char *src)
{ size_t n=strlen(src); if(n>=cap) return 0; memcpy(dst,src,n+1); return 1; }
static inline int cf_number(const char *s,uint64_t *value)
{
    uint64_t n=0; if(!*s) return 0;
    for(;*s;s++) { unsigned d=(unsigned char)*s-'0'; if(d>9 || n>(UINT64_MAX-d)/10) return 0; n=n*10+d; }
    *value=n; return 1;
}
static inline char *cf_word(char **rest)
{
    char *s=*rest,*p; while(*s==' '||*s=='\t') s++;
    p=s; while(*p && *p!=' ' && *p!='\t') p++;
    if(*p) *p++=0;
    while(*p==' '||*p=='\t') p++;
    *rest=p; return s;
}
/* Caller serializes access to both buffer and allocation budget. */
static inline void cf_buffer_free(cf_buffer *b,size_t *budget)
{ if(b->data) { *budget-=b->cap; free(b->data); } memset(b,0,sizeof(*b)); }
static inline int cf_buffer_add(cf_buffer *b,const void *data,size_t n,size_t limit,size_t *budget)
{
    size_t need,cap; unsigned char *p;
    if(n>limit || b->len>limit-n) return 0;
    need=b->len+n;
    if(b->start && b->start+need>b->cap) { memmove(b->data,b->data+b->start,b->len); b->start=0; }
    if(need>b->cap) {
        cap=b->cap?b->cap:4096; while(cap<need) cap*=2; if(cap>limit) cap=limit;
        if(cap-b->cap>CF_SESSION_LIMIT-*budget) return 0;
        p=(unsigned char *)realloc(b->data,cap); if(!p) return 0;
        *budget+=cap-b->cap; b->data=p; b->cap=cap;
    }
    if(n) memcpy(b->data+b->start+b->len,data,n);
    b->len+=n; return 1;
}
static inline void cf_buffer_take(cf_buffer *b,size_t n)
{ b->start+=n; b->len-=n; if(!b->len) b->start=0; }
static inline int cf_packet_valid(const cf_packet *p,int v2,int unflagged)
{
    unsigned off=unflagged?0u:1u;
    if(p->len>CF_MAX_PAYLOAD || p->type<CF_PING || p->type>(v2?CF_CANCEL:CF_LOG)) return 0;
    if(p->type==CF_PING) return p->id==0 && p->len==0;
    if(p->type==CF_LOG) return p->id==0 && p->len==2 && (p->data[0]=='0'||p->data[0]=='1') && p->data[1]==0;
    if(p->type==CF_MESSAGE) return p->len>0 && p->data[p->len-1]==0;
    if(!p->id) return 0;
    switch(p->type) {
    case CF_DISCONNECT: case CF_FINISH: case CF_CANCEL: return p->len==0;
    case CF_CREDIT: return p->len==4 && cf_u32(p->data)>0 && cf_u32(p->data)<=CF_WINDOW;
    case CF_DATA: case CF_COMPRESSED: return p->len>0;
    case CF_RESULT: off=0; break;
    default: break;
    }
    return p->len>off+1 && (!off||p->data[0]<=1) && p->data[p->len-1]==0 && !memchr(p->data+off,0,p->len-off-1);
}
static inline size_t cf_encode(unsigned char *out,const cf_packet *p,int v2)
{
    size_t h=v2?16:sizeof(cf_legacy_header); memset(out,0,h);
    if(v2) { memcpy(out,"CTF2",4); out[4]=2; out[5]=(unsigned char)p->type; cf_put32(out+8,p->id); cf_put32(out+12,p->len); }
    else { cf_legacy_header header; memset(&header,0,sizeof(header)); header.type=(int8_t)p->type; header.id=p->id; header.len=(int16_t)p->len; memcpy(out,&header,h); }
    memcpy(out+h,p->data,p->len); return h+p->len;
}
static inline int cf_feed(cf_decoder *q,const void *data,size_t n)
{
    if(q->failed || n>sizeof(q->data)-q->len) { q->failed=1; return 0; }
    memcpy(q->data+q->len,data,n); q->len+=n; return 1;
}
/* 1 packet, 0 incomplete, -1 terminal framing error. */
static inline int cf_decode(cf_decoder *q,cf_packet *p,int v2,int unflagged)
{
    size_t h=v2?16:sizeof(cf_legacy_header);
    if(q->failed) return -1;
    if(q->len<h) return 0;
    if(v2) {
        if(memcmp(q->data,"CTF2",4)||q->data[4]!=2||q->data[6]||q->data[7]) goto bad;
        p->type=q->data[5]; p->id=cf_u32(q->data+8); p->len=cf_u32(q->data+12);
    } else {
        cf_legacy_header header; memcpy(&header,q->data,h); if(header.len<0) goto bad;
        p->type=(unsigned char)header.type; p->id=header.id; p->len=(unsigned)header.len;
    }
    if(p->len>CF_MAX_PAYLOAD || p->type<CF_PING || p->type>(v2?CF_CANCEL:CF_LOG)) goto bad;
    if(q->len<h+p->len) return 0;
    memcpy(p->data,q->data+h,p->len); if(!cf_packet_valid(p,v2,unflagged)) goto bad;
    q->len-=h+p->len; memmove(q->data,q->data+h+p->len,q->len); return 1;
bad: q->failed=1; return -1;
}
#endif
