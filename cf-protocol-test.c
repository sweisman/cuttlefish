/* Bounded parser corpus, suitable for ASan/UBSan. */
#include <assert.h>
#include "common.h"
int main(void)
{
    static cf_decoder q;
    cf_packet in={CF_DATA,1024,7,{0}},out;
    unsigned char wire[1040]; size_t size;
    for(int v2=0;v2<=1;v2++) {
        memset(&q,0,sizeof(q)); size=cf_encode(wire,&in,v2);
        for(size_t i=0;i<size;i++) {
            assert(cf_feed(&q,wire+i,1));
            assert(cf_decode(&q,&out,v2,0)==(i+1==size));
        }
        assert(out.id==7 && out.len==1024 && !memcmp(out.data,in.data,1024));
        for(unsigned i=0;i<20;i++) assert(cf_feed(&q,wire,size));
        for(unsigned i=0;i<20;i++) assert(cf_decode(&q,&out,v2,0)==1);
        assert(cf_decode(&q,&out,v2,0)==0);
    }
    uint32_t state=12345;
    for(unsigned test=0;test<20000;test++) {
        memset(&q,0,sizeof(q));
        size_t n=test%sizeof(wire);
        for(size_t i=0;i<n;i++) { state=state*1664525u+1013904223u; wire[i]=(unsigned char)(state>>24); }
        assert(cf_feed(&q,wire,n));
        while(cf_decode(&q,&out,test&1,0)>0) {}
    }
    memset(&q,0,sizeof(q));
    q.len=sizeof(q.data)-1;
    assert(!cf_feed(&q,wire,2));
    assert(cf_decode(&q,&out,0,0)==-1);
    cf_buffer b={0}; size_t budget=CF_SESSION_LIMIT;
    assert(!cf_buffer_add(&b,"x",1,CF_STREAM_LIMIT,&budget));
    budget=0;
    assert(cf_buffer_add(&b,"hello",5,CF_STREAM_LIMIT,&budget));
    cf_buffer_take(&b,3);
    assert(cf_buffer_add(&b," world",6,CF_STREAM_LIMIT,&budget));
    assert(b.len==8 && !memcmp(b.data+b.start,"lo world",8));
    cf_buffer_free(&b,&budget); assert(!budget);
    puts("protocol corpus passed");
    return 0;
}
