/* Windows regression fixture: enough stderr to fill a pipe. */
#include <stdio.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>
int main(int argc,char **argv)
{
    if(argc==2&&!strcmp(argv[1],"flood")) {
        char data[4096]; memset(data,'e',sizeof(data));
        _setmode(_fileno(stdout),_O_BINARY);
        for(unsigned i=0;i<25;i++) fwrite(data,1,sizeof(data),stderr);
        fputs("stdout complete\n",stdout);
        return 0;
    }
    return 2;
}
