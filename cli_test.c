
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

int tcp_connect(char *host , int port)
{

    struct sockaddr_in dst;
    int len; 
    int	sfd=0;
    struct hostent* pHE = gethostbyname(host);

    if (pHE == 0) {
            return (-1);
    }
    dst.sin_addr.s_addr = *((u_long*)pHE->h_addr_list[0]);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    len = sizeof(dst);

    /*Create socket & err check*/
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) {
	logNow("ERROR tcp_connect >> socket()\n");
	return -1;
    }

    if ((connect(sfd, (struct sockaddr *)&dst, len)) < 0) {
	logNow("ERROR tcp_connect >> connect(),%s,%d\n",host,port);
	return -1;
    }

    return sfd;


}

int tcp_send (int sd,int nlen,char *str) 
{
    int nSentBytes = 0;
    while (nSentBytes < nlen) {
        int nTemp = send(sd, str + nSentBytes,nlen - nSentBytes, MSG_NOSIGNAL);
        if (nTemp > 0) nSentBytes += nTemp;
        else {
		break;
	}
    }

    return(nSentBytes);
}

int tcp_recv(int sd, int len, char *buff)
{
	int left = len;
	int nTotal = 0;
	char *ptr = buff;

	if(len <=0) return(0);

	do {
		int nReadBytes = recv(sd, ptr, left, 0);
		if(nReadBytes<=0) break;
		else {
			nTotal = nTotal + nReadBytes;
			ptr = ptr + nReadBytes;
			left = len - nTotal;
		}
	} while(left>0);

	return(nTotal);
}

int tcp_close(int sd)
{
	close(sd);
	return(0);
}

int main()
{
	int sd = 0;
	char host[100]="";
	int port = 0;

	sd = tcp_connect(char *host , int port)





}
