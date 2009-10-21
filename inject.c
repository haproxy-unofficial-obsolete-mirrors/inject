#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <libtools.h>
#include <libSelect.h>
#include <libNetTools.h>
#include <fcntl.h>
#include <errno.h>

int injectdelay = 500;
struct sockaddr_in *sa;

#define SIZE	65536


char buf[SIZE];
static struct timeval now;
int nbconn=0;

char req[1024];

void Event(int fd, int flags, struct timeval *demarre) {
    tv_now(&now);
    if (flags & EV_READ) {
	read(fd, buf, SIZE);
	close(fd);
	DeregisterEvent(fd);
	Log(LOG_LPERF,"[inject] client %d : fin après %d ms. %d connections restantes.\n",
	    fd, tv_delta(&now, demarre), --nbconn);
    }
    else if (flags & EV_WRITE) {
	Log(LOG_LPERF,"[inject] client %d : connection après %d ms\n",fd,tv_delta(&now, demarre));
	SetEvent(fd, EV_READ);
	write(fd, req, strlen(req)+1);
    }
}

int injecteur(void *arg) {
    static struct timeval next;
    unsigned int delay;
    int sock;

    tv_now(&now);
    delay=tv_delta(&now, &next);
    if (delay < injectdelay)
	return delay;

    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
	Log(LOG_LERR," impossible de créer une socket\n");
    else {
	if (fcntl(sock, F_SETFL, O_NONBLOCK)==-1) {
	    Log(LOG_LERR," impossible de mettre la socket en O_NONBLOCK\n");
        } else if ((connect(sock, sa, sizeof(*sa)) == -1) && (errno != EINPROGRESS)) {
	    Log(LOG_LERR," impossible de faire le connect() pour %d\n",sock);
	}
	else {
	    nbconn++;
	    Log(LOG_LPERF,"Nouveau client : %d. %d connections actives.\n",
		sock, nbconn);
	    RegisterEvent(sock, EV_READ | EV_WRITE, &Event, &now);
	}
    }

    tv_delayfrom(&next, &now, injectdelay);
    return injectdelay;
}


int main(int argc, char **argv) {

    if (argc != 4) {
	fprintf(stderr,"Syntaxe : inject <addr:port> <delai> <URI>\n");
	exit(1);
    }
    sa = str2sa(argv[1]);
    injectdelay = atol(argv[2]);
    sprintf(req, "GET %s HTTP/1.0\r\n\r\n",argv[3]);
    LogOpen("/tmp/injecteur.log", LOG_LPERF | LOG_LWARN | LOG_LERR);
    RegisterScheduler(&injecteur, NULL);
    SelectRun();
    return 0;
}

