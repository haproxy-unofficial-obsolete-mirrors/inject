/* à réécrire en gérant des files d'attente suivant l'état des clients */

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
#include <signal.h>

#define METH_NONE	0
#define METH_GET	1
#define METH_POST	2

#define STATUS_START	1
#define STATUS_RUN	2
#define STATUS_THINK	3
#define STATUS_ERROR	4

#define BUFSIZE		1024
#define MAXSOCK		1000

#define Log(a, b...)	;

struct pageobj {
    struct sockaddr_in addr;
    int fd;
    char *buf;
    char *read;
    char meth;
    char *uri;
    char *vars;
    char *host;
    struct pageobj *next;
    struct page *page;
};

struct page {
    struct pageobj *objects;
    struct timeval begin, end;
    int objleft;
    int thinktime;
    int status;
    int dataread;
    struct page *next;
    struct client *client;
};

struct client {
    struct page *pages;
    struct page *current;
    char *username;
    char *password;
    char *cookie;
    int status;
    int dataread;
    struct timeval nextevent;
    struct client *next;
};

struct scnobj {
    char meth;
    char *host;
    char *uri;
    char *vars;
    struct scnobj *next;
};

struct scnpage {
    int thinktime;
    char *name;
    struct scnobj *objects;
    struct scnpage *next;
} *firstscnpage = NULL;

struct scnpage *curscnpage = NULL;
struct scnobj  *curscnobj = NULL;
char curscnhost[64]="host not set !";

struct client *clients = NULL;
unsigned long int nbclients=100;
unsigned long int nbiterations, iterations=0;
int injectdelay = 500;
static struct timeval now={0,0};
int nbconn=0;
int clientid=0;
int nbactcli=0;
long int totalread=0;
char trash[16384];
char *scnfile = NULL;
static struct timeval starttime;
static int needschedule = 0;

/* crée un objet pour une page :
   methode = { METH_GET | METH_POST } 
   addr    = ADRESSE:PORT
   uri     = "/accesi/ia10.html" par exemple
   vars    = "codcli1=truc&codcli2=truc2" ou NULL
   page    = page web de rattachement
   Toutes les chaines sont réallouées dynamiquement (strdup).
*/   
struct pageobj *newobj(char methode, char *addr, char *uri, char *vars, struct page *page) {
    struct pageobj *obj;

    obj=(struct pageobj *)calloc(1, sizeof(struct pageobj));
    memcpy(&obj->addr, str2sa(addr), sizeof(obj->addr));
    obj->fd	= -1;  /* fd non ouvert */
    obj->meth	= methode;
    obj->uri	= strdup(uri);
    obj->host	= strdup(addr);
    if (vars != NULL)
	obj->vars	= strdup(vars);
    obj->next	= NULL;
    obj->page	= page;
    obj->read = obj->buf = (char *)malloc(BUFSIZE);
#if 0
    printf("client=<%s:%s>, uri=<%s>, vars=<%s>\n",
	   page->client->username, page->client->password,
	   obj->uri, obj->vars);
#endif
    return obj;
}

/* crée une page pour un client existant. Les username et password du client doivent exister */
struct page *newpage(struct scnpage *scn, struct client *client) {
    struct page *page;
    struct pageobj **obj;
    struct scnobj *scnobj;
    char variables[256];

    page=(struct page *)calloc(1, sizeof(struct page));
    page->client = client;
    page->thinktime = scn->thinktime;

    obj = &(page->objects);

    for (scnobj = scn->objects; scnobj; scnobj = scnobj->next) {
	if ((scnobj->vars != NULL) && (client != NULL) &&
	    (client->username != NULL) && (client->password != NULL)) {
	    sprintf(variables, scnobj->vars, client->username, client->password);
	    *obj = newobj(scnobj->meth, scnobj->host, scnobj->uri, variables, page);
	}
	else 
	    *obj = newobj(scnobj->meth, scnobj->host, scnobj->uri, NULL, page);

	obj=&((*obj)->next);
    }
    return page;
}

void newclient(char *username, char *password) {
    struct client *newclient;
    struct page **page;
    struct scnpage *scn;

    newclient=(struct client*)calloc(1, sizeof(struct client));
    newclient->cookie=NULL;
    if (username != NULL)
	newclient->username=strdup(username);
    if (password != NULL)
	newclient->password=strdup(password);

    page=&(newclient->pages);
    for (scn = firstscnpage; scn != NULL; scn = scn->next) {
	*page=newpage(scn, newclient);
	page=&((*page)->next);
    }

    newclient->next = clients;
    newclient->cookie = NULL;
    newclient->status = STATUS_START;
    newclient->current = newclient->pages;
    Log(LOG_LDEBUG, "nouveau client créé <%p> : user=<%s>, current=<%p>\n",
	newclient, newclient->username, newclient->current);
    clients = newclient;
}

void destroyclient(struct client *client) {
    struct page *page, *nextpage;
    struct pageobj *obj, *nextobj;
    struct client *liste;

    page=client->pages;
    while (page) {
	obj=page->objects;
	while (obj) {
	    nextobj=obj->next;
	    free(obj->uri);
	    free(obj->buf);
	    if (obj->vars)
		free(obj->vars);
	    free(obj);
	    obj=nextobj;
	}
	nextpage=page->next;
	free(page);
	page=nextpage;
    }

    if (clients == client)
	clients=clients->next;
    else {
	liste = clients;
	while ((liste != NULL) && (liste->next != client)) {
	    liste = liste->next;
	}
	if (liste != NULL)
	    liste->next = client->next;
    }
    if (client->cookie)
	free(client->cookie);
    if (client->username)
	free(client->username);
    if (client->password)
	free(client->password);
    free(client);
}

/* creates a new scenario page, set its name and thinktime */
struct scnpage *newscnpage(char *name, int thinktime) {
    struct scnpage *page = (struct scnpage *)calloc(1, sizeof(struct scnpage));

    if (curscnpage != NULL) {
	curscnpage->next = page;
    }
    else {
	firstscnpage = page;
    }
    page->thinktime = thinktime;
    page->name = strdup(name);

    curscnobj = NULL;

    Log(LOG_LDEBUG, "[inject] - New page : %s %d\n", name, thinktime);
    return curscnpage = page;
}

/* adds a new object to the current page. aborts if no current page set */
struct scnobj *newscnobj(int meth, char *host, char *uri, char *vars) {
    struct scnobj *obj;

    if (curscnpage == NULL)
	Abort("Scenario must define PAGE before OBJECT.\n");

    obj = (struct scnobj *)calloc(1, sizeof(struct scnobj));

    obj->meth = meth;
    obj->host = strdup(host);
    obj->uri = strdup(uri);
    obj->vars = (vars == NULL) ? NULL : strdup(vars);

    if (curscnobj == NULL)
	curscnpage->objects = obj;
    else
	curscnobj->next = obj;

    Log(LOG_LDEBUG, "[inject] --- New object : meth=<%d> host=<%s> uri=<%s> vars=<%p>\n", meth, host, uri, vars);

    return curscnobj = obj;
}

/* returns 0 if OK, -1 if error */
int parsescnline(char *line) {
    char *cmd;
    char *pagename;
    long int time;
    char *srv;
    char *vars;
    int meth;

    char *args[10];
    int arg;

    /* skips leading spaces */
    while (isspace(*line))
	line++;

    /* cleans up line contents */
    cmd = line;
    while (*cmd) {
	if (*cmd == '#' || *cmd == ';' || *cmd == '\n' || *cmd == '\r')
	    *cmd = 0; /* end of string, end of loop */
	else
	    cmd++;
    }

    if (*line == 0)
	return 0;

    /* fills args with the line contents */
    for (arg=0; arg<9; arg++) {
	args[arg] = line;
	while (*line && !isspace(*line)) line++;
	if (*line) {
	    *(line++) = 0;
	    while (isspace(*line))
		line++;
	}
    }

    if (**args == 'H' || **args == 'h') {  /* host */
	if (isalnum(*args[1])) {
	    strncpy0(curscnhost, args[1], sizeof(curscnhost));
	    Log(LOG_LDEBUG,"[inject] <parsescnline> : host is now %s\n",curscnhost);
	}
	return 0;
    }
    
    if (**args == 'N' || **args == 'n') { /* new page */
	pagename = args[1];
	time = atol(args[2]);
	newscnpage(pagename, time);
	return 0;
    }

    meth = METH_NONE;
    if (**args == 'G' || **args == 'g')  /* new object : GET */
	meth = METH_GET;
    else if (**args == 'P' || **args == 'p')  /* new object : POST */
	meth = METH_POST;

    if (meth != METH_NONE) {
	if (*args[1] == '.') /* stay on current host */
	    srv = curscnhost;
	else
	    srv = args[1];

	if (*args[3])
	    vars = args[3];
	else
	    vars = NULL;
	newscnobj(meth, srv, args[2], vars);
	return 0;
    }

    Log(LOG_LERR,"[inject] <parsescnline> : args=<%s> <%s> <%s> <%s> ...\n",args[0], args[1], args[2], args[3]);

    return -1; /* unknown sequence */
}


/****************************************/

void Event(int fd, int flags, struct pageobj *obj) {
    int ret;
    char req[2048];
    char *r = req;

    Log(LOG_LFUNC,"[Event].\n");

    /* small optimization for the scheduler */
    needschedule = 1;

    if (flags & EV_WRITE) {
	int data, ldata;

	ldata=sizeof(data);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &data, &ldata);

	if (data > 0) {  /* erreur sur la socket */
	    Log(LOG_LERR,"[Event] erreur sur le connect() : %d\n",data);
	    DeregisterEvent(fd);
	    close(fd);
	    nbconn--;
	    obj->page->objleft--;
	    tv_now(&obj->page->end);
	    obj->page->client->status = obj->page->status = STATUS_ERROR;
	    Reschedule();
	    return;
	}

	/* pas d'erreur */
	Log(LOG_LPERF,"[Event] client <%s> : connection établie.\n", obj->page->client->username);
	/* créer la requête */
	if (obj->meth == METH_POST) {	    
	    r+=sprintf(r, "POST %s HTTP/1.0\r\n", obj->uri);
	    if (obj->page->client->cookie)
		r+=sprintf(r, "Cookie: %s\r\n", obj->page->client->cookie);
	    if (obj->vars) {		
		r+=sprintf(r,"Content-length: %d\r\n",strlen(obj->vars));
		r+=sprintf(r,"\r\n");
		r+=sprintf(r, "%s", obj->vars);
	    }
	    else
		r+=sprintf(r,"\r\n");
	}
	else /* meth = METH_GET */ {
	    r+=sprintf(r, "GET %s", obj->uri);
	    if (obj->vars)
		r+=sprintf(r,"?%s", obj->vars);
	    r+=sprintf(r," HTTP/1.0\r\n");
	    if (obj->page->client->cookie)
		r+=sprintf(r, "Cookie: %s\r\n", obj->page->client->cookie);
	    r+=sprintf(r, "Host: %s\r\n", obj->host);
	    r+=sprintf(r,"\r\n");
	}
	/* la requete est maintenant prete */
	if (write(fd, req, strlen(req)) == -1) {
	    if (errno != EAGAIN) {
		Log(LOG_LERR,"[Event] erreur sur le write().\n");
		DeregisterEvent(fd);
		close(fd);
		nbconn--;
		obj->page->objleft--;
		tv_now(&obj->page->end);
		obj->page->client->status = obj->page->status = STATUS_ERROR;
		Reschedule();
		return;
	    }
	}
	else {
	    SetEvent(fd, EV_READ);
	    Log(LOG_LDEBUG,"[Event] envoi de la requete <%s>\n",req);
	    //	    obj->page->client->status = obj->page->status = STATUS_START;
	}
    }
    else if (flags & EV_READ) {
	if (obj->buf + BUFSIZE == obj->read)  /* on ne stocke pas les data dépassant le buffer */
	    ret=read(fd, trash, sizeof(trash));  /* lire les data mais ne pas les stocker */
	else {
	    ret=read(fd, obj->read, BUFSIZE - (obj->read - obj->buf)); /* lire et stocker les data */
	    if (ret > 0)
		obj->read+=ret;
	}
	Log(LOG_LDEBUG,"[Event] socket <%d> du client <%s> : read() = %d.\n",
	    fd, obj->page->client->username, ret);
	if (ret>0) {

	    if ((starttime.tv_sec | starttime.tv_usec) == 0)  /* la premiere fois, on démarre le chrono */
		tv_now(&starttime);

	    obj->page->dataread+=ret;
	    obj->page->client->dataread+=ret;
	}
	else if (ret == 0) {
	    char *ptr1, *ptr2, *cookie, *ptr3;
	    char *header;
	    DeregisterEvent(fd);
	    close(fd);
	    nbconn--;

	    /* lire les headers pour savoir s'il y a un cookie */
	    ptr1=obj->buf;
	    while (ptr1<obj->read) {
		/* si on a un saut de ligne ici, c'est forcément une fin de headers */
		if ((*ptr1 == '\r') || (*ptr1 == '\n'))
		    break;
		ptr2=ptr1;

		/* recherche la fin de la chaine */
		while ((ptr1<obj->read) && (*ptr1 != '\n') && (*ptr1 != '\r'))
		    ptr1++;
		/* ptr1 pointe sur le premier saut de ligne ou retour charriot */

		header = (char *)calloc(1, ptr1-ptr2+1);
		strncpy(header, ptr2, ptr1-ptr2);
		Log(LOG_LDEBUG, "[Event] : header de %d octets : %s\n",ptr1-ptr2, header);
		free(header);

		if (!strncasecmp(ptr2,"Set-Cookie:",11)) {
		    ptr2+=11;
		    while ((ptr2<ptr1) && isspace(*ptr2))
			ptr2++;
		    /* on va se débarrasser des lignes ne contenant pas "path=" */
		    if (((ptr3=strstr(ptr2,"path=")) != NULL) && (ptr3<ptr1)) {
			/* et on se débarrasse aussi de "; path=" */
			while ((ptr3 > ptr2) && ((*(ptr3-1)==' ') || (*(ptr3-1)==';')))
			    ptr3--;

			/* le cookie est compris entre ptr2 et ptr3 */
			/* on va le concaténer au cookie existant */
			if (obj->page->client->cookie != NULL) {
			    cookie=(char *)calloc(1, strlen(obj->page->client->cookie) + ptr3-ptr2 + 3);
			    strcpy(cookie, obj->page->client->cookie);
			    strcat(cookie,"; ");
			    strncat(cookie, ptr2, ptr3-ptr2);
			    /* on a forcément le zéro final */
			    free(obj->page->client->cookie);
			    obj->page->client->cookie=cookie;
			    Log(LOG_LDEBUG,"[Event] Cookie = %s\n", cookie);
			}
			else {
			    cookie=(char *)calloc(1, ptr3-ptr2+1);
			    strncpy(cookie, ptr2, ptr3-ptr2);
			    /* on a forcément le zéro final */
			    obj->page->client->cookie=cookie;
			    Log(LOG_LDEBUG,"[Event] Cookie = %s\n", cookie);
			}
		    }
		}

		/* recherche la fin du saut de ligne */
		if (ptr1<obj->read) {
		    if (ptr1+1 < obj->read) {
			if ((*ptr1 == '\n') && (ptr1[1] == '\r'))
			    ptr1++;
			else if ((*ptr1 == '\r') && (ptr1[1] == '\n'))
			    ptr1++;
		    }
		    ptr1++;
		}
	    }


	    if (--obj->page->objleft == 0) {  /* dernier objet de cette page */
		Log(LOG_LDEBUG,"[Event] dernier objet de la page, mise en veille du client.\n");
		tv_now(&obj->page->end);
		tv_wait(&obj->page->client->nextevent, obj->page->thinktime);
		if (obj->page->client->status != STATUS_ERROR) {
		    obj->page->client->status = obj->page->status = STATUS_THINK;
		    Reschedule();
		}
	    }
	    else 
		Log(LOG_LDEBUG,"[Event] encore <%d> objets sur la page <%p>.\n",
		    obj->page->objleft, obj->page);

	}
	else if ((ret == -1) && (errno != EAGAIN)) {
	    Log(LOG_LDEBUG,"[Event] erreur, arrêt du client <%p>.\n", obj->page->client);
	    DeregisterEvent(fd);
	    close(fd);
	    nbconn--;

	    obj->page->objleft--;
	    obj->page->client->status = STATUS_ERROR;
	    Reschedule();
	}
	/* sinon c'est un EAGAIN, pas grave */
    }
}

/* ce scheduler s'occupe d'injecter des clients tant qu'il n'y en a pas assez, mais jamais
   plus d'un tous les <injectdelay> ms
*/
int injecteur(void *arg) {
    static struct timeval next, now;
    unsigned int delay;
    char uname[32];

    Log(LOG_LFUNC,"[injecteur].\n");
    tv_now(&now);

    if (nbconn < MAXSOCK) {
	if ((nbactcli < nbclients)  && (iterations < nbiterations)
	    && (tv_cmp(&next, &now) <= 0)) {  /* on doit créer un nouveau client */
	    sprintf(uname, "%d", clientid++);
	    /* on entre dans le scheduler directement à partir de ce client */
	    newclient(uname, uname);
	    nbactcli++;
	    Log(LOG_LAPP, "Création du client <%s> : <%d> clients actifs.\n",uname,nbactcli);
	    delay=injectdelay;
	    tv_delayfrom(&next, &now, injectdelay);
	    iterations++;
	    needschedule = 1;
	}
	else
	    delay=tv_delta(&next, &now);
    }
    else
	delay = 1000;  /* 1 seconde si plus de sockets */

    return delay;
}


/* ce scheduler s'occupe de gérer les clients (think time, ...)
*/
int scheduler(void *arg) {
    static struct timeval next, now;
    struct client *cli;
    unsigned int delay;
    char uname[32];
    int sock;

    Log(LOG_LFUNC,"[scheduler].\n");
    tv_now(&now);

    cli = clients;
    delay=tv_remain(&now, &next);

    if (!needschedule && delay>0)
	return delay;

    needschedule = 0;

    while (cli) {
	struct page *page;
	struct pageobj *obj;


	//	Log(LOG_LDEBUG, "Evaluation du client <%s>, status=%d, delta=%d.\n",
	//		    cli->username, cli->status, tv_delta(&cli->nextevent, &now));
	if (cli->status == STATUS_THINK) {
	    if (tv_cmp(&cli->nextevent, &now) <= 0) {  /* passer à la page suivante */
		Log(LOG_LDEBUG, "Réveil du client <%s>.\n", cli->username);
		cli->current = cli->current->next;
		if (cli->current == NULL) {  /* fin du scénario pour ce client */
		    struct client *newcli = cli->next;
		    
		    Log(LOG_LAPP, "Terminaison du client <%s> : <%d> octets lus, <%ld> au total -> moy = %ld kB/s.\n",
			cli->username, cli->dataread, totalread,
			totalread / (tv_delta(&now, &starttime)?:1));
		    totalread += cli->dataread;
		    destroyclient(cli);
		    cli=newcli;
		    nbactcli--;

		    continue;
		}
		else {
		    cli->status = STATUS_START;  /* on repart tout de suite en start */
		}
	    }
	    else {
		int del2;
		del2 = tv_remain(&now, &cli->nextevent);
		if (del2 < delay)
		    delay=del2;
	    }
	}

	if ((cli->status == STATUS_ERROR) && (cli->current->objleft == 0)) {
	    struct client *newcli = cli->next;

	    Log(LOG_LWARN, "Destruction du client <%s> pour cause d'erreur.\n",cli->username);
	    destroyclient(cli);
	    cli=newcli;
	    nbactcli--;
	    Reschedule();  /* on peut avoir à relancer des clients */
	    goto nextclient;
	}

	if (cli->status == STATUS_START) {  /* envoyer une nouvelle page */
	    Log(LOG_LAPP, "nouvelle page pour client <%s> : <%d> clients actifs.\n",cli->username,nbactcli);
	    page = cli->current;
	    if (page) {
		Log(LOG_LDEBUG, "création des objets de la page <%p> pour <%s>.\n",page,cli->username);
		obj=page->objects;
		while (obj) {
		    Log(LOG_LDEBUG, "connexion de l'objet <%s> de la page <%p> pour le client <%s>.\n",
			obj->uri, page, cli->username);
		    if ((obj->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
	    		struct client *newcli = cli->next;

			Log(LOG_LERR, "impossible de créer une socket\n");
		        destroyclient(cli);
		        cli=newcli;
		        nbactcli--;
		        Reschedule();  /* on peut avoir à relancer des clients */
		        goto nextclient;
		    }
		    if (fcntl(obj->fd, F_SETFL, O_NONBLOCK)==-1) {
			Log(LOG_LERR,"impossible de mettre la socket en O_NONBLOCK\n");
		    } else if ((connect(obj->fd, &obj->addr, sizeof(obj->addr)) == -1) && (errno != EINPROGRESS)) {
	    		struct client *newcli = cli->next;

			Log(LOG_LERR,"impossible de faire le connect() pour %d\n", obj->fd);
		        destroyclient(cli);
		        cli=newcli;
		        nbactcli--;
		        Reschedule();  /* on peut avoir à relancer des clients */
		        goto nextclient;
		    }
		    else {
			nbconn++;
			Log(LOG_LPERF,"Nouvelle connexion : %d. %d connections actives pour %d clients.\n", obj->fd,
			    nbconn, nbactcli);
			RegisterEvent(obj->fd, EV_WRITE, &Event, obj);
		    }
		    obj=obj->next;
		    page->objleft++;
		}
	    }
	    cli->status = STATUS_RUN;
	}

	cli = cli->next;
nextclient:
    }

    if ((nbactcli == 0) && (iterations == nbiterations)) {
	Log(LOG_LPERF, "Fin: %ld clients ont chargé %ld octets en %ld ms : %ld kB/s.\n",
	    iterations, totalread, tv_delta(&now, &starttime), totalread/(tv_delta(&now, &starttime)?:1));
	printf("Fin: %ld clients ont chargé %ld octets en %ld ms : %ld kB/s.\n",
	    iterations, totalread, tv_delta(&now, &starttime), totalread/(tv_delta(&now, &starttime)?:1));
	exit(0);
    }

    return delay;
}


/* returns 0 if OK, -1 if error */
int readscnfile(char *file) {
    FILE *f;

    if ((f=fopen(file,"r")) == NULL)
	return -1;

    while (fgets(trash, sizeof(trash), f) != NULL) {
	if (parsescnline(trash) < 0)
	    return -1;
    }
    fclose(f);
    return 0;
}


void stopper(int sig) {
    static struct timeval now;
    tv_now(&now);
    printf("Arret: %ld clients ont chargé %ld octets en %ld ms : %ld kB/s.\n",
	   iterations, totalread, tv_delta(&now, &starttime), totalread/(tv_delta(&now, &starttime)?:1));
    exit(0);
}


int main(int argc, char **argv) {

    if (argc != 5) {
	fprintf(stderr,"Syntaxe : inject <nbusers> <nbiterations> <injectdelay> <scnfile>\n");
	exit(1);
    }
    nbclients = atol(argv[1]);
    nbiterations = atol(argv[2]) * nbclients;
    injectdelay = atol(argv[3]);
    scnfile = argv[4];
    tv_now(&starttime);  /* just in case it's stopped too early */
    signal(SIGINT, &stopper);

    //    LogOpen("/tmp/injecteur.log", LOG_LERR | LOG_LPERF | LOG_LWARN | LOG_LAPP);

    if (readscnfile(scnfile) < 0) {
	Log(LOG_LFATAL, "[inject] Error reading scn file : %s\n", scnfile);
	exit(1);
    }

    RegisterScheduler(&injecteur, NULL);
    RegisterScheduler(&scheduler, NULL);
    SelectRun();
    return 0;
}

