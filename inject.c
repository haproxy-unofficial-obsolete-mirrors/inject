/* 2000/11/18 : correction du SEGV.
 * 2000/11/21 : grand nettoyage de l'automate et correction de nombreux bugs.
 *
 * Obs : parfois l'injecteur se bloque s'il y a peu de client. strace montre
 *       que c'est parce qu'un connect() n'aboutit pas. Sans doute une table
 *       de sockets qui se fige quelque part, ou un bug sur l'OS :-(
 *       Voir la trace à la fin de ce fichier.
 *
 * TODO :
 *  - réécrire en gérant des files d'attente suivant l'état des clients.
 *  - gérer les unités d'affichage
 *  - passer les data en long long
 *  - traiter un timeout sur inactivité d'un client.
 *  - terminaison automatique (et brutale) de l'injection au bout d'une durée
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>

#define METH_NONE	0
#define METH_GET	1
#define METH_POST	2

#define STATUS_RUN	1
#define STATUS_THINK	2
#define STATUS_ERROR	3

#define BUFSIZE		4096
#define MAXSOCK		10000
#define MAXNBFD		(3+MAXSOCK)


/* show stats this every millisecond, 0 to disable */
#define STATTIME	2000

#define EV_READ 1
#define EV_WRITE 2
#define EV_EXCEPT 4

/* sur combien de bits code-t-on la taille d'un entier (ex: 32bits -> 5) */
#define	INTBITS		5

#define MINTIME(old, new)	(((new)<0)?(old):(((old)<0||(new)<(old))?(new):(old)))

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
    int hits;
    struct timeval nextevent;
    struct client *next;
};

struct scnobj {
    struct sockaddr_in addr;
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
unsigned long int reqclients=0;
unsigned long int nbclients=0;
unsigned long int nbiterations, iterations=0;
int injectdelay = 500;
static struct timeval now={0,0};
int nbconn=0;
int clientid=0;
int nbactcli=0;
long int totalread=0;
long int totalhits=0;
char trash[16384];
char *scnfile = NULL;
static struct timeval starttime = {0,0};
int maxfd = 0;
int stopnow = 0;

static struct pageobj *fdtab[MAXNBFD];

fd_set ReadEvent[(MAXNBFD + FD_SETSIZE - 1) / FD_SETSIZE],
    WriteEvent[(MAXNBFD + FD_SETSIZE - 1) / FD_SETSIZE];

fd_set StaticReadEvent[(MAXNBFD + FD_SETSIZE - 1) / FD_SETSIZE],
    StaticWriteEvent[(MAXNBFD + FD_SETSIZE - 1) / FD_SETSIZE];

/*****  prototypes **********************************************/
void destroyclient(struct client *client);
/****************************************************/

/***************** libtools ************************/

/* Arreter avec un ABORT apres avoir affiche un message d'erreur sur STDERR.
 * Cette fonction est de type int pour pouvoir etre inseree dans une expression.
 * Elle ne retourne jamais.
 */
int Abort(char *fmt, ...) {
    va_list argp;
    struct timeval tv;
    struct tm *tm;

    va_start(argp, fmt);

    gettimeofday(&tv, NULL);
    tm=localtime(&tv.tv_sec);
    fprintf(stderr, "[ABT] %03d %02d%02d%02d pid=%d, cause=",
	    tm->tm_yday, tm->tm_hour, tm->tm_min, tm->tm_sec, getpid());
    vfprintf(stderr, fmt, argp);
    fflush(stderr);
    va_end(argp);
    abort();
    return 0;	// juste pour eviter un warning a la compilation
}


/* sets <tv> to the current time */
struct timeval *tv_now(struct timeval *tv) {
    if (tv)
	gettimeofday(tv, NULL);
    return tv;
}

/* adds <ms> ms to <from>, set the result to <tv> and returns a pointer <tv> */
struct timeval *tv_delayfrom(struct timeval *tv, struct timeval *from, int ms) {
  if (!tv || !from)
    return NULL;
  tv->tv_usec = from->tv_usec + (ms%1000)*1000;
  tv->tv_sec  = from->tv_sec  + (ms/1000);
  while (tv->tv_usec >= 1000000) {
    tv->tv_usec -= 1000000;
    tv->tv_sec++;
  }
  return tv;
}

/* sets tv to now + <ms> ms, and returns a pointer to the newly filled struct */
struct timeval *tv_wait(struct timeval *tv, int ms) {
  if (!tv)
    return NULL;
  gettimeofday(tv, NULL);
  tv->tv_usec += (ms%1000)*1000;
  tv->tv_sec  += (ms/1000);
  while (tv->tv_usec >= 1000000) {
    tv->tv_usec -= 1000000;
    tv->tv_sec++;
  }
}

/* compares <tv1> and <tv2> : returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2 */
int tv_cmp(struct timeval *tv1, struct timeval *tv2) {
  if (tv1->tv_sec > tv2->tv_sec)
    return 1;
  else if (tv1->tv_sec < tv2->tv_sec)
    return -1;
  else if (tv1->tv_usec > tv2->tv_usec)
    return 1;
  else if (tv1->tv_usec < tv2->tv_usec)
    return -1;
  else return 0;
}

/* returns the absolute difference, in ms, between tv1 and tv2 */
unsigned long tv_delta(struct timeval *tv1, struct timeval *tv2) {
  int cmp;
  unsigned long ret;
  

  cmp=tv_cmp(tv1, tv2);
  if (!cmp)
    return 0; /* same dates, null diff */
  else if (cmp<0) {
    struct timeval *tmp=tv1;
    tv1=tv2;
    tv2=tmp;
  }
  ret=(tv1->tv_sec - tv2->tv_sec)*1000;
  if (tv1->tv_usec > tv2->tv_usec)
    ret+=(tv1->tv_usec - tv2->tv_usec)/1000;
  else
    ret-=(tv2->tv_usec - tv1->tv_usec)/1000;
  return (unsigned long) ret;
}

/* returns the remaining time between tv1=now and event=tv2
   if tv2 is passed, 0 is returned.
*/
unsigned long tv_remain(struct timeval *tv1, struct timeval *tv2) {
  int cmp;
  unsigned long ret;
  

  cmp=tv_cmp(tv1, tv2);
  if (cmp >= 0)
    return 0; /* event elapsed */

  ret=(tv2->tv_sec - tv1->tv_sec)*1000;
  if (tv2->tv_usec > tv1->tv_usec)
    ret+=(tv2->tv_usec - tv1->tv_usec)/1000;
  else
    ret-=(tv1->tv_usec - tv2->tv_usec)/1000;
  return (unsigned long) ret;
}


/* retourne un pointeur sur une structure de type sockaddr_in remplie d'après
   la chaine <str> entrée au format "123.123.123.123:12345". */
struct sockaddr_in *str2sa(char *str) {
    static struct sockaddr_in sa;
    char *c;
    int port;

    bzero(&sa, sizeof(sa));
    str=strdup(str);
    if ((c=strrchr(str,':')) != NULL) {
	*c++=0;
	port=atol(c);
    }
    else
	port=0;

    if (!inet_aton(str, &sa.sin_addr)) {
	struct hostent *he;

	if ((he = gethostbyname(str)) == NULL)
	    fprintf(stderr,"[NetTools] Invalid server name: %s\n",str);
	else
	    sa.sin_addr = *(struct in_addr *) *(he->h_addr_list);
    }
    sa.sin_port=htons(port);
    sa.sin_family=AF_INET;

    free(str);
    return &sa;
}

/* crée un objet pour une page :
   methode = { METH_GET | METH_POST } 
   addr    = ADRESSE:PORT
   uri     = "/accesi/ia10.html" par exemple
   vars    = "codcli1=truc&codcli2=truc2" ou NULL
   page    = page web de rattachement
   Toutes les chaines sont réallouées dynamiquement (strdup).
*/   
struct pageobj *newobj(char methode, char *host, struct sockaddr_in *addr, char *uri, char *vars, struct page *page) {
    struct pageobj *obj;

    obj=(struct pageobj *)calloc(1, sizeof(struct pageobj));
    memcpy(&obj->addr, addr, sizeof(obj->addr));
    obj->fd	= -1;  /* fd non ouvert */
    obj->meth	= methode;
    obj->uri	= strdup(uri);
    obj->host	= strdup(host);
    if (vars != NULL)
	obj->vars	= strdup(vars);
    obj->next	= NULL;
    obj->page	= page;
    obj->read = obj->buf = (char *)malloc(BUFSIZE);

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
	    *obj = newobj(scnobj->meth, scnobj->host, &scnobj->addr, scnobj->uri, variables, page);
	}
	else 
	    *obj = newobj(scnobj->meth, scnobj->host, &scnobj->addr, scnobj->uri, NULL, page);

	obj=&((*obj)->next);
    }
    return page;
}

/* démarre un client. Si une erreur se produit lors du démarrage, alors
   les ressources sont libérées et le client est détruit.
*/
void start_client(struct client *cli) {
    struct page *page;
    struct pageobj *obj;

    cli->status = STATUS_RUN;
    if ((page = cli->current) == NULL) /* rien à ajouter */
	return;

    obj=page->objects;
    while (obj) {
	if ((obj->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
	    fprintf(stderr, "impossible de créer une socket, destruction du client.\n");
	    destroyclient(cli); /* renvoie un pointeur sur le suivant */
	    return;
	}
	else
	    nbconn++;
	
	if (fcntl(obj->fd, F_SETFL, O_NONBLOCK)==-1) {
	    fprintf(stderr,"impossible de mettre la socket en O_NONBLOCK\n");
	}
	else if ((connect(obj->fd, &obj->addr, sizeof(obj->addr)) == -1) && (errno != EINPROGRESS)) {
	    fprintf(stderr,"impossible de faire le connect() pour %d, destruction du client.\n", obj->fd);
	    destroyclient(cli); /* renvoie un pointeur sur le suivant */
	    return;
	}
	else {
	    fdtab[obj->fd]=obj;
	    FD_SET(obj->fd, StaticWriteEvent);
	    
	    if (obj->fd+1 > maxfd)
		maxfd = obj->fd+1;
	}
	obj=obj->next;
	page->objleft++;
    }
    /* le client est démarré */
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
    newclient->current = newclient->pages;
    start_client(clients = newclient);
}

/* detruit le client, libère ses fd encore ouverts, décompte le nombre de connexions
   associées, et décrémente le nombre de clients actifs */
void destroyclient(struct client *client) {
    struct page *page, *nextpage;
    struct pageobj *obj, *nextobj;
    struct client *liste;

    page=client->pages;
    while (page) {
	obj=page->objects;
	while (obj) {
	    int fd = obj->fd;
	    nextobj=obj->next;
	    if (fd > 0) {
		close(fd);
		nbconn--;
		fdtab[fd] = NULL;
		FD_CLR(fd, StaticReadEvent);
		FD_CLR(fd, StaticWriteEvent);

		if (maxfd == fd+1) {   /* recompute maxfd */
		    while ((maxfd-1 >= 0) && (fdtab[maxfd-1] == NULL))
			maxfd--;
		}
	    }
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
    nbactcli--;
    return;
}

int stats(void *arg) {
	static lines;
	static struct timeval nextevt;
	static unsigned long lasthits;
	static unsigned long lastread;
	static struct timeval lastevt;
	unsigned long totaltime, deltatime;
	if (tv_cmp(&now, &nextevt) >= 0) {
		deltatime = (tv_delta(&now, &lastevt)?:1);
		totaltime = (tv_delta(&now, &starttime)?:1);
		if (lines++ % 16 == 0)
		fprintf(stderr,"\n   time +delta clients    hits +delta hits/s  last     bytes +   delta  kB/s  last\n");

		if (lines>1)
			fprintf(stderr,"%7ld +%5ld %7ld %7ld +%5ld  %5ld %5ld %9ld +%8ld %5ld %5ld\n",
				totaltime, deltatime,
				iterations,
				totalhits, totalhits-lasthits,
				totalhits*1000/totaltime,
				(totalhits-lasthits)*1000/deltatime,
				totalread, totalread-lastread,
				totalread/totaltime, (totalread-lastread)/deltatime);
		
		tv_delayfrom(&nextevt, &now, STATTIME);
		lasthits=totalhits;
		lastread=totalread;
		lastevt=now;
	}	
	return tv_remain(&now, &nextevt);
}

static void onemoreclient() {
    char uname[32];
    sprintf(uname, "%d", clientid++);
    /* on entre dans le scheduler directement à partir de ce client */
    newclient(uname, uname);
    nbactcli++;
    iterations++;
}

/* ce scheduler s'occupe d'injecter des clients tant qu'il n'y en a pas assez, mais jamais
   plus d'un tous les <injectdelay> ms
*/
static inline int injecteur(void *arg) {
    static struct timeval next;

    //    if
    while
	(nbactcli < nbclients)
	onemoreclient();

    if ((iterations == nbiterations) /* c'est la fin, on ne veut plus injecter */
	|| (nbconn >= MAXSOCK) /* on ne peut plus injecter par manque de sockets */
	|| (nbclients >= reqclients)) /* il y a assez de clients */
	return -1;

    if (tv_cmp(&next, &now) > 0)  /* on ne doit pas encore créer de nouveau client */
	return tv_remain(&now, &next);

    if (nbclients < reqclients)
	nbclients++;

    tv_delayfrom(&next, &now, injectdelay);
    return injectdelay;
}


/*
 * ce scheduler s'occupe de gérer les clients (think time, ...)
 */
int scheduler(void *arg) {
    static struct timeval next;
    struct client *cli, *nextcli;
    unsigned int delay;

    delay = -1;

    nextcli = clients;
    while ((cli = nextcli) != NULL) {
	struct page *page;
	struct pageobj *obj;

	nextcli = cli->next;

	if (cli->status == STATUS_RUN) {
	    continue;
	}
	else if (cli->status == STATUS_THINK) {
	    unsigned int del2;
	    if ((del2 = tv_remain(&now, &cli->nextevent)) > 0) {  /* attendre avant de passer à la page suivante */
		if (del2 < delay)
		    delay = del2;
		continue;
	    }
	    else {
		page = cli->current = cli->current->next;
		if (page == NULL) {  /* fin du scénario pour ce client */
		    totalread += cli->dataread;
		    totalhits += cli->hits;
		    destroyclient(cli);
		    continue;
		}
		else {
		    start_client(cli);
		    continue;
		}
	    }
	}
	else if ((cli->status == STATUS_ERROR) && (cli->current->objleft == 0)) {
	    destroyclient(cli);
	    continue;
	}
    }
    
    if
	//    while
	(nbactcli < nbclients) {
	onemoreclient();
    }

    if ((nbactcli == 0) && (iterations == nbiterations)) {
	int deltatime = (tv_delta(&now, &starttime)?:1);
	printf("Fin: %ld clients ont généré %ld hits et chargé %ld octets en %ld ms soit %ld kB/s et %ld hits/s.\n",
	    iterations, totalhits, totalread, deltatime, totalread/deltatime, totalhits*1000/deltatime);
	exit(0);
    }

    tv_delayfrom(&next, &now, delay);

#if 0
    {
	  struct timeval nowexit;
	  tv_now(&nowexit);
	  if (tv_delta(&now, &nowexit) > 10)
	      printf("+de 10ms dans le scheduler\n");
    }
#endif
    return delay;
}

int SelectRun() {
  int next_time, time2;
  int status;
  int fd,i;
  struct timeval delta;
  int readnotnull, writenotnull;

  while(!stopnow) {
      next_time = -1;
      tv_now(&now);

      time2 = injecteur(NULL);
      next_time = MINTIME(time2, next_time);
	  
      time2 = scheduler(NULL);
      next_time = MINTIME(time2, next_time);
	  
#if STATTIME > 0
      time2 = stats(NULL);
      next_time = MINTIME(time2, next_time);
#endif

      if (next_time >= 0) {
	  /* Convert to timeval */
	  delta.tv_sec=next_time/1000; 
	  delta.tv_usec=(next_time%1000)*1000;
      }


    /* on restitue l'etat des fdset */
      //      memcpy(ReadEvent, StaticReadEvent, sizeof(ReadEvent));
      //      memcpy(WriteEvent, StaticWriteEvent, sizeof(WriteEvent));

      readnotnull = 0; writenotnull = 0;
      for (i = 0; i < sizeof(ReadEvent)/sizeof(int); i++) {
	  readnotnull |= (*((int*)ReadEvent+i) = *((int*)StaticReadEvent+i)) != 0;
	  writenotnull |= (*((int*)WriteEvent+i) = *((int*)StaticWriteEvent+i)) != 0;
      }
      
      /* On va appeler le select(). Si le temps fixé est nul, on considère que
	 c'est un temps infini donc on passe NULL à select() au lieu de {0,0}.  */
      status=select(maxfd,
		    readnotnull ? ReadEvent : NULL,
		    writenotnull ? WriteEvent : NULL,
		    NULL,
		    (next_time >= 0) ? &delta : NULL);
      
      if (status > 0) { /* Appeller les events */

	  int fds;
	  char count;
	  char closeit = 0;
	  
	  /* test sur les FD en lecture. On les parcourt 32 par 32 pour gagner du temps */
	  for (fds = 0; (fds << INTBITS) < maxfd; fds++)
	      if ((((int *)(ReadEvent))[fds] | ((int *)(WriteEvent))[fds]) != 0)  /* au moins un FD non nul */
		  for (count = 1<<INTBITS, fd = fds << INTBITS; count && fd < maxfd; count--, fd++) {
		      
		      if (fdtab[fd] == NULL)
			  continue;
		      closeit = 0;
		      
		      if (!closeit && FD_ISSET(fd, WriteEvent))
			  closeit |= EventWrite(fd);
		      
		      if (!closeit && FD_ISSET(fd, ReadEvent))
			  closeit |= EventRead(fd);
		      
		      if (closeit) {
			  close(fd);
			  nbconn--;
			  fdtab[fd]->page->objleft--;
			  FD_CLR(fd, StaticReadEvent);
			  FD_CLR(fd, StaticWriteEvent);
			  fdtab[fd]->fd = 0;
			  fdtab[fd]=NULL;
			  
			  if (maxfd == fd+1) {   /* recompute maxfd */
			      while ((fd >= 0) && (fdtab[fd] == NULL))
				  fd--;
			      maxfd = fd+1;
			  }
		      }
		  }
      }
  }
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

    return curscnpage = page;
}

/* adds a new object to the current page. aborts if no current page set */
struct scnobj *newscnobj(int meth, char *host, char *uri, char *vars) {
    struct scnobj *obj;

    if (curscnpage == NULL)
	Abort("Scenario must define PAGE before OBJECT.\n");

    obj = (struct scnobj *)calloc(1, sizeof(struct scnobj));
    memcpy(&obj->addr, str2sa(host), sizeof(obj->addr));

    obj->meth = meth;
    obj->host = strdup(host);
    obj->uri = strdup(uri);
    obj->vars = (vars == NULL) ? NULL : strdup(vars);

    if (curscnobj == NULL)
	curscnpage->objects = obj;
    else
	curscnobj->next = obj;

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
	    strncpy(curscnhost, args[1], sizeof(curscnhost));
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

    fprintf(stderr,"[inject] <parsescnline> : args=<%s> <%s> <%s> <%s> ...\n",args[0], args[1], args[2], args[3]);

    return -1; /* unknown sequence */
}


/*** retourne 0 si OK, 1 si on doit fermer le FD ***/
int EventWrite(int fd) {
    int ret;
    char req[2048];
    char *r = req;
    struct pageobj *obj;
    int data, ldata;


    obj = fdtab[fd];

    ldata=sizeof(data);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &data, &ldata);

    if (data == 0) {  /* pas d'erreur sur la socket */
	/* créer la requête */
	if (obj->meth == METH_GET)  {
	    r+=sprintf(r, "GET %s", obj->uri);
	    if (obj->vars)
		r+=sprintf(r,"?%s", obj->vars);
	    r+=sprintf(r," HTTP/1.0\r\n");
	    if (obj->page->client->cookie)
		r+=sprintf(r, "Cookie: %s\r\n", obj->page->client->cookie);
	    r+=sprintf(r, "Host: %s\r\n", obj->host);
	    r+=sprintf(r,"\r\n");
	}
	else { /* meth = METH_POST */
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
	
	/* la requete est maintenant prete */
	if (write(fd, req, strlen(req)) != -1) {
	    FD_SET(fd, StaticReadEvent);
	    FD_CLR(fd, StaticWriteEvent);
	    //	    shutdown(fd, SHUT_WR);
	    return 0;
	}
	else {
	    if (errno != EAGAIN) {
		fprintf(stderr,"[Event] erreur sur le write().\n");
		tv_now(&obj->page->end);
		obj->page->client->status = obj->page->status = STATUS_ERROR;
		return 1;
	    }
	    return 0;  /* erreur = EAGAIN */
	}
    }
    else { /* erreur sur la socket */
	fprintf(stderr,"[Event] erreur sur le connect() : %d\n",data);
	tv_now(&obj->page->end);
	obj->page->client->status = obj->page->status = STATUS_ERROR;
	return 1;
    }

}


/*** retourne 0 si OK, 1 si on doit fermer le FD ***/
int EventRead(int fd) {
    int ret, moretoread;
    char req[2048];
    char *r = req;
    struct pageobj *obj;

    obj = fdtab[fd];

    do {
	moretoread = 0;
	if (obj->buf + BUFSIZE <= obj->read)  /* on ne stocke pas les data dépassant le buffer */
	    ret=read(fd, trash, sizeof(trash));  /* lire les data mais ne pas les stocker */
	else {
	    ret=read(fd, obj->read, BUFSIZE - (obj->read - obj->buf)); /* lire et stocker les data */
	    if (ret > 0)
		obj->read+=ret;
	}

	if (ret>0) {
	    if ((starttime.tv_sec | starttime.tv_usec) == 0)  /* la premiere fois, on démarre le chrono */
		tv_now(&starttime);

	    obj->page->dataread+=ret;
	    obj->page->client->dataread+=ret;

	    moretoread = 1;
	}
	else if (ret == 0) {
	    char *ptr1, *ptr2, *cookie, *ptr3;
	    char *header;
	    /* lire les headers pour savoir s'il y a un cookie */
	    ptr1 = obj->buf;
	    while (ptr1 < obj->read) {
		/* si on a un saut de ligne ici, c'est forcément une fin de headers */
		if ((*ptr1 == '\r') || (*ptr1 == '\n'))
		    break;

		ptr2 = ptr1;

		/* recherche la fin de la chaine */
		while ((ptr1<obj->read) && (*ptr1 != '\n') && (*ptr1 != '\r'))
		    ptr1++;
		/* ptr1 pointe sur le premier saut de ligne ou retour charriot */

#if 0
		header = (char *)calloc(1, ptr1-ptr2+1);
		strncpy(header, ptr2, ptr1-ptr2);
		fprintf(stderr,"read : header=%d octets : %s \n",ptr1-ptr2, header);
		free(header);
#endif

		if ((ptr1-ptr2 > 11) && !strncasecmp(ptr2,"Set-Cookie:",11)) {
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
			    // Log(LOG_LDEBUG,"[Event] Cookie = %s\n", cookie);
			}
			else {
			    cookie=(char *)calloc(1, ptr3-ptr2+1);
			    strncpy(cookie, ptr2, ptr3-ptr2);
			    /* on a forcément le zéro final */
			    obj->page->client->cookie=cookie;
			    // Log(LOG_LDEBUG,"[Event] Cookie = %s\n", cookie);
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

	    if (obj->page->objleft == 1) {  /* dernier objet de cette page */
		// Log(LOG_LDEBUG,"[Event] dernier objet de la page, mise en veille du client.\n");
		obj->page->client->hits++;
		tv_now(&obj->page->end);
		tv_wait(&obj->page->client->nextevent, obj->page->thinktime);
		if (obj->page->client->status != STATUS_ERROR) {
		    obj->page->client->status = obj->page->status = STATUS_THINK;
		}
	    }
	    else {
		obj->page->client->hits++;
		// Log(LOG_LDEBUG,"[Event] encore <%d> objets sur la page <%p>.\n", obj->page->objleft-1, obj->page);
	    }
	    /* liberer le fd en sortant */
	    return 1;
	}
	else if ((ret == -1) && (errno != EAGAIN)) {
	    // Log(LOG_LDEBUG,"[Event] erreur, arrêt du client <%p>.\n", obj->page->client);
	    obj->page->client->status = STATUS_ERROR;
	    return 1;
	}
    } while (moretoread);
    /* sinon c'est un EAGAIN, pas grave */
    return 0;
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

void sighandler(int sig) {
    stopnow = 1;
    return;
}

int main(int argc, char **argv) {
    int deltatime;

    if (1<<INTBITS != sizeof(int)*8) {
	fprintf(stderr,"Erreur: recompiler avec pour que sizeof(int)=%d\n",sizeof(int)*8);
	exit(1);
    }
    if (argc != 5) {
	fprintf(stderr,"Syntaxe : inject <nbusers> <nbiterations> <injectdelay> <scnfile>\n"
		"Le fichier de scenario a pour syntaxe :\n"
		"host addr:port\n"
		"new pageXXX <think time en ms>\n"
		"\tget . /fichier1.html\n"
		"\tget . /fichier2.html\n"
		"new pageYYY <think time ...>\n");
	exit(1);
    }
    reqclients = atol(argv[1]);
    nbclients = 1;
    nbiterations = atol(argv[2]) * reqclients;
    injectdelay = atol(argv[3]);
    scnfile = argv[4];

    if (readscnfile(scnfile) < 0) {
	fprintf(stderr, "[inject] Error reading scn file : %s\n", scnfile);
	exit(1);
    }

    FD_ZERO(StaticReadEvent);
    FD_ZERO(StaticWriteEvent);
    bzero(fdtab, sizeof(fdtab));

    signal(SIGINT, sighandler);
    SelectRun();

    tv_now(&now);
    deltatime = (tv_delta(&now, &starttime)?:1);
    printf("Fin: %ld clients ont généré %ld hits et chargé %ld octets en %ld ms soit %ld kB/s et %ld hits/s.\n",
	   iterations, totalhits, totalread, deltatime, totalread/deltatime, totalhits*1000/deltatime);
    return 0;
}


/*
 * Trace du probleme du connect().
 * Injecteur sur un kernel 2.4.0test11, serveur sur un 2.2.18-22wt4.
 * --> Voir la socket 4 : elle ne se débloque jamais.
 *
 * socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 4
 * fcntl(4, F_SETFL, O_RDONLY|O_NONBLOCK)  = 0
 * connect(4, {sin_family=AF_INET, sin_port=htons(10000), sin_addr=inet_addr("10.101.23.11")}}, 16) = -1 EINPROGRESS (Operation now in progress)
 * select(5, NULL, [3 4], NULL, {0, 748000}) = 1 (out [3], left {0, 750000})
 * getsockopt(3, SOL_SOCKET, SO_ERROR, [0], [4]) = 0
 * write(3, "GET /1k HTTP/1.0\r\nHost: 10.101.2"..., 46) = 46
 * gettimeofday({974847718, 831384}, NULL) = 0
 * select(5, [3], [4], NULL, {0, 746000})  = 1 (in [3], left {0, 750000})
 * read(3, "HTTP/1.0 200 OK\nContent-Length: "..., 4096) = 38
 * read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 4058) = 1024
 * read(3, "", 3034)                       = 0
 * close(3)                                = 0
 * gettimeofday({974847718, 832247}, NULL) = 0
 * select(5, NULL, [4], NULL, {0, 745000}) = 0 (Timeout)
 * gettimeofday({974847719, 577047}, NULL) = 0
 * select(5, NULL, [4], NULL, {0, 0})      = 0 (Timeout)
 * gettimeofday({974847719, 577262}, NULL) = 0


 */
