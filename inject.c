/*
 * Injecteur HTTP simple - (C) 2000-2004 Willy Tarreau <willy@ant-computing.com>
 * Utilisation et redistribution soumises a la licence GPL.
 *
 * 2000/11/18 : correction du SEGV.
 * 2000/11/21 : grand nettoyage de l'automate et correction de nombreux bugs.
 * 2000/11/22 : ajout des time-outs, erreurs, temps par hit et par page.
 * 2000/11/22 : limitation du nombre de sockets simultanées par client.
 * 2000/11/24 : correction du bug infame lie a la limitation du nombre de FD.
 * 2001/02/26 : ajout du "User-Agent" et du "Connection: close". Acceptation
 *              des cookies sans "path=/"
 *              TODO: gérer le referer, et controler la longueur des cookies lors des remplacements.
 * 2001/03/02 : ajout de headers personnalisés
 * 2001/08/07 : heure de demarrage dans les logs, affichage toutes les secondes.
 *              correction d'un bug sur l'allocation des variables
 * 2001/08/09 : Affinage du delai d'affichage des stats à la milliseconde. Ce
 *              temps devient paramétrable par l'option "-w".
 *              Le démarrage en douceur fonctionne bien, même pour des petits délais.
 *              Le temps cumulé affiché est désormais "-1" tant que l'injection n'a pas
 *              pu démarrer.
 * 2001/08/10 : correction de l'arret premature et ajout de la ligne de commande dans les logs.
 * 2002/02/04 : correction d'un nouveau bug dans la gestion des headers, et affinage de la
 *              gestion mémoire pour tenter de faire tenir plus d'utilisateurs.
 *		Il faudrait refaire la partie serveur (voir haproxy) pour libérer les headers
 *		aussitôt que possible, et lire les data à la volée.
 * 2004/05/14 : ajout de l'option '-a' pour afficher la date absolue.
 * 2004/09/26 : passage en mode multi-processus
 *
 * Remarque : le champ "variables" HTTP peut contenir 2 "%s" qui seront remplacés par l'id du client
 *            et son mot de passe (=id)
 *
 * Obs : parfois l'injecteur se bloque vers le serveur sizesrv, s'il y a peu
 *	 de clients. strace montre que c'est parce qu'un connect() n'aboutit
 *       pas. C'est maintenant rattrapé par le timeout. Sans doute une table
 *       de sockets qui se fige quelque part, ou un bug sur l'OS :-(
 *       Voir la trace à la fin de ce fichier.
 *
 * TODO :
 *  - réécrire en gérant des files d'attente suivant l'état des clients.
 *  - gérer les unités d'affichage
 *
 * Détail des affichages :
 *  time delta clients    hits ^hits hits/s  ^h/s     bytes   ^bytes  kB/s  last  errs  tout htime ptime
 *
 * - time est le nombre de millisecondes écoulées depuis le début du test
 * - delta est le temps en millisecondes depuis le dernier affichage
 * - clients est le nombre total de clients ayant déroulé un scénario (avec ou sans erreurs)
 * - hits est le nombre total de hits réussis (=sans erreur) depuis le début du test
 * - ^hits est le nombre de hits réussis depuis le dernier affichage
 * - hits/s est le nombre moyen de hits par seconde depuis le début du test
 * - ^h/s est le nombre moyen de hits par seconde depuis le dernier affichage
 * - bytes est le nombre total d'octets lus depuis le début du test
 * - ^bytes est le nombre d'octets recus depuis le dernier affichage
 * - kB/s est le débit moyen depuis le début du test, en kilooctets par seconde
 * - ^k/s est le débit moyen depuis le dernier affichage, en ko/s
 * - errs est le nombre d'erreurs (déconnexions ...) depuis le début du test
 * - tout est le nombre de timeouts depuis le début du test
 * - htime donne l'évolution du temps moyen d'un hit (en ms)
 * - ptime donne l'évolution du temps moyen de chargement d'une page avec tous ses objets (en ms)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <time.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <math.h>

#ifndef TCP_NODELAY
#define TCP_NODELAY	1
#endif

#define METH_NONE	0
#define METH_GET	1
#define METH_POST	2

#define STATUS_RUN	1
#define STATUS_THINK	2
#define STATUS_ERROR	3

#define OBJ_STNEW	-1
#define OBJ_STTERM	-2

#define BUFSIZE		4096
#define TRASHSIZE	65536

/* this reduces the number of calls to select() by choosing appropriate
 * sheduler precision in milliseconds. It should be near the minimum
 * time that is needed by select() to collect all events. All timeouts
 * are rounded up by adding this value prior to pass it to select().
 */
#define SCHEDULER_RESOLUTION	9

/* show stats this every millisecond, 0 to disable */
#define STATTIME	1000

/* sur combien de bits code-t-on la taille d'un entier (ex: 32bits -> 5) */
#define	INTBITS		5

#define	USER_AGENT	"Mozilla/4.0.(compatible; MSIE 4.01; Windows)"

#define MINTIME(old, new)	(((new)<0)?(old):(((old)<0||(new)<(old))?(new):(old)))
#define SETNOW(a)		(*a=now)

/* un objet dont le fd est -1 est inactif */
struct pageobj {
    struct pageobj *next;
    struct page *page;
    struct sockaddr_in addr;
    int fd;
    char *buf;
    char *read;
    char meth;
    char *uri;
    char *vars;
    char *host;
    struct timeval starttime;
};

struct page {
    struct page *next;
    struct pageobj *objects;
    struct pageobj *objecttostart;
    struct client *client;
    struct timeval begin;
    int actobj;
    int objleft;
    int thinktime;
    int status;
    int dataread;
};

struct client {
    struct client *next;
    struct timeval nextevent;
    struct timeval expire;
    struct page *current;
    struct scnpage *pages;
    char *username;
    char *password;
    char *cookie;
    int status;
    int dataread;
    int hits;
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
char *global_headers = NULL;

unsigned long int arg_nbclients=0;
unsigned long int nbclients=0;
unsigned int arg_maxobj = 8;
unsigned long int arg_maxiter=0;
int arg_nbprocs = 1;
int arg_slowstart = 0;
int arg_stattime = STATTIME;
int arg_maxsock = 1000;
char *arg_scnfile = NULL;
int arg_random_delay = 0;
static int arg_timeout = 0;
static int arg_log = 0, arg_abs_time = 0;
static int arg_maxtime = 0;

static struct timeval now={0,0};
static int one = 1;
int nbconn=0;
int clientid=0;
int nbactcli=0;
int shmid=0;
char *shmaddr=NULL;


/* stats[0] = global. stats[x]=per thread */
struct stats {
    unsigned long long int totalread;
    unsigned long int totalhits;
    unsigned long int totalerr;
    unsigned long int totaltout;
    unsigned long int iterations;
    unsigned long int stat_hits;
    unsigned long int stat_ptime, stat_pages;
    double moy_htime, moy_sdhtime, moy_ptime;
    double tot_htime, tot_sqhtime;	/* utilisés pour le calcul de l'écart-type */
} *stats = NULL;

char trash[TRASHSIZE];
static struct timeval starttime = {0,0};
static struct timeval stoptime = {0,0};

int maxfd = 0;
int thr = 0;
int stopnow = 0;
static struct pageobj **fdtab;

fd_set	*ReadEvent,
	*WriteEvent,
	*StaticReadEvent,
    	*StaticWriteEvent;

void **pool_pageobj = NULL,
    **pool_buffer = NULL,
    **pool_page = NULL,
    **pool_client = NULL,
    **pool_str = NULL,
    **pool_vars = NULL;

/*****  prototypes **********************************************/
void destroyclient(struct client *client, struct client *prev);
int EventRead(int fd);
int EventWrite(int fd);
/****************************************************/

/****** gestion mémoire *******/
#define sizeof_pageobj (sizeof(struct pageobj))
#define sizeof_buffer (BUFSIZE)
#define sizeof_page (sizeof(struct page))
#define sizeof_client (sizeof(struct client))
#define sizeof_str (128)
#define sizeof_vars (1024)

#define MEM_OPTIM
#ifdef MEM_OPTIM
/*
   Returns a pointer to type <type> taken from the
   pool <pool_type> or dynamically allocated. In the
   first case, <pool_type> is updated to point to the
   next element in the list.
*/
#define alloc_pool(type) ({			\
    void *p;					\
    if ((p = pool_##type) == NULL)		\
	p = malloc(sizeof_##type);		\
    else {					\
	pool_##type = *(void **)pool_##type;	\
    }						\
    p;						\
})

/*
   Puts a memory area back to the corresponding pool.
   Items are chained directly through a pointer that
   is written in the beginning of the memory area, so
   there's no need for any carrier cells. This implies
   that each memory area is at least as big as one
   pointer.
*/
#define free_pool(type, ptr) ({				\
    *(void **)ptr = (void *)pool_##type;		\
    pool_##type = (void *)ptr;				\
})

#else
#define alloc_pool(type) (calloc(1,sizeof_##type));
#define free_pool(type, ptr) (free(ptr));
#endif

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
static inline struct timeval *tv_now(struct timeval *tv) {
    if (tv)
	gettimeofday(tv, NULL);
    return tv;
}

/* adds <ms> ms to <from>, set the result to <tv> and returns a pointer <tv> */
static inline struct timeval *tv_delayfrom(struct timeval *tv, struct timeval *from, int ms) {
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

/* compares <tv1> and <tv2> : returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2 */
static inline int tv_cmp(struct timeval *tv1, struct timeval *tv2) {
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

/*
 * compares <tv1> and <tv2> modulo 1ms: returns 0 if equal, -1 if tv1 < tv2, 1 if tv1 > tv2
 */
static inline int tv_cmp_ms(struct timeval *tv1, struct timeval *tv2) {
    if (tv1->tv_sec == tv2->tv_sec) {
	if (tv1->tv_usec >= tv2->tv_usec + 1000)
	    return 1;
	else if (tv2->tv_usec >= tv1->tv_usec + 1000)
	    return -1;
	else
	    return 0;
    }
    else if ((tv1->tv_sec > tv2->tv_sec + 1) ||
	     ((tv1->tv_sec == tv2->tv_sec + 1) && (tv1->tv_usec + 1000000 >= tv2->tv_usec + 1000)))
	return 1;
    else if ((tv2->tv_sec > tv1->tv_sec + 1) ||
	     ((tv2->tv_sec == tv1->tv_sec + 1) && (tv2->tv_usec + 1000000 >= tv1->tv_usec + 1000)))
	return -1;
    else
	return 0;
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
static inline unsigned long tv_remain(struct timeval *tv1, struct timeval *tv2) {
  int cmp;
  unsigned long ret;
  

  cmp=tv_cmp_ms(tv1, tv2);
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
static inline struct pageobj *newobj(char methode, char *host, struct sockaddr_in *addr, char *uri, char *vars, struct page *page) {
    struct pageobj *obj;

    //    obj=(struct pageobj *)calloc(1, sizeof(struct pageobj));
    obj = alloc_pool(pageobj);
    //    memset(obj, 0, sizeof_pageobj);

    memset(&obj->starttime, 0, sizeof(struct timeval));
    memcpy(&obj->addr, addr, sizeof(obj->addr));
    obj->fd	= OBJ_STNEW;  /* fd non ouvert */
    obj->meth	= methode;

    obj->uri = uri;
    obj->host = host;
    if (vars) {
	obj->vars = (char *)alloc_pool(vars);
	strcpy(obj->vars, vars);
    }
    else
	obj->vars = NULL;

    obj->next	= NULL;
    obj->buf	= NULL;
    obj->page	= page;
    //    obj->read = obj->buf = (char *)malloc(BUFSIZE);
    //    obj->read = obj->buf = (char *)alloc_pool(buffer);

    return obj;
}

/* crée une page pour un client existant. Les username et password du client doivent exister */
struct page *newpage(struct scnpage *scn, struct client *client) {
    struct page *page;
    struct pageobj **obj;
    struct scnobj *scnobj;
    char variables[sizeof_str];

    //    page=(struct page *)calloc(1, sizeof(struct page));
    page=(struct page *)alloc_pool(page);
    memset(page, 0, sizeof_page);
    page->client = client;
    page->thinktime = scn->thinktime;
    if (arg_random_delay)
	page->thinktime += random() % (1+scn->thinktime/10) - scn->thinktime/20;

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
    page->objecttostart = page->objects;

    return page;
}

/* tente de rajouter les fetchs non initiés pour une page donnée.
   renvoie 0 si le client a été supprimé suite à une erreur.
   renvoie 1 si le fetch a correctement été initié, et 2 s'il a échoué (manque de ressources)
*/
/*static inline*/ int continue_fetch(struct page *page) {
    struct pageobj *obj;

    while ((obj = page->objecttostart) != NULL) {
	int fd;
	if (nbconn >= arg_maxsock ||
	    page->actobj >= arg_maxobj) { /* on ne peut pas démarrer le fetch tout de suite */
	    return 2;
	}

	if ((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
	    //	    fprintf(stderr, "impossible de créer une socket, destruction du client.\n");
	    //	    destroyclient(page->client, NULL); /* renvoie un pointeur sur le suivant */
	    //	    return 0; /* killed client */
	    return 2;
	}
	
	if ((setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &one, sizeof(one)) == -1) ||
	    (fcntl(fd, F_SETFL, O_NONBLOCK)==-1)) {
	    fprintf(stderr,"impossible de mettre la socket en O_NONBLOCK\n");
	}
	if ((connect(fd, (struct sockaddr *)&obj->addr, sizeof(obj->addr)) == -1) && (errno != EINPROGRESS)) {
	    if (errno == EAGAIN) { /* plus de ports en local -> réessayer plus tard */
		close(fd);
		return 2;
	    }
	    else if (errno != EALREADY && errno != EISCONN) {
		//		fprintf(stderr,"impossible de faire le connect() pour le fd %d, errno ) %d. destruction du client.\n",
		//			fd, errno);
		close(fd);
		destroyclient(page->client, NULL); /* renvoie un pointeur sur le suivant */
		return 0; /* killed client */
	    }
	    /* else connection delayed or accepted */
	}
	else {
	    obj->fd = fd;
	    nbconn++;
	    page->actobj++;

	    SETNOW(&obj->starttime);
	    fdtab[fd]=obj;
	    FD_SET(fd, StaticWriteEvent);
	    
	    if (fd+1 > maxfd)
		maxfd = fd+1;
	}
	page->objecttostart = obj->next;
    }
    return 1; /* ok */
}

/* démarre un client. Si une erreur se produit lors du démarrage, alors
   les ressources sont libérées et le client est détruit.
   retourne 0 si le client a été détruit.
*/
int start_client(struct client *cli) {
    struct page *page;
    struct pageobj *obj;

    cli->status = STATUS_RUN;
    if (arg_timeout > 0)
	tv_delayfrom(&cli->expire, &now, arg_timeout);

    if ((page = cli->current) == NULL) /* fin des pages pour ce client */
	return 1;

    /* initie autant de fetches que possible pour cette page */
    if (continue_fetch(page) == 0)
	return 0; /* client détruit */

    /* on va terminer de compter les objets pour savoir combien il en reste */
    obj = page->objecttostart;
    page->objleft = page->actobj;
    while (obj != NULL) {
	page->objleft++;
	obj = obj->next;
    }

    SETNOW(&page->begin);
    /* le client est (re)démarré */
    return 1;
}


/* retourne 0 si le client a du être détruit. */
int newclient(char *username, char *password) {
    struct client *newclient;

//    newclient=(struct client*)calloc(1, sizeof(struct client));
    newclient=(struct client*)alloc_pool(client);
	memset(newclient, 0, sizeof_client);
//fprintf(stderr,"client calloc %p\n", newclient);

    if (username != NULL)
    	newclient->username=strdup(username);
    if (password != NULL)
    	newclient->password=strdup(password);

    newclient->pages = firstscnpage;
    newclient->current = newpage(newclient->pages, newclient);
    nbactcli++;
    newclient->next = clients;

    return start_client(clients = newclient);
}

/* retourne 0 si le client a été détruit */
static inline int onemoreclient() {
    char uname[32];
    sprintf(uname, "%d", clientid++);

    /* on entre dans le scheduler directement à partir de ce client */
    if (newclient(uname, uname) == 0)
	return 0;

    stats[thr].iterations++;
    return 1;
}

void destroypage(struct page *page) {
    struct pageobj *obj, *nextobj;

    obj=page->objects;
    while (obj) {
	int fd = obj->fd;
	nextobj = obj->next;
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
	if (obj->vars)
		free_pool(vars, obj->vars);
	if (obj->buf)
		free_pool(buffer, obj->buf);
	free_pool(pageobj, obj);
	obj=nextobj;
    }
    free_pool(page, page);
}

/* detruit le client, libère ses fd encore ouverts, décompte le nombre de connexions
   associées, et décrémente le nombre de clients actifs */
void destroyclient(struct client *client, struct client *prev) {

    if (client->current) {
	destroypage(client->current);
    }

    if (clients == client)
	clients = clients->next;
    else {
	if ((prev != NULL) &&
	    (prev->next == client)) { /* si on connait le précédent dans la liste, on y va directement */
	}
	else {
	    prev = clients;
	    while (prev->next != client) {
		prev = prev->next;
	    	if (prev == NULL)
			abort(); /* ca ne doit jamais arriver */
	    }
	}
	prev->next = client->next;
    }
    if (client->cookie)
	free(client->cookie);
    if (client->password)
	free(client->password);
    if (client->username)
	free(client->username);
    free_pool(client, client);

    nbactcli--;

    while (nbactcli < nbclients) {
	if ((arg_maxiter > 0) && (stats[thr].iterations >= arg_maxiter)) {
		if (nbactcli == 0)
			stopnow = 1;
		break;
	}
	else if (onemoreclient() == 0) {
	    break; /* si ret==0, plus possible d'injecter à cause d'erreurs */
	}
    }

    return;
}

int show_stats(void *arg) {
	static int lines;
	static struct timeval nextevt;
	static unsigned long lasthits;
	static unsigned long long lastread;
	static struct timeval lastevt;
	long totaltime, deltatime;

	if ((nextevt.tv_sec | nextevt.tv_usec) == 0)
	    tv_now(&nextevt);

	if (tv_cmp(&now, &nextevt) >= 0) {
	    unsigned long long int totalread=0;
	    unsigned long int totalhits=0;
	    unsigned long int totalerr=0;
	    unsigned long int totaltout=0;
	    unsigned long int iterations=0;
	    unsigned long int stat_hits=0;
	    unsigned long int stat_ptime=0, stat_pages=0;
	    double tot_htime=0, tot_sqhtime=0;

		int t;
		deltatime = (tv_delta(&now, &lastevt)?:1);
		if ((starttime.tv_sec | starttime.tv_usec) == 0)
		    totaltime = -1;
		else
		    totaltime = (tv_delta(&now, &starttime)?:1);


		for (t = 1; t <= arg_nbprocs; t++) {
		    unsigned long long int tr1, tr2;

		    tr1 = stats[t].totalread;
		    totalhits  += stats[t].totalhits;
		    totalerr   += stats[t].totalerr;
		    totaltout  += stats[t].totaltout;
		    iterations += stats[t].iterations;
		    tot_htime  += stats[t].tot_htime;		    stats[t].tot_htime = 0;
		    tot_sqhtime+= stats[t].tot_sqhtime;	 	    stats[t].tot_sqhtime = 0;
		    stat_ptime += stats[t].stat_ptime;		    stats[t].stat_ptime = 0;
		    stat_hits  += stats[t].stat_hits;		    stats[t].stat_hits = 0;
		    stat_pages += stats[t].stat_pages;		    stats[t].stat_pages = 0;
		    /* try to avoid inter-thread race without any lock */
		    tr2 = stats[t].totalread;
		    if ((tr2 & 0xffffffff) < (tr1 & 0xffffffff)) {
			tr2 = tr1;
		    }
		    totalread += tr2;
		}

		stats[0].totalread   = totalread;
		stats[0].totalhits   = totalhits;
		stats[0].totalerr    = totalerr;
		stats[0].totaltout   = totaltout;
		stats[0].iterations  = iterations;
		stats[0].tot_htime   = tot_htime;
		stats[0].tot_sqhtime = tot_sqhtime;
		stats[0].stat_ptime  = stat_ptime;
		stats[0].stat_hits  += stat_hits;
		stats[0].stat_pages += stat_pages;

		/*
		 * standard deviation = sqrt(sum(x-moy)^2/n) = sqrt((sum(x^2)-2*moy*sum(x))/n + moy^2)
		 */
		if (stats[0].stat_hits) {
		    stats[0].moy_htime = stats[0].tot_htime / (double)stats[0].stat_hits;
		    stats[0].moy_sdhtime =
			sqrt(
			     (stats[0].tot_sqhtime
			      - 2*stats[0].moy_htime*stats[0].tot_htime) / (double)stats[0].stat_hits
			     + stats[0].moy_htime * stats[0].moy_htime);
		}
		else
		    stats[0].moy_sdhtime = stats[0].moy_htime = stats[0].moy_ptime = 0;

		if (stats[0].stat_pages)
		    stats[0].moy_ptime = (float)stats[0].stat_ptime/(float)stats[0].stat_pages;


		if ((lines++ % 16 == 0) && !arg_log)
		    fprintf(stderr,
			    "\n   hits ^hits"
			    " hits/s  ^h/s     bytes  kB/s"
			    "  last  errs  tout htime  sdht ptime\n");
		if (lines>1) {
		    if (arg_log)
			fprintf(stdout,"%7ld %5ld %7ld %7ld %5ld  %5ld %5ld %9lld %8lld %5ld %5ld %5ld %5ld %03.1f %3.1f %03.1f %5d\n",
				arg_abs_time ? now.tv_sec + (now.tv_usec >= 500000) : totaltime, deltatime,
				stats[0].iterations,
				stats[0].totalhits, stats[0].stat_hits/*totalhits-lasthits*/,
				(unsigned long)((unsigned long long)stats[0].totalhits*1000ULL/totaltime),
				stats[0].stat_hits/*(totalhits-lasthits)*/*1000/deltatime,
				stats[0].totalread, stats[0].totalread-lastread,
				(long)(stats[0].totalread/(unsigned long long)totaltime),
				(long)((stats[0].totalread-lastread)/(unsigned long long)deltatime),
				stats[0].totalerr, stats[0].totaltout,
				stats[0].moy_htime, stats[0].moy_sdhtime, stats[0].moy_ptime, nbactcli);
		    else
			fprintf(stderr,"%7ld %5ld  %5ld %5ld %9lld %5ld %5ld %5ld %5ld %03.1f %3.1f %03.1f\n",
				stats[0].totalhits, stats[0].stat_hits/*totalhits-lasthits*/,
				(unsigned long)((unsigned long long)stats[0].totalhits*1000ULL/totaltime),
				stats[0].stat_hits/*(totalhits-lasthits)*/*1000/deltatime,
				stats[0].totalread,
				(long)(stats[0].totalread/(unsigned long long)totaltime),
				(long)((stats[0].totalread-lastread)/(unsigned long long)deltatime),
				stats[0].totalerr, stats[0].totaltout,
				stats[0].moy_htime, stats[0].moy_sdhtime, stats[0].moy_ptime);
		}
		else if (arg_log) { /* print it once */
				    fprintf(stderr,
					    "   time delta clients    hits ^hits"
					    " hits/s  ^h/s     bytes   ^bytes  kB/s"
					    "  last  errs  tout htime  sdht ptime nbcli\n");
		}
		if (totaltime > 0)
		    deltatime = arg_stattime - totaltime % arg_stattime; /* correct imprecision */
		else
		    deltatime = arg_stattime;

		if (deltatime < arg_stattime/2) /* avoid too short time */
		    deltatime += arg_stattime;

		tv_delayfrom(&nextevt, &now, deltatime);
		lasthits=stats[0].totalhits;
		lastread=stats[0].totalread;
		lastevt=now;
		stats[0].stat_hits  = 0;
		stats[0].stat_pages = stats[0].stat_ptime = 0;
		stats[0].tot_htime = stats[0].tot_sqhtime = 0;

		if ((arg_maxtime > 0 && tv_cmp_ms(&stoptime, &now) < 0)
		    /*|| (arg_maxiter > 0 && stats[0].iterations > arg_maxiter)*/)
		    stopnow=1;  /* bench must terminate now */
	}	
	return tv_remain(&now, &nextevt);
}

/* ce scheduler s'occupe d'injecter des clients tant qu'il n'y en a pas assez, mais jamais
   plus d'un tous les <arg_slowstart> ms
*/
static inline int injecteur(void *arg) {
    static struct timeval next;
    int delay = -1;

    if ((arg_maxiter > 0) && (stats[thr].iterations >= arg_maxiter)) /* c'est la fin, on ne veut plus injecter */
	return -1;

    if (nbclients < arg_nbclients) {
	unsigned long times;

	if ((next.tv_sec | next.tv_usec) == 0)
	    tv_now(&next);

	if (arg_slowstart == 0)
	    nbclients = arg_nbclients; /* no soft start, all clients at once */
	else {
	    times = tv_remain(&next, &now) / arg_slowstart; /* client needed during elapsed time since last visiting */
	    if (times > 0) {
		tv_delayfrom(&next, &next, (times + 1) * arg_slowstart); /* decrement remaining time, but delay it for 1 iteration */
		nbclients += times;
		if (nbclients > arg_nbclients)
		    nbclients = arg_nbclients;
	    }
	    delay = tv_remain(&now, &next);
	}
    }
    else
	delay = -1;

    /* try to get as many clients as required */
    while ((nbactcli < nbclients) && (onemoreclient() != 0));

    return delay;
}


/*
 * ce scheduler s'occupe de gérer les clients (think time, ...)
 */
int scheduler(void *arg) {
    static struct timeval next;
    struct client *cli, *nextcli, *prev;
    unsigned int delay;

    delay = -1;

    nextcli = clients; prev = NULL;
    while ((cli = nextcli) != NULL && !stopnow) {
	nextcli = cli->next;
#ifdef SANITY_CHECKS
	if (cli->current == NULL)
		abort();  /* ca ne doit jamais arriver ici */
#endif
	if (cli->status == STATUS_RUN) {
	    unsigned int del2;

	    if (arg_timeout > 0) {
		if ((del2 = tv_remain(&now, &cli->expire)) > 0) {
		    delay = MINTIME(del2, delay);
		}
		else {
		    stats[thr].totaltout++;
		    destroyclient(cli, prev);
		    continue;
		}
	    }
	    if (cli->current->objecttostart != NULL) { /* s'il reste des fetches à effectuer, on les fait. */
		if (continue_fetch(cli->current) == 0)
			continue; /* le client a été détruit ? */
	    }
	    prev = cli; /* conserve le chainage pour accélérer la suppression */
	    continue;
	}
	else if (cli->status == STATUS_THINK) {
	    unsigned int del2;
	    if ((del2 = tv_remain(&now, &cli->nextevent)) > 0) {  /* attendre avant de passer à la page suivante */
		delay = MINTIME(del2, delay);
		prev = cli; /* conserve le chainage pour accélérer la suppression */
		continue;
	    }
	    else {
#ifndef PER_CLIENT_STATS
		//		stats[thr].totalread += cli->current->dataread;
#endif
		if ((cli->pages = cli->pages->next) == NULL) { /* fin du scénario pour ce client */
#ifdef PER_CLIENT_STATS
		    //		    stats[thr].totalread += cli->dataread;
		    stats[thr].totalhits += cli->hits;
#endif
		    destroyclient(cli, prev);
		    continue;
		}
		else {
		    destroypage(cli->current);
		    cli->current = newpage(cli->pages, cli);

		    if (start_client(cli) != 0)
			prev = cli; /* conserve le chainage pour accélérer la suppression */
		    continue;
		}
	    }
	}
	else if ((cli->status == STATUS_ERROR) /*&& (cli->current->actobj == 0)*/) {
	    stats[thr].totalerr++;
	    destroyclient(cli, prev);
	    continue;
	}
	prev = cli; /* conserve le chainage pour accélérer la suppression */
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

void SelectRun() {
  int next_time, time2;
  int status;
  int fd,i;
  struct timeval delta;
  int readnotnull, writenotnull;

  while (!stopnow) {
      next_time = -1;
      tv_now(&now);

      if (nbactcli < arg_nbclients) { /* ne pas y aller si ce n'est pas nécessaire */
	  time2 = injecteur(NULL);
	  next_time = MINTIME(time2, next_time);
      }
	  
      time2 = scheduler(NULL);
      next_time = MINTIME(time2, next_time);
	  
      /* arg_stattime is forced to zero on thr>1 */
      if (arg_stattime > 0) {
	  time2 = show_stats(NULL);
	  next_time = MINTIME(time2, next_time);
      }

      if (next_time > 0) {
	  /* Convert to timeval */
	  /* to avoid eventual select loops due to timer precision */
	  next_time += SCHEDULER_RESOLUTION;
	  delta.tv_sec  = next_time / 1000; 
	  delta.tv_usec = (next_time % 1000) * 1000;
      }
      else if (next_time == 0) { /* allow select to return immediately when needed */
	  delta.tv_sec = delta.tv_usec = 0;
      }


      /* on restitue l'etat des fdset */

#define FDSET_OPTIM
#ifndef FDSET_OPTIM
	memcpy(ReadEvent, StaticReadEvent, sizeof(ReadEvent));
	memcpy(WriteEvent, StaticWriteEvent, sizeof(WriteEvent));
      readnotnull = 1; writenotnull = 1;
#else
      readnotnull = 0; writenotnull = 0;
      for (i = 0; i < (arg_maxsock + 3 + FD_SETSIZE - 1)/(8*sizeof(int)); i++) {
	  readnotnull |= (*((int*)ReadEvent+i) = *((int*)StaticReadEvent+i)) != 0;
	  writenotnull |= (*((int*)WriteEvent+i) = *((int*)StaticWriteEvent+i)) != 0;
      }
#endif
      /* On va appeler le select(). Si le temps fixé est nul, on considère que
	 c'est un temps infini donc on passe NULL à select() au lieu de {0,0}.  */
      status=select(maxfd,
		    readnotnull ? ReadEvent : NULL,
		    writenotnull ? WriteEvent : NULL,
		    NULL,
		    (next_time >= 0) ? &delta : NULL);
      
      tv_now(&now);
      if (status > 0) { /* Appeller les events */

	  int fds;
	  char count;
	  
	  /* test sur les FD en lecture. On les parcourt 32 par 32 pour gagner du temps */
	  for (fds = 0; (fds << INTBITS) < maxfd; fds++)
	      if ((((int *)(ReadEvent))[fds] | ((int *)(WriteEvent))[fds]) != 0)  /* au moins un FD non nul */
		  for (count = 1<<INTBITS, fd = fds << INTBITS; count && fd < maxfd; count--, fd++) {
		      
		      if (fdtab[fd] == NULL)
			  continue;
		      
		      /* better to free system buffers first */
		      if ((!FD_ISSET(fd, ReadEvent) || !EventRead(fd))
			  && (!FD_ISSET(fd, WriteEvent) || !EventWrite(fd)))
			  continue;

		      close(fd);
		      nbconn--;
		      fdtab[fd]->page->objleft--;
		      fdtab[fd]->page->actobj--;
		      FD_CLR(fd, StaticReadEvent);
		      FD_CLR(fd, StaticWriteEvent);
		      fdtab[fd]->fd = OBJ_STTERM;
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
    obj->vars = (vars == NULL) ? NULL : strdup(vars);  // pas plutot alloc_pool(vars) ?

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

    if (!strcasecmp(*args, "host")) {  /* host */
	if (isalnum(*args[1])) {
	    strncpy(curscnhost, args[1], sizeof(curscnhost));
	}
	return 0;
    }
    
    if (!strcasecmp(*args, "header")) {  /* header */
	char *ptr, *ptr2;
	int arg;

	if (global_headers != NULL) {
	    ptr2 = ptr = (char *)malloc(strlen(global_headers) + 256 + 3);
	    ptr += sprintf(ptr, "%s%s", global_headers, args[1]);
	    free(global_headers);
	}
	else {
	    ptr2 = ptr = (char *)malloc(256 + 1);
	    ptr += sprintf(ptr, "%s", args[1]);
	}
	global_headers = ptr2;
	arg=2;
	while (arg<9 && *args[arg]) {
	    ptr += sprintf(ptr, " %s", args[arg]);
	    arg++;
	}
	*(ptr++) = '\r';
	*(ptr++) = '\n';
	*(ptr++) = '\0';

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
    char req[4096];
    char *r = req;
    struct pageobj *obj;
    int data;

    obj = fdtab[fd];

    if (arg_timeout > 0)
	tv_delayfrom(&obj->page->client->expire, &now, arg_timeout);

    /* créer la requête */
    if (obj->meth == METH_GET)  {
	r+=sprintf(r, "GET %s", obj->uri);
	if (obj->vars)
	    r+=sprintf(r,"?%s", obj->vars);
	r+=sprintf(r," HTTP/1.0\r\n"
		   "Host: %s\r\nUser-Agent: " USER_AGENT "\r\n", obj->host);
	if (obj->page->client->cookie)
	    r+=sprintf(r, "Cookie: %s\r\n", obj->page->client->cookie);
	if (global_headers)
	    r+=sprintf(r, "%s", global_headers);
	r+=sprintf(r, "Connection: close\r\n\r\n");
    }
    else { /* meth = METH_POST */
	r+=sprintf(r,
		   "POST %s HTTP/1.0\r\n"
		   "Host: %s\r\nUser-Agent: " USER_AGENT "\r\n"
		   "Connection: close\r\n"
		   "Content-Type: application/x-www-form-urlencoded\r\n", obj->uri, obj->host);
	
	if (obj->page->client->cookie)
	    r+=sprintf(r, "Cookie: %s\r\n", obj->page->client->cookie);
	if (global_headers)
	    r+=sprintf(r, "%s", global_headers);
	if (obj->vars) {		
	    r+=sprintf(r,"Content-length: %d\r\n\r\n%s", strlen(obj->vars), obj->vars);
	}
	else
	    r+=sprintf(r,"\r\n");
    }
    
    /* a ce stade, obj->vars ne devrait plus servir */
    if (obj->vars) {
	free_pool(vars, obj->vars);
	obj->vars = NULL;
    }
    
#ifndef MSG_NOSIGNAL
    {
	int ldata = sizeof(data);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &data, &ldata);
	if (data)
	    data = -1;
	else
	    data = send(fd, req, r-req, MSG_DONTWAIT);
    }
#else
    data = send(fd, req, r-req, MSG_DONTWAIT | MSG_NOSIGNAL);
#endif
    /* la requete est maintenant prete */
    if (data != -1) {
	FD_SET(fd, StaticReadEvent);
	FD_CLR(fd, StaticWriteEvent);
	//	    shutdown(fd, SHUT_WR);
	return 0;
    }
    else {
	if (errno != EAGAIN) {
	    //		fprintf(stderr,"[Event] erreur sur le write().\n");
	    //		/*tv_now*/SETNOW(&obj->page->end);
	    obj->page->client->status = obj->page->status = STATUS_ERROR;
	    return 1;
	}
	return 0;  /* erreur = EAGAIN */
    }
}


/*** retourne 0 si OK, 1 si on doit fermer le FD ***/
int EventRead(int fd) {
    int ret, moretoread;
    struct pageobj *obj;

    obj = fdtab[fd];

    if (arg_timeout > 0)
	tv_delayfrom(&obj->page->client->expire, &now, arg_timeout);

    do {
	moretoread = 0;
	if (obj->buf == NULL) { /* pas encore alloué */
	    obj->read = obj->buf = (char *)alloc_pool(buffer);
	}

	if (obj->buf + BUFSIZE <= obj->read) { /* on ne stocke pas les data dépassant le buffer */
            int readsz = sizeof(trash);
#ifndef MSG_NOSIGNAL
	    ret=recv(fd, trash, readsz,0);  /* lire les data mais ne pas les stocker */
#else
	    ret=recv(fd, trash, readsz,MSG_NOSIGNAL/*|MSG_WAITALL*/);  /* lire les data mais ne pas les stocker */
#endif
	} else {
            int readsz = BUFSIZE - (obj->read - obj->buf);
#ifndef MSG_NOSIGNAL
	    ret=recv(fd, obj->read, readsz, 0); /* lire et stocker les data */
#else
	    ret=recv(fd, obj->read, readsz, MSG_NOSIGNAL/*|MSG_WAITALL*/); /* lire et stocker les data */
#endif
	    if (ret > 0)
		obj->read += ret;
	}

	if (ret > 0) {
	    if ((starttime.tv_sec | starttime.tv_usec) == 0)  /* la premiere fois, on démarre le chrono */
		/*tv_now*/SETNOW(&starttime);

	    obj->page->dataread+=ret;
	    obj->page->client->dataread+=ret;
	    stats[thr].totalread += ret;

	    moretoread = 1;
	}
	else if ((ret == 0) || (ret == -1 && errno == ECONNRESET)) {
	    char *ptr1, *ptr2, *cookie, *ptr3;
	    unsigned long delta;
	    //char *header;

	    /* on relève les mesures le plus tôt possible */
	    delta = tv_delta(&obj->starttime, &now);
	    stats[thr].tot_htime += delta;
	    stats[thr].tot_sqhtime += delta*delta;
	    stats[thr].stat_hits ++;

#ifndef DONT_ANALYSE_HTTP_HEADERS

	    /* lire les headers pour savoir s'il y a un cookie */
	    ptr1 = obj->buf;
	    while (ptr1 < obj->read) {
		/* si on a un saut de ligne ici, c'est forcément une fin de headers */
		if ((*ptr1 == '\r') || (*ptr1 == '\n'))
		    break;

		ptr2 = ptr1;

		/* recherche la fin de la chaine */
		while ((ptr1 < obj->read) && (*ptr1 != '\n') && (*ptr1 != '\r'))
		    ptr1++;
		/* ptr1 pointe sur le premier saut de ligne ou retour charriot */

#if 0
		header = (char *)calloc(1, ptr1-ptr2+1);
		strncpy(header, ptr2, ptr1-ptr2);
		fprintf(stderr,"read : header=%d octets : %s \n",ptr1-ptr2, header);
		free(header);
#endif

		if ((ptr1-ptr2 > 11) && !strncasecmp(ptr2,"Set-Cookie:",11)) {

		    /* recherche du début de la partie utile du cookie */
		    ptr2+=11;
		    while ((ptr2 < ptr1) && isspace(*ptr2))
			ptr2++;

		    /* on va se débarrasser des "path=" */
		    //		    *ptr1=0;

		    ptr3 = ptr2;
		    while ((ptr3 <= ptr1-5) && (strncmp(ptr3, "path=", 5) != 0))
			ptr3++;

		    //		    if (((ptr3=strstr(ptr2,"path=")) != NULL)) {
		    if (ptr3 <= ptr1-5) {
			/* et on se débarrasse aussi de "; path=" */
			while ((ptr3 > ptr2) && ((*(ptr3-1)==' ') || (*(ptr3-1)==';') || (*(ptr3-1)=='\t')))
			    ptr3--;
		    } else {
			ptr3=ptr2;
			while (ptr3 < ptr1 && *ptr3 && *ptr3 != '\n' && *ptr3 != '\r'
			       && *ptr3 != ' ' && *ptr3 != '\t' && *ptr3 != ';')
				ptr3++;
		    }

		    /* on ne devrait pas faire ceci car on écrase peut-etre un CR ou un LF */
		    //		    *ptr3=0;


		    /* a ce niveau, le nouveau cookie est compris exactement entre ptr2 et ptr3
		     * sous la forme var=val sans délimiteur. ptr2 est terminé par un zero.
		     */
		    //		    fprintf(stderr,"---ptr2-ptr3=<%s>\n", ptr2);

		    /* le cookie est compris entre ptr2 et ptr3 */
		    /* on va le concaténer au cookie existant */
		    if (obj->page->client->cookie != NULL) {
			char *equal, *oldcookie = obj->page->client->cookie;
			char *newcookie, *end;
			newcookie = cookie = (char *)calloc(1, strlen(oldcookie) + ptr3-ptr2 + 6);

			/* si les cookies actuels contiennent le meme cookie, il faut le remplacer */
			equal = ptr2;

			/* a remplacer par un strstr */
			while ((equal < ptr3) && *equal && (*equal != '='))
			    equal++;
			
			/* le nom du cookie est maintenant compris entre ptr2 et ptr3 */

			//			strncpy(newcookie, ptr2, ptr3-ptr2);
			//			*(newcookie+=(ptr3-ptr2)) = 0;
			//			strcpy(newcookie, "; "); newcookie += 2;


			//			fprintf(stderr,"ptr2=<%s>, oldcookie=<%s>\n", ptr2, oldcookie);


			//			if ((equal < ptr3) && (*equal == '='))
			{
			    while (*oldcookie) {
				end = oldcookie;

				/* cherche la fin du premier cookie */
				while (*end && (*end != ' ') && (*end != ';'))
				    end++;

				//				fprintf(stderr,"ptr2=%s, oldcookie=%s\n", ptr2, oldcookie);

				/* tous les cookies differents sont recopies */
				if (strncmp(oldcookie, ptr2, equal-ptr2+1) != 0) {  /* copier ce cookie */
				    //				    fprintf(stderr,"recopie: %s\n", oldcookie);
				    memcpy(newcookie, oldcookie, end-oldcookie);
				    newcookie += (end-oldcookie);
				    strcpy(newcookie, "; "); newcookie += 2;
				}

				/* passer au cookie suivant */
				oldcookie = end;
				while (*oldcookie && (*oldcookie == ' ' || *oldcookie == ';'))
				    oldcookie++;
			    }
			    
			    //				    strcpy(cookie, obj->page->client->cookie);
			    //				    strcat(cookie,"; ");
			    //				    strncat(cookie, ptr2, ptr3-ptr2);
			    memcpy(newcookie, ptr2, ptr3-ptr2);
			    newcookie+=(ptr3-ptr2);
			    strcpy(newcookie, "; "); newcookie += 2;
			}
			free(obj->page->client->cookie);
			obj->page->client->cookie = cookie; /* affectation du nouveau cookie */
			// Log(LOG_LDEBUG,"[Event] Cookie = %s\n", cookie);
		    }
		    else {
			cookie=(char *)calloc(1, ptr3-ptr2+1);
			memcpy(cookie, ptr2, ptr3-ptr2);
			cookie[ptr3-ptr2]=0;
			obj->page->client->cookie=cookie;
			// Log(LOG_LDEBUG,"[Event] Cookie = %s\n", cookie);
		    }
		    //		    fprintf(stderr,"---cookie=<%s>\n", cookie);
		}
		
		/* recherche la fin du saut de ligne */
		if (ptr1 < obj->read) {
		    if (ptr1+1 < obj->read) {
			if ((*ptr1 == '\n') && (ptr1[1] == '\r'))
			    ptr1++;
			else if ((*ptr1 == '\r') && (ptr1[1] == '\n'))
			    ptr1++;
		    }
		    ptr1++;
		}
	    }
#endif

#ifndef PER_CLIENT_STATS
	    stats[thr].totalhits ++;
#endif

	    if (obj->page->objleft == 1) {  /* dernier objet de cette page */
		// Log(LOG_LDEBUG,"[Event] dernier objet de la page, mise en veille du client.\n");
		obj->page->client->hits++;
		//		/*tv_now*/SETNOW(&obj->page->end);
		tv_delayfrom(&obj->page->client->nextevent, &now, obj->page->thinktime);
		if (obj->page->client->status != STATUS_ERROR) {
		    obj->page->client->status = obj->page->status = STATUS_THINK;
		    stats[thr].stat_ptime += tv_delta(&obj->page->begin, &now);
		    stats[thr].stat_pages ++;
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
	    //	    printf("erreur = %d\n",errno);
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

void usage() {
    fprintf(stderr,
	    "Syntaxe : inject -u <users> -f <scnfile> [ -i <iter> ] [ -d <duration> ] [ -l ]\n"
	    "          [ -r ] [ -t <timeout> ] [ -n <maxsock> ] [ -o <maxobj> ] [ -a ]\n"
	    "          [ -s <starttime> ] [ -w <waittime> ] [ -p nbprocs ] \n"
	    "- users    : nombre de clients simultanes (=nb d'instances du scenario)\n"
	    "- iter     : nombre maximal d'iterations a effectuer par client\n"
	    "- waittime : temps (en ms) entre deux affichages des stats (0=jamais)\n"
	    "- starttime: temps (en ms) d'incrementation du nb de clients (montee en charge)\n"
	    "- scnfile  : nom du fichier de scénario a utiliser\n"
	    "- timeout  : timeout (en ms) sur un objet avant destruction du client\n"
	    "- duration : duree maximale du test (en secondes)\n"
	    "- maxobj   : nombre maximal d'objets en cours de lecture par client\n"
	    "- maxsock  : nombre maximal de sockets utilisees\n"
	    "- [ -r ]   : ajoute 10%% de random sur le thinktime\n"
	    "- [ -l ]   : passe en format de logs (plus large, pas de repetition de legende)\n"
	    "- [ -a ]   : affiche la date absolue (uniquement avec -l)\n"
	    "Le fichier de scenario a pour syntaxe :\n"
	    "host addr:port\n"
	    "new pageXXX <think time en ms>\n"
	    "\t{get|post} {ip:port|.} /fichier1.html var1=val&clientid=%%s&passwd=%%s\n"
	    "\t{get|post} {ip:port|.} /fichier2.html var2=val&clientid=%%s&passwd=%%s\n"
	    "new pageYYY <think time ...>\n");
    exit(1);
}

int main(int argc, char **argv) {
    struct rlimit rlim;
    long int deltatime;
    time_t launch_time;
    struct tm *tm;
    int t;
    int orig_argc = argc;
    char **orig_argv = argv;
    char *mois[12]={"Jan","Fev","Mar","Avr","Mai","Juin",
                    "Juil","Aou","Sep","Oct","Nov","Dec"};

    if (1<<INTBITS != sizeof(int)*8) {
	fprintf(stderr,"Erreur: recompiler avec pour que sizeof(int)=%d\n",sizeof(int)*8);
	exit(1);
    }

    argc--; argv++;
    while (argc > 0) {
	char *flag;

	if (**argv == '-') {
	    flag = *argv+1;

	    /* 1 arg */
	    if (*flag == 'l')
		arg_log = 1;
	    else if (*flag == 'r')
		arg_random_delay = 1;
	    else if (*flag == 'a')
		arg_abs_time = 1;
	    else { /* 2+ args */
		argv++; argc--;
		if (argc == 0)
		    usage();

		switch (*flag) {
		case 'p' : arg_nbprocs = atol(*argv); break;
		case 't' : arg_timeout = atol(*argv); break;
		case 'u' : arg_nbclients = atol(*argv); break;
		case 'i' : arg_maxiter = atol(*argv); break;
		case 'd' : arg_maxtime = atol(*argv); break;
		case 'f' : arg_scnfile = *argv; break;
		case 'n' : arg_maxsock = atol(*argv); break;
		case 'o' : arg_maxobj = atol(*argv); break;
		case 's' : arg_slowstart = atol(*argv); break;
		case 'w' : arg_stattime = atol(*argv); break;
		default: usage();
		}
	    }
	}
	else
	    usage();
	    argv++; argc--;
    }
    nbclients = 0;
    arg_maxiter *= arg_nbclients;

    if (!arg_scnfile ||	!arg_nbclients)
	usage();

    if (geteuid() == 0) {
	rlim.rlim_cur = rlim.rlim_max = arg_maxsock + 3;
	if (setrlimit(RLIMIT_NOFILE, &rlim) == -1)
	    fprintf(stderr,"Warning: cannot set RLIMIT_NOFILE to %d\n", arg_maxsock+3);
    }
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
	if (rlim.rlim_max < arg_maxsock + 3)
	    fprintf(stderr,"Warning: system will not allocate more than %ld sockets\n", rlim.rlim_max);
    }
    else
	fprintf(stderr,"Warning: cannot verify if system will accept %d sockets\n", arg_maxsock+3);

    if (readscnfile(arg_scnfile) < 0) {
	fprintf(stderr, "[inject] Error reading scn file : %s\n", arg_scnfile);
	exit(1);
    }

    ReadEvent = (fd_set *)calloc(1,
		sizeof(fd_set) *
		(arg_maxsock + 3 + FD_SETSIZE - 1) / FD_SETSIZE);
    WriteEvent = (fd_set *)calloc(1,
		sizeof(fd_set) *
		(arg_maxsock + 3 + FD_SETSIZE - 1) / FD_SETSIZE);
    StaticReadEvent = (fd_set *)calloc(1,
		sizeof(fd_set) *
		(arg_maxsock + 3 + FD_SETSIZE - 1) / FD_SETSIZE);
    StaticWriteEvent = (fd_set *)calloc(1,
		sizeof(fd_set) *
		(arg_maxsock + 3 + FD_SETSIZE - 1) / FD_SETSIZE);
    fdtab = (struct pageobj **)calloc(1,
		sizeof(struct pageobj *) * (arg_maxsock + 3));


    shmid=shmget(IPC_PRIVATE, sizeof(struct stats)*(1+arg_nbprocs), IPC_CREAT);
    shmaddr=shmat(shmid, NULL, 0);
    stats=(void *)shmaddr;
    if (stats == (void *)-1) {
	stats = (struct stats *)calloc(1+arg_nbprocs, sizeof(struct stats));
        printf("shmid = %d, shmaddr = %p, stats = %p\n", shmid, shmaddr, stats);
	printf("shmat error, retry as root or do not use multi-process.\n");
	exit(1);
    }
    memset(stats, 0, sizeof(struct stats)*(1+arg_nbprocs));
    shmctl(shmid, IPC_RMID, NULL);

    time(&launch_time); tm=localtime(&launch_time);
    tv_now(&now);
    tv_delayfrom(&stoptime, &now, arg_maxtime * 1000);

    signal(SIGINT, sighandler);

    if (arg_nbprocs > 1) {

        for (t = 1; t <= arg_nbprocs; t++) {
	    if (t > 1) {
		thr=t;
	        if (fork() == 0) {
	            /* only one thread does the stats */
		    arg_stattime = 0;
		    SelectRun();
		    exit(0);
	        }
	    }
        }
    }

    thr = 1;
    SelectRun();
    tv_now(&now);

    deltatime = (tv_delta(&now, &starttime)?:1);
    printf("\nFin.\nClients : %ld\nHits    : %ld\nOctets  : %lld\nDuree   : %ld ms\n"
	   "Debit   : %lld kB/s\nReponse : %ld hits/s\n"
	   "Erreurs : %ld\nTimeouts: %ld\n"
	   "Temps moyen de hit: %3.1f ms\n"
	   "Temps moyen d'une page complete: %3.1f ms\n"
	   "Date de demarrage: %ld (%d %s %d - %d:%02d:%02d)\n",
	   stats[0].iterations, stats[0].totalhits, stats[0].totalread, deltatime,
	   stats[0].totalread/(unsigned long long)deltatime, (unsigned long)((unsigned long long)stats[0].totalhits*1000ULL/deltatime),
	   stats[0].totalerr, stats[0].totaltout,
           stats[0].moy_htime, stats[0].moy_ptime,
	   (long)launch_time,
           tm->tm_mday, mois[tm->tm_mon], tm->tm_year+1900,
           tm->tm_hour, tm->tm_min, tm->tm_sec);
    printf("Ligne de commande : ");
    while (orig_argc--) {
	printf("%s ", *orig_argv++);
    }
    putchar('\n');
    return 0;
}


/*
 * Trace du probleme du connect().
 * Injecteur <inject6> sur un kernel 2.4.0test11, serveur <sizesrv> sur un 2.2.18-22wt4.
 * --> Voir la socket 4 : elle ne se débloque jamais.
 * rem: un problème similaire a été observé sur sizesrv dans la gestion des signaux.
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
