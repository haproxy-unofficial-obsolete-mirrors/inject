/*
 * Injecteur HTTP simple (C) 2000-2011 Willy Tarreau <willy@ant-computing.com>
 * Utilisation et redistribution soumises a la licence GPL.
 *
 * Compilation :
 *    gcc -O2 -o inject inject.c -lm          # par défaut
 *    gcc -O2 -DNO_SD -o inject inject.c      # désactive sdht (pas besoin de libm)
 *    gcc -O2 -DDONT_ANALYSE_HTTP_HEADERS -o inject inject.c -lm  # désactive parseur HTTP
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
 * 2005/01/10 : affichage des moyenne et ecart-type des temps de réponse
 * 2005/01/19 : Ne plus démarrer un client si pas assez de FD.
 *		Synthèse des statistiques avant affichage final.
 * 2005/08/09 : ajout des options -H, -T, -G, -P pour faire le scénario en ligne de commande.
 * 2005/10/09 : correction du nom 'host' si utilisation de -G.
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
#include <limits.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
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

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0
#endif

#ifndef MSG_MORE
#define MSG_MORE	0
#endif

#ifdef ENABLE_SPLICE
#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ (1024 + 7)
#endif

#ifndef __NR_splice
#if defined(__x86_64__)
#define __NR_splice             275
#define __NR_tee                276
#define __NR_vmsplice           278
#elif defined (__i386__)
#define __NR_splice             313
#define __NR_tee                315
#define __NR_vmsplice           316
#elif defined (__arm__)
#define __NR_splice             340
#define __NR_tee                342
#define __NR_vmsplice           343
#endif /* $arch */
#endif /* __NR_splice */

#ifndef SPLICE_F_NONBLOCK
#define SPLICE_F_MOVE     1
#define SPLICE_F_NONBLOCK 2
#define SPLICE_F_MORE     4

#ifndef _syscall4
#define _syscall4(tr, nr, t1, n1, t2, n2, t3, n3, t4, n4)  \
        inline tr nr(t1 n1, t2 n2, t3 n3, t4 n4) {         \
                return syscall(__NR_##nr, n1, n2, n3, n4); \
        }
#endif
#ifndef _syscall6
#define _syscall6(tr, nr, t1, n1, t2, n2, t3, n3, t4, n4, t5, n5, t6, n6) \
        inline tr nr(t1 n1, t2 n2, t3 n3, t4 n4, t5 n5, t6 n6) {          \
                return syscall(__NR_##nr, n1, n2, n3, n4, n5, n6);        \
        }
#endif
static _syscall6(int, splice, int, fdin, loff_t *, off_in, int, fdout, loff_t *, off_out, size_t, len, unsigned long, flags);
static _syscall4(long, vmsplice, int, fd, const struct iovec *, iov, unsigned long, nr_segs, unsigned int, flags);
static _syscall4(long, tee, int, fd_in, int, fd_out, size_t, len, unsigned int, flags);
#endif
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
// 100 HZ
//#define SCHEDULER_RESOLUTION	9
// 250 HZ
//#define SCHEDULER_RESOLUTION	3

// trade off CPU for better accuracy
#define SCHEDULER_RESOLUTION	0

/* show stats this every millisecond, 0 to disable */
#define STATTIME	1000

/* sur combien de bits code-t-on la taille d'un entier (ex: 32bits -> 5) */
#define	INTBITS		5

#define	USER_AGENT	"Mozilla/4.0.(compatible; MSIE 4.01; Windows)"

#define MINTIME(old, new)	(((new)<0)?(old):(((old)<0||(new)<(old))?(new):(old)))
#define SETNOW(a)		(*a=now)

/*
 * Gcc >= 3 provides the ability for the programme to give hints to the
 * compiler about what branch of an if is most likely to be taken. This
 * helps the compiler produce the most compact critical paths, which is
 * generally better for the cache and to reduce the number of jumps.
 */
#if !defined(likely)
#if __GNUC__ < 3
#define __builtin_expect(x,y) (x)
#define likely(x) (x)
#define unlikely(x) (x)
#elif __GNUC__ < 4
/* gcc 3.x does the best job at this */
#define likely(x) (__builtin_expect((x) != 0, 1))
#define unlikely(x) (__builtin_expect((x) != 0, 0))
#else
/* GCC 4.x is stupid, it performs the comparison then compares it to 1,
 * so we cheat in a dirty way to prevent it from doing this. This will
 * only work with ints and booleans though.
 */
#define likely(x) (x)
#define unlikely(x) (__builtin_expect((unsigned long)(x), 0))
#endif
#endif

/* a local IP addresses list */
struct local_ip {
    struct in_addr addr;
    u_int16_t *freeports; /* ports in host byte order */
    int size; /* number of allocatable ports + 1 */
    int reserved; /* # of reserved ports (preallocated) */
    int get, put; /* indexes of where to get and put a free port. Empty if get == put */
    struct local_ip *next;
};

/* un objet dont le fd est -1 est inactif */
struct pageobj {
    struct pageobj *next;
    struct page *page;
    struct sockaddr_in addr;
    u_int16_t local_port; /* local port in host byte order. 0 if not assigned. */
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
    struct local_ip *addr; /* NULL if automatically assigned */
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
int arg_stepsize = 1; /* #of clients to add every <arg_slowstart> */
int arg_stattime = STATTIME;
int arg_maxsock = 1000;
char *arg_scnfile = NULL;
char *arg_sourceaddr = NULL;
int arg_random_delay = 0;
int arg_random_distance = 0;
int arg_fast_connect = 0;
int arg_fast_close = 0;
int arg_use_splice = 0;
int arg_regular_time = 0;
static int arg_timeout = 0;
static int arg_log = 0, arg_abs_time = 0;
static int arg_maxtime = 0;

static int arg_nbpages, arg_thinktime;
static char *arg_geturl = NULL;
int active_thread = 0;

static struct timeval now={0,0};
static struct timeval ramp_start={0,0};
static int one = 1;
static int zero = 0;
int nbconn=0;
int nbactconn=0;
int clientid=0;
int nbactcli=0;
int ramp_step=0;

/* set to the local_ip list if required */
static struct local_ip *local_ip_list = NULL;
static struct local_ip *next_ip = NULL;

/* stats[0] = global. stats[x]=per thread */
struct stats {
    unsigned long long int totalread;
    unsigned long int totalhits;
    unsigned long int aborted;
    unsigned long int totalerr;
    unsigned long int totaltout;
    unsigned long int iterations;
    unsigned long int stat_hits;
    unsigned long int stat_ptime, stat_pages;
    unsigned long int nbconn, nbcli;
    double moy_htime, moy_sdhtime, moy_ptime;
    double tot_htime, tot_sqhtime;	/* utilisés pour le calcul de l'écart-type */
} *stats = NULL;

char trash[TRASHSIZE];
static struct timeval starttime = {0,0};
static struct timeval stoptime = {0,0};
const struct linger nolinger = { .l_onoff = 1, .l_linger = 0 };

int master_pipe[2]; /* pipe used by splice() */
int pipe_count = 0;
int dev_null_fd=0;
int pipesize = TRASHSIZE;

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

char *cmd_line; /* this contain the original command line for repporting */

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
#define sizeof_str (2048)
#define sizeof_vars (2048)

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
	    //fprintf(stderr, "%s, %d\n", vars, strlen(vars));
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


/* finds an IP with at least <nbports> free ports. Returns a pointer to the
 * structure with the pre-reserved ports, or NULL if not found.
 */
static inline struct local_ip *get_free_ip(int nbports) {
    struct local_ip *orig = next_ip;

    do {
	if (!next_ip)
	    next_ip = local_ip_list;

	if (next_ip->size - next_ip->reserved >= nbports) {
	    next_ip->reserved += nbports;
	    orig = next_ip;
	    next_ip = next_ip->next;
	    return orig;
	}
	next_ip = next_ip->next;
    } while (next_ip != orig);
    return NULL;
}

/* frees the ip */
static inline void put_free_ip(struct local_ip *ip, int nbports) {
    ip->reserved -= nbports;
}

/* returns a free port from the ip address <ip>, or 0 if none or if <ip> is NULL.
 * The port is in host byte order.
 */
static inline u_int16_t get_free_port(struct local_ip *ip, int offset) {
    u_int16_t port;

    if (!ip)
	return 0;

    //fprintf(stderr,"%s:%d - entering\n", __FUNCTION__, __LINE__);

    port = 0;
    if (ip->get != ip->put) {
	port = ip->freeports[ip->get++] + offset;
	if (ip->get >= ip->size)
	    ip->get = 0;
    }
    //fprintf(stderr,"%s:%d - leaving : %d\n", __FUNCTION__, __LINE__, port);
    return port;
}

/* frees the host byte order port <p> into the <ip> list. Does nothing if
 * called with port 0, or NULL ip.
 */
static inline void put_free_port(struct local_ip *ip, u_int16_t p, int offset) {
    if (!p || !ip)
	return;
    //fprintf(stderr,"%s:%d - entering with %d,%d\n", __FUNCTION__, __LINE__, p, offset);
    ip->freeports[ip->put++] = p - offset;
    if (ip->put >= ip->size)
	ip->put = 0;
    //fprintf(stderr,"%s:%d - leaving\n", __FUNCTION__, __LINE__);
}

/* tente de rajouter les fetchs non initiés pour une page donnée.
   renvoie 0 si le client a été supprimé suite à une erreur.
   renvoie 1 si le fetch a correctement été initié, et 2 s'il a échoué (manque de ressources)
*/
/*static inline*/ int continue_fetch(struct page *page) {
    struct pageobj *obj;
    int attempts = 0;

    while ((obj = page->objecttostart) != NULL) {
	int fd;
	obj->local_port = 0;
	if (unlikely(nbconn+arg_maxobj >= arg_maxsock || page->actobj >= arg_maxobj)) {
	    /* on ne peut pas démarrer le fetch tout de suite */
	    /* ce n'est pas de la faute du serveur en face, donc on reporte le timeout */
	    if (arg_timeout > 0)
		tv_delayfrom(&page->client->expire, &now, arg_timeout);
	    return 2;
	}

	if ((page->begin.tv_sec | page->begin.tv_usec) == 0)
	    SETNOW(&page->begin);

    retry:
	if (unlikely((fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)) {
	    //	    fprintf(stderr, "impossible de créer une socket, destruction du client.\n");
	    //	    destroyclient(page->client, NULL); /* renvoie un pointeur sur le suivant */
	    //	    return 0; /* killed client */
	    return 2;
	}

	if (page->client->addr) {
	    if ((obj->local_port = get_free_port(page->client->addr, thr-1)) != 0) {
		struct sockaddr_in local_addr;

		local_addr.sin_addr = page->client->addr->addr;
		local_addr.sin_port = htons(obj->local_port);
		local_addr.sin_family = AF_INET;

		/* if bind fails, let the system do its own work */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &one, sizeof(one)) == -1 ||
		    bind(fd, (struct sockaddr *)&local_addr, sizeof local_addr) == -1) {
		    put_free_port(page->client->addr, obj->local_port, thr-1);
		    obj->local_port = 0;
		}

		if (arg_random_distance) {
			/* set a pseudo-random TTL depending only on the source /24 network */
			unsigned int ttl = ntohl(*(uint32_t *)&local_addr.sin_addr);

			ttl &= -64;
			ttl ^= 0x12345678;
			ttl ^= ttl << 13;
			ttl ^= ttl >> 17;
			ttl ^= ttl << 5;

			while (ttl >= 64) {
				ttl = (ttl & 0x3f) + (ttl >> 6);
			}
			ttl += 64;
			setsockopt(fd, IPPROTO_IP, IP_TTL, (char *) &ttl, sizeof(ttl));
		}
	    }
	}

	fcntl(fd, F_SETFL, O_NONBLOCK);

#ifdef TCP_QUICKACK
	/* we don't want quick ACKs there */
	if (arg_fast_connect)
		setsockopt(fd, SOL_TCP, TCP_QUICKACK, (char *) &zero, sizeof(zero));
#endif
	if (unlikely((connect(fd, (struct sockaddr *)&obj->addr, sizeof(obj->addr)) == -1) && (errno != EINPROGRESS))) {
	    if (errno == EAGAIN || errno == EADDRNOTAVAIL) { /* plus de ports en local -> réessayer plus tard */
		put_free_port(page->client->addr, obj->local_port, thr-1);
		obj->local_port = 0;
		close(fd);
		if (attempts++ < 10)
			goto retry;
		return 2;
	    }
	    else if (errno != EALREADY && errno != EISCONN) {
		//		fprintf(stderr,"impossible de faire le connect() pour le fd %d, errno ) %d. destruction du client.\n",
		//			fd, errno);
		put_free_port(page->client->addr, obj->local_port, thr-1);
		obj->local_port = 0;
		close(fd);
		return 2;
		/* ne pas renouveler le client, sinon on risque une récursivité ! */
		//destroyclient(page->client, NULL); /* renvoie un pointeur sur le suivant */
		//return 0; /* killed client */
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
	attempts = 0;
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

    if (arg_regular_time) {
	/* will be needed later to compute next start time */
	cli->nextevent = now;
	// it's important to get the real time and not the cycle time if we
	// want to spread the load
	//tv_now(&cli->nextevent);
    }

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

    //SETNOW(&page->begin);
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

    newclient->addr = NULL;
    if (local_ip_list)
	newclient->addr = get_free_ip(arg_maxobj);

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
	    put_free_port(page->client->addr, obj->local_port, thr-1);
	    obj->local_port = 0;
	    setsockopt(fd, SOL_SOCKET, SO_LINGER,
		       (struct linger *) &nolinger, sizeof(struct linger));
	    close(fd);
	    nbconn--;
	    stats[thr].aborted++;
	    if (!FD_ISSET(fd, StaticWriteEvent) && FD_ISSET(fd, StaticReadEvent))
		/* the connect() succeeded */
		nbactconn--;
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
    if (client->addr)
	put_free_ip(client->addr, arg_maxobj);
    if (client->cookie)
	free(client->cookie);
    if (client->password)
	free(client->password);
    if (client->username)
	free(client->username);
    free_pool(client, client);

    nbactcli--;

    /* dynamically compute the number of clients if the step size is > 1 */
    if (arg_slowstart && arg_stepsize > 1 && nbclients < ramp_step + arg_stepsize) {
	    nbclients = arg_stepsize * 10 * tv_remain(&ramp_start, &now) / arg_slowstart;
	    if (nbclients >= arg_stepsize)
		    nbclients = arg_stepsize;
	    nbclients += ramp_step;
	    if (nbclients < 1)
		    nbclients = 1;
    }

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

	if (tv_cmp(&now, &nextevt) < 0)
	    return tv_remain(&now, &nextevt);
	else {
	    unsigned long long int totalread=0;
	    unsigned long int totalhits=0;
	    unsigned long int aborted=0;
	    unsigned long int totalerr=0;
	    unsigned long int totaltout=0;
	    unsigned long int iterations=0;
	    unsigned long int stat_hits=0;
	    unsigned long int stat_ptime=0, stat_pages=0;
	    unsigned long int nbconn=0, nbcli=0;
	    double tot_htime=0, tot_sqhtime=0;
	    int t;

	    for (t = 1; t <= arg_nbprocs; t++) {
		unsigned long long int tr1, tr2;

		tr1 = stats[t].totalread;
		totalhits  += stats[t].totalhits;
		aborted    += stats[t].aborted;
		totalerr   += stats[t].totalerr;
		totaltout  += stats[t].totaltout;
		iterations += stats[t].iterations;
		tot_htime  += stats[t].tot_htime;     stats[t].tot_htime = 0;
		tot_sqhtime+= stats[t].tot_sqhtime;   stats[t].tot_sqhtime = 0;
		stat_ptime += stats[t].stat_ptime;    stats[t].stat_ptime = 0;
		stat_hits  += stats[t].stat_hits;     stats[t].stat_hits = 0;
		stat_pages += stats[t].stat_pages;    stats[t].stat_pages = 0;
		nbcli      += stats[t].nbcli;         stats[t].nbcli  = 0;
		nbconn     += stats[t].nbconn;        stats[t].nbconn = 0;
		/* try to avoid inter-thread race without any lock */
		tr2 = stats[t].totalread;
		if ((tr2 & 0xffffffff) < (tr1 & 0xffffffff)) {
		    tr2 = tr1;
		}
		totalread += tr2;
	    }

	    //if (totalhits > 0)
		if ((starttime.tv_sec | starttime.tv_usec) == 0)  /* la premiere fois, on démarre le chrono */
		    SETNOW(&starttime);

	    deltatime = (tv_delta(&now, &lastevt)?:1);
	    if ((starttime.tv_sec | starttime.tv_usec) == 0)
		totaltime = -1;
	    else
		totaltime = (tv_delta(&now, &starttime)?:deltatime);


	    stats[0].totalread   = totalread;
	    stats[0].totalhits   = totalhits;
	    stats[0].aborted     = aborted;
	    stats[0].totalerr    = totalerr;
	    stats[0].totaltout   = totaltout;
	    stats[0].iterations  = iterations;
	    stats[0].tot_htime   = tot_htime;
	    stats[0].tot_sqhtime = tot_sqhtime;
	    stats[0].stat_ptime  = stat_ptime;
	    stats[0].nbconn      = nbconn;
	    stats[0].nbcli       = nbcli;
	    stats[0].stat_hits  += stat_hits;
	    stats[0].stat_pages += stat_pages;

	    /*
	     * standard deviation = sqrt(sum(x-moy)^2/n) = sqrt((sum(x^2)-2*moy*sum(x))/n + moy^2)
	     */
#ifndef NO_SD
	    if (stats[0].stat_hits) {
		double nb1;
		stats[0].moy_htime = stats[0].tot_htime / (double)stats[0].stat_hits;

		nb1 = (stats[0].tot_sqhtime - 2*stats[0].moy_htime*stats[0].tot_htime) /
		    (double)stats[0].stat_hits + stats[0].moy_htime * stats[0].moy_htime;
		if (nb1 < 0.0) /* it can happen sometimes, so let's not return nans */
		    nb1 = 0;
		stats[0].moy_sdhtime = sqrt(nb1);
	    }
	    else
#endif
		stats[0].moy_sdhtime = stats[0].moy_htime = stats[0].moy_ptime = 0;
	    
	    if (stats[0].stat_pages)
		stats[0].moy_ptime = (float)stats[0].stat_ptime/(float)stats[0].stat_pages;

	    if (arg_log) {
		if (lines == 0)
		    fprintf(stderr,
			    "   time delta clients    hits ^hits"
			    "  hits/s  ^h/s     bytes   ^bytes  kB/s"
			    "  last  errs  tout htime  sdht ptime nbcli nbconn\n");
	    } else {
		if (lines % 16 == 0)
		    fprintf(stderr,
			    "\n   hits ^hits"
			    " hits/s  ^h/s     bytes  kB/s"
			    "  last  errs  tout htime  sdht ptime\n");
	    }
	    lines++;

	    if (lines>1) {
		if (arg_log) {
		    fprintf(stdout,"%7ld %5ld %7ld %7ld %5ld  %5ld %5ld %9lld %8lld %5ld %5ld %5ld %5ld %03.1f %3.1f %03.1f %5ld %6ld\n",
			    arg_abs_time ? now.tv_sec + (now.tv_usec >= 500000) : totaltime, deltatime,
			    stats[0].iterations,
			    stats[0].totalhits, stats[0].stat_hits,
			    (unsigned long)((unsigned long long)stats[0].totalhits*1000ULL/totaltime),
			    stats[0].stat_hits*1000/deltatime,
			    stats[0].totalread, stats[0].totalread-lastread,
			    (long)(stats[0].totalread/(unsigned long long)totaltime),
			    (long)((stats[0].totalread-lastread)/(unsigned long long)deltatime),
			    stats[0].totalerr, stats[0].totaltout,
			    stats[0].moy_htime, stats[0].moy_sdhtime, stats[0].moy_ptime, stats[0].nbcli, stats[0].nbconn);
		   fflush(stdout);
		} else {
		    fprintf(stderr,"%7ld %5ld  %5ld %5ld %9lld %5ld %5ld %5ld %5ld %03.1f %3.1f %03.1f\n",
			    stats[0].totalhits, stats[0].stat_hits,
			    (unsigned long)((unsigned long long)stats[0].totalhits*1000ULL/totaltime),
			    stats[0].stat_hits*1000/deltatime,
			    stats[0].totalread,
			    (long)(stats[0].totalread/(unsigned long long)totaltime),
			    (long)((stats[0].totalread-lastread)/(unsigned long long)deltatime),
			    stats[0].totalerr, stats[0].totaltout,
			    stats[0].moy_htime, stats[0].moy_sdhtime, stats[0].moy_ptime);
		   fflush(stdout);
		}
	    }
	    
	    if (totaltime > 0)
		deltatime = arg_stattime - totaltime % arg_stattime;   /* correct imprecision */
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

	    if ((arg_maxtime > 0 && tv_cmp_ms(&stoptime, &now) < 0))
		stopnow=1;  /* bench must terminate now */
	}	
	return tv_remain(&now, &nextevt);
}

/* ce scheduler s'occupe d'injecter des clients tant qu'il n'y en a pas assez, mais jamais
   plus d'une fois <arg_stepsize> tous les <arg_slowstart> ms. Le principe est que l'on
   calcule une prochaine date 'next' servant de référence pour le prochain ajout de clients.
   Les clients sont ajoutés dès que (now-next) > arg_slowstart.
*/
static inline int injecteur(void *arg) {
    static struct timeval next;
    int delay = -1;

    if ((arg_maxiter > 0) && (stats[thr].iterations >= arg_maxiter)) /* c'est la fin, on ne veut plus injecter */
	return -1;

    if (nbclients < arg_nbclients) {
	if ((next.tv_sec | next.tv_usec) == 0)
	    SETNOW(&next);

	if (arg_slowstart == 0)
	    nbclients = arg_nbclients; /* no soft start, all clients at once */
	else {
	    if (ramp_step == -1) {
		SETNOW(&next); /* base for next step computation */
		tv_delayfrom(&next, &next, arg_slowstart); /* next time we add that many clients */
		ramp_start = now;
		ramp_step = 0;
	    }
	    else {
		unsigned long times;
		delay = tv_remain(&now, &next);
		if (!delay) {
			tv_delayfrom(&next, &next, arg_slowstart);
			ramp_start = now;
			ramp_step += arg_stepsize;
		}
	    }

	    if (ramp_step >= arg_nbclients)
		    ramp_step = arg_nbclients;
	    else
		    delay = -1;
	    delay = tv_remain(&now, &next);
	}
    }
    else
	delay = -1;

    if (arg_slowstart && nbclients < ramp_step + arg_stepsize) {
	    int rem = tv_remain(&ramp_start, &now);

	    if (10*rem < arg_slowstart) {
		    nbclients = arg_stepsize * 10 * rem / arg_slowstart;
		    delay = delay < 10 ? delay : 10; // 10ms max
	    }
	    else
		    nbclients = arg_stepsize;

	    if (nbclients >= arg_stepsize)
		    nbclients = arg_stepsize;
	    nbclients += ramp_step;
    }

    if (nbclients < 1)
	    nbclients = 1;

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
		if ((cli->pages = cli->pages->next) == NULL || stopnow) { /* fin du scénario pour ce client */
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

      if (active_thread) {
	  if (nbactcli < arg_nbclients && !stopnow) {
	      /* ne pas y aller si ce n'est pas nécessaire */
	      time2 = injecteur(NULL);
	      next_time = MINTIME(time2, next_time);
	  }
	  
	  time2 = scheduler(NULL);
	  next_time = MINTIME(time2, next_time);

	  if (nbactconn > stats[thr].nbconn)
	      stats[thr].nbconn = nbactconn;
	  if (nbactcli > stats[thr].nbcli)
	      stats[thr].nbcli = nbactcli;
      }
	  
      /* Note: arg_stattime is forced to zero on thr>1 */
      if (arg_stattime > 0) {
	  time2 = show_stats(NULL);
	  next_time = MINTIME(time2, next_time);
      } else {
	  /* Other threads must at least check if they have to stop */
	  if ((arg_maxtime > 0 && tv_cmp_ms(&stoptime, &now) < 0))
	      stopnow=1;  /* bench must terminate now */
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
			  && (!FD_ISSET(fd, WriteEvent) || EventWrite(fd) <= 0))
			  continue;

		      put_free_port(fdtab[fd]->page->client->addr, fdtab[fd]->local_port, thr-1);
		      fdtab[fd]->local_port = 0;
		      if (arg_fast_close)
		            setsockopt(fd, SOL_SOCKET, SO_LINGER,
		      		 (struct linger *) &nolinger, sizeof(struct linger));
		      close(fd);
		      nbconn--;
		      fdtab[fd]->page->objleft--;
		      fdtab[fd]->page->actobj--;
		      if (!FD_ISSET(fd, StaticWriteEvent) && FD_ISSET(fd, StaticReadEvent))
			  /* the connect() succeeded */
			  nbactconn--;
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
    char *end;
    char *pagename;
    long int time;
    char *srv;
    char *vars;
    int meth;

    char *args[10];
    int arg;

    end = line + strlen(line);
    /* skips leading spaces */
    while (isspace(*line))
	line++;


    arg = 0;
    args[arg] = line;

    while (*line && arg < sizeof(args)/sizeof(args[0])) {
	/* first, we'll replace \\, \<space>, \#, \r, \n, \t, \xXX with their
	 * C equivalent value. Other combinations left unchanged (eg: \1).
	 */
	if (*line == '\\') {
	    int skip = 0;
	    if (line[1] == ' ' || line[1] == '\\' || line[1] == '#') {
		*line = line[1];
		skip = 1;
	    }
	    else if (line[1] == 'r') {
		*line = '\r';
		skip = 1;
	    } 
	    else if (line[1] == 'n') {
		*line = '\n';
		skip = 1;
	    }
	    else if (line[1] == 't') {
		*line = '\t';
		skip = 1;
	    }
	    else if (line[1] == 'x' && (line + 3 < end )) {
		unsigned char hex1, hex2;
		hex1 = toupper(line[2]) - '0'; hex2 = toupper(line[3]) - '0';
		if (hex1 > 9) hex1 -= 'A' - '9' - 1;
		if (hex2 > 9) hex2 -= 'A' - '9' - 1;
		*line = (hex1<<4) + hex2;
		skip = 3;
		} 
	    if (skip) {
		memmove(line + 1, line + 1 + skip, end - (line + skip + 1));
		end -= skip;
	    }
	    line++;
	}
	else if (*line == '#' || *line == ';' || *line == '\n' || *line == '\r') {
	    /* end of string, end of loop */
	    *line = 0;
	    break;
	}
	else if (isspace((int)*line)) {
	    /* a non-escaped space is an argument separator */
	    *line++ = 0;
	    while (isspace((int)*line))
		line++;
	    args[++arg] = line;
	}
	else {
	    line++;
	}
    }

    /* empty line */
    if (!**args)
	return 0;

    /* zero out remaining args */
    while (++arg < sizeof(args)/sizeof(args[0])) {
	args[arg] = line;
    }

    if (!strcasecmp(*args, "host")) {  /* host */
	if (isalnum(*args[1])) {
	    strncpy(curscnhost, args[1], sizeof(curscnhost) - 1);
	    curscnhost[sizeof(curscnhost)-1] = 0;
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

/* return pointer to the final 0.
 * Warning: it's up to the caller to check the length.
 */
char *str_add(char *dst, const char *add)
{
	dst--;
	do {
		*++dst = *add++;
	} while (*dst);

	return dst;
}

/*** retourne -1 si attendre, 0 si OK, 1 si on doit fermer le FD ***/
int EventWrite(int fd) {
    char req[4096];
    char *r = req;
    struct pageobj *obj;
    int data;

    obj = fdtab[fd];

    if (arg_timeout > 0)
	tv_delayfrom(&obj->page->client->expire, &now, arg_timeout);

    /* créer la requête */
    if (likely(obj->meth == METH_GET)) {
	r = str_add(r, "GET ");
	r = str_add(r, obj->uri);
	if (obj->vars) {
		*r++ = '?';
		r = str_add(r, obj->vars);
	}

	r = str_add(r,
		    " HTTP/1.1\r\n"
		    "Connection: close\r\n"
		    "User-Agent: " USER_AGENT "\r\n"
		    "Host: "
		    );

	r = str_add(r, obj->host);
	*r++ = '\r';
	*r++ = '\n';

	if (obj->page->client->cookie) {
		r = str_add(r, "Cookie: ");
		r = str_add(r, obj->page->client->cookie);
		*r++ = '\r';
		*r++ = '\n';
	}

	if (global_headers)
		r = str_add(r, global_headers);

	*r++ = '\r';
	*r++ = '\n';
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
	    r+=sprintf(r,"Content-length: %d\r\n\r\n%s", (int)strlen(obj->vars), obj->vars);
	}
	else
	    r+=sprintf(r,"\r\n");
    }
    
    if (!MSG_NOSIGNAL) {
	int ldata = sizeof(data);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &data, &ldata);
	if (data)
	    data = -1;
	else
	    data = send(fd, req, r-req, MSG_DONTWAIT);
    } else {
	    /* If we force binding to a local port, we have SO_REUSEADDR set,
	     * so we're not annoyed with local TIME_WAIT sockets. Thus, we can
	     * send a fast shutdown, so it makes sense to try to merge FIN with
	     * last ACK, hence this MSG_MORE ! But we only do this with fast
	     * close enabled, this allows us to disable the feature by default.
	     */
	    /* FIXME: this does not work often unfortunately, let's disable this */
	    data = send(fd, req, r-req, MSG_DONTWAIT | MSG_NOSIGNAL |
			((0 && MSG_MORE && arg_fast_close && obj->local_port) ? MSG_MORE : 0));
    }

    if (unlikely(data == -1)) {
	if (errno != EAGAIN) {
	    obj->page->client->status = obj->page->status = STATUS_ERROR;
	    return 1;
	}
	return -1;  /* erreur = EAGAIN */
    }

    /* a ce stade, obj->vars ne devrait plus servir */
    if (obj->vars) {
	free_pool(vars, obj->vars);
	obj->vars = NULL;
    }

    /* la requete est maintenant prete */
    FD_SET(fd, StaticReadEvent);
    FD_CLR(fd, StaticWriteEvent);

    /* we can and must shutdown write if we use cork, see explanation above */
    if (0 && MSG_MORE && arg_fast_close && obj->local_port) {
	    shutdown(fd, SHUT_WR);
    }

#ifdef TCP_QUICKACK
    /* we need to re-enable quick ACKs here so that we flush sender's buffers ASAP */
    if (arg_fast_connect)
	    setsockopt(fd, SOL_TCP, TCP_QUICKACK, (char *) &one, sizeof(zero));
#endif

    nbactconn++; /* we are connected, let's account it */
    return 0;
}


/*** retourne 0 si OK, 1 si on doit fermer le FD ***/
int EventRead(int fd) {
    int ret, moretoread, maxloops = 4;
    struct pageobj *obj;

    obj = fdtab[fd];

    if (arg_timeout > 0)
	tv_delayfrom(&obj->page->client->expire, &now, arg_timeout);

    do {
	moretoread = 0;
#ifndef DONT_ANALYSE_HTTP_HEADERS
	if (obj->buf == NULL) { /* pas encore alloué */
	    obj->read = obj->buf = (char *)alloc_pool(buffer);
	}

	if (obj->read < obj->buf + BUFSIZE) { /* on ne stocke que les data qui tiennent dans le buffer */
		int readsz = BUFSIZE - (obj->read - obj->buf);
		ret=recv(fd, obj->read, readsz, MSG_NOSIGNAL/*|MSG_WAITALL*/); /* lire et stocker les data */
		if (ret > 0)
			obj->read += ret;
	} else
#endif
	{
		int readsz;

#ifdef ENABLE_SPLICE
		if (arg_use_splice) {
			/* try to send useless data directly to /dev/null */
			if (pipe_count) {
				/* first try to flush pending data from the pipe even though unlikely */
				readsz = splice(master_pipe[0], NULL, dev_null_fd, NULL, pipe_count, SPLICE_F_NONBLOCK);
				if (readsz > 0)
					pipe_count -= readsz;
			}
			ret = splice(fd, NULL, master_pipe[1], NULL, pipesize, SPLICE_F_NONBLOCK);
			if (ret > 0) {
				pipe_count += ret;
				readsz = splice(master_pipe[0], NULL, dev_null_fd, NULL, pipe_count, SPLICE_F_NONBLOCK);
				if (readsz > 0)
					pipe_count -= readsz;
				//maxloops = 0; // don't loop any more, we'd hurt other connections.
			}
		} else
#endif
		{
#if defined(ENABLE_TRUNC)
			ret = recv(fd, NULL, INT_MAX, MSG_NOSIGNAL | MSG_TRUNC);  /* détruire les data sans les stocker */
#else
			ret = recv(fd, trash, sizeof(trash), MSG_NOSIGNAL/*|MSG_WAITALL*/);  /* lire les data mais ne pas les stocker */
#endif
		}
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
	    stats[thr].tot_sqhtime += (double)delta*(double)delta;
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
		if (arg_regular_time) {
		    /* we want the next fetch to start a certain time after the start of the previous one */
		    tv_delayfrom(&obj->page->client->nextevent,
				 &obj->page->client->nextevent,
				 obj->page->thinktime);
		}
		else
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
    } while (moretoread && maxloops--);
    /* sinon c'est un EAGAIN, pas grave */
    return 0;
}

/* Takes an ip/port range in the form ip1[-ip2][:p1-p2][,...] and completes or
 * initializes the local_ip_list from this. Returns 1 if OK, 0 if error.
 * Ports are incremented by <step>.
 * The string is destroyed during the process.
 */
int build_local_ip(char *range, int step) {
    char *colon;
    char *dash;
    char *coma;

    struct in_addr ip1, ip2;
    int port1, port2;
    int ip, port;

    struct local_ip *cur_ip, **list_end;

    while (range && *range) {
	coma = strchr(range, ',');
	if (coma)
	    *coma++ = 0;

	colon = strchr(range, ':');
	if (colon)
	    *colon++ = 0;

	dash = strchr(range, '-');
	if (dash)
	    *dash++ = 0;

	if (!inet_aton(range, &ip1))
	    return 0;

	if (dash) {
	    if (!inet_aton(dash, &ip2))
		return 0;
	} else
	    ip2 = ip1;

	if (colon) {
	    dash = strchr(colon, '-');
	    if (!dash)
		return 0;
	    *dash++ = 0;
	    port1 = atol(colon);
	    port2 = atol(dash);
	} else {
	    port1 = 16384;
	    port2 = 49151;
	}

	list_end = &local_ip_list;
	while (*list_end != NULL)
	    list_end = &(*list_end)->next;

	for (ip = ntohl(ip1.s_addr); ip <= ntohl(ip2.s_addr); ip ++) {
	    cur_ip = (struct local_ip *)calloc(1, sizeof (struct local_ip));
	    if (cur_ip == NULL)
		return 0;
	    cur_ip->addr.s_addr = htonl(ip);
	    cur_ip->size = 1 + (port2 - port1 + 1) / step;
	    // we want 1 more free port in the list
	    cur_ip->freeports = (u_int16_t *)malloc(sizeof(u_int16_t) * cur_ip->size);
	    cur_ip->put = cur_ip->get = 0;
	    for (port = port1; port <= port2 + 1 - step; port += step)
		cur_ip->freeports[cur_ip->put++] = port;
	    *list_end = cur_ip;
	    list_end = &cur_ip->next;
	}
	range = coma;
    }
    return local_ip_list != NULL;
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
	    "Inject36 - simple HTTP load generator (C) 2000-2012 Willy Tarreau <w@1wt.eu>\n"
	    "Syntaxe : inject -u <users> -f <scnfile> [-i <iter>] [-d <duration>] [-l] [-r]\n"
	    "          [-t <timeout>] [-n <maxsock>] [-o <maxobj>] [-a] [-s <starttime>]\n"
	    "          [-C <cli_at_once>] [-w <waittime>] [-p nbprocs] [-S ip-ip:p-p]* [-N]\n"
	    "          [-H \"<header>\"]* [-T <thktime>] [-G <URL>] [-P <nbpages>] [-R] [-F]\n"
	    "- users    : nombre de clients simultanes (=nb d'instances du scenario)\n"
	    "- iter     : nombre maximal d'iterations a effectuer par client\n"
	    "- waittime : temps (en ms) entre deux affichages des stats (0=jamais)\n"
	    "- starttime: temps (en ms) d'incrementation du nb de clients (montee en charge)\n"
	    "- scnfile  : nom du fichier de scénario a utiliser\n"
	    "- timeout  : timeout (en ms) sur un objet avant destruction du client\n"
	    "- duration : duree maximale du test (en secondes)   ; -D = random distance\n"
	    "- maxobj   : nombre maximal d'objets en cours de lecture par client\n"
	    "- maxsock  : nombre maximal de sockets utilisees    ; -c = fast close\n"
	    "- [ -r ]   : ajoute 10%% de random sur le thinktime  ; -R = regular think time.\n"
	    "- [ -l ]   : passe en format de logs (plus large, pas de repetition de legende)\n"
	    "- [ -a ]   : affiche la date absolue (uniquement avec -l) ; -F = fast connect\n"
	    "Ex: inject -H \"Host: www\" -T 1000 -G \"10.0.0.1:80/\" -o 4 -u 1\n"
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
    struct tm tm, tm2;
    int t;
    int cmd_line_len = 0;
    char *p;
    char *mois[12]={"Jan","Fev","Mar","Avr","Mai","Juin",
                    "Juil","Aou","Sep","Oct","Nov","Dec"};

    if (1<<INTBITS != sizeof(int)*8) {
	fprintf(stderr,"Erreur: recompiler avec pour que sizeof(int)=%ld\n",sizeof(int)*8);
	exit(1);
    }

    /* count final size of the command line */
    for (t=0; t<argc; t++)
	cmd_line_len += strlen(argv[t]) + 1;
    
    /* get memory for the command line storage */
    cmd_line = calloc(cmd_line_len, 1);

    /* copy command line */
    p = cmd_line;
    for (t=0; t<argc; t++) {
	cmd_line_len = strlen(argv[t]);
	memcpy(p, argv[t], cmd_line_len);
	p += cmd_line_len;
	*p = ' ';
	p++;
    }
    p--;
    *p = '\0';

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
	    else if (*flag == 'R')
		arg_regular_time = 1;
	    else if (*flag == 'a')
		arg_abs_time = 1;
	    else if (*flag == 'F')
		arg_fast_connect = 1;
	    else if (*flag == 'c')
		arg_fast_close = 1;
	    else if (*flag == 'D')
		arg_random_distance = 1;
#ifdef ENABLE_SPLICE
	    else if (*flag == 'N')
		arg_use_splice = 1;
#endif
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
		case 'C' : arg_stepsize = atol(*argv); break;
		case 'w' : arg_stattime = atol(*argv); break;

		case 'G' : arg_geturl = *argv; break;
		case 'P' : arg_nbpages = atol(*argv); break;
		case 'T' : arg_thinktime = atol(*argv); break;
		case 'S' : arg_sourceaddr = *argv; break;
		case 'H' :
		    if (global_headers != NULL) {
			char *ptr;
			ptr = (char *)malloc(strlen(global_headers) + strlen(*argv) + 3);
			sprintf(ptr, "%s%s\r\n", global_headers, *argv);
			free(global_headers);
			global_headers = ptr;
		    }
		    else {
			char *ptr;
			ptr = (char *)malloc(strlen(*argv) + 3);
			sprintf(ptr, "%s\r\n", *argv);
			global_headers = ptr;
		    }
		    break;
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

    if ((!arg_geturl && !arg_scnfile) || !arg_nbclients)
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

    
    /* we'll step through the number of processes so that each process gets different ports */
    if (arg_sourceaddr) {
	char *source = strdup(arg_sourceaddr);
	if (!build_local_ip(source, arg_nbprocs))
	    usage();
	free(source);
    }

    if (arg_geturl) {  /* URI on command line */
	int curpage, curobj;
	int nbpages = arg_nbpages;
	char curhost[256];
	char *uri, *args;
	int urilen;

	if (!nbpages)
	    nbpages = 10;

	/* look for the '/' starting the URI */
	uri = strchr(arg_geturl, '/');
	if (uri == NULL)
	    uri = arg_geturl + strlen(arg_geturl);

	urilen = uri - arg_geturl;
	if (urilen > sizeof(curhost) - 1)
	    urilen = sizeof(curhost) - 1;
	memcpy(curhost, arg_geturl, urilen);
	curhost[urilen] = 0;

	/* support host:port without trailing '/' */
	if (!*uri)
	    uri = "/";

	args = strchr(uri, '?');
	if (args)
	    *args++ = 0;

	for (curpage = 0; curpage < nbpages; curpage++) {
	    char pagename[20];
	    snprintf(pagename, sizeof(pagename), "page%09d\n", curpage);
	    newscnpage(pagename, arg_thinktime);

	    for (curobj = 0; curobj < arg_maxobj; curobj++)
		newscnobj(METH_GET, curhost, uri, args);

	    //fprintf(stderr, "curhost=%s, uri=%s, args=%s.\n", curhost, uri, args);

	}
    }
    else if (readscnfile(arg_scnfile) < 0) {
	fprintf(stderr, "[inject] Error reading scn file : %s\n", arg_scnfile);
	exit(1);
    }

    //fprintf(stderr, "Fin de lecture du scénario.\n");

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

    /* first try mmap(anonymous|shared) */
    stats = mmap(NULL, sizeof(struct stats)*(1+arg_nbprocs), PROT_READ|PROT_WRITE,
		 MAP_ANONYMOUS|MAP_SHARED, 0, 0);

    if (stats == MAP_FAILED) {
	    int shmid=0;
	    char *shmaddr=NULL;

	    shmid=shmget(IPC_PRIVATE, sizeof(struct stats)*(1+arg_nbprocs), IPC_CREAT);
	    shmaddr=shmat(shmid, NULL, 0);
	    stats=(void *)shmaddr;
	    if (stats == (void *)-1) {
		    stats = (struct stats *)calloc(1+arg_nbprocs, sizeof(struct stats));
		    if (arg_nbprocs > 1) {
			    printf("shmid = %d, shmaddr = %p, stats = %p\n", shmid, shmaddr, stats);
			    printf("shmat error, retry as root or do not use multi-process.\n");
			    exit(1);
		    }
	    }
	    memset(stats, 0, sizeof(struct stats)*(1+arg_nbprocs));
	    shmctl(shmid, IPC_RMID, NULL);
    }

    time(&launch_time); localtime_r(&launch_time, &tm);
    tv_now(&now);
    tv_delayfrom(&stoptime, &now, arg_maxtime * 1000);

    signal(SIGINT, sighandler);

#ifdef ENABLE_SPLICE
    if (arg_use_splice) {
	if ((dev_null_fd = open("/dev/null", O_WRONLY)) < 0) {
		fprintf(stderr, "[inject] Cannot open /dev/null\n");
		exit(1);
	}
    }
#endif

    if (arg_nbprocs > 1) {

        for (t = 1; t <= arg_nbprocs; t++) {
	    thr=t;
	    if (fork() == 0) {
#ifdef ENABLE_SPLICE
		    if (arg_use_splice) {
			    int total, ret;

			    if (pipe(master_pipe) < 0) {
				    fprintf(stderr, "[inject] Failed to create pipes for splice\n");
				    exit(1);
			    }
	    
			    fcntl(master_pipe[0], F_SETPIPE_SZ, pipesize * 5 / 4);
		    }
#endif

		/* those threads don't collect stats */
		arg_stattime = 0;
		active_thread=1;
		SelectRun();
		exit(0);
	    }
        }
	/* the remaining thread does only collect stats */
	active_thread=0;
	thr = 0;
    }
    else {
	/* the only thread does everything */
	active_thread=1;
	thr = 1;
    }


#ifdef ENABLE_SPLICE
    if (arg_use_splice) {
	int total, ret;

	if (pipe(master_pipe) < 0) {
	    fprintf(stderr, "[inject] Failed to create pipes for splice\n");
	    exit(1);
	}
	    
	fcntl(master_pipe[0], F_SETPIPE_SZ, pipesize * 5 / 4);
    }
#endif

    ramp_start = now;
    ramp_step = -1;

    SelectRun();
    tv_now(&now);
    localtime_r(&now.tv_sec, &tm2);

    show_stats(NULL);
    deltatime = (tv_delta(&now, &starttime)?:1);
    printf("\nFin.\nClients : %ld\nHits    : %ld + %ld abortés\nOctets  : %lld\nDuree   : %ld ms\n"
	   "Debit   : %lld kB/s\nReponse : %ld hits/s\n"
	   "Erreurs : %ld\nTimeouts: %ld\n"
	   "Temps moyen de hit: %3.1f ms\n"
	   "Temps moyen d'une page complete: %3.1f ms\n"
	   "Date de demarrage: %ld (%d %s %d - %d:%02d:%02d)\n"
	   "Date de fin: %ld (%d %s %d - %d:%02d:%02d)\n",
	   stats[0].iterations, stats[0].totalhits, stats[0].aborted, stats[0].totalread, deltatime,
	   stats[0].totalread/(unsigned long long)deltatime, (unsigned long)((unsigned long long)stats[0].totalhits*1000ULL/deltatime),
	   stats[0].totalerr, stats[0].totaltout,
           stats[0].moy_htime, stats[0].moy_ptime,
	   (long)launch_time,
           tm.tm_mday, mois[tm.tm_mon], tm.tm_year+1900,
           tm.tm_hour, tm.tm_min, tm.tm_sec,
	   (long)now.tv_sec,
           tm2.tm_mday, mois[tm2.tm_mon], tm2.tm_year+1900,
           tm2.tm_hour, tm2.tm_min, tm2.tm_sec);
    printf("Ligne de commande : %s\n", cmd_line);
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
