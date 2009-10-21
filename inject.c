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

#define METH_GET	1
#define METH_POST	2

#define NBPAGES		4
//#define NBPAGES		2

#define STATUS_START	1
#define STATUS_RUN	2
#define STATUS_THINK	3
#define STATUS_ERROR	4

#define BUFSIZE		1024
#define MAXSOCK		1000

struct pageobj {
    struct sockaddr_in addr;
    int fd;
    char *buf;
    char *read;
    char meth;
    char *uri;
    char *vars;
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

struct client *clients = NULL;
int nbclients=100;
//char *appaddr ="192.32.83.175:7999";
char *appaddr ="192.32.83.175:7979";
//char *appaddr ="192.32.83.176:7979";
char *imgaddr ="192.32.83.175:80";
int injectdelay = 500;
int thinktime = 20000;
static struct timeval now;
int nbconn=0;
int clientid=0;
int nbactcli=0;
long int totalread=0;
char trash[16384];

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

/* crée une page pour un client existant. Le username et password du client doivent exister */
struct page *newpage(int position, int time, struct client *client) {
    struct page *page;
    struct pageobj **obj;
    char variables[256];

    page=(struct page *)calloc(1, sizeof(struct page));
    page->client = client;
    page->thinktime = time;
    obj = &(page->objects);
    
    switch (position) {
    case 0 : /* page d'authentification */
	*obj = newobj(METH_GET, appaddr, "/accesi/ia10.html", NULL, page);
	obj=&((*obj)->next);
	break;
    case 1 : /* validation de la page d'authentification -> liste des comptes */
	if ((client != NULL) && (client->username != NULL) && (client->password != NULL))
	    sprintf(variables, "codcli1=%s&codsec=%s", client->username, client->password);
	else
	    *variables=0;
	*obj = newobj(METH_POST, appaddr, "/accesi/ia10.html", variables, page);
	obj=&((*obj)->next);
	*obj = newobj(METH_GET, appaddr, "/menu/menu.html", NULL, page);
	obj=&((*obj)->next);
	*obj = newobj(METH_GET, appaddr, "/consultation/consu10.html", NULL, page);
	obj=&((*obj)->next);
	break;
    case 2 : /* détail d'un compte */
	*obj = newobj(METH_GET, appaddr, "/consultation/cav20.html", NULL, page);
	obj=&((*obj)->next);
	break;
    case 3 : /* quitte */
	*obj = newobj(METH_GET, appaddr, "/accesi/byebye.html", NULL, page);
	obj=&((*obj)->next);
	break;
    default :
	break;
    }
    return page;
}

void newclient(char *username, char *password) {
    struct client *newclient;
    struct page **page;
    int i;

    newclient=(struct client*)calloc(1, sizeof(struct client));
    newclient->cookie=NULL;
    if (username != NULL)
	newclient->username=strdup(username);
    if (password != NULL)
	newclient->password=strdup(password);

    page=&(newclient->pages);
    for (i=0; i<NBPAGES; i++) {
	*page=newpage(i, thinktime, newclient);
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


/****************************************/

void Event(int fd, int flags, struct pageobj *obj) {
    int ret;
    char req[2048];
    char *r = req;

    Log(LOG_LFUNC,"[Event].\n");
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
	else /* meth = METH_GEST */ {
	    r+=sprintf(r, "GET %s", obj->uri);
	    if (obj->vars)
		r+=sprintf(r,"?%s", obj->vars);
	    r+=sprintf(r," HTTP/1.0\r\n");
	    if (obj->page->client->cookie)
		r+=sprintf(r, "Cookie: %s\r\n", obj->page->client->cookie);
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

/* ce scheduler s'occupe de gérer les clients (think time, ...)
   et d'injecter des clients tant qu'il n'y en a pas assez, mais jamais
   plus d'un tous les <injectdelay> ms
*/
int injecteur(void *arg) {
    static struct timeval next, now;
    struct client *cli;
    unsigned int delay;
    char uname[32];
    int sock;

    Log(LOG_LFUNC,"[injecteur].\n");
    tv_now(&now);
    if (nbconn < MAXSOCK) {
	if ((nbactcli < nbclients) && (tv_cmp(&next, &now) <= 0)) {  /* on doit créer un nouveau client */
	    sprintf(uname, "%d", clientid++);
	    newclient(uname, uname);
	    nbactcli++;
	    Log(LOG_LAPP, "Création du client <%s> : <%d> clients actifs.\n",uname,nbactcli);
	    delay=injectdelay;
	    tv_delayfrom(&next, &now, injectdelay);
	}
	else
	    delay=tv_delta(&next, &now);
    }
    else
	delay = 1000;  /* 1 seconde si plus de sockets */

    cli = clients;
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
		    
		    Log(LOG_LAPP, "Terminaison du client <%s> : <%d> octets lus, <%ld> au total.\n",
			cli->username, cli->dataread, totalread);
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
		del2 = tv_delta(&now, &cli->nextevent);
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
	    continue;
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
			Log(LOG_LERR, "impossible ce créer une socket\n");
			break;
		    }
		    if (fcntl(obj->fd, F_SETFL, O_NONBLOCK)==-1) {
			Log(LOG_LERR,"impossible de mettre la socket en O_NONBLOCK\n");
		    } else if ((connect(obj->fd, &obj->addr, sizeof(obj->addr)) == -1) && (errno != EINPROGRESS)) {
			Log(LOG_LERR,"impossible de faire le connect() pour %d\n", obj->fd);
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
    }

    return delay;
}


int main(int argc, char **argv) {

    if (argc != 4) {
	fprintf(stderr,"Syntaxe : inject <nbusers> <injectdelay> <think time>\n");
	exit(1);
    }
    nbclients = atol(argv[1]);
    injectdelay = atol(argv[2]);
    thinktime = atol(argv[3]);
    LogOpen("/tmp/injecteur.log", LOG_LPERF | LOG_LWARN | LOG_LERR | LOG_LAPP);
    RegisterScheduler(&injecteur, NULL);
    SelectRun();
    return 0;
}

