/* Sniffit Data File                                                       */

#include "pcap.h"

typedef void (*sig_hand)(int );  /* sighandler_t gave errors, weird */

extern int add_itemlist(struct shared_conn_data *, char *, char *);
extern void child_exit (void);
extern void clear_shared_mem(char);
extern int del_itemlist(struct shared_conn_data *, char *);
extern void forced_refresh (void);
extern char *input_field(char *, char *, int);
extern void mem_exit (void);
extern void run_interface (void);

/* semaphore helper functions */
extern int sysv_sem_wait(int semid, int sem_num);
extern int sysv_sem_post(int semid, int sem_num);
extern int sysv_sem_timedwait(int semid, int sem_num, int timeout_sec);
extern int sysv_mutex_lock(int semid, int sem_num);
extern int sysv_mutex_unlock(int semid, int sem_num);
