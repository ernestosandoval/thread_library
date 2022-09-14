#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define STACK_SIZE 32767
#define MAX_NUM_THREADS 128
#define INTERVAL 50000
#define EXITED 0
#define RUNNING 1
#define READY 2
#define BLOCKED 3
#define SEM_VALUE_MAX 65536

#define JB_RBX   0
#define JB_RBP   1
#define JB_R12   2
#define JB_R13   3
#define JB_R14   4
#define JB_R15   5
#define JB_RSP   6
#define JB_PC    7

static long int i64_ptr_mangle(long int p)
{
    long int ret;
    asm(" mov %1, %%rax;\n"
        " xor %%fs:0x30, %%rax;"
        " rol $0x11, %%rax;"
        " mov %%rax, %0;"
    : "=r"(ret)
    : "r"(p)
    : "%rax"
    );
    return ret;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void*), void *arg);
void pthread_exit(void *value_ptr);
pthread_t pthread_self(void);
int pthread_join(pthread_t thread, void **value_ptr);
void lock();
void unlock();
int sem_init(sem_t *sem, int pshared, unsigned value);
int sem_destroy(sem_t *sem);
int sem_wait(sem_t *sem);
int sem_post(sem_t *sem);
void init();
void scheduler(int signum);
void wrapper();
void limbo(void);

// thread control block
typedef struct {
	// thread id
	pthread_t tid;

	// stack
	void *stack;

	// current state of thread used by setjmp and longjmp
	jmp_buf env;

	// we will call start_routine(arg)
	void * (*start_routine)(void *);
	void * arg;

	// EXITED, RUNNING, READY, or BLOCKED
	int status;

	// exit status
	void *exit_status;
} tcb_t;

typedef struct
{
	int value;
} my_sem_t;

static tcb_t* active_threads[MAX_NUM_THREADS];
static void* returned_threads[MAX_NUM_THREADS];
static bool has_returned[MAX_NUM_THREADS];
static pthread_t blocked_threads[MAX_NUM_THREADS];
static bool has_initialized = false;
static pthread_t current = 0;
static struct sigaction act;

static tcb_t* main_tcb;
static tcb_t* garbage_collector;

// initialize timer which handles sigalarms every 50 ms
void init() {
	for (int i = 0; i < MAX_NUM_THREADS; i++) {
		active_threads[i] = NULL;
		returned_threads[i] = NULL;
		has_returned[i] = false;
		blocked_threads[i] = -1;
	}

	// since we are in the first thread, we save it
	main_tcb = (tcb_t*) malloc(sizeof(tcb_t));
	main_tcb->tid = current;
	main_tcb->stack = NULL;
	main_tcb->start_routine = NULL;
	main_tcb->arg = NULL;
	main_tcb->status=RUNNING;
	main_tcb->exit_status = NULL;
	active_threads[current] = main_tcb;

	// we call this thread after pthread_exit to free memory used by thread
	garbage_collector = (tcb_t*) malloc(sizeof(tcb_t));
	garbage_collector->tid = -1;
	garbage_collector->stack = malloc(STACK_SIZE);
	garbage_collector->env->__jmpbuf[JB_RSP] = i64_ptr_mangle((intptr_t) garbage_collector->stack + STACK_SIZE);
	garbage_collector->env->__jmpbuf[JB_PC] = i64_ptr_mangle((intptr_t)limbo);
	garbage_collector->start_routine = NULL;
	garbage_collector->arg = NULL;
	garbage_collector->status=READY;
	garbage_collector->exit_status = NULL;

	// set alarm
	ualarm(INTERVAL, INTERVAL);

	// set scheduler to be SIGALRM handler
	sigemptyset(&act.sa_mask);
	act.sa_handler = &scheduler;
	act.sa_flags = SA_NODEFER;
	if(sigaction(SIGALRM, &act, NULL) == -1) {
		perror("unable to catch SIGALRM");
		exit(1);
	}

	has_initialized = true;
	return;
}

// scheduler handles sigalarms
void scheduler(int signum) {
	lock();

	tcb_t* this_thread = active_threads[current];

	current = (current + 1) % MAX_NUM_THREADS;
	tcb_t* new_thread = active_threads[current];
	while ((new_thread == NULL) || (new_thread->status == EXITED) || (new_thread->status == BLOCKED)) {
		current = (current + 1) % MAX_NUM_THREADS;
		new_thread = active_threads[current];
	}

	if (this_thread == new_thread) {
		return;
	}

	if (this_thread->status != BLOCKED) {
		this_thread->status = READY;
	}
	if (setjmp(this_thread->env)) {
		return;
	}

	new_thread->status = RUNNING;

	unlock();

	longjmp(new_thread->env,1);
	return;
}

void wrapper() {
	tcb_t* thread = active_threads[current];
	pthread_exit(thread->start_routine(thread->arg));
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void*), void *arg) {
	// if this is our first thread initialize timer
	if(!has_initialized) {
		init();
	}

	lock();

	// construct tcb_t
	int new_thread_index = (current + 1) % MAX_NUM_THREADS;
	while (active_threads[new_thread_index] != NULL) {
		for (int i = 0; i < MAX_NUM_THREADS; i++) {
			if (active_threads[new_thread_index] == NULL) {
				break;
			}
			new_thread_index = (new_thread_index + 1) % MAX_NUM_THREADS;
		}
		if (active_threads[new_thread_index] != NULL) {
			unlock();
			pause();
			lock();
		}
	}

	*thread = new_thread_index;

	tcb_t* new_thread = (tcb_t*) malloc(sizeof(tcb_t));
	new_thread->tid = new_thread_index;
	new_thread->stack = malloc(STACK_SIZE);
	new_thread->env->__jmpbuf[JB_RSP] = i64_ptr_mangle((intptr_t) new_thread->stack + STACK_SIZE);
	new_thread->env->__jmpbuf[JB_PC] = i64_ptr_mangle((intptr_t) wrapper);
	new_thread->start_routine = start_routine;
	new_thread->arg = arg;
	new_thread->status = READY;
	new_thread->exit_status = NULL;
	active_threads[new_thread_index] = new_thread;

	unlock();

	// returns 0 on success
	return 0;
}

void pthread_exit(void *value_ptr) {
	if(has_initialized == false) {
		exit(0);
	}
	lock();
	active_threads[current]->exit_status = value_ptr;
	longjmp(garbage_collector->env,1); 
}

void limbo(void) {
	tcb_t* thread_to_delete = active_threads[current];
	active_threads[current] = NULL;
	thread_to_delete->status = EXITED;
	free((void*) thread_to_delete->stack);
	thread_to_delete->stack = NULL;
	returned_threads[current] = thread_to_delete->exit_status;
	has_returned[current] = true;
	pthread_t blocked_thread = blocked_threads[current];
	if (blocked_thread != -1) {
		active_threads[blocked_thread]->status = READY;
		blocked_threads[current] = -1;
	}
	current = (current + 1) % MAX_NUM_THREADS;
	tcb_t* new_thread = active_threads[current];
	while ((new_thread == NULL) || (new_thread->status == EXITED) || (new_thread->status == BLOCKED)) {
		current = (current + 1) % MAX_NUM_THREADS;
		new_thread = active_threads[current];
	}

	unlock();

	longjmp(new_thread->env,1);
}

pthread_t pthread_self(void) {
	return active_threads[current]->tid;
}

int pthread_join(pthread_t thread, void **value_ptr) {
	if (active_threads[thread] == NULL) {
		return ESRCH;
	}

	lock();
	if (has_returned[thread]) {
		if (value_ptr != NULL) {
			*value_ptr = returned_threads[thread];
		}
		returned_threads[thread] = NULL;
		has_returned[thread] = false;
		unlock();
		return 0;
	}
	active_threads[current]->status = BLOCKED;
	blocked_threads[thread] = active_threads[current]->tid;
	unlock();
	pause();
	lock();
	if (has_returned[thread]) {
		if (value_ptr != NULL) {
			*value_ptr = returned_threads[thread];
		}
		returned_threads[thread] = NULL;
		has_returned[thread] = false;
		unlock();
		return 0;
	}
	unlock();


	// whats the diff?
	if (value_ptr != NULL) {
		return 1;
	} else {
		return ESRCH;
	}
}

void lock() {
	sigset_t set;
	if (sigemptyset(&set) == -1) {
		perror("Failed to empty the signal set");
		exit(1);
	}
	if (sigaddset(&set, SIGALRM) == -1) {
		perror("Failed to add SIGALRM to the signal set");
		exit(1);
	}
	if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
		perror("Failed to change the signal mask");
		exit(1);
	}
}

void unlock() {
	if(sigprocmask(SIG_SETMASK, &act.sa_mask, NULL) == -1) {
		perror("Failed to change the signal mask");
		exit(1);
	}
}

int sem_init(sem_t *sem, int pshared, unsigned value) {
	if (pshared != 0) {
		return -1;
		//return EPERM;
	} else if (value > (unsigned int)SEM_VALUE_MAX) {
		return -1;
		//return EINVAL;
	}
	my_sem_t* s = (my_sem_t*) malloc(sizeof(my_sem_t));
	sem->__align = (long int) s;
	s->value = value;
	return 0;
}

int sem_destroy(sem_t *sem) {
	if (sem == NULL) {
		return EINVAL;
	}
	my_sem_t* s = (my_sem_t*) sem->__align;
	free(s);
	return 0;
}

int sem_wait(sem_t *sem) {
	if (sem == NULL) {
		return EINVAL;
	}
	my_sem_t* s = (my_sem_t*) sem->__align;
	while(s->value == 0);
	lock();
	--(s->value);
	unlock();
	return 0;
}

int sem_post(sem_t *sem) {
	my_sem_t* s = (my_sem_t*) sem->__align;
	if (sem == NULL) {
		return EINVAL;
	}
	lock();
	++(s->value);
	unlock();
	return 0;
}
