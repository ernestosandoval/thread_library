#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <semaphore.h>
#include <errno.h>

#define PAGE_SIZE getpagesize()
#define MAX_NUM_THREADS 128

int tls_create(unsigned int size);
int tls_write(unsigned int offset, unsigned int length, char *buffer);
int tls_read(unsigned int offset, unsigned int length, char *buffer);
int tls_destroy();
int tls_clone(pthread_t tid);
void* tls_get_internal_start_address();

void initialize_signal_handler(void);
void tls_handle_page_fault(int sig, siginfo_t *si, void *context);

struct tls {
	pthread_t tid;
	unsigned int size;
	unsigned int page_num;
	struct page** pages;
};

struct page {
	void * address;
	int ref_count;
};

static struct tls* all_tls[MAX_NUM_THREADS];
static sem_t sem;
bool has_initialized = false;

int tls_create(unsigned int size) {
	if (!has_initialized) {
		has_initialized = true;
		initialize_signal_handler();
		for (int i = 0; i < MAX_NUM_THREADS; i++) {
			all_tls[i] = NULL;
		}
	}

	sem_wait(&sem);

	if (size <= 0) {
		sem_post(&sem);
		return -1;
	}

	for (int i = 0; i < MAX_NUM_THREADS; i++) {
		if ((all_tls[i] != NULL) && (all_tls[i]->tid == pthread_self())) {
			sem_post(&sem);
			return -1;
		}
	}

	struct tls* storage = malloc(sizeof(struct tls));
	for (int i = 0; i < MAX_NUM_THREADS; i++) {
		if (all_tls[i] == NULL) {
			all_tls[i] = storage;
			break;
		}
	}

	storage->tid = pthread_self();
	storage->size = size;
	int new_pages = (size+PAGE_SIZE-1)/PAGE_SIZE;
	storage->page_num = new_pages;
	storage->pages = (struct page**)malloc(sizeof(struct page**)*new_pages);

	for (int i = 0; i < new_pages; i++) {
		void * addr;
		addr = mmap(NULL, PAGE_SIZE, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
		storage->pages[i]=malloc(sizeof(struct page));
		storage->pages[i]->address = addr;
		storage->pages[i]->ref_count = 1;
	}

	sem_post(&sem);

	return 0;
}

int tls_write(unsigned int offset, unsigned int length, char *buffer) {
	sem_wait(&sem);

	struct tls* storage = NULL;
	for (int i = 0; i<MAX_NUM_THREADS; i++) {
		if ((all_tls[i] != NULL) && (all_tls[i]->tid == pthread_self())) {
			storage = all_tls[i];
			break;
		}
	}

	if (storage == NULL) {
		sem_post(&sem);
		return -1;
	}

	if (offset+length > storage->size) {
		sem_post(&sem);
		return -1;
	}

	int offset_pages = offset/PAGE_SIZE;
	int offset_bytes = offset%PAGE_SIZE;
	int length_pages = (offset_bytes+length+PAGE_SIZE-1)/PAGE_SIZE;
	int length_copied = 0;

	for (int i = offset_pages; i < offset_pages + length_pages; i++) {
		if (mprotect(storage->pages[i]->address, PAGE_SIZE, PROT_WRITE) == -1) {
			sem_post(&sem);
			return -1;
		}

		if (storage->pages[i]->ref_count > 1) {
			storage->pages[i]->ref_count--;

			void* addr;
			addr = mmap(NULL, PAGE_SIZE, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			memcpy(addr, (const void*)(intptr_t) storage->pages[i]->address, PAGE_SIZE);
			if (mprotect( storage->pages[i]->address, PAGE_SIZE, PROT_NONE) == -1) {
				sem_post(&sem);
				return -1;
			}

			storage->pages[i]=malloc(sizeof(struct page));
			storage->pages[i]->ref_count = 1;
			storage->pages[i]->address = addr;
                }

		if (length_pages == 1) {
			void * dest_addr = storage->pages[i]->address + offset_bytes;
			void * src_addr = (void*) buffer;
			memcpy(dest_addr, src_addr, length);
		} else if (i == offset_pages) {
			void * dest_addr = storage->pages[i]->address + offset_bytes;
			void * src_addr = (void*) buffer;
			memcpy(dest_addr, src_addr, PAGE_SIZE-offset_bytes);
			length_copied = PAGE_SIZE-offset_bytes;
		} else if (i == offset_pages+length_pages-1) {
			void * dest_addr = storage->pages[i]->address;
			void * src_addr = (void*) buffer + length_copied;
			memcpy(dest_addr, src_addr, length-length_copied);
		} else {
			void * dest_addr = storage->pages[i]->address;
			void * src_addr = (void*) buffer + length_copied;
			memcpy(dest_addr, src_addr, PAGE_SIZE);	
			length_copied+=PAGE_SIZE;
		}

		if (mprotect((void*)(intptr_t) storage->pages[i]->address, PAGE_SIZE, PROT_NONE) == -1) {
			sem_post(&sem);
			return -1;
		}
	}

	sem_post(&sem);

	return 0;
}

int tls_read(unsigned int offset, unsigned int length, char *buffer) {
	sem_wait(&sem);

	struct tls* storage = NULL;
	for (int i = 0; i < MAX_NUM_THREADS; i++) {
		if ((all_tls[i] != NULL) && (all_tls[i]->tid == pthread_self())) {
			storage = all_tls[i];
			break;
		}
	}

	if (storage == NULL) {
		sem_post(&sem);
		return -1;
	}

	if (offset+length > storage->size) {
		sem_post(&sem);
		return -1;
	}

	int offset_pages = offset / PAGE_SIZE;
	int offset_bytes = offset % PAGE_SIZE;
	int length_pages = (offset_bytes+length+PAGE_SIZE-1) / PAGE_SIZE;
	int length_copied = 0;

	for (int i = offset_pages; i < offset_pages+length_pages; i++) {
		if (mprotect((void*)(intptr_t) storage->pages[i]->address, PAGE_SIZE, PROT_READ) == -1) {
			sem_post(&sem);
			return -1;
		}

		if (length_pages == 1) {
			void * src_addr = storage->pages[i]->address + offset_bytes;
			void * dest_addr = (void *) buffer;
			memcpy(dest_addr, src_addr, length);
		} else if (i == offset_pages) {
			void * src_addr = storage->pages[i]->address + offset_bytes;
			void * dest_addr = (void *) buffer;
			memcpy(dest_addr, src_addr, PAGE_SIZE-offset_bytes);
			length_copied = PAGE_SIZE-offset_bytes;
		} else if (i == offset_pages+length_pages-1) {
			void * src_addr = storage->pages[i]->address;
			void * dest_addr = (void *) buffer+length_copied;
			memcpy(dest_addr, src_addr, length-length_copied);
		} else {
			void * src_addr = storage->pages[i]->address;
			void * dest_addr = (void *) buffer+length_copied;
			memcpy(dest_addr, src_addr, PAGE_SIZE);
			length_copied+=PAGE_SIZE;
		}

		if (mprotect(storage->pages[i]->address, PAGE_SIZE, PROT_WRITE) == -1) {
			sem_post(&sem);
			return -1;
		}
	}

	sem_post(&sem);

	return 0;
}

int tls_destroy() {
	sem_wait(&sem);

	struct tls* storage = NULL;
	for(int i = 0; i < MAX_NUM_THREADS; i++) {
		if ((all_tls[i] != NULL) && (all_tls[i]->tid == pthread_self())) {
			storage = all_tls[i];
			break;
		}
	}

	if (storage == NULL) {
		sem_post(&sem);
		return -1;
	}

	for (int i = 0; i < storage->page_num; i++) {
		if (storage->pages[i]->ref_count == 1) {
			void * addr = storage->pages[i]->address;
			munmap(addr, PAGE_SIZE);
			free(storage->pages[i]);
		} else {
			storage->pages[i]->ref_count--;
		}
	}

	storage->tid = 0;
	storage->size = 0;
	storage->page_num = 0;
	free(storage->pages);
	storage->pages = NULL;
	free(storage);

	sem_post(&sem);

	return 0;
}

int tls_clone(pthread_t tid) {
	sem_wait(&sem);


	for (int i = 0; i < MAX_NUM_THREADS; i++) {
		if ((all_tls[i] != NULL) && (all_tls[i]->tid == pthread_self())) {
			sem_post(&sem);
			return -1;
		}
	}

	struct tls* target = NULL;
	for (int i = 0; i < MAX_NUM_THREADS; i++) {
		if ((all_tls[i] != NULL) && (all_tls[i]->tid == tid)) {
			target = all_tls[i];
			break;
		}
	}

	if (target == NULL) {
		sem_post(&sem);
		return -1;
	}

	struct tls* storage = NULL;
	for (int i = 0; i < MAX_NUM_THREADS; i++) {
		if (all_tls[i] == NULL) {
			storage = malloc(sizeof(struct tls));
			all_tls[i] = storage;
			break;
		}
	}
	if (storage == NULL) {
		sem_post(&sem);
		return -1;
	}

	storage->tid = pthread_self();
	storage->size = target->size;
	storage->page_num = target->page_num;
	storage->pages = (struct page**)malloc(sizeof(struct page**)*storage->page_num);

	for (int i = 0; i < storage->page_num; i++) {
		storage->pages[i] = target->pages[i];
		storage->pages[i]->ref_count++;
	}

	sem_post(&sem);
	return 0;
}

void initialize_signal_handler() {
	for (int i = 0; i < MAX_NUM_THREADS; i++) {
		if (all_tls[i] != NULL) {
			all_tls[i]->tid = 0;
		}
	}

	sem_init(&sem, 0, 1);
	struct sigaction sigact;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = SA_SIGINFO;
	sigact.sa_sigaction = tls_handle_page_fault;

	sigaction(SIGBUS, &sigact, NULL);
	sigaction(SIGSEGV, &sigact, NULL);
}

void tls_handle_page_fault(int sig, siginfo_t *si, void *context) {
	int p_fault = ((intptr_t) si->si_addr) & ~(PAGE_SIZE - 1);

	for (int i = 0; i < MAX_NUM_THREADS; i++) {
		if (all_tls[i] != NULL) {
			for (int j = 0; j < all_tls[i]->page_num; j++) {
				if ((intptr_t)all_tls[i]->pages[j]->address == p_fault) {
					tls_destroy();
					pthread_exit(NULL);
				}
			}
		}
	}

	signal(SIGSEGV, SIG_DFL);
	signal(SIGBUS, SIG_DFL);
	raise(sig);
}

void* tls_get_internal_start_address() {
	struct tls* storage = NULL;
	for (int i = 0; i < MAX_NUM_THREADS; i++) {
		if ((all_tls[i] != NULL) && (all_tls[i]->tid == pthread_self())) {
			storage = all_tls[i];
			break;
		}
	}

	if (storage == NULL) {
		return NULL;
	}

	return storage->pages[0]->address;
}

