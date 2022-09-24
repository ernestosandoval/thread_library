# thread_library

In this project, we implement a basic thread library: 

    int pthread_create(pthread_t *restrict thread, const pthread_attr_t *restrict attr, void *(*start_routine)(void*), void *restrict arg);
    void pthread_exit(void *value_ptr);
    pthread_t pthread_self(void);

    int pthread_join(pthread_t thread, void **value_ptr);
    int sem_init(sem_t *sem, int pshared, unsigned value);
    int sem_destroy(sem_t *sem);
    int sem_wait(sem_t *sem);
    int sem_post(sem_t *sem);

We also implement thread-local storage for our thread library: 

    int tls_create(unsigned int size)
    int tls_write(unsigned int offset, unsigned int length, char *buffer)
    int tls_read(unsigned int offset, unsigned int length, char *buffer)
    int tls_destroy()
    int tls_clone(pthread_t tid)
    void* tls_get_internal_start_address()

To compile, run:

    gcc -c -o threads.o threads.c
    gcc -c -lpthread -o tls.o tls.c
    gcc -pthread -o application [list of application object files] threads.o tls.o
