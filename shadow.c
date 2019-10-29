#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include<pthread.h>
#include<errno.h>
#include<sys/types.h>
#include<signal.h>
#include<sys/syscall.h>
#include<unistd.h>


#define TRUE 0
#define FALSE -1
size_t MAX = 4000000;
size_t ALL_SIZE = 0;


// typedef int (*origin_open)(const char *path, int flag, mode_t mode);

int open(const char *path, int flag, mode_t mode)
{
	fprintf(stderr, "Child process trying to open file %s\n", path);
	static int (*origin_open)(const char *path, int flag, mode_t mode);
	origin_open = dlsym(RTLD_NEXT,"open");
	pid_t caller = syscall(SYS_gettid);
	kill(caller,9);
	return FALSE;
}

int open64(const char *path, int flag, mode_t mode)
{
	fprintf(stderr, "Child process trying to open file %s\n", path);
	static int (*origin_open64)(const char *path, int flag, mode_t mode);
	origin_open64 = dlsym(RTLD_NEXT,"open64");
	pid_t caller = syscall(SYS_gettid);
	kill(caller,9);
	return FALSE;
}

extern FILE *fopen64(const char *__restrict __filename, const char *__restrict __modes) 
{
	fprintf(stderr, "Child process trying to open file\n"); 
	static FILE *(*origin_fopen64)(const char *__restrict__filename,const char *__restrict__modes);
	origin_fopen64 = dlsym(RTLD_NEXT,"fopen64");
	pid_t caller = syscall(SYS_gettid);
	kill(caller, 9); 
	return NULL;
}

extern FILE *fopen(const char *__restrict __filename, const char *__restrict __modes) 
{
	fprintf(stderr, "Child process trying to open file\n"); 
	static FILE *(*origin_fopen)(const char *__restrict__filename,const char *__restrict__modes);
	origin_fopen = dlsym(RTLD_NEXT,"fopen");
	pid_t caller = syscall(SYS_gettid);
	kill(caller, 9); 
	return NULL;
}

extern pid_t fork()
{
	fprintf(stderr, "Child process trying to fork\n");
	pid_t caller = syscall(SYS_gettid);
	kill(caller,9);
	return FALSE;
}

extern int pthread_create (pthread_t *__restrict __newthread, const pthread_attr_t *__restrict __attr, void *(*__start_routine) (void *), void *__restrict __arg) 
{
	fprintf(stderr, "Child process attempting to create a thread\n"); 
	pid_t caller = syscall(SYS_gettid);
	kill(caller, 9); 
	return FALSE;
}

void *malloc(size_t size)
{
	void *ptr;
	if(size + ALL_SIZE >= MAX)
	{
		fprintf(stderr, "Child process trying to allocate more than 4MB heap!\n");
		pid_t caller = syscall(SYS_gettid);
		kill(caller, 9); 
		return NULL;
	}
	ALL_SIZE += size;
	static void* (*origin_malloc)(size_t size);
	origin_malloc = dlsym(RTLD_NEXT, "malloc");
	ptr = origin_malloc(size);
	return ptr;
}












