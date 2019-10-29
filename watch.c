/* Ruoxi Ren
* COMP111 Assignment 3
* How to compile:
*    gcc -g watch watch.c -lpthread -lrt
*    gcc -g -fPIC -shared shadow.c -o shadow.so -ldl
*/




#define _POSIX_C_SOURCE 199309L
#define _XOPEN_SOURCE 700


#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h>
#include <stdint.h> 
#include <time.h>
#include <sys/time.h> 
#include <sys/resource.h> 
#include <pthread.h> 
#include <semaphore.h> 
#include <fcntl.h> 
#include <signal.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <sys/times.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/wait.h>
#include<sys/stat.h>
#include<string.h>

//#define _GNU_SOURCE
#define TRUE 1
#define FALSE 0
#define SIGNO 11
#define LIMITS 4000000
#define BSS_LIMITS 1000000

int reaped = FALSE;
int printline = 0;
pid_t childpid;
struct rusage begin={0},end={0};
struct timespec t_begin={0},t_end={0};
time_t death_time;


int setenv(const char *name, const char *value,int overwrite);
int unsetenv(const char *name);

void reaper(int sig);


void reaper(int sig)
{
	//fprintf(stderr, "sig = %d!\n",sig);
	if(sig == SIGINT || sig == SIGKILL || sig == SIGUSR1)
	{
		fprintf(stderr,"Child process generate signal %d. Killing.\n",sig);
		kill(childpid,9);
	}
	if(sig == SIGSEGV)
	{
		fprintf(stderr,"Child process generate signal %d.\n",sig);
		fprintf(stderr, "Child process exceeding the 4MB stack.\n");
	}
	int stat;
	pid_t childstat = waitpid(0,&stat,WNOHANG);
	if(childstat != childpid && childstat > 0)// not what we are waiting for
	{
		//fprintf(stderr, "Not what we are waiting for!\n");
		return ;
	}
	if(childstat > 0) // sucessfully returned
	{
		// get the time
		getrusage(RUSAGE_SELF,&end);
		clock_gettime(CLOCK_REALTIME,&t_end);
		time(&death_time);
		if(WIFEXITED(stat))
		{
			fprintf(stderr, "Child process exited with status %d.\n", WEXITSTATUS(stat));
		}
		if(WIFSIGNALED(stat))
		{
			if(WTERMSIG(stat)==SIGNO)
				fprintf(stderr, "Child process exceeding the 4MB stack.\n");
			fprintf(stderr, "Child process exited by signal %d.\n", WTERMSIG(stat));
		}
	}
	else if(childstat < 0) // an error occurred
	{
		fprintf(stderr, "Error occured!\n");
		if(errno == ECHILD)
		{
			fprintf(stderr, "Child process does not exist!\n");
		}
		exit(EXIT_FAILURE);
	}
	reaped = TRUE;
	return;
}

int check_bss(char **argv)
{
	FILE *proc;
	int text, data, bss, dec, hex;
	char filename[128];
	char buf[128];
	char tmp[256];
	sprintf(buf,"size %s",argv[1]);
	proc = popen(buf,"r");
	if(proc)
	{
		fgets(tmp,256,proc);
		fgets(tmp,256,proc);
		sscanf(tmp,"%d %d %d %d %d %s",&text,&data,&bss,&dec,&hex,filename);
		if(bss > BSS_LIMITS)
		{
			return TRUE;
		}
		else 
		{
			return FALSE;
		}
	}
	return FALSE;
}

// All the lines printed by child process
void all_lines(FILE *stream)
{
	char buf[2048];
	while(!reaped && !ferror(stream) && !feof(stream) && fgets(buf,sizeof(buf),stream)!=NULL)
	{
		//fprintf(stderr,"we are here!\n");
		printline ++;
		fputs(buf,stderr);
	}
}

// print out rusage
void print_rusage(char **argv)
{
	struct rusage *r_begin = &begin, *r_end = &end;
	double begin_user = (double)r_begin->ru_utime.tv_sec + ((double)r_begin->ru_utime.tv_usec)/1e6;
	double begin_syst = (double)r_begin->ru_stime.tv_sec + ((double)r_begin->ru_stime.tv_usec)/1e6;
	double end_user = (double)r_end->ru_utime.tv_sec + ((double)r_end->ru_utime.tv_usec)/1e6;
	double end_syst = (double)r_end->ru_stime.tv_sec + ((double)r_end->ru_stime.tv_usec)/1e6;
	fprintf(stderr, "User time of %s: %e s\n", argv[1],end_user-begin_user);
	fprintf(stderr, "System time of %s: %e s\n", argv[1],end_syst-begin_syst);
}

// print out the wallclock time of death
void print_time(char **argv)
{
	struct timespec *begin_time = &t_begin, *end_time = &t_end;
	double b = (double)begin_time->tv_sec + ((double)begin_time->tv_nsec)/1e9;
	double e = (double)end_time->tv_sec + ((double)end_time->tv_nsec)/1e9;
	fprintf(stderr, "Real time for %s: %e s\n", argv[1], e-b);
	fprintf(stderr, "Wallclock time of death: %s\n", ctime(&death_time));	
}

void print_child_info(char **argv)
{
	fprintf(stderr, "Total lines from child process: %d\n", printline);
	print_rusage(argv);
	print_time(argv);
}

int main(int argc, char **argv)
{
	if(argc!=2)
	{
		fprintf(stderr, "Usage: %s <Excutable File Name>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	int fd[2];
	FILE *stream;
	struct rlimit stack_limit, old_stack;
	struct rlimit *pstack_limit = NULL;
	struct sigaction sa;
	stack_t ss;
	//sigset_t mask;


	//pipe
	pipe(fd);

	// set limit to stack size
	stack_limit.rlim_cur = LIMITS;
	stack_limit.rlim_max = LIMITS;
	pstack_limit = &stack_limit;

	// register signal handler
	ss.ss_sp = malloc(LIMITS);
	ss.ss_size = LIMITS;
	sa.sa_handler = reaper;
	sa.sa_flags = SA_ONSTACK;
	sigemptyset(&sa.sa_mask);

	// if failure occured on sigaction
	if(sigaltstack(&ss,NULL) == -1)
	{
		fprintf(stderr, "sigaltstack fails: %s", strerror(errno));
	    exit(EXIT_FAILURE);   
	}
	if (sigaction(SIGCHLD, &sa, NULL) == -1){
	    fprintf(stderr, "sigaction fails: %s", strerror(errno));
	    exit(EXIT_FAILURE);   
	} 
	if (sigaction(SIGINT, &sa, NULL) == -1){
	    fprintf(stderr, "sigaction fails: %s", strerror(errno));
	    exit(EXIT_FAILURE);   
	} 
	// if (sigaction(SIGNO, &sa, NULL) == -1){
	//     fprintf(stderr, "SIGACTION fails: %s", strerror(errno));
	//     exit(EXIT_FAILURE);   
	// } 
	if (sigaction(SIGSEGV, &sa, NULL) == -1){
	    fprintf(stderr, "sigaction fails: %s", strerror(errno));
	    exit(EXIT_FAILURE);   
	} 
	if (sigaction(SIGUSR1, &sa, NULL) == -1){
	    fprintf(stderr, "sigaction fails: %s", strerror(errno));
		exit(EXIT_FAILURE);   
	} 

	// limit the global variables size of child process
	if(check_bss(argv)){
	    fprintf(stderr, "File %s bss larger than 1MB. Exiting.\n", argv[1]);
	    exit(EXIT_SUCCESS);
	}

	//set limit on child process
	if((childpid=fork()))
	{
		clock_gettime(CLOCK_REALTIME,&t_begin);
		getrusage(RUSAGE_SELF,&begin);
	}
	else
	{
		if(setrlimit(RLIMIT_STACK, pstack_limit) == -1)
		{
			fprintf(stderr, "setrlimit failure %d: %s\n",errno,strerror(errno));
			exit(EXIT_FAILURE);
		}
		// dup
		close(1);
		dup(fd[1]);
		close(fd[0]);
		// execl
		setenv("LD_PRELOAD", "./shadow.so", 1); 
		unsetenv("LD_LIBRARY_PATH"); 
		if(execl(argv[1], argv[1], NULL) == -1)
		{
			fprintf(stderr, "execl error %d: %s\n", errno, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}
	stream = fdopen(fd[0],"r");
	close(fd[1]);
	if(stream==NULL)
	{
		perror("Can not dup!\n");
		exit(EXIT_FAILURE);
	}
	all_lines(stream);
	print_child_info(argv);
	return EXIT_SUCCESS;
}






















