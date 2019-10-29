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
#include <sys/sem.h>
#include <sys/wait.h>
#include<sys/stat.h>
#include<string.h>

#define _GNU_SOURCE
#define TRUE 1
#define FALSE 0
#define SIGNO 11
#define LIMITS 4000000

int reaped = FALSE;
int printline = 0;
pid_t pid;
struct rusage begin,end;
struct timespec t_begin,t_end;
time_t death_time;


int setenv(const char *name, const char *value,int overwrite);
int unsetenv(const char *name);

void reaper(int sig);


void reaper(int sig)
{
	if(sig == SIGINT || sig == SIGSEGV || sig == SIGKILL || sig == SIGUSR1)
	{
		kill(childsig,9);
		fprintf(stderr,"Child process generate signal %d. Killed.\n");
	}
	int stat;
	pid_t childstat = waitpid(0,&stat,WNOHANG);
	if(childstat != pid && childstat > 0)// not what we are waiting for
	{
		fprintf(stderr, "Not what we are waiting for!\n");
		return ;
	}
	if(childstat > 0) // sucessfully returned
	{
		// get the time
		getrusage(RUSAGE_SELF,&begin);
		clock_gettime(CLOCK_REALTIME,t_begin);
		time(&death_time);
		if(WIFEXITED(stat))
		{
			fprintf(stderr, "Child process exited with status %d\n", WEXITSTATUS(stat));
		}
		if(WIFSIGNALED(stat))
		{
			fprintf(stderr, "Child process exited by signal %d\n", WTERMSIG(stat));
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
	char filenaame[128];
	char buf[128];
	char tmp[256];
	sprintf(buf,"size %s",argv[1]);
	proc = popen(buf,"r");
	if(proc)
	{
		fgets(tmp,256,proc);
		fgets(tmp,256,proc);
		sscanf(tmp,"%d %d %d %d %d %s",&text,&data,&bss,&dec,&hex,filename);
		if(bss > LIMITS)
		{
			return TRUE;
		}
		else 
		{
			return FALSE;
		}
	}
	return FALSE
}

// All the lines printed by child process
void all_lines(FILE *stream)
{
	char buf[2048];
	while(!reaped && !ferror(stream) && !feof(stream) && fgets(buf,sizeof(buf),stream)!=NULL)
	{
		printline ++;
		fputs(buf,stderr);
	}
}

// print out rusage
void print_rusage(char **argv)
{
	struct rusage *r_begin = &begin, *r_end = &end;
	double begin_user = (double)r_begin->ru_utime.tv_sec + ((double)r_begin->ru_utime.tv_sec)/1e6;
	double begin_syst = (double)r_begin->ru_stime.tv_sec + ((double)r_begin->ru_stime.tv_sec)/1e6;
	double end_user = (double)r_end->ru_utime.tv_sec + ((double)r_end->ru_utime.tv_sec)/1e6;
	double end_syst = (double)r_end->ru_stime.tv_sec + ((double)r_end->ru_stime.tv_sec)/1e6;
	fprintf(stderr, "User time of %s: %e s\n", argv[1],end_user-begin_user);
	fprintf(stderr, "System time of %s: %e s\n", argv[1],end_syst-begin_syst);
}

// print out the wallclock time of death
void print_time(char **argv)
{
	struct timespec *begin_time = &t_begin, end_time = &t_end;
	double b = (double)begin_time->tv_sec + ((double)begin_time->tv_nsec)/1e9;
	double e = (double)end_time->tv_sec + ((double)end_time->tv_nsec)/1e9;
	fprintf(stderr, "Real time for %s: %e s\n", argv[1], e-b);
	fprintf(stderr, "Wallclock time of death: %s\n", ctime(death_time));	
}

void print_child_info(char **argv)
{
	fprintf(stderr, "==========================INFO==========================\n");
	fprintf(stderr, "Total lines from child process: %d\n", printline);
	print_rusage(argv);
	print_time(argv);
}

int main(int argc, char **argv)
{
	if(argc!=2)
	{
		fprintf(stderr, "Usage: %s <Excutable File Name>\n", argv[0]);
	}
	int fd[2];
	FILE *stream;
	struct rlimit stack_limit, old_stack;
	struct rlimit *pstack_limit = NULL;
	struct sigaction sa;
	sigset_t mask;

	// set limit to stack size
	stack_limit.rlim_cur = LIMITS;
	stack_limit.rlim_max = LIMITS;
	pstack_limit = &stack_limit;

	// register signal handler
	sa.sa_handler = reaper;
	sigemptyset(&sa.sa_mask);

	// if failure occured on sigaction
	if (sigaction(SIGCHLD, &sa, NULL) == -1){
	    fprintf(stderr, "SIGACTION failure: %s", strerror(errno));
	    exit(EXIT_FAILURE);   
	} 
	if (sigaction(SIGINT, &sa, NULL) == -1){
	    fprintf(stderr, "SIGACTION failure: %s", strerror(errno));
	    exit(EXIT_FAILURE);   
	} 
	if (sigaction(childsig, &sa, NULL) == -1){
	    fprintf(stderr, "SIGACTION failure: %s", strerror(errno));
	    exit(EXIT_FAILURE);   
	} 
	if (sigaction(SIGSEGV, &sa, NULL) == -1){
	    fprintf(stderr, "SIGACTION failure: %s", strerror(errno));
	    exit(EXIT_FAILURE);   
	} 
	if (sigaction(SIGUSR1, &sa, NULL) == -1){
	    fprintf(stderr, "SIGACTION failure: %s", strerror(errno));
		exit(EXIT_FAILURE);   
	} 

	// limit the global variables size of child process
	if(check_bss(argv)){
	    fprintf(stderr, "File %s bss larger than 1MB. Exiting\n", argv[1]);
	    exit(EXIT_SUCCESS);
	}

	//set limit on child process
	if((pid=fork()))
	{
		clock_gettime(CLOCK_REALTIME,&t_begin);
		getrusage(RUSAGE_SELF,&begin);
	}
	else
	{
		if(prlimit(0, RLIMIT_STACK, pstack_limit, &old_stack) == -1)
		{
			fprintf(stderr, "prlimit failure %d: %s\n",errno,strerror(errno));
			exit(EXIT_FAILURE);
		}
		// dup
		close(1);
		dup(fd[1]);
		close(fd[0]);
		close(fd[1]);
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
	all_lines(stream);
	print_child_info(argv);
	exit(EXIT_SUCCESS);
}






















