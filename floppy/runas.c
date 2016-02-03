/* Chester Holtz
 * chesterholtz@gmail.com
 * Univerity of Rochester csc_292 Foundations of System Security
 * mp1 - a simple program to run programs as a user.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h> /* waitpid */

/*
 * barebones implementation of a user based on definition in <pwd.h>
 */
typedef struct{
    char   *pw_name;       /* username */
    char   *pw_passwd;     /* user password */
    uid_t   pw_uid;        /* user ID */
    gid_t   pw_gid;        /* group ID */
} user;

/*
 * Function: char *trim(char *s)
 *
 * Description:
 *   Helper function for tokenizer.
 *
 * Inputs:
 *   char *s - input string
 *
 * Output:
 *   s - s trimmed of all newline characters.
 */
char *trim (char *s) {
    int i = strlen(s)-1;
    if ((i > 0) && (s[i] == '\n'))
        s[i] = '\0';
    return s;
}

/*
 * Function: int log_exec(int status, char *command, int arg_num, char*args[])
 *
 * Description:
 *   log exit status of program executed with runas.
 *
 * Inputs:
 *   int status    - Returned status from run program.
 *   char *command - Program that was.
 *   int arg_num   - Number of arguments passed to program.
 *   char *args[]  - Arguments
 *
 * Output:
 *   0 - Program terminated normally.
 *   1 - Program terminated abnormally.
 */
int log_exec(int status, char *command, int arg_num, char *args[]) {
    char* fname = "/var/tmp/runaslog";
    int i = 0;
    if(access( fname, F_OK ) != -1) {
        FILE *f = fopen(fname, "a");
        fprintf(f, "%d %s", status, command);
        if (arg_num > 0) {
            for(i = 1; i <= arg_num; i++) {
                fprintf(f, " %s", args[i]);
            }
        }
        fprintf(f,"\n");
        fclose(f);
        return 0;
    } else {
        fprintf(stderr, "/var/tmp/runaslog: file does not exist\n");
        exit(2);
    }
    return 1;
}

/*
 * Function: int can_run(char *uname_a, char *uname_b, char *pwd_b)  
 * 
 * Description: 
 *   Parse runas file. return 1 if user a can run programs as user b given password for user b, else return 0
 *
 * Input:
 *   char *uname_a - username of a
 *   char *uname_b - username of b
 *   char *pwd_b   - password of b
 *
 * Output:
 *   0 - user a can run as user b
 *   1 - user a cannot run as user b
 */
int can_run(char *uname_a, char *uname_b, char *pwd_b) {
    char* fname = "/etc/runas";
    char ptr[1024];
    char *token;
    char *entry[2];
    int i=0, j=0;

    if(access(fname, F_OK) != -1) {
        FILE *f = fopen(fname, "r");
        while (fgets(ptr, 1024, f) != NULL) {
            token = strtok(ptr, ":");
            while(token) {
                entry[i] = malloc(strlen(token) + 1);
                strcpy(entry[i], trim(token)); /* need to trim, since fgets include trailing newline */
                token = strtok(NULL, ":");
                i++;
            }
            /* compare entry to arguments, and move on...if we find a matching entry in runas file */
            if(strcmp(uname_a, entry[0]) == 0 && strcmp(uname_b,entry[1]) == 0 && strcmp(pwd_b,entry[2]) == 0) {
                return 0;
            }

            /* reinitialize iterator to 0, free entry memory. */
            i = 0; 
            for (j = 0; j < 2; j++) {
                free(entry[j]);
            }
        }

        /* no entry matching found */
        fclose(f);
        return 1;
    } else {
        fprintf(stderr, "/etc/runas: file does not exist\n");
        exit(2);
    }
    return 0;
}

/*
 * Function: user get_user(char* uname, int uid)
 *
 * Description:
 *   Returns user object given uname or uid
 *
 * Input:
 *   char* uname - (optional) username
 *   int uid     - (optional) userid
 *
 * Output:
 *   user self - return user
 */
user get_user(char* uname, int uid) {
    user self;
    self.pw_name = ""; /* in case no user found */

    char* fname = "/etc/passwd";
    char ptr[1024];
    char *token;
    char *overflow; /* string overflow parameter for strtol */
    char *entry[6]; /* entry in runas file */
    int i=0, j=0;

    if( access( fname, F_OK ) != -1 ) {
        FILE *f = fopen(fname, "r");
        while (fgets(ptr, 1024, f) != NULL) {
            token = strtok(ptr, ":");
            while(token) {
                entry[i] = malloc(strlen(token) + 1);
                strcpy(entry[i], trim(token)); /* need to trim, since fgets include trailing newline */
                token = strtok(NULL, ":");
                i++;
            }
            /* compare entry to arguments, and move on. */ 
            if(strcmp(uname, entry[0]) == 0) {
                /* found user by name */
                //printf("found user %s\n",entry[0]);
                self.pw_name = entry[0];
                self.pw_passwd = "";
                self.pw_uid = strtol(entry[2],&overflow,10);//atoi(entry[2]);
                self.pw_gid = strtol(entry[3],&overflow,10);//atoi(entry[3]);
                return self;
            } else if (uid == strtol(entry[1],&overflow,10)){//atoi(entry[1])) { /* given uid matches */
                /* found user by id */
                //printf("found user %s\n",entry[0]);
                self.pw_name = entry[0];
                self.pw_passwd = "";
                self.pw_uid = strtol(entry[2],&overflow,10);//atoi(entry[2]);
                self.pw_gid = strtol(entry[3],&overflow,10);//atoi(entry[3]);
                return self;
            }
            /* reinitialize iterator to 0, free entry memory */
            i = 0;
            for (j = 0; j < 6; j++) {
                free(entry[j]);
            }
        }
        /* no entry matching found */
        fclose(f);
    } else { /* something is really wrong */
        fprintf(stderr, "/etc/passwd: file does not exist\n");
        exit(2);
    }

    fprintf(stderr, "user does not exist\n");
    exit(127);
}

/*
 * Function: main()
 *
 * Description:
 *   Entry point for this program.
 *
 * Inputs:
 *   argc - The number of argument with which this program was executed.
 *   argv - Array of pointers to strings containing the command-line arguments. 
 *
 * Output::
 *   0 - This program terminated normally.
 */
int main(int argc, char *argv[]) {
    char command[60];
    char *args[argc];
    int arg_num = argc - 2;
    char runas_uname[20];
    int i;

    user cur_user = get_user("",getuid());
    user runas_user;
    //user runas_user = get_user(argv[1], -1);

    if (argc >= 2) {
        //strcpy(runas_uname, argv[1]);
        runas_user = get_user(argv[1], -1);
        strcpy(command, argv[2]);
        for (i = 2; i < argc; i++)  {    
            args[i - 2] = (char *)malloc(strlen (argv [i]) * sizeof(char) + 1); 
            strcpy(args[i - 2], argv[i]);     
        }
        args[argc - 2] = NULL;
    } else {
        setuid(getuid());
        fprintf(stderr, "%s: No username or command specified\n", argv[0]);
        exit(127);
    }
    char *pwd = getpass("Password: "); // getpass system call disables echo
    
    if(can_run(cur_user.pw_name,runas_user.pw_name,pwd) == 0) {
        // user has permission to run programs as this user
    } else {
        setuid(getuid());
        fprintf(stderr, "%s: user not found, or password incorrect\n", runas_uname);
        exit(1);
    }

    /* Spawn a child to run the program. */
    int status;
    pid_t pid=fork();
    if (pid==0) { /* child process */
        //setuid(cur_user.pw_uid);
        //seteuid(runas_user.pw_uid);
        setreuid(cur_user.pw_uid,runas_user.pw_uid);
        setregid(cur_user.pw_gid,runas_user.pw_gid);
        //setresuid(cur_user.pw_uid,runas_user.pw_uid,cur_user.pw_uid,getsuid());
        execvp(command,args);
        exit(127); /* only if execvp fails */
    }
    else { /* pid!=0; parent process */
        waitpid(pid,&status,0); /* wait for child to exit */
        if(WIFEXITED(status) != 0) {
            log_exec(WEXITSTATUS(status), command, arg_num, args);
        } else { /* process exited abnormally, do not log */
            fprintf(stderr, "%s: process exited abnormally with status %d\n", command, status);
            exit(1);
        }
    }

    setuid(getuid());
    return 0;
}
