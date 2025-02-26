#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);
void initialize_pcb(struct thread *t);
void free_all_files(void);
struct file *get_file_by_fd(int fd);
struct list_elem *get_file_elem_by_fd(int fd);

/* Process control block for a user program */
struct pcb
{
    struct thread *parent;  /* Parent thread */
    struct thread *process; /* Process thread */
    struct file *file;      /* Executable file */
    struct list fd_table;   /* File descriptor table */
    int highest_fd;         /* Highest file descriptor */

    struct list_elem elem; /* List element */
};

/* File info for an entry in a PCB FD table */
struct file_descriptor
{
    int fd;            /* File descriptor */
    char *file_name;   /* File name */
    struct file *file; /* File pointer */

    struct list_elem elem; /* List element */
};

#endif /* userprog/process.h */
