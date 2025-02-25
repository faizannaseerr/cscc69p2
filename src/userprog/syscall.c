#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "pagedir.h"
#include "process.h"

static struct lock lock; /* Lock for file system operations */

/* All Handler Functions */
static void syscall_handler(struct intr_frame *);
static int exec_handler(char *);
static int wait_handler(int);
static void exit_handler(int);
static void halt_handler(void);

static bool create_handler(char *, unsigned);
static bool remove_handler(char *);

static int open_handler(char *);
static void close_handler(int);
static int read_handler(int, char *, unsigned);
static int write_handler(int, char *, unsigned);
static void seek_handler(int, unsigned);
static unsigned tell_handler(int);
static int size_handler(int);

void syscall_init(void)
{
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&lock);
}

/* Halts the OS. */
static void halt_handler(void)
{
    shutdown_power_off();
}

/* Exit the current thread. */
static void exit_handler(int status)
{
    struct thread *cur = thread_current();
    struct child_thread *child = get_child_thread(cur->parent, cur->tid);
    child->exit_status = status;
    thread_exit();
    NOT_REACHED();
}

/* Runs file. */
static int exec_handler(char *cmd_line)
{
    if (!is_valid_char_pointer(cmd_line))
    {
        thread_exit();
    }
    int pid = process_execute(cmd_line);
    struct child_thread *child = get_child_thread(thread_current(), pid);
    sema_down(&child->sema_load);
    return child->is_loaded ? pid : -1;
}

/* Waits for a child process to die. */
static int wait_handler(int pid)
{
    return process_wait(pid);
}

/* Creates a file. */
static bool create_handler(char *file, unsigned initial_size)
{
    if (!is_valid_char_pointer(file))
    {
        thread_exit();
    }
    lock_acquire(&lock);
    bool success = filesys_create(file, initial_size);
    lock_release(&lock);
    return success;
}

/* Removes a file. */
static bool remove_handler(char *file)
{
    if (!is_valid_char_pointer(file))
    {
        thread_exit();
    }
    lock_acquire(&lock);
    bool success = filesys_remove(file);
    lock_release(&lock);
    return success;
}

/* Opens file. */
static int open_handler(char *file)
{
    if (!is_valid_char_pointer(file))
    {
        thread_exit();
    }
    lock_acquire(&lock);
    struct file *f = filesys_open(file);
    lock_release(&lock);
    if (f == NULL)
    {
        return -1;
    }
    struct thread *cur = thread_current();
    struct file_descriptor *fd_entry = malloc(sizeof(struct file_descriptor));
    cur->pcb->highest_fd++;
    fd_entry->fd = cur->pcb->highest_fd;
    fd_entry->file = f;
    fd_entry->file_name = file;
    list_push_back(&cur->pcb->fd_table, &fd_entry->elem);
    return fd_entry->fd;
}

/* Closes file. */
static void close_handler(int fd)
{
    struct list_elem *fd_table_entry = get_file_elem_by_fd(fd);
    if (fd_table_entry != NULL)
    {
        struct file_descriptor *fd_entry = list_entry(fd_table_entry, struct file_descriptor, elem);
        lock_acquire(&lock);
        file_close(fd_entry->file);
        lock_release(&lock);
        list_remove(fd_table_entry);
        free(fd_entry);
    }
}

/* Reads from a file. */
static int read_handler(int fd, char *buffer, unsigned size)
{
    if (!is_valid_pointer_with_length(buffer, sizeof(char) * size))
    {
        thread_exit();
    }
    if (fd == 0)
    {
        char c;
        int i;
        i = 0;
        while (i < size && (c = input_getc()) != '\n')
        {
            buffer[i] = c;
            i++;
        }
        buffer[i] = '\0';
        return i;
    }
    struct file *f = get_file_by_fd(fd);
    if (f != NULL)
    {
        lock_acquire(&lock);
        int bytes_read = file_read(f, buffer, size);
        lock_release(&lock);
        return bytes_read;
    }
    return -1;
}

/* Writes into a file. */
static int write_handler(int fd, char *buffer, unsigned size)
{
    if (!is_valid_pointer_with_length(buffer, sizeof(char) * size))
    {
        thread_exit();
    }
    if (fd == 1)
    {
        putbuf(buffer, size);
        return size;
    }
    struct file *f = get_file_by_fd(fd);
    if (f != NULL)
    {
        lock_acquire(&lock);
        int bytes_written = file_write(f, buffer, size);
        lock_release(&lock);
        return bytes_written;
    }
    return -1;
}

/* Seeks to a position in a file. */
static void seek_handler(int fd, unsigned position)
{
    struct file *f = get_file_by_fd(fd);
    if (f == NULL)
    {
        thread_exit();
    }
    lock_acquire(&lock);
    file_seek(f, position);
    lock_release(&lock);
}

/* Tells the position in a file. */
static unsigned tell_handler(int fd)
{
    struct file *f = get_file_by_fd(fd);
    if (f == NULL)
    {
        thread_exit();
    }
    lock_acquire(&lock);
    unsigned position = file_tell(f);
    lock_release(&lock);
    return position;
}

/* Gets the size of a file. */
static int size_handler(int fd)
{
    struct file *f = get_file_by_fd(fd);
    if (f == NULL)
    {
        thread_exit();
    }
    lock_acquire(&lock);
    int size = file_length(f);
    lock_release(&lock);
    return size;
}

/* System calls handler (calls relevant function) */
static void
syscall_handler(struct intr_frame *f)
{
    int *intr_code = (int *)f->esp;
    void *arg1 = f->esp + 4;
    void *arg2 = f->esp + 8;
    void *arg3 = f->esp + 12;

    /* Validates the interrupt code pointer. */
    if (!is_valid_pointer(intr_code))
    {
        thread_exit();
    }

    /* Validates first arguement if its an int pointer. */
    if ((*intr_code == SYS_WAIT || *intr_code == SYS_EXIT || *intr_code >= SYS_FILESIZE) && !is_valid_pointer(arg1))
    {
        thread_exit();
    }

    /* Validates first arguement if its a pointer to a char pointer. */
    if ((*intr_code == SYS_EXEC || *intr_code == SYS_CREATE || *intr_code == SYS_REMOVE || *intr_code == SYS_OPEN) && !is_valid_pointer(arg1))
    {
        thread_exit();
    }

    switch (*intr_code)
    {
    case SYS_HALT:
        halt_handler();
        break;
    case SYS_EXIT:
        exit_handler(*(int *)arg1);
        break;
    case SYS_EXEC:
        f->eax = exec_handler(*(char **)arg1);
        break;
    case SYS_WAIT:
        f->eax = wait_handler(*(int *)arg1);
        break;
    case SYS_CREATE:
        if (!is_valid_pointer(arg2))
        {
            thread_exit();
        }
        f->eax = create_handler(*(char **)arg1, *(unsigned *)arg2);
        break;
    case SYS_REMOVE:
        f->eax = remove_handler(*(char **)arg1);
        break;
    case SYS_OPEN:
        f->eax = open_handler(*(char **)arg1);
        break;
    case SYS_CLOSE:
        close_handler(*(int *)arg1);
        break;
    case SYS_READ:
        if (!is_valid_pointer(arg2) || !is_valid_pointer(arg3))
        {
            thread_exit();
        }
        f->eax = read_handler(*(int *)arg1, *(char **)arg2, *(unsigned *)arg3);
        break;
    case SYS_WRITE:
        if (!is_valid_pointer(arg2) || !is_valid_pointer(arg3))
        {
            thread_exit();
        }
        f->eax = write_handler(*(int *)arg1, *(char **)arg2, *(unsigned *)arg3);
        break;
    case SYS_SEEK:
        if (!is_valid_pointer(arg2))
        {
            thread_exit();
        }
        seek_handler(*(int *)arg1, *(unsigned *)arg2);
        break;
    case SYS_TELL:
        f->eax = tell_handler(*(int *)arg1);
        break;
    case SYS_FILESIZE:
        f->eax = size_handler(*(int *)arg1);
        break;
    default:
        thread_exit();
    }
}

/* Pointer Validation For Chars */
static bool is_valid_char_pointer(char *ptr)
{
    uintptr_t address = (uintptr_t)ptr;
    if (ptr == NULL || is_kernel_vaddr(ptr) || pagedir_get_page(thread_current()->pagedir, ptr) == NULL)
    {
        return false;
    }
    bool boundary = false;
    int size = 0;
    /*  Make sure less than 14 chars */
    while (size < 14 && (ptr + size) != '\0')
    {
        size++;
        if (is_kernel_vaddr(ptr + size))
        {
            return false;
        }
        if (!boundary && address / PGSIZE < (address + size) / PGSIZE)
        {
            boundary = true;
            if (pagedir_get_page(thread_current()->pagedir, ptr + size) == NULL)
            {
                return false;
            }
        }
    }
    return true;
}

/* Pointer Validation (with length) */
static bool is_valid_pointer_with_length(void *ptr, int length)
{
    uintptr_t address = (uintptr_t)ptr;
    return ptr != NULL && is_user_vaddr(ptr) &&
           is_user_vaddr(ptr + length - 1) &&
           pagedir_get_page(thread_current()->pagedir, ptr) != NULL &&
           (address / PGSIZE == (address + length - 1) / PGSIZE || pagedir_get_page(thread_current()->pagedir, ptr + length - 1) != NULL);
}

/* Pointer Validation (any) */
static bool is_valid_pointer(void *ptr)
{
    return is_valid_pointer_with_length(ptr, sizeof(int));
}
