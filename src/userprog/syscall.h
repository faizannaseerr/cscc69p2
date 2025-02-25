#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

void syscall_init(void);

/* Pointer Validation */
static bool is_valid_char_pointer(char *);
static bool is_valid_pointer_with_length(void *, int);
static bool is_valid_pointer(void *);

#endif /* userprog/syscall.h */
