#include "userprog/syscall.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/stdio.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

struct file_desc
  {
    int fd;
    struct file *file;
    struct list_elem elem;
  };

static void syscall_handler (struct intr_frame *);
static void kill_process (void) NO_RETURN;
static void check_uaddr_range (const void *uaddr, size_t size);
static size_t check_cstring (const char *uaddr);
static uint32_t fetch_u32 (const void *uaddr);
static struct file_desc *fd_lookup (int fd);
static int fd_insert (struct file *file);
static void fd_close_desc (struct file_desc *desc);
static bool sys_create (const char *file_name, unsigned initial_size);
static bool sys_remove (const char *file_name);
static tid_t sys_exec (const char *cmd_line);
static int sys_open (const char *file_name);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static void sys_close (int fd);
static int sys_write (int fd, const void *buffer, unsigned size);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);

static struct lock filesys_lock;

void
syscall_init (void) 
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  const uint32_t *esp = f->esp;
  uint32_t syscall_nr = fetch_u32 (esp);

  switch (syscall_nr)
    {
    case SYS_HALT:
      shutdown_power_off ();
      break;

    case SYS_EXIT:
      thread_current ()->exit_code = (int) fetch_u32 (esp + 1);
      thread_exit ();
      break;

    case SYS_WAIT:
      f->eax = process_wait ((tid_t) fetch_u32 (esp + 1));
      break;

    case SYS_EXEC:
      f->eax = sys_exec ((const char *) fetch_u32 (esp + 1));
      break;

    case SYS_CREATE:
      f->eax = sys_create ((const char *) fetch_u32 (esp + 1),
                           (unsigned) fetch_u32 (esp + 2));
      break;

    case SYS_REMOVE:
      f->eax = sys_remove ((const char *) fetch_u32 (esp + 1));
      break;

    case SYS_OPEN:
      f->eax = sys_open ((const char *) fetch_u32 (esp + 1));
      break;

    case SYS_FILESIZE:
      f->eax = sys_filesize ((int) fetch_u32 (esp + 1));
      break;

    case SYS_READ:
      f->eax = sys_read ((int) fetch_u32 (esp + 1),
                         (void *) fetch_u32 (esp + 2),
                         (unsigned) fetch_u32 (esp + 3));
      break;

    case SYS_CLOSE:
      sys_close ((int) fetch_u32 (esp + 1));
      break;

    case SYS_WRITE:
      f->eax = sys_write ((int) fetch_u32 (esp + 1),
                          (const void *) fetch_u32 (esp + 2),
                          (unsigned) fetch_u32 (esp + 3));
      break;

    case SYS_SEEK:
      sys_seek ((int) fetch_u32 (esp + 1),
                (unsigned) fetch_u32 (esp + 2));
      break;

    case SYS_TELL:
      f->eax = sys_tell ((int) fetch_u32 (esp + 1));
      break;

    default:
      kill_process ();
      break;
    }
}

static void
kill_process (void)
{
  thread_current ()->exit_code = -1;
  thread_exit ();
}

static void
check_uaddr_range (const void *uaddr, size_t size)
{
  uintptr_t start = (uintptr_t) uaddr;
  uintptr_t end;
  uintptr_t page;
  struct thread *cur = thread_current ();

  if (size == 0)
    return;
  if (start == 0)
    kill_process ();

  end = start + size - 1;
  if (end < start
      || !is_user_vaddr ((const void *) start)
      || !is_user_vaddr ((const void *) end))
    kill_process ();

  page = (uintptr_t) pg_round_down ((const void *) start);
  while (page <= end)
    {
      if (pagedir_get_page (cur->pagedir, (const void *) page) == NULL)
        kill_process ();
      page += PGSIZE;
    }
}

static size_t
check_cstring (const char *uaddr)
{
  size_t len = 0;

  if (uaddr == NULL)
    kill_process ();

  while (true)
    {
      check_uaddr_range (uaddr + len, 1);
      if (uaddr[len] == '\0')
        return len;
      len++;
      if (len >= PGSIZE)
        kill_process ();
    }
}

static uint32_t
fetch_u32 (const void *uaddr)
{
  check_uaddr_range (uaddr, sizeof (uint32_t));
  return *(const uint32_t *) uaddr;
}

static struct file_desc *
fd_lookup (int fd)
{
  struct list_elem *e;
  struct thread *cur = thread_current ();

  for (e = list_begin (&cur->fd_table); e != list_end (&cur->fd_table);
       e = list_next (e))
    {
      struct file_desc *desc = list_entry (e, struct file_desc, elem);
      if (desc->fd == fd)
        return desc;
    }
  return NULL;
}

static int
fd_insert (struct file *file)
{
  struct thread *cur = thread_current ();
  struct file_desc *desc = malloc (sizeof *desc);

  if (desc == NULL)
    return -1;
  desc->fd = cur->next_fd++;
  desc->file = file;
  list_push_back (&cur->fd_table, &desc->elem);
  return desc->fd;
}

static void
fd_close_desc (struct file_desc *desc)
{
  file_close (desc->file);
  list_remove (&desc->elem);
  free (desc);
}

static bool
sys_create (const char *file_name, unsigned initial_size)
{
  bool ok;

  check_cstring (file_name);
  syscall_filesys_lock ();
  ok = filesys_create (file_name, (off_t) initial_size);
  syscall_filesys_unlock ();
  return ok;
}

static bool
sys_remove (const char *file_name)
{
  bool ok;

  check_cstring (file_name);
  syscall_filesys_lock ();
  ok = filesys_remove (file_name);
  syscall_filesys_unlock ();
  return ok;
}

static tid_t
sys_exec (const char *cmd_line)
{
  size_t len = check_cstring (cmd_line);
  char *kcmd = palloc_get_page (0);
  tid_t tid;

  if (kcmd == NULL)
    return TID_ERROR;
  memcpy (kcmd, cmd_line, len + 1);
  tid = process_execute (kcmd);
  palloc_free_page (kcmd);
  return tid;
}

static int
sys_open (const char *file_name)
{
  struct file *file;
  int fd;

  check_cstring (file_name);
  syscall_filesys_lock ();
  file = filesys_open (file_name);
  if (file == NULL)
    {
      syscall_filesys_unlock ();
      return -1;
    }
  fd = fd_insert (file);
  if (fd == -1)
    file_close (file);
  syscall_filesys_unlock ();
  return fd;
}

static int
sys_filesize (int fd)
{
  struct file_desc *desc = fd_lookup (fd);
  int len;

  if (desc == NULL)
    return -1;

  syscall_filesys_lock ();
  len = (int) file_length (desc->file);
  syscall_filesys_unlock ();
  return len;
}

static int
sys_read (int fd, void *buffer, unsigned size)
{
  uint8_t *dst = buffer;

  check_uaddr_range (buffer, size);

  if (fd == 0)
    {
      unsigned i;
      for (i = 0; i < size; i++)
        dst[i] = input_getc ();
      return (int) size;
    }
  else
    {
      struct file_desc *desc = fd_lookup (fd);
      int read_bytes;

      if (desc == NULL)
        return -1;

      syscall_filesys_lock ();
      read_bytes = (int) file_read (desc->file, buffer, (off_t) size);
      syscall_filesys_unlock ();
      return read_bytes;
    }
}

static void
sys_close (int fd)
{
  struct file_desc *desc = fd_lookup (fd);
  if (desc != NULL)
    {
      syscall_filesys_lock ();
      fd_close_desc (desc);
      syscall_filesys_unlock ();
    }
}

static int
sys_write (int fd, const void *buffer, unsigned size)
{
  const uint8_t *src = buffer;
  struct file_desc *desc;

  if (fd == 0)
    return -1;

  check_uaddr_range (buffer, size);

  if (fd == 1)
    {
      unsigned remaining = size;

      while (remaining > 0)
        {
          uint8_t kbuf[256];
          unsigned chunk = remaining < sizeof kbuf ? remaining : sizeof kbuf;
          memcpy (kbuf, src, chunk);
          putbuf ((const char *) kbuf, chunk);
          src += chunk;
          remaining -= chunk;
        }
      return (int) size;
    }

  desc = fd_lookup (fd);
  if (desc == NULL)
    return -1;

  syscall_filesys_lock ();
  size = (unsigned) file_write (desc->file, buffer, (off_t) size);
  syscall_filesys_unlock ();
  return (int) size;
}

static void
sys_seek (int fd, unsigned position)
{
  struct file_desc *desc = fd_lookup (fd);

  if (desc == NULL)
    return;

  syscall_filesys_lock ();
  file_seek (desc->file, (off_t) position);
  syscall_filesys_unlock ();
}

static unsigned
sys_tell (int fd)
{
  struct file_desc *desc = fd_lookup (fd);
  unsigned pos;

  if (desc == NULL)
    return (unsigned) -1;

  syscall_filesys_lock ();
  pos = (unsigned) file_tell (desc->file);
  syscall_filesys_unlock ();
  return pos;
}

void
syscall_close_all_files (void)
{
  struct thread *cur = thread_current ();

  syscall_filesys_lock ();
  while (!list_empty (&cur->fd_table))
    {
      struct list_elem *e = list_pop_front (&cur->fd_table);
      struct file_desc *desc = list_entry (e, struct file_desc, elem);
      file_close (desc->file);
      free (desc);
    }
  syscall_filesys_unlock ();
}

void
syscall_filesys_lock (void)
{
  lock_acquire (&filesys_lock);
}

void
syscall_filesys_unlock (void)
{
  lock_release (&filesys_lock);
}
