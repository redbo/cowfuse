#define FUSE_USE_VERSION 26
#define _XOPEN_SOURCE 600 // atoll
#define _GNU_SOURCE
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <pthread.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <dirent.h>
#include <limits.h>
#include <pwd.h>
#include <stddef.h>
#include <linux/falloc.h>

#define BLOCK_SIZE 4194304 // 4 MB
#define DEFAULT_ROOT "/srv"

struct options {
  char *root;
};
struct options options;

typedef struct filetype
{
  int (*read)(struct filetype *, char *, size_t, off_t);
  int (*write)(struct filetype *, const char *, size_t, off_t);
  int (*fsync)(struct filetype *, int);
  int (*close)(struct filetype *);
} filetype;

typedef struct volumefile
{
  struct filetype of; // has to be the first item so we can pretend it's a ft
  int fd;
  char path[PATH_MAX];
  uint8_t *map;
  uint64_t size;
  struct volumefile *next;
  struct snapfile *snapshots;
} volumefile;

typedef struct snapfile
{
  struct filetype of;
  int fd;
  uint8_t *map;
  uint64_t mapsize;
  struct volumefile *parent;
  struct snapfile *next;
} snapfile;

// mutext that protects the global volume_cache and per-vf linked lists
static pthread_mutex_t dmut;
volumefile *global_volume_cache = NULL;
int global_debug = 0;


// UTIL SHIT

void debugf(char *fmt, ...)
{
  if (global_debug)
  {
    va_list args;
    va_start(args, fmt);
    fputs("!!! ", stderr);
    vfprintf(stderr, fmt, args);
    va_end(args);
    putc('\n', stderr);
  }
}

void debugperror(char *msg)
{
  if (global_debug)
  {
    char buf[1024];
    strerror_r(errno, buf, sizeof(buf));
    fprintf(stderr, "!!! %s: %s", msg, buf);
  }
}

void restore_block(volumefile *vf, int block)
{
  // TODO fetch from cold store
  vf->map[block] = 1;
}

void volume_path(char *out, const char *volume_path, const char *filename)
{
  strcpy(out, volume_path);
  if (out[strlen(out)] != '/')
    strcat(out, "/");
  strcat(out, filename);
}

uint64_t volume_size(const char *path)
{
  char sizefile[PATH_MAX];
  volume_path(sizefile, path, "size");
  FILE *fp = fopen(sizefile, "r");
  if (fread(sizefile, 1, sizeof(sizefile), fp))
  {
    fclose(fp);
    return atoll(sizefile);
  }
  return -1;
}

void copy_block(int from_fd, int to_fd, int block)
{
  char block_buf[64 * 1024];
  uint64_t pos = block * BLOCK_SIZE, to = (block + 1) * BLOCK_SIZE;
  while (pos < to)
  {
    int read_amt = pread(from_fd, block_buf, pos, sizeof(block_buf));
    if (read_amt + pos > to)
      read_amt = to - pos;
    pos += pwrite(to_fd, block_buf, read_amt, pos);
  }
}

void lock_block(int fd, int block, int lock)
{
  struct flock fl = {
    .l_type = lock ? F_WRLCK : F_UNLCK,
    .l_whence = SEEK_SET,
    .l_start = block * BLOCK_SIZE,
    .l_len = 1,
  };
  fcntl(fd, F_SETLKW, &fl);
}


// VOLUME SHIT

static int volume_read(struct filetype *of, char *buf, size_t len, off_t offset)
{
  volumefile *vf = (volumefile *)of;
  int block = offset / BLOCK_SIZE;
  if (len > (BLOCK_SIZE - (offset % BLOCK_SIZE)))
    len = (BLOCK_SIZE - (offset % BLOCK_SIZE));
  if (!vf->map[block])
  {
    lock_block(vf->fd, block, 1);
    if (!vf->map[block])
      restore_block(vf, block);
    lock_block(vf->fd, block, 0);
  }
  return pread(vf->fd, (void *)buf, len, offset);
}

static int volume_write(struct filetype *of, const char *buf,
                        size_t len, off_t offset)
{
  int block = offset / BLOCK_SIZE;
  volumefile *vf = (volumefile *)of;
  if (len > (BLOCK_SIZE - (offset % BLOCK_SIZE)))
    len = (BLOCK_SIZE - (offset % BLOCK_SIZE));
  if (!vf->map[block] || vf->snapshots)
  {
    struct snapfile *sf;
    lock_block(vf->fd, block, 1);
    if (!vf->map[block])
      restore_block(vf, block);
    for (sf = vf->snapshots; sf; sf = sf->next)
      if (!sf->map[block])
      {
        lock_block(sf->fd, block, 1);
        if (!sf->map[block])
        {
          copy_block(vf->fd, sf->fd, block);
          sf->map[block] = 1;
        }
        lock_block(sf->fd, block, 0);
      }
    lock_block(vf->fd, block, 0);
  }
  return pwrite(vf->fd, (void *)buf, len, offset);
}

static int volume_fsync(struct filetype *of, int data)
{
  volumefile *vf = (volumefile *)of;
  msync(vf->map, vf->size / BLOCK_SIZE, MS_ASYNC);
  return fdatasync(vf->fd);
}

struct filetype *open_volume(const char *path)
{
  volumefile *vf;

  pthread_mutex_lock(&dmut);
  for (vf = global_volume_cache; vf; vf = vf->next)
  {
    if (!strncasecmp(vf->path, path, sizeof(vf->path)))
    {
      pthread_mutex_unlock(&dmut);
      return (filetype *)vf;
    }
  }
  vf = (volumefile *)malloc(sizeof(volumefile));
  vf->size = volume_size(path);
  strncpy(vf->path, path, sizeof(vf->path));
  vf->of.read = volume_read;
  vf->of.write = volume_write;
  vf->of.fsync = volume_fsync;
  vf->of.close = NULL;
  vf->next = global_volume_cache;
  global_volume_cache = vf;
  vf->snapshots = NULL;

  char datafile[PATH_MAX];
  volume_path(datafile, path, "volume");
  vf->fd = open(datafile, O_CREAT | O_RDWR, 0666);
  if (ftruncate(vf->fd, vf->size) ||
      fallocate(vf->fd, FALLOC_FL_KEEP_SIZE, 0, vf->size))
    debugperror("ftruncate volume");

  volume_path(datafile, path, "map");
  int mapfile = open(datafile, O_CREAT | O_RDWR, 0666);
  if (ftruncate(mapfile, vf->size / BLOCK_SIZE) ||
      fallocate(mapfile, FALLOC_FL_KEEP_SIZE, 0, vf->size / BLOCK_SIZE))
    debugperror("ftruncate mapfile");
  vf->map = mmap(NULL, vf->size / BLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED,
                    mapfile, 0);
  memset(vf->map, 0x1, vf->size / BLOCK_SIZE); // TODO: temporary for demo purposes
  close(mapfile);
  pthread_mutex_unlock(&dmut);

  return (filetype *)vf;
}


// SNAPSHOT SHIT

static int snapshot_read(struct filetype *of, char *buf, size_t len,
                         off_t offset)
{
  snapfile *sf = (snapfile *)of;
  int block = offset / BLOCK_SIZE;
  if (len > (BLOCK_SIZE - (offset % BLOCK_SIZE)))
    len = (BLOCK_SIZE - (offset % BLOCK_SIZE));
  if (sf->map[block])
    return pread(sf->fd, (void *)buf, len, offset);
  else if (sf->parent->map[block])
    return sf->parent->of.read((struct filetype *)(sf->parent), buf,
                                      BLOCK_SIZE, block * BLOCK_SIZE);
  else
    return -ENODATA;
}

static int snapshot_write(struct filetype *of, const char *buf,
                          size_t len, off_t offset)
{
  return -ENOSYS; // let's not worry about writable snapshots for now...
}

static int snapshot_fsync(struct filetype *of, int data)
{
  return -ENOSYS;
}

static int snapshot_close(struct filetype *of)
{
  pthread_mutex_lock(&dmut);
  snapfile *sf = (snapfile *)of;
  if (sf->parent->snapshots == sf)
    sf->parent->snapshots = sf->next;
  else
  {
    snapfile *itf;
    for (itf = sf->parent->snapshots; itf->next; itf = itf->next)
      if (itf->next == sf)
      {
        itf->next = itf->next->next;
        break;
      }
  }
  close(sf->fd);
  free(sf->map);
  free(sf);
  pthread_mutex_unlock(&dmut);
  return 0;
}

struct filetype *open_snapshot(const char *path)
{
  pthread_mutex_lock(&dmut);
  char volumepath[PATH_MAX], datafile[PATH_MAX];
  int len = strlen(path);

  strcpy(volumepath, path);
  if (len > 9 && !strcmp(&volumepath[len - 9], ".snapshot"))
    strcpy(&volumepath[len - 9], ".volume");

  snapfile *sf = (snapfile *)malloc(sizeof(snapfile));
  sf->of.read = snapshot_read;
  sf->of.write = snapshot_write;
  sf->of.fsync = snapshot_fsync;
  sf->of.close = snapshot_close;

  uint64_t size = volume_size(volumepath);

  volume_path(datafile, volumepath, "snapshot");
  sf->fd = open(datafile, O_CREAT | O_RDWR, 0666);
  unlink(datafile);
  if (ftruncate(sf->fd, size))
    debugperror("ftruncate snapshot");

  sf->map = malloc(size / BLOCK_SIZE);

  volumefile *vf;
  for (vf = global_volume_cache; vf; vf = vf->next)
  {
    if (!strncasecmp(vf->path, volumepath, sizeof(vf->path)))
    {
      sf->next = vf->snapshots;
      vf->snapshots = sf;
      sf->parent = vf;
    }
  }

  pthread_mutex_unlock(&dmut);
  return (filetype *)sf;
}


// FUSE SHIT

static int cbs_getattr(const char *path, struct stat *stbuf)
{
  char localpath[PATH_MAX] = ".";
  strcat(localpath, path);
  int len = strlen(localpath);
  if (len > 9 && !strcmp(&localpath[len - 9], ".snapshot"))
  {
    strcpy(&localpath[len - 9], ".volume");
    len -= 2;
  }
  if (len > 7 && !strcmp(&localpath[len - 7], ".volume"))
  {
    stat(localpath, stbuf);
    stbuf->st_size = volume_size(localpath);
    stbuf->st_mode = S_IFREG | 0666;
    stbuf->st_nlink = 1;
    return 0;
  }
  else
    return -stat(localpath, stbuf);
}

static int cbs_fgetattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *info)
{
  return cbs_getattr(path, stbuf);
}

static int cbs_readdir(const char *path, void *buf, fuse_fill_dir_t filldir,
                       off_t offset, struct fuse_file_info *info)
{
  char localpath[PATH_MAX] = ".";
  strcat(localpath, path);
  DIR *dir = opendir(localpath);
  struct dirent entry, *result;
  if (!dir)
    return -errno;
  filldir(buf, ".", NULL, 0);
  filldir(buf, "..", NULL, 0);
  do
  {
    readdir_r(dir, &entry, &result);
    if (result)
    {
      int len = strlen(result->d_name);
      filldir(buf, result->d_name, NULL, 0);
      if (len > 7 && !strcmp(&result->d_name[len - 7], ".volume"))
      {
        char snappath[PATH_MAX];
        strcpy(snappath, result->d_name);
        strcpy(&snappath[len - 7], ".snapshot");
        filldir(buf, snappath, NULL, 0);
      }
    }
  } while (result);
  return 0;
}

static int cbs_open(const char *path, struct fuse_file_info *info)
{
  char localpath[PATH_MAX] = ".";
  strcat(localpath, path);
  int len = strlen(localpath);
  info->direct_io = 1;
  if (len > 7 && !strcmp(&localpath[len - 7], ".volume"))
    info->fh = (uintptr_t)open_volume(localpath);
  else if (len > 9 && !strcmp(&localpath[len - 9], ".snapshot"))
  {
    strcpy(&localpath[len - 9], ".volume");
    info->fh = (uintptr_t)open_volume(localpath);
  }
  return 0;
}

static int cbs_read(const char *path, char *buf, size_t size,
                    off_t offset, struct fuse_file_info *info)
{
  return ((filetype *)(uintptr_t)info->fh)->read(
      (filetype *)(uintptr_t)info->fh, buf, size, offset);
}

static int cbs_release(const char *path, struct fuse_file_info *info)
{
  filetype *of = (filetype *)(uintptr_t)info->fh;
  if (of->close)
    return of->close(of);
  else
    return 0;
}

static int cbs_write(const char *path, const char *buf, size_t length,
                     off_t offset, struct fuse_file_info *info)
{
  return ((filetype *)(uintptr_t)info->fh)->write(
      (filetype *)(uintptr_t)info->fh, buf, length, offset);
}

static int cbs_fsync(const char *path, int data, struct fuse_file_info *info)
{
  return ((filetype *)(uintptr_t)info->fh)->fsync(
      (filetype *)(uintptr_t)info->fh, data);
}

static void *cbs_init(struct fuse_conn_info *conn)
{
  if (chdir(options.root))
    debugperror("chdir");
  return NULL;
}

static int cbs_statfs(const char *path, struct statvfs *stat)
{
  stat->f_bsize = 4096;
  stat->f_frsize = 4096;
  stat->f_blocks = INT_MAX;
  stat->f_bfree = INT_MAX;
  stat->f_bavail = INT_MAX;
  stat->f_files = INT_MAX;
  stat->f_ffree = INT_MAX;
  stat->f_favail = INT_MAX;
  stat->f_namemax = INT_MAX;
  return 0;
}

int main(int argc, char **argv)
{
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  fuse_parse_cmdline(&args, NULL, NULL, &global_debug);

  static struct fuse_operations cbs_oper =
  {
    .readdir = cbs_readdir,
    .open = cbs_open,
    .fgetattr = cbs_fgetattr,
    .getattr = cbs_getattr,
    .release = cbs_release,
    .read = cbs_read,
    .write = cbs_write,
    .fsync = cbs_fsync,
    .statfs = cbs_statfs,
    .init = cbs_init,
  };

  options.root = DEFAULT_ROOT;
  static struct fuse_opt cbs_opts[] =
  {
    {"root=%s", offsetof(struct options, root), 0},
    FUSE_OPT_END
  };

  fuse_opt_parse(&args, &options, cbs_opts, NULL);
  pthread_mutex_init(&dmut, NULL);
  signal(SIGPIPE, SIG_IGN);
  return fuse_main(argc, argv, &cbs_oper, NULL);
}

