/**
 * Basic overlay filesystem implementation
 * @author Kumar Saurav
 * @date 05-09-2025
 */

#define FUSE_USE_VERSION 31

#ifndef PATH_MAX
#define PATH_MAX 512
#endif

#include<syslog.h>
#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <libgen.h>

/** 
 * Providing command line arguments for running the filesystem daemon
 */
static struct options {
	const char *lower;
	const char *upper;
	int show_help;
} options;

#define TRY(x) do {if((x) == -1) { return -errno; }} while(0)
#define OPTION(t, p) { t, offsetof(struct options, p), 1 } 
static const struct fuse_opt option_spec[] = {
	OPTION("--lower=%s", lower), // The lower layer of the filesystem
	OPTION("--upper=%s", upper), // The upper layer of the filesystem
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};

/**
 * Minimal linux/list.h inspired linked list implementation 
 */

struct list_head {
    struct list_head *next, *prev;
};

/* Initialize a list head (both next and prev point to itself) */
#define INIT_LIST_HEAD(ptr) do { \
    (ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

/* Insert a new entry between two known consecutive entries */
static inline void __list_add(struct list_head *new,
                              struct list_head *prev,
                              struct list_head *next) {
    next->prev = new;
    new->next  = next;
    new->prev  = prev;
    prev->next = new;
}

/* Add at the beginning */
static inline void list_add(struct list_head *new, struct list_head *head) {
    __list_add(new, head, head->next);
}

/* Add at the end */
static inline void list_add_tail(struct list_head *new, struct list_head *head) {
    __list_add(new, head->prev, head);
}

/* Delete entry */
static inline void __list_del(struct list_head * prev, struct list_head * next) {
    next->prev = prev;
    prev->next = next;
}

static inline void list_del(struct list_head *entry) {
    __list_del(entry->prev, entry->next);
    entry->next = entry->prev = NULL;
}

/* Iterate over list */
#define list_for_each(pos, head) \
    for (pos = (head)->next; pos != (head); pos = pos->next)

/* Get struct from list_head pointer */
#define list_entry(ptr, type, member) \
    ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

/* Iterate over entries */
#define list_for_each_entry(pos, head, member)              \
    for (pos = list_entry((head)->next, typeof(*pos), member); \
		&pos->member != (head);                            \
		pos = list_entry(pos->member.next, typeof(*pos), member))

		 
#define list_for_each_entry_safe(pos, n, head, member)                  \
    for (pos = list_entry((head)->next, typeof(*pos), member),          \
		n = list_entry(pos->member.next, typeof(*pos), member);        \
		&pos->member != (head);                                        \
		pos = n, n = list_entry(n->member.next, typeof(*n), member))

#define FREE_LIST(head, type, member) do {                       \
    type *pos, *tmp;                                             \
    list_for_each_entry_safe(pos, tmp, head, member) {           \
        list_del(&pos->member);                                  \
        free(pos);                                               \
    }                                                            \
} while (0)


/**
 * Helper methods to construct lower and upper directory paths 
 */

void lower_path(const char* path, char* buffer) {
	snprintf(buffer, PATH_MAX, "%s%s", options.lower, path);
	// syslog(LOG_INFO, "Lower path resolved to %s", buffer);
}

void upper_path(const char* path, char* buffer) {
	snprintf(buffer, PATH_MAX, "%s%s", options.upper, path);
	// syslog(LOG_INFO, "Upper path resolved to %s", buffer);
}

/**
 * @param path: a path to a file 
 * @return whether or not there is a whiteout file(path :: .wh)
 */
static bool is_whiteout(const char *path) {
    char wh_path[PATH_MAX];
    snprintf(wh_path, PATH_MAX, "%s.wh", path);
    return access(wh_path, F_OK) == 0;
}

/* Check if any parent directory is whited out */
static bool is_path_whiteout(const char *path) {
    char path_copy[PATH_MAX];
    strncpy(path_copy, path, PATH_MAX-1);
    path_copy[PATH_MAX-1] = '\0';

    /* First check the path itself */
    if (is_whiteout(path_copy))
        return true;

    /* Then check each parent directory */
    while (1) {
        char *last_slash = strrchr(path_copy, '/');
        if (!last_slash)
            break;
        
        /* Truncate to parent path */
        *last_slash = '\0';
        
        /* Skip empty path from double slashes */
        if (strlen(path_copy) == 0)
            break;
            
        if (is_whiteout(path_copy))
            return true;
    }
    
    return false;
}

/* Create a whiteout marker */
static int create_whiteout(const char *path) {
    char wh_path[PATH_MAX];
    snprintf(wh_path, PATH_MAX, "%s.wh", path);
    int fd = open(wh_path, O_CREAT | O_WRONLY, 0644);
    if (fd == -1) return -errno;
    close(fd);
    return 0;
}

bool exists_dir(const char *path) {
    struct stat st;
    if (lstat(path, &st) == -1) return false;
    /* Check if it's a directory and not whited out */
    return S_ISDIR(st.st_mode) && !is_whiteout(path);
}

enum layer { LAYER_NONE, LAYER_UPPER, LAYER_LOWER };

struct resolved {
    enum layer where;
    char real_path[PATH_MAX];
};

static struct resolved resolve_path(const char *relpath) {
    struct resolved r = {0};
    
    // try upper first
    char upath[PATH_MAX];
    upper_path(relpath, upath);
    
    // Check for whiteout first
    if (is_whiteout(upath)) {
        r.where = LAYER_NONE;
        return r;
    }
    
    if (access(upath, F_OK) == 0) {
        r.where = LAYER_UPPER;
        strcpy(r.real_path, upath);
        return r;
    }
    
    // else check lower if not whited out
    char lpath[PATH_MAX];
    lower_path(relpath, lpath);
    if (access(lpath, F_OK) == 0) {
        r.where = LAYER_LOWER;
        strcpy(r.real_path, lpath);
        return r;
    }
    
    r.where = LAYER_NONE;
    return r;
}

static void *baby_init(struct fuse_conn_info *conn,
			struct fuse_config *cfg) {
	(void) conn;
    
	cfg->kernel_cache = 1; // Let the kernel cache file data instead of repeatedly bothering my baby 
	return NULL;
}

/** Getattr syscall
 */
static int baby_getattr(const char *path, struct stat *stbuf,
			 struct fuse_file_info *fi) {
	(void) fi;

	syslog(LOG_INFO, "GETATTR CALL");
    char lpath[PATH_MAX], upath[PATH_MAX];
	lower_path(path, lpath); 
	upper_path(path, upath);
    
    /* Check for whiteouts first */
    if (is_path_whiteout(upath)) {
        syslog(LOG_INFO, "getattr: path or parent is whited out");
        return -ENOENT;
    }
    
    memset(stbuf, 0, sizeof(struct stat));
    if(lstat(upath, stbuf) == 0) {
        return 0;
    } 
	if(lstat(lpath, stbuf) == 0) {
		stbuf->st_mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
        return 0;
    }
    return -ENOENT;
}

static int baby_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi,
			 enum fuse_readdir_flags flags) {
	(void) offset;
	(void) fi;
	
	syslog(LOG_INFO, "READDIR CALL for path %s", path);
	char lpath[PATH_MAX], upath[PATH_MAX];
	lower_path(path, lpath);
	upper_path(path, upath);
    
    /* Check if directory itself or any parent is whited out by having a .wh file */
    if (is_path_whiteout(upath)) {
        syslog(LOG_INFO, "readdir: directory or parent is whited out");
        return -ENOENT;
    }

	/**
	 * Track entries we've seen in upper to avoid duplicates from lower,
	 * and track entries that have whiteout files to skip them in lower
	 */
	struct dir_name {
		char name[PATH_MAX];
		struct list_head list;
	};

	struct list_head seen_entries;
	struct list_head whiteout_entries;
	INIT_LIST_HEAD(&seen_entries);
	INIT_LIST_HEAD(&whiteout_entries);

	int fill_dir_plus = 0;

	/* First read upper directory */
	DIR* dp = opendir(upath);
	if(dp != NULL) {
		struct dirent *de;
		while ((de = readdir(dp)) != NULL) {
            /* Skip . and .. since they're handled automatically */
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                continue;
                
            /* Check if this is a .wh file */
            size_t len = strlen(de->d_name);
            if (len > 3 && strcmp(de->d_name + len - 3, ".wh") == 0) {
                /* This is a whiteout file - store the original name (without .wh) */
                char *orig_name = strdup(de->d_name);
                orig_name[len - 3] = '\0';
                struct dir_name *wh = malloc(sizeof(*wh));
                strncpy(wh->name, orig_name, PATH_MAX-1);
                wh->name[PATH_MAX-1] = '\0';
                list_add_tail(&wh->list, &whiteout_entries);
                free(orig_name);
                continue;
            }
            
            /* Regular file/directory in upper - add to seen list and show it */
            struct dir_name *d_name = malloc(sizeof(*d_name));
            strncpy(d_name->name, de->d_name, PATH_MAX-1);
            d_name->name[PATH_MAX-1] = '\0';
            list_add_tail(&d_name->list, &seen_entries);
            
            struct stat st;
            if (fill_dir_plus) {
                fstatat(dirfd(dp), de->d_name, &st, AT_SYMLINK_NOFOLLOW);
            } else {
                memset(&st, 0, sizeof(st));
                st.st_ino = de->d_ino;
                st.st_mode = de->d_type << 12;
            }
            if (filler(buf, de->d_name, &st, 0, fill_dir_plus))
                break;
		}
		closedir(dp);
	}
	/* Now read lower directory */
	dp = opendir(lpath);
	if(dp != NULL) {
		struct dirent *de;
		while ((de = readdir(dp)) != NULL) {
            /* Skip . and .. */
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                continue;
                
            /* Skip if this entry exists in upper layer */
            bool skip = false;
            struct dir_name* pos;
            list_for_each_entry(pos, &seen_entries, list) {
                if(strcmp(pos->name, de->d_name) == 0) {
                    skip = true;
                    break;
                }
            }
            if(skip) continue;
            
            /* Skip if there's a whiteout for this entry */
            list_for_each_entry(pos, &whiteout_entries, list) {
                if(strcmp(pos->name, de->d_name) == 0) {
                    syslog(LOG_INFO, "readdir: skipping whited out entry %s", de->d_name);
                    skip = true;
                    break;
                }
            }
            if(skip) continue;

            /* Entry from lower layer that isn't shadowed or whited out - show it */
            struct stat st;
            if (fill_dir_plus) {
                fstatat(dirfd(dp), de->d_name, &st, AT_SYMLINK_NOFOLLOW);
            } else {
                memset(&st, 0, sizeof(st));
                st.st_ino = de->d_ino;
                st.st_mode = de->d_type << 12;
            }
            if (filler(buf, de->d_name, &st, 0, fill_dir_plus))
                break;  
		}
		closedir(dp);
	}
	
	/* Clean up our tracking lists */
	FREE_LIST(&seen_entries, struct dir_name, list);
	FREE_LIST(&whiteout_entries, struct dir_name, list);
	return 0;
}

static int baby_create(const char *path, mode_t mode,
		      struct fuse_file_info *fi) {
	char upath[PATH_MAX];
	upper_path(path, upath);
    
    /* Check for whiteouts in parent directories */
    if (is_path_whiteout(upath)) {
        syslog(LOG_INFO, "baby_create: path or parent is whited out");
        return -ENOENT;
    }
    
	syslog(LOG_INFO, "baby_create: trying upper path %s with flags %d", upath, fi->flags);
	int res = open(upath, fi->flags, mode);
	if (res == -1)
		return -errno;

	fi->fh = res;
	return 0;
}

static int baby_open(const char *path, struct fuse_file_info *fi) {
	char lpath[PATH_MAX], upath[PATH_MAX];
	lower_path(path, lpath);
	upper_path(path, upath);
    
    /* First check if path or any parent is whited out */
    if (is_path_whiteout(upath)) {
        syslog(LOG_INFO, "baby_open: path or parent is whited out");
        return -ENOENT;
    }
    
	syslog(LOG_INFO, "baby_open: trying upper path %s with flags %d", upath, fi->flags);
	int res = open(upath, fi->flags);
	if (res != -1) {
		syslog(LOG_INFO, "baby_open: opened in upper successfully");
		fi->fh = res;
		return 0;
	}
	syslog(LOG_INFO, "baby_open: upper open failed with errno=%d", errno);

	/* If upper doesn't exist, lower exists, and caller requested write access,
	   perform a copy-up from lower -> upper before opening. */
	if (errno == ENOENT && access(lpath, F_OK) == 0 && ((fi->flags & O_ACCMODE) != O_RDONLY)) {
		syslog(LOG_INFO, "baby_open: attempting copy-up from %s to %s", lpath, upath);
		struct stat st; 
		TRY(lstat(lpath, &st));

		/* Ensure parent directories exist in upper */
		char upath_copy[PATH_MAX];
		strncpy(upath_copy, upath, PATH_MAX);
		upath_copy[PATH_MAX-1] = '\0';
		char *parent = dirname(upath_copy);

		/* mkdir -p style creation */
		char dir_acc[PATH_MAX];
		dir_acc[0] = '\0';
		const char *p = parent;
		/* If parent is absolute, start with '/' */
		if (p[0] == '/') {
			strncpy(dir_acc, "/", PATH_MAX);
		}
		char tmp[PATH_MAX];
		strncpy(tmp, parent, PATH_MAX);
		for (char *c = tmp + 1; *c; ++c) {
			if (*c == '/') {
				*c = '\0';
				if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
					TRY(-1);  /* Let TRY handle errno */
				}
				*c = '/';
			}
		}
		/* final mkdir for full parent */
		if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
			TRY(-1);  /* Let TRY handle errno */
		}

		/* Copy file contents */
		syslog(LOG_INFO, "baby_open: parent directories created, starting file copy");
		int fdl, fdu;
		TRY(fdl = open(lpath, O_RDONLY));
		
		if ((fdu = open(upath, O_WRONLY | O_CREAT | O_EXCL, st.st_mode & 0777)) == -1) {
			close(fdl);
			/* If file was created by a race, try opening it normally */
			if (errno == EEXIST) {
				res = open(upath, fi->flags);
				if (res != -1) {
					fi->fh = res;
					close(fdl);
					return 0;
				}
				/* fallthrough to try lower */
			}
			TRY(-1);  /* Let TRY handle errno */
		}

		ssize_t r;
		char buf[8192];
		while ((r = read(fdl, buf, sizeof(buf))) > 0) {
			ssize_t w = write(fdu, buf, r);
			if (w != r) {
				close(fdl); close(fdu);
				return -EIO;
			}
		}
		if (r == -1) {
			close(fdl); close(fdu);
			TRY(-1);
		}
		close(fdl);
		close(fdu);

		/* Now open the copy with requested flags */
		syslog(LOG_INFO, "baby_open: copy successful, opening new copy");
		TRY(res = open(upath, fi->flags));
		fi->fh = res;
		return 0;
	}

	/* fallback: try opening lower file */
	syslog(LOG_INFO, "baby_open: falling back to lower file %s", lpath);
	TRY(res = open(lpath, fi->flags));
	fi->fh = res;
	return 0;
}

static int baby_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi) {
    /* Don't check whiteouts here - open() already did */
	(void) path;
	ssize_t res = pread(fi->fh, buf, size, offset);
	return res == -1 ? -errno : res;
}

static int baby_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi) {
	syslog(LOG_INFO, "baby_write: path=%s size=%zu offset=%ld", path, size, offset);

	/* If we don't have a file handle, need to copy-up and open */
	if (fi == NULL) {
		char lpath[PATH_MAX], upath[PATH_MAX];
		lower_path(path, lpath);
		upper_path(path, upath);
        
        /* Check for whiteouts */
        if (is_path_whiteout(upath)) {
            syslog(LOG_INFO, "baby_write: path or parent is whited out");
            return -ENOENT;
        }
		
		/* First check if it exists in upper */
		int fd = open(upath, O_WRONLY);
		if (fd == -1 && errno == ENOENT) {
			/* Not in upper - check lower and copy up if needed */
			if (access(lpath, F_OK) == 0) {
				syslog(LOG_INFO, "baby_write: copying up for write");
				/* Get source file mode */
				struct stat st;
				TRY(lstat(lpath, &st));

				/* Create parent directories */
				char upath_copy[PATH_MAX];
				strncpy(upath_copy, upath, PATH_MAX);
				char *parent = dirname(upath_copy);
				char tmp[PATH_MAX];
				strncpy(tmp, parent, PATH_MAX);
				
				for (char *c = tmp + 1; *c; ++c) {
					if (*c == '/') {
						*c = '\0';
						if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
							TRY(-1);
						}
						*c = '/';
					}
				}
				if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
					TRY(-1);
				}

				/* Copy up the file */
				int fdl, fdu;
				TRY(fdl = open(lpath, O_RDONLY));
				TRY(fdu = open(upath, O_WRONLY | O_CREAT, st.st_mode & 0777));

				char copybuf[8192];
				ssize_t r;
				while ((r = read(fdl, copybuf, sizeof(copybuf))) > 0) {
					ssize_t w = write(fdu, copybuf, r);
					if (w != r) {
						close(fdl);
						close(fdu);
						return -EIO;
					}
				}
				if (r == -1) {
					close(fdl);
					close(fdu);
					TRY(-1);
				}
				close(fdl);
				close(fdu);

				/* Now open for writing */
				TRY(fd = open(upath, O_WRONLY));
			} else {
				/* Neither exists - create in upper */
				TRY(fd = open(upath, O_WRONLY | O_CREAT, 0666));
			}
		}
		
		/* Write the data */
		ssize_t res = pwrite(fd, buf, size, offset);
		close(fd);
		return res == -1 ? -errno : res;
	}

	/* We have a file handle from open() - just write to it */
	ssize_t res = pwrite(fi->fh, buf, size, offset);
	return res == -1 ? -errno : res;
}


static int baby_release(const char *path, struct fuse_file_info *fi) {
	(void) path;
	close(fi->fh);
	return 0;
}

static int baby_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    char lpath[PATH_MAX], upath[PATH_MAX];
    lower_path(path, lpath);
    upper_path(path, upath);
    
    syslog(LOG_INFO, "truncate: trying to truncate %s to size %ld", path, size);

    /* Check for whiteouts */
    if (is_path_whiteout(upath)) {
        syslog(LOG_INFO, "truncate: path or parent is whited out");
        return -ENOENT;
    }

    /* If file exists in upper, truncate it directly */
    if (access(upath, F_OK) == 0) {
        syslog(LOG_INFO, "truncate: truncating file in upper layer");
        return truncate(upath, size);
    }

    /* If file exists in lower, need to copy-up first */
    if (access(lpath, F_OK) == 0) {
        syslog(LOG_INFO, "truncate: copying up file from lower layer");
        
        /* Get source file mode */
        struct stat st;
        TRY(lstat(lpath, &st));

        /* Ensure parent directories exist in upper */
        char upath_copy[PATH_MAX];
        strncpy(upath_copy, upath, PATH_MAX);
        upath_copy[PATH_MAX-1] = '\0';
        char *parent = dirname(upath_copy);

        /* mkdir -p style creation */
        char tmp[PATH_MAX];
        strncpy(tmp, parent, PATH_MAX);
        for (char *c = tmp + 1; *c; ++c) {
            if (*c == '/') {
                *c = '\0';
                if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
                    TRY(-1);
                }
                *c = '/';
            }
        }
        if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
            TRY(-1);
        }

        /* Copy up the file */
        int fdl, fdu;
        TRY(fdl = open(lpath, O_RDONLY));
        TRY(fdu = open(upath, O_WRONLY | O_CREAT, st.st_mode & 0777));

        char buf[8192];
        ssize_t r;
        while ((r = read(fdl, buf, sizeof(buf))) > 0) {
            ssize_t w = write(fdu, buf, r);
            if (w != r) {
                close(fdl);
                close(fdu);
                return -EIO;
            }
        }
        if (r == -1) {
            close(fdl);
            close(fdu);
            TRY(-1);
        }
        close(fdl);
        close(fdu);

        /* Now truncate the copy */
        syslog(LOG_INFO, "truncate: truncating copied file");
        return truncate(upath, size);
    }

    return -ENOENT;
}

static int baby_mkdir(const char *path, mode_t mode) {
    char upath[PATH_MAX], lpath[PATH_MAX];
    lower_path(path, lpath);
    upper_path(path, upath);
    syslog(LOG_INFO, "mkdir: l=%s u=%s", lpath, upath);
    
    /* Check for whiteouts in parent directories */
    if (is_path_whiteout(upath)) {
        syslog(LOG_INFO, "mkdir: path or parent is whited out");
        return -ENOENT;
    }

    if (exists_dir(upath) || exists_dir(lpath)) {
        return -EEXIST;
    }

    TRY(mkdir(upath, mode));
    return 0;
}

static int baby_unlink(const char *path) {
    char upath[PATH_MAX], lpath[PATH_MAX];
    lower_path(path, lpath);
    upper_path(path, upath);
    
    syslog(LOG_INFO, "unlink: trying to remove %s (u=%s, l=%s)", path, upath, lpath);

    struct stat st;
    bool had_upper = false;
    
    /* Check if file exists in upper layer */
    if (lstat(upath, &st) == 0) {
        syslog(LOG_INFO, "unlink: removing file from upper layer");
        TRY(unlink(upath));
        had_upper = true;
    }

    /* If file exists in lower layer, create a whiteout in upper */
    if (lstat(lpath, &st) == 0) {
        syslog(LOG_INFO, "unlink: creating whiteout for lower layer file after %s", 
               had_upper ? "removing upper" : "checking lower");
        
        /* Ensure parent directories exist */
        char upath_copy[PATH_MAX];
        strncpy(upath_copy, upath, PATH_MAX);
        char *parent = dirname(upath_copy);
        
        if (access(parent, F_OK) != 0) {
            char tmp[PATH_MAX];
            strncpy(tmp, parent, PATH_MAX);
            for (char *c = tmp + 1; *c; ++c) {
                if (*c == '/') {
                    *c = '\0';
                    if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
                        return -errno;
                    }
                    *c = '/';
                }
            }
            if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
                return -errno;
            }
        }
        
        /* Create the whiteout marker */
        return create_whiteout(upath);
    }

    return had_upper ? 0 : -ENOENT;
}

static int baby_rename(const char *from, const char *to) {
    char from_upath[PATH_MAX], from_lpath[PATH_MAX];
    char to_upath[PATH_MAX], to_lpath[PATH_MAX];
    lower_path(from, from_lpath);
    upper_path(from, from_upath);
    lower_path(to, to_lpath);
    upper_path(to, to_upath);
    
    syslog(LOG_INFO, "rename: trying to rename %s to %s", from, to);

    /* Check for whiteouts in source or destination */
    if (is_path_whiteout(from_upath)) {
        syslog(LOG_INFO, "rename: source path or parent is whited out");
        return -ENOENT;
    }
    if (is_path_whiteout(to_upath)) {
        syslog(LOG_INFO, "rename: destination path or parent is whited out");
        return -ENOENT;
    }

    struct stat st;
    bool source_in_upper = false;
    bool need_whiteout = false;

    /* First check if source exists in upper layer */
    if (lstat(from_upath, &st) == 0) {
        source_in_upper = true;
    } else if (lstat(from_lpath, &st) == 0) {
        /* Source exists in lower - need to copy up */
        need_whiteout = true;

        /* Ensure parent directories exist for source copy-up */
        char from_upath_copy[PATH_MAX];
        strncpy(from_upath_copy, from_upath, PATH_MAX);
        from_upath_copy[PATH_MAX-1] = '\0';
        char *parent = dirname(from_upath_copy);

        char tmp[PATH_MAX];
        strncpy(tmp, parent, PATH_MAX);
        for (char *c = tmp + 1; *c; ++c) {
            if (*c == '/') {
                *c = '\0';
                if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
                    TRY(-1);
                }
                *c = '/';
            }
        }
        if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
            TRY(-1);
        }

        /* Copy up the source file */
        int fdl, fdu;
        TRY(fdl = open(from_lpath, O_RDONLY));
        TRY(fdu = open(from_upath, O_WRONLY | O_CREAT, st.st_mode & 0777));

        char buf[8192];
        ssize_t r;
        while ((r = read(fdl, buf, sizeof(buf))) > 0) {
            ssize_t w = write(fdu, buf, r);
            if (w != r) {
                close(fdl);
                close(fdu);
                return -EIO;
            }
        }
        if (r == -1) {
            close(fdl);
            close(fdu);
            TRY(-1);
        }
        close(fdl);
        close(fdu);
        source_in_upper = true;
    } else {
        return -ENOENT;
    }

    /* Create parent directories for destination if needed */
    char to_upath_copy[PATH_MAX];
    strncpy(to_upath_copy, to_upath, PATH_MAX);
    to_upath_copy[PATH_MAX-1] = '\0';
    char *parent = dirname(to_upath_copy);

    char tmp[PATH_MAX];
    strncpy(tmp, parent, PATH_MAX);
    for (char *c = tmp + 1; *c; ++c) {
        if (*c == '/') {
            *c = '\0';
            if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
                TRY(-1);
            }
            *c = '/';
        }
    }
    if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
        TRY(-1);
    }

    /* If destination exists in upper or lower, we might need to handle replacement */
    if (lstat(to_upath, &st) == 0 || lstat(to_lpath, &st) == 0) {
        /* If destination is a directory, it must be empty */
        if (S_ISDIR(st.st_mode)) {
            DIR *dp = opendir(to_upath);
            if (dp != NULL) {
                struct dirent *de;
                bool empty = true;
                while ((de = readdir(dp)) != NULL) {
                    if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) {
                        empty = false;
                        break;
                    }
                }
                closedir(dp);
                if (!empty) {
                    return -ENOTEMPTY;
                }
            }
        }
        
        /* Remove existing destination in upper layer */
        if (lstat(to_upath, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                TRY(rmdir(to_upath));
            } else {
                TRY(unlink(to_upath));
            }
        }
    }

    /* Now we can do the actual rename in upper layer */
    TRY(rename(from_upath, to_upath));

    /* If source was in lower layer, create a whiteout for it */
    if (need_whiteout) {
        return create_whiteout(from_upath);
    }

    return 0;
}

static int baby_rmdir(const char *path) {
    char upath[PATH_MAX], lpath[PATH_MAX];
    lower_path(path, lpath);
    upper_path(path, upath);
    
    syslog(LOG_INFO, "rmdir: trying to remove %s (u=%s, l=%s)", path, upath, lpath);

    /* Check for logical emptiness first */
    DIR *dp;
    struct dirent *de;
    bool has_content = false;

    /* Check upper dir first */
    dp = opendir(upath);
    if (dp != NULL) {
        while ((de = readdir(dp)) != NULL) {
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                continue;
                
            /* If it's not a whiteout file, dir is not empty */
            char full_path[PATH_MAX];
            size_t uplen = strlen(upath);
            size_t namelen = strlen(de->d_name);
            if (uplen + namelen + 2 > PATH_MAX) {
                syslog(LOG_ERR, "Path too long in rmdir check");
                continue;
            }
            snprintf(full_path, PATH_MAX, "%s/%s", upath, de->d_name);
            if (!is_whiteout(full_path)) {
                has_content = true;
                break;
            }
        }
        closedir(dp);
    }

    /* If upper is all whiteouts, check lower */
    if (!has_content && exists_dir(lpath)) {
        dp = opendir(lpath);
        if (dp != NULL) {
            while ((de = readdir(dp)) != NULL) {
                if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                    continue;

                /* Check if this entry is whited out in upper */
                char wh_check[PATH_MAX];
                size_t uplen = strlen(upath);
                size_t namelen = strlen(de->d_name);
                if (uplen + namelen + 2 > PATH_MAX) {
                    syslog(LOG_ERR, "Path too long in whiteout check");
                    continue;
                }
                snprintf(wh_check, PATH_MAX, "%s/%s", upath, de->d_name);
                if (!is_whiteout(wh_check)) {
                    has_content = true;
                    break;
                }
            }
            closedir(dp);
        }
    }

    if (has_content) {
        syslog(LOG_INFO, "rmdir: directory not empty");
        return -ENOTEMPTY;
    }

    /* Directory exists in upper - remove it and its whiteouts */
    bool had_upper = false;
    if (exists_dir(upath)) {
        syslog(LOG_INFO, "rmdir: removing directory and whiteouts from upper layer");
        had_upper = true;
        
        /* First remove all whiteout files */
        dp = opendir(upath);
        if (dp != NULL) {
            while ((de = readdir(dp)) != NULL) {
                if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                    continue;
                char full_path[PATH_MAX];
                size_t uplen = strlen(upath);
                size_t namelen = strlen(de->d_name);
                if (uplen + namelen + 2 > PATH_MAX) {
                    syslog(LOG_ERR, "Path too long in cleanup");
                    continue;
                }
                snprintf(full_path, PATH_MAX, "%s/%s", upath, de->d_name);
                unlink(full_path);  /* Ignore errors, just try to clean up */
            }
            closedir(dp);
        }
        
        TRY(rmdir(upath));
    }

    /* If directory existed in upper AND there's one in lower, or just exists in lower,
       we need to create a whiteout */
    if (exists_dir(lpath)) {
        syslog(LOG_INFO, "rmdir: creating whiteout for lower layer directory after %s", 
               had_upper ? "removing upper" : "checking lower");
        
        /* Ensure parent directories exist */
        char upath_copy[PATH_MAX];
        strncpy(upath_copy, upath, PATH_MAX);
        char *parent = dirname(upath_copy);
        
        if (access(parent, F_OK) != 0) {
            char tmp[PATH_MAX];
            strncpy(tmp, parent, PATH_MAX);
            for (char *c = tmp + 1; *c; ++c) {
                if (*c == '/') {
                    *c = '\0';
                    if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
                        return -errno;
                    }
                    *c = '/';
                }
            }
            if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
                return -errno;
            }
        }
        
        /* Create the whiteout marker */
        return create_whiteout(upath);
    }

    return had_upper ? 0 : -ENOENT;

    /* If it exists in lower layer, create a whiteout in upper */
    if (exists_dir(lpath)) {
        syslog(LOG_INFO, "rmdir: creating whiteout for lower layer directory");
        
        /* Ensure parent directories exist */
        char upath_copy[PATH_MAX];
        strncpy(upath_copy, upath, PATH_MAX);
        char *parent = dirname(upath_copy);
        
        if (access(parent, F_OK) != 0) {
            char tmp[PATH_MAX];
            strncpy(tmp, parent, PATH_MAX);
            for (char *c = tmp + 1; *c; ++c) {
                if (*c == '/') {
                    *c = '\0';
                    if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
                        return -errno;
                    }
                    *c = '/';
                }
            }
            if (mkdir(tmp, 0755) == -1 && errno != EEXIST) {
                return -errno;
            }
        }
        
        /* Create the whiteout marker */
        return create_whiteout(upath);
    }

    return -ENOENT;
}

/**
 * Statx syscall
 */
#ifdef HAVE_STATX //WSL seems to have statx
static int baby_statx(const char *path, int flags, int mask, struct statx *stxbuf,
		     struct fuse_file_info *fi) {
	int fd = -1;

	if (fi)
		fd = fi->fh;

	TRY(statx(fd, path, flags | AT_SYMLINK_NOFOLLOW, mask, stxbuf));
	return 0;
}

#endif

/**
 * This is the operations table that FUSE refers to for performing syscalls
 */
static const struct fuse_operations operations = {
    .init = baby_init,
    .getattr = baby_getattr,
    .readdir = baby_readdir,
	.open = baby_open, 
	.create = baby_create,
	.release = baby_release,
	.rmdir = baby_rmdir,
	.unlink = baby_unlink,
	.read = baby_read,
	.write = baby_write,
	.mkdir = baby_mkdir,
    .truncate = baby_truncate,
    .rename = baby_rename
};

static void show_help(const char *progname) {
	printf("usage: %s [options] <mountpoint>\n\n", progname);
	printf("File-system specific options:\n"
           "    --lower=<s>             Use path s as the lower directory"
           "    --upper=<s>             Use path s as the upper directory"
	       "\n");
}

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    
	/* Parse options */
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
    return 1;

	/* When --help is specified, first print our own file-system
    specific help text, then signal fuse_main to show
    additional help (by adding `--help` to the options again)
    without usage: line (by setting argv[0] to the empty
    string) */
	if (options.show_help) {
        show_help(argv[0]);
		assert(fuse_opt_add_arg(&args, "--help") == 0);
		args.argv[0][0] = '\0';
	}

    int ret;
	ret = fuse_main(args.argc, args.argv, &operations, NULL);
	fuse_opt_free_args(&args);
	return ret;
}