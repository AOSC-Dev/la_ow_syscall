extern int (*p_vfs_fstatat)(int dfd, const char __user *filename,
                              struct kstat *stat, int flags);
extern int (*p_vfs_fstat)(int fd, struct kstat *stat);
