# nfs
we should also add several lines in include/linux/nfs_fs.h:

extern int nfs3_register_sysctl(void);

extern int nfs3_unregister_sysctl(void);

extern int nfs_zql_control;
