/*
 * linux/fs/nfs/sysctl.c
 *
 * Sysctl interface to NFS parameters
 */
#include <linux/types.h>
#include <linux/linkage.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/sysctl.h>
#include <linux/module.h>
#include <linux/nfs_fs.h>

static struct ctl_table_header *nfs3_callback_sysctl_table;

static struct ctl_table nfs3_cb_sysctls[] = {
	{
		.procname	= "nfs_zql_control",
		.data		= &nfs_zql_control,
		.maxlen		= sizeof(nfs_zql_control),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static struct ctl_table nfs3_cb_sysctl_dir[] = {
	{
		.procname = "nfs",
		.mode = 0555,
		.child = nfs3_cb_sysctls,
	},
	{ }
};

static struct ctl_table nfs3_cb_sysctl_root[] = {
	{
		.procname = "fs",
		.mode = 0555,
		.child = nfs3_cb_sysctl_dir,
	},
	{ }
};

int nfs3_register_sysctl(void)
{
	nfs3_callback_sysctl_table = register_sysctl_table(nfs3_cb_sysctl_root);
	if (nfs3_callback_sysctl_table == NULL)
		return -ENOMEM;
	return 0;
}

void nfs3_unregister_sysctl(void)
{
	unregister_sysctl_table(nfs3_callback_sysctl_table);
	nfs3_callback_sysctl_table = NULL;
}
