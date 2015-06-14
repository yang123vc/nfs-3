/*
 *  linux/fs/nfs/nfs3proc.c
 *
 *  Client-side NFSv3 procedures stubs.
 *
 *  Copyright (C) 1997, Olaf Kirch
 */

#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/sunrpc/clnt.h>
#include <linux/slab.h>
#include <linux/nfs.h>
#include <linux/nfs3.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_page.h>
#include <linux/lockd/bind.h>
#include <linux/nfs_mount.h>
#include <linux/freezer.h>
#include <linux/xattr.h>
#include <linux/delay.h>
#include <linux/sunrpc/addr.h>
#include <linux/spinlock.h>

#include "iostat.h"
#include "internal.h"
#include "nfs3_fs.h"
#include "nfs.h"

#define NFSDBG_FACILITY		NFSDBG_PROC

int nfs_zql_control = 10;
static DEFINE_SPINLOCK(zql_switch_status);
static int switch_status = 0;

static struct nfs_parsed_mount_data *nfs_alloc_parsed_mount_data(void)
{
	struct nfs_parsed_mount_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data) {
		data->acregmin		= NFS_DEF_ACREGMIN;
		data->acregmax		= NFS_DEF_ACREGMAX;
		data->acdirmin		= NFS_DEF_ACDIRMIN;
		data->acdirmax		= NFS_DEF_ACDIRMAX;
		data->mount_server.port	= NFS_UNSPEC_PORT;
		data->nfs_server.port	= NFS_UNSPEC_PORT;
		data->nfs_server.protocol = XPRT_TRANSPORT_TCP;
		data->selected_flavor	= RPC_AUTH_MAXFLAVOR;
		data->minorversion	= 0;
		data->need_mount	= true;
		data->net		= current->nsproxy->net_ns;
		security_init_mnt_opts(&data->lsm_opts);
	}
	return data;
}

static void nfs_free_parsed_mount_data(struct nfs_parsed_mount_data *data)
{
	if (data) {
		kfree(data->client_address);
		kfree(data->mount_server.hostname);
		kfree(data->nfs_server.export_path);
		kfree(data->nfs_server.hostname);
		kfree(data->fscache_uniq);
		security_free_mnt_opts(&data->lsm_opts);
		kfree(data);
	}
}

static int nfs_verify_server_address(struct sockaddr *addr)
{
	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sa = (struct sockaddr_in *)addr;
		return sa->sin_addr.s_addr != htonl(INADDR_ANY);
	}
	case AF_INET6: {
		struct in6_addr *sa = &((struct sockaddr_in6 *)addr)->sin6_addr;
		dfprintk(MOUNT, "zql: nfs_verify_server_address AF_INET6 error\n");
		return !ipv6_addr_any(sa);
	}
	}

	dfprintk(MOUNT, "NFS: Invalid IP address specified\n");
	return 0;
}

static void nfs_validate_transport_protocol(struct nfs_parsed_mount_data *mnt)
{
	switch (mnt->nfs_server.protocol) {
	case XPRT_TRANSPORT_UDP:
	case XPRT_TRANSPORT_TCP:
	case XPRT_TRANSPORT_RDMA:
		break;
	default:
		mnt->nfs_server.protocol = XPRT_TRANSPORT_TCP;
	}
}

static void nfs_set_mount_transport_protocol(struct nfs_parsed_mount_data *mnt)
{
	nfs_validate_transport_protocol(mnt);

	if (mnt->mount_server.protocol == XPRT_TRANSPORT_UDP ||
	    mnt->mount_server.protocol == XPRT_TRANSPORT_TCP)
			return;
	switch (mnt->nfs_server.protocol) {
	case XPRT_TRANSPORT_UDP:
		mnt->mount_server.protocol = XPRT_TRANSPORT_UDP;
		break;
	case XPRT_TRANSPORT_TCP:
	case XPRT_TRANSPORT_RDMA:
		mnt->mount_server.protocol = XPRT_TRANSPORT_TCP;
	}
}

static void nfs_set_port(struct sockaddr *sap, int *port,
				 const unsigned short default_port)
{
	if (*port == NFS_UNSPEC_PORT)
		*port = default_port;

	rpc_set_port(sap, *port);
}

static int migrate_nfs_validate_text_mount_data168(/*void *options,*/
					struct nfs_parsed_mount_data *args/*,
					const char *dev_name*/)
{
	int port = 0;
	//int max_namelen = PAGE_SIZE;
	//int max_pathlen = NFS_MAXPATHLEN;
	struct sockaddr *sap = (struct sockaddr *)&args->nfs_server.address;
	char mnt_addr[] = "162.105.146.168";
	char mnt_hostname[] = "162.105.146.168";
	char mnt_dirpath[] = "/home/disk1";

	//if (nfs_parse_mount_options((char *)options, args) == 0)
	//	return -EINVAL;
	/* security_sb_parse_opts_str() */
	/* address */
	args->nfs_server.addrlen = 
		rpc_pton(args->net, mnt_addr, strlen(mnt_addr),
			(struct sockaddr *)
			&args->nfs_server.address,
			sizeof(args->nfs_server.address));
	if (args->nfs_server.addrlen == 0)
		dfprintk(MOUNT, "zql: invalid address\n");
	/* version vers=3 */
	args->flags |= NFS_MOUNT_VER3;
	args->version = 3;
	/* proto=tcp, Opt_xprt_tcp */
	args->flags |= NFS_MOUNT_TCP;
	args->nfs_server.protocol = XPRT_TRANSPORT_TCP;
	/* mountvers=3 */
	args->mount_server.version = 3;
	/* mountproto=udp */
	args->mount_server.protocol = XPRT_TRANSPORT_UDP;
	/* mountport=20048 */
	args->mount_server.port = 20048;

	if (!nfs_verify_server_address(sap))
		goto out_no_address;

	if (args->version == 4) {
		dfprintk(MOUNT, "zql: version 4 error not supported\n");
	} else
		nfs_set_mount_transport_protocol(args);

	nfs_set_port(sap, &args->nfs_server.port, port);

	//return nfs_parse_devname(dev_name,
	//			   &args->nfs_server.hostname,
	//			   max_namelen,
	//			   &args->nfs_server.export_path,
	//			   max_pathlen);
	args->nfs_server.hostname = kstrndup(mnt_hostname, strlen(mnt_hostname), GFP_KERNEL);
	args->nfs_server.export_path = kstrndup(mnt_dirpath, strlen(mnt_dirpath), GFP_KERNEL);
	return 0;

out_no_address:
	dfprintk(MOUNT, "zql: NFS: mount program didn't pass remote address\n");
	return -EINVAL;
}

static int migrate_nfs_validate_text_mount_data169(/*void *options,*/
					struct nfs_parsed_mount_data *args/*,
					const char *dev_name*/)
{
	int port = 0;
	//int max_namelen = PAGE_SIZE;
	//int max_pathlen = NFS_MAXPATHLEN;
	struct sockaddr *sap = (struct sockaddr *)&args->nfs_server.address;
	char mnt_addr[] = "162.105.146.169";
	char mnt_hostname[] = "162.105.146.169";
	char mnt_dirpath[] = "/home/disk1";

	//if (nfs_parse_mount_options((char *)options, args) == 0)
	//	return -EINVAL;
	/* security_sb_parse_opts_str() */
	/* address */
	args->nfs_server.addrlen = 
		rpc_pton(args->net, mnt_addr, strlen(mnt_addr),
			(struct sockaddr *)
			&args->nfs_server.address,
			sizeof(args->nfs_server.address));
	if (args->nfs_server.addrlen == 0)
		dfprintk(MOUNT, "zql: invalid address\n");
	/* version vers=3 */
	args->flags |= NFS_MOUNT_VER3;
	args->version = 3;
	/* proto=tcp, Opt_xprt_tcp */
	args->flags |= NFS_MOUNT_TCP;
	args->nfs_server.protocol = XPRT_TRANSPORT_TCP;
	/* mountvers=3 */
	args->mount_server.version = 3;
	/* mountproto=udp */
	args->mount_server.protocol = XPRT_TRANSPORT_UDP;
	/* mountport=20048 */
	args->mount_server.port = 20048;

	if (!nfs_verify_server_address(sap))
		goto out_no_address;

	if (args->version == 4) {
		dfprintk(MOUNT, "zql: version 4 error not supported\n");
	} else
		nfs_set_mount_transport_protocol(args);

	nfs_set_port(sap, &args->nfs_server.port, port);

	//return nfs_parse_devname(dev_name,
	//			   &args->nfs_server.hostname,
	//			   max_namelen,
	//			   &args->nfs_server.export_path,
	//			   max_pathlen);
	args->nfs_server.hostname = kstrndup(mnt_hostname, strlen(mnt_hostname), GFP_KERNEL);
	args->nfs_server.export_path = kstrndup(mnt_dirpath, strlen(mnt_dirpath), GFP_KERNEL);
	return 0;

out_no_address:
	dfprintk(MOUNT, "zql: NFS: mount program didn't pass remote address\n");
	return -EINVAL;
}

static int migrate_nfs_set_client(struct nfs_server *server,
					const char *hostname,
					const struct sockaddr *addr,
					const size_t addrlen,
					const char *ip_addr,
					rpc_authflavor_t authflavour,
					int proto, const struct rpc_timeout *timeparms,
					u32 minorversion, struct net *net)
{
	struct nfs_client_initdata cl_init = {
		.hostname = hostname,
		.addr = addr,
		.addrlen = addrlen,
		.nfs_mod = &nfs_v3,
		.proto = proto,
		.minorversion = minorversion,
		.net = net,
	};
	struct nfs_client *clp;
	int error;

	dfprintk(MOUNT, "zql: migrate_nfs_set_client\n");

	if (server->flags & NFS_MOUNT_NORESVPORT)
		set_bit(NFS_CS_NORESVPORT, &cl_init.init_flags);
	//if (server->options & NFS_OPTION_MIGRATION)
		//set_bit(NFS_CS_MIGRATION, &cl_init.init_flags);
	
	clp = nfs_get_client(&cl_init, timeparms, ip_addr, authflavour);
	if (IS_ERR(clp)) {
		error = PTR_ERR(clp);
		dfprintk(MOUNT, "zql: nfs_get_client error\n");
		goto error;
	}

	set_bit(NFS_CS_CHECK_LEASE_TIME, &clp->cl_res_state);

	server->nfs_client = clp;
	dfprintk(MOUNT, "zql: <-- migrate_nfs_set_client() = 0 [new %p]\n", clp);
	return 0;
error:
	dfprintk(MOUNT, "zql: <-- migrate_nfs_set_client() = xerror %d\n", error);
	return error;
}

static void zql_control_test(struct nfs_server *server);

/* A wrapper to handle the EJUKEBOX error messages */
static int
nfs3_rpc_wrapper(struct rpc_clnt *clnt, struct rpc_message *msg, int flags)
{
	int res;
	do {
		res = rpc_call_sync(clnt, msg, flags);
		if (res != -EJUKEBOX)
			break;
		freezable_schedule_timeout_killable_unsafe(NFS_JUKEBOX_RETRY_TIME);
		res = -ERESTARTSYS;
	} while (!fatal_signal_pending(current));
	return res;
}

#define rpc_call_sync(clnt, msg, flags)	nfs3_rpc_wrapper(clnt, msg, flags)

static int
nfs3_async_handle_jukebox(struct rpc_task *task, struct inode *inode)
{
	if (task->tk_status != -EJUKEBOX)
		return 0;
	if (task->tk_status == -EJUKEBOX)
		nfs_inc_stats(inode, NFSIOS_DELAY);
	task->tk_status = 0;
	rpc_restart_call(task);
	rpc_delay(task, NFS_JUKEBOX_RETRY_TIME);
	return 1;
}

static int
do_proc_get_root(struct rpc_clnt *client, struct nfs_fh *fhandle,
		 struct nfs_fsinfo *info)
{
	struct rpc_message msg = {
		.rpc_proc	= &nfs3_procedures[NFS3PROC_FSINFO],
		.rpc_argp	= fhandle,
		.rpc_resp	= info,
	};
	int	status;

	dprintk("%s: call  fsinfo\n", __func__);
	nfs_fattr_init(info->fattr);
	status = rpc_call_sync(client, &msg, 0);
	dprintk("%s: reply fsinfo: %d\n", __func__, status);
	if (status == 0 && !(info->fattr->valid & NFS_ATTR_FATTR)) {
		msg.rpc_proc = &nfs3_procedures[NFS3PROC_GETATTR];
		msg.rpc_resp = info->fattr;
		status = rpc_call_sync(client, &msg, 0);
		dprintk("%s: reply getattr: %d\n", __func__, status);
	}
	return status;
}

/*
 * Bare-bones access to getattr: this is for nfs_get_root/nfs_get_sb
 */
static int
nfs3_proc_get_root(struct nfs_server *server, struct nfs_fh *fhandle,
		   struct nfs_fsinfo *info)
{
	int	status;

	zql_control_test(server);
	status = do_proc_get_root(server->client, fhandle, info);
	if (status && server->nfs_client->cl_rpcclient != server->client)
		status = do_proc_get_root(server->nfs_client->cl_rpcclient, fhandle, info);
	return status;
}

/*
 * One function for each procedure in the NFS protocol.
 */
static int
nfs3_proc_getattr(struct nfs_server *server, struct nfs_fh *fhandle,
		struct nfs_fattr *fattr, struct nfs4_label *label)
{
	struct rpc_message msg = {
		.rpc_proc	= &nfs3_procedures[NFS3PROC_GETATTR],
		.rpc_argp	= fhandle,
		.rpc_resp	= fattr,
	};
	int	status;

	dprintk("NFS call  getattr\n");
	zql_control_test(server);
	nfs_fattr_init(fattr);
	status = rpc_call_sync(server->client, &msg, 0);
	dprintk("NFS reply getattr: %d\n", status);
	return status;
}

static int
nfs3_proc_setattr(struct dentry *dentry, struct nfs_fattr *fattr,
			struct iattr *sattr)
{
	struct inode *inode = dentry->d_inode;
	struct nfs3_sattrargs	arg = {
		.fh		= NFS_FH(inode),
		.sattr		= sattr,
	};
	struct rpc_message msg = {
		.rpc_proc	= &nfs3_procedures[NFS3PROC_SETATTR],
		.rpc_argp	= &arg,
		.rpc_resp	= fattr,
	};
	int	status;

	dprintk("NFS call  setattr\n");
	if (sattr->ia_valid & ATTR_FILE)
		msg.rpc_cred = nfs_file_cred(sattr->ia_file);
	nfs_fattr_init(fattr);
	zql_control_test(NFS_SERVER(inode));
	status = rpc_call_sync(NFS_CLIENT(inode), &msg, 0);
	if (status == 0)
		nfs_setattr_update_inode(inode, sattr, fattr);
	dprintk("NFS reply setattr: %d\n", status);
	return status;
}

static int
nfs3_proc_lookup(struct inode *dir, struct qstr *name,
		 struct nfs_fh *fhandle, struct nfs_fattr *fattr,
		 struct nfs4_label *label)
{
	struct nfs3_diropargs	arg = {
		.fh		= NFS_FH(dir),
		.name		= name->name,
		.len		= name->len
	};
	struct nfs3_diropres	res = {
		.fh		= fhandle,
		.fattr		= fattr
	};
	struct rpc_message msg = {
		.rpc_proc	= &nfs3_procedures[NFS3PROC_LOOKUP],
		.rpc_argp	= &arg,
		.rpc_resp	= &res,
	};
	int			status;

	dprintk("NFS call  lookup %s\n", name->name);
	res.dir_attr = nfs_alloc_fattr();
	if (res.dir_attr == NULL)
		return -ENOMEM;

	nfs_fattr_init(fattr);
	zql_control_test(NFS_SERVER(dir));
	status = rpc_call_sync(NFS_CLIENT(dir), &msg, 0);
	nfs_refresh_inode(dir, res.dir_attr);
	if (status >= 0 && !(fattr->valid & NFS_ATTR_FATTR)) {
		msg.rpc_proc = &nfs3_procedures[NFS3PROC_GETATTR];
		msg.rpc_argp = fhandle;
		msg.rpc_resp = fattr;
		status = rpc_call_sync(NFS_CLIENT(dir), &msg, 0);
	}
	nfs_free_fattr(res.dir_attr);
	dprintk("NFS reply lookup: %d\n", status);
	return status;
}

static int nfs3_proc_access(struct inode *inode, struct nfs_access_entry *entry)
{
	struct nfs3_accessargs	arg = {
		.fh		= NFS_FH(inode),
	};
	struct nfs3_accessres	res;
	struct rpc_message msg = {
		.rpc_proc	= &nfs3_procedures[NFS3PROC_ACCESS],
		.rpc_argp	= &arg,
		.rpc_resp	= &res,
		.rpc_cred	= entry->cred,
	};
	int mode = entry->mask;
	int status = -ENOMEM;

	dprintk("NFS call  access\n");

	if (mode & MAY_READ)
		arg.access |= NFS3_ACCESS_READ;
	if (S_ISDIR(inode->i_mode)) {
		if (mode & MAY_WRITE)
			arg.access |= NFS3_ACCESS_MODIFY | NFS3_ACCESS_EXTEND | NFS3_ACCESS_DELETE;
		if (mode & MAY_EXEC)
			arg.access |= NFS3_ACCESS_LOOKUP;
	} else {
		if (mode & MAY_WRITE)
			arg.access |= NFS3_ACCESS_MODIFY | NFS3_ACCESS_EXTEND;
		if (mode & MAY_EXEC)
			arg.access |= NFS3_ACCESS_EXECUTE;
	}

	res.fattr = nfs_alloc_fattr();
	if (res.fattr == NULL)
		goto out;

	zql_control_test(NFS_SERVER(inode));
	status = rpc_call_sync(NFS_CLIENT(inode), &msg, 0);
	nfs_refresh_inode(inode, res.fattr);
	if (status == 0) {
		entry->mask = 0;
		if (res.access & NFS3_ACCESS_READ)
			entry->mask |= MAY_READ;
		if (res.access & (NFS3_ACCESS_MODIFY | NFS3_ACCESS_EXTEND | NFS3_ACCESS_DELETE))
			entry->mask |= MAY_WRITE;
		if (res.access & (NFS3_ACCESS_LOOKUP|NFS3_ACCESS_EXECUTE))
			entry->mask |= MAY_EXEC;
	}
	nfs_free_fattr(res.fattr);
out:
	dprintk("NFS reply access: %d\n", status);
	return status;
}

static int nfs3_proc_readlink(struct inode *inode, struct page *page,
		unsigned int pgbase, unsigned int pglen)
{
	struct nfs_fattr	*fattr;
	struct nfs3_readlinkargs args = {
		.fh		= NFS_FH(inode),
		.pgbase		= pgbase,
		.pglen		= pglen,
		.pages		= &page
	};
	struct rpc_message msg = {
		.rpc_proc	= &nfs3_procedures[NFS3PROC_READLINK],
		.rpc_argp	= &args,
	};
	int status = -ENOMEM;

	dprintk("NFS call  readlink\n");
	fattr = nfs_alloc_fattr();
	if (fattr == NULL)
		goto out;
	msg.rpc_resp = fattr;

	zql_control_test(NFS_SERVER(inode));
	status = rpc_call_sync(NFS_CLIENT(inode), &msg, 0);
	nfs_refresh_inode(inode, fattr);
	nfs_free_fattr(fattr);
out:
	dprintk("NFS reply readlink: %d\n", status);
	return status;
}

struct nfs3_createdata {
	struct rpc_message msg;
	union {
		struct nfs3_createargs create;
		struct nfs3_mkdirargs mkdir;
		struct nfs3_symlinkargs symlink;
		struct nfs3_mknodargs mknod;
	} arg;
	struct nfs3_diropres res;
	struct nfs_fh fh;
	struct nfs_fattr fattr;
	struct nfs_fattr dir_attr;
};

static struct nfs3_createdata *nfs3_alloc_createdata(void)
{
	struct nfs3_createdata *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data != NULL) {
		data->msg.rpc_argp = &data->arg;
		data->msg.rpc_resp = &data->res;
		data->res.fh = &data->fh;
		data->res.fattr = &data->fattr;
		data->res.dir_attr = &data->dir_attr;
		nfs_fattr_init(data->res.fattr);
		nfs_fattr_init(data->res.dir_attr);
	}
	return data;
}

static int nfs3_do_create(struct inode *dir, struct dentry *dentry, struct nfs3_createdata *data)
{
	int status;

	status = rpc_call_sync(NFS_CLIENT(dir), &data->msg, 0);
	nfs_post_op_update_inode(dir, data->res.dir_attr);
	if (status == 0)
		status = nfs_instantiate(dentry, data->res.fh, data->res.fattr, NULL);
	return status;
}

static void nfs3_free_createdata(struct nfs3_createdata *data)
{
	kfree(data);
}

/*
 * Create a regular file.
 */
static int
nfs3_proc_create(struct inode *dir, struct dentry *dentry, struct iattr *sattr,
		 int flags)
{
	struct posix_acl *default_acl, *acl;
	struct nfs3_createdata *data;
	int status = -ENOMEM;

	dprintk("NFS call  create %pd\n", dentry);

	data = nfs3_alloc_createdata();
	if (data == NULL)
		goto out;

	data->msg.rpc_proc = &nfs3_procedures[NFS3PROC_CREATE];
	data->arg.create.fh = NFS_FH(dir);
	data->arg.create.name = dentry->d_name.name;
	data->arg.create.len = dentry->d_name.len;
	data->arg.create.sattr = sattr;

	data->arg.create.createmode = NFS3_CREATE_UNCHECKED;
	if (flags & O_EXCL) {
		data->arg.create.createmode  = NFS3_CREATE_EXCLUSIVE;
		data->arg.create.verifier[0] = cpu_to_be32(jiffies);
		data->arg.create.verifier[1] = cpu_to_be32(current->pid);
	}

	status = posix_acl_create(dir, &sattr->ia_mode, &default_acl, &acl);
	if (status)
		goto out;

	zql_control_test(NFS_SERVER(dir));
	for (;;) {
		status = nfs3_do_create(dir, dentry, data);

		if (status != -ENOTSUPP)
			break;
		/* If the server doesn't support the exclusive creation
		 * semantics, try again with simple 'guarded' mode. */
		switch (data->arg.create.createmode) {
			case NFS3_CREATE_EXCLUSIVE:
				data->arg.create.createmode = NFS3_CREATE_GUARDED;
				break;

			case NFS3_CREATE_GUARDED:
				data->arg.create.createmode = NFS3_CREATE_UNCHECKED;
				break;

			case NFS3_CREATE_UNCHECKED:
				goto out;
		}
		nfs_fattr_init(data->res.dir_attr);
		nfs_fattr_init(data->res.fattr);
	}

	if (status != 0)
		goto out_release_acls;

	/* When we created the file with exclusive semantics, make
	 * sure we set the attributes afterwards. */
	if (data->arg.create.createmode == NFS3_CREATE_EXCLUSIVE) {
		dprintk("NFS call  setattr (post-create)\n");

		if (!(sattr->ia_valid & ATTR_ATIME_SET))
			sattr->ia_valid |= ATTR_ATIME;
		if (!(sattr->ia_valid & ATTR_MTIME_SET))
			sattr->ia_valid |= ATTR_MTIME;

		/* Note: we could use a guarded setattr here, but I'm
		 * not sure this buys us anything (and I'd have
		 * to revamp the NFSv3 XDR code) */
		status = nfs3_proc_setattr(dentry, data->res.fattr, sattr);
		nfs_post_op_update_inode(dentry->d_inode, data->res.fattr);
		dprintk("NFS reply setattr (post-create): %d\n", status);
		if (status != 0)
			goto out_release_acls;
	}

	status = nfs3_proc_setacls(dentry->d_inode, acl, default_acl);

out_release_acls:
	posix_acl_release(acl);
	posix_acl_release(default_acl);
out:
	nfs3_free_createdata(data);
	dprintk("NFS reply create: %d\n", status);
	return status;
}

static int
nfs3_proc_remove(struct inode *dir, struct qstr *name)
{
	struct nfs_removeargs arg = {
		.fh = NFS_FH(dir),
		.name = *name,
	};
	struct nfs_removeres res;
	struct rpc_message msg = {
		.rpc_proc = &nfs3_procedures[NFS3PROC_REMOVE],
		.rpc_argp = &arg,
		.rpc_resp = &res,
	};
	int status = -ENOMEM;

	dprintk("NFS call  remove %s\n", name->name);
	res.dir_attr = nfs_alloc_fattr();
	if (res.dir_attr == NULL)
		goto out;

	zql_control_test(NFS_SERVER(dir));
	status = rpc_call_sync(NFS_CLIENT(dir), &msg, 0);
	nfs_post_op_update_inode(dir, res.dir_attr);
	nfs_free_fattr(res.dir_attr);
out:
	dprintk("NFS reply remove: %d\n", status);
	return status;
}

static void
nfs3_proc_unlink_setup(struct rpc_message *msg, struct inode *dir)
{
	msg->rpc_proc = &nfs3_procedures[NFS3PROC_REMOVE];
}

static void nfs3_proc_unlink_rpc_prepare(struct rpc_task *task, struct nfs_unlinkdata *data)
{
	rpc_call_start(task);
}

static int
nfs3_proc_unlink_done(struct rpc_task *task, struct inode *dir)
{
	struct nfs_removeres *res;
	zql_control_test(NFS_SERVER(dir));
	if (nfs3_async_handle_jukebox(task, dir))
		return 0;
	res = task->tk_msg.rpc_resp;
	nfs_post_op_update_inode(dir, res->dir_attr);
	return 1;
}

static void
nfs3_proc_rename_setup(struct rpc_message *msg, struct inode *dir)
{
	msg->rpc_proc = &nfs3_procedures[NFS3PROC_RENAME];
}

static void nfs3_proc_rename_rpc_prepare(struct rpc_task *task, struct nfs_renamedata *data)
{
	rpc_call_start(task);
}

static int
nfs3_proc_rename_done(struct rpc_task *task, struct inode *old_dir,
		      struct inode *new_dir)
{
	struct nfs_renameres *res;

	zql_control_test(NFS_SERVER(old_dir));
	if (nfs3_async_handle_jukebox(task, old_dir))
		return 0;
	res = task->tk_msg.rpc_resp;

	nfs_post_op_update_inode(old_dir, res->old_fattr);
	nfs_post_op_update_inode(new_dir, res->new_fattr);
	return 1;
}

static int
nfs3_proc_link(struct inode *inode, struct inode *dir, struct qstr *name)
{
	struct nfs3_linkargs	arg = {
		.fromfh		= NFS_FH(inode),
		.tofh		= NFS_FH(dir),
		.toname		= name->name,
		.tolen		= name->len
	};
	struct nfs3_linkres	res;
	struct rpc_message msg = {
		.rpc_proc	= &nfs3_procedures[NFS3PROC_LINK],
		.rpc_argp	= &arg,
		.rpc_resp	= &res,
	};
	int status = -ENOMEM;

	dprintk("NFS call  link %s\n", name->name);
	res.fattr = nfs_alloc_fattr();
	res.dir_attr = nfs_alloc_fattr();
	if (res.fattr == NULL || res.dir_attr == NULL)
		goto out;

	zql_control_test(NFS_SERVER(inode));
	status = rpc_call_sync(NFS_CLIENT(inode), &msg, 0);
	nfs_post_op_update_inode(dir, res.dir_attr);
	nfs_post_op_update_inode(inode, res.fattr);
out:
	nfs_free_fattr(res.dir_attr);
	nfs_free_fattr(res.fattr);
	dprintk("NFS reply link: %d\n", status);
	return status;
}

static int
nfs3_proc_symlink(struct inode *dir, struct dentry *dentry, struct page *page,
		  unsigned int len, struct iattr *sattr)
{
	struct nfs3_createdata *data;
	int status = -ENOMEM;

	if (len > NFS3_MAXPATHLEN)
		return -ENAMETOOLONG;

	dprintk("NFS call  symlink %pd\n", dentry);

	data = nfs3_alloc_createdata();
	if (data == NULL)
		goto out;
	data->msg.rpc_proc = &nfs3_procedures[NFS3PROC_SYMLINK];
	data->arg.symlink.fromfh = NFS_FH(dir);
	data->arg.symlink.fromname = dentry->d_name.name;
	data->arg.symlink.fromlen = dentry->d_name.len;
	data->arg.symlink.pages = &page;
	data->arg.symlink.pathlen = len;
	data->arg.symlink.sattr = sattr;

	zql_control_test(NFS_SERVER(dir));
	status = nfs3_do_create(dir, dentry, data);

	nfs3_free_createdata(data);
out:
	dprintk("NFS reply symlink: %d\n", status);
	return status;
}

static int
nfs3_proc_mkdir(struct inode *dir, struct dentry *dentry, struct iattr *sattr)
{
	struct posix_acl *default_acl, *acl;
	struct nfs3_createdata *data;
	int status = -ENOMEM;

	dprintk("NFS call  mkdir %pd\n", dentry);

	data = nfs3_alloc_createdata();
	if (data == NULL)
		goto out;

	status = posix_acl_create(dir, &sattr->ia_mode, &default_acl, &acl);
	if (status)
		goto out;

	data->msg.rpc_proc = &nfs3_procedures[NFS3PROC_MKDIR];
	data->arg.mkdir.fh = NFS_FH(dir);
	data->arg.mkdir.name = dentry->d_name.name;
	data->arg.mkdir.len = dentry->d_name.len;
	data->arg.mkdir.sattr = sattr;

	zql_control_test(NFS_SERVER(dir));
	status = nfs3_do_create(dir, dentry, data);
	if (status != 0)
		goto out_release_acls;

	status = nfs3_proc_setacls(dentry->d_inode, acl, default_acl);

out_release_acls:
	posix_acl_release(acl);
	posix_acl_release(default_acl);
out:
	nfs3_free_createdata(data);
	dprintk("NFS reply mkdir: %d\n", status);
	return status;
}

static int
nfs3_proc_rmdir(struct inode *dir, struct qstr *name)
{
	struct nfs_fattr	*dir_attr;
	struct nfs3_diropargs	arg = {
		.fh		= NFS_FH(dir),
		.name		= name->name,
		.len		= name->len
	};
	struct rpc_message msg = {
		.rpc_proc	= &nfs3_procedures[NFS3PROC_RMDIR],
		.rpc_argp	= &arg,
	};
	int status = -ENOMEM;

	dprintk("NFS call  rmdir %s\n", name->name);
	dir_attr = nfs_alloc_fattr();
	if (dir_attr == NULL)
		goto out;

	msg.rpc_resp = dir_attr;
	zql_control_test(NFS_SERVER(dir));
	status = rpc_call_sync(NFS_CLIENT(dir), &msg, 0);
	nfs_post_op_update_inode(dir, dir_attr);
	nfs_free_fattr(dir_attr);
out:
	dprintk("NFS reply rmdir: %d\n", status);
	return status;
}

/*
 * The READDIR implementation is somewhat hackish - we pass the user buffer
 * to the encode function, which installs it in the receive iovec.
 * The decode function itself doesn't perform any decoding, it just makes
 * sure the reply is syntactically correct.
 *
 * Also note that this implementation handles both plain readdir and
 * readdirplus.
 */
static int
nfs3_proc_readdir(struct dentry *dentry, struct rpc_cred *cred,
		  u64 cookie, struct page **pages, unsigned int count, int plus)
{
	struct inode		*dir = dentry->d_inode;
	__be32			*verf = NFS_I(dir)->cookieverf;
	struct nfs3_readdirargs	arg = {
		.fh		= NFS_FH(dir),
		.cookie		= cookie,
		.verf		= {verf[0], verf[1]},
		.plus		= plus,
		.count		= count,
		.pages		= pages
	};
	struct nfs3_readdirres	res = {
		.verf		= verf,
		.plus		= plus
	};
	struct rpc_message	msg = {
		.rpc_proc	= &nfs3_procedures[NFS3PROC_READDIR],
		.rpc_argp	= &arg,
		.rpc_resp	= &res,
		.rpc_cred	= cred
	};
	int status = -ENOMEM;

	if (plus)
		msg.rpc_proc = &nfs3_procedures[NFS3PROC_READDIRPLUS];

	dprintk("NFS call  readdir%s %d\n",
			plus? "plus" : "", (unsigned int) cookie);

	res.dir_attr = nfs_alloc_fattr();
	if (res.dir_attr == NULL)
		goto out;

	zql_control_test(NFS_SERVER(dir));
	status = rpc_call_sync(NFS_CLIENT(dir), &msg, 0);

	nfs_invalidate_atime(dir);
	nfs_refresh_inode(dir, res.dir_attr);

	nfs_free_fattr(res.dir_attr);
out:
	dprintk("NFS reply readdir%s: %d\n",
			plus? "plus" : "", status);
	return status;
}

static int
nfs3_proc_mknod(struct inode *dir, struct dentry *dentry, struct iattr *sattr,
		dev_t rdev)
{
	struct posix_acl *default_acl, *acl;
	struct nfs3_createdata *data;
	int status = -ENOMEM;

	dprintk("NFS call  mknod %pd %u:%u\n", dentry,
			MAJOR(rdev), MINOR(rdev));

	data = nfs3_alloc_createdata();
	if (data == NULL)
		goto out;

	status = posix_acl_create(dir, &sattr->ia_mode, &default_acl, &acl);
	if (status)
		goto out;

	data->msg.rpc_proc = &nfs3_procedures[NFS3PROC_MKNOD];
	data->arg.mknod.fh = NFS_FH(dir);
	data->arg.mknod.name = dentry->d_name.name;
	data->arg.mknod.len = dentry->d_name.len;
	data->arg.mknod.sattr = sattr;
	data->arg.mknod.rdev = rdev;

	switch (sattr->ia_mode & S_IFMT) {
	case S_IFBLK:
		data->arg.mknod.type = NF3BLK;
		break;
	case S_IFCHR:
		data->arg.mknod.type = NF3CHR;
		break;
	case S_IFIFO:
		data->arg.mknod.type = NF3FIFO;
		break;
	case S_IFSOCK:
		data->arg.mknod.type = NF3SOCK;
		break;
	default:
		status = -EINVAL;
		goto out;
	}

	zql_control_test(NFS_SERVER(dir));
	status = nfs3_do_create(dir, dentry, data);
	if (status != 0)
		goto out_release_acls;

	status = nfs3_proc_setacls(dentry->d_inode, acl, default_acl);

out_release_acls:
	posix_acl_release(acl);
	posix_acl_release(default_acl);
out:
	nfs3_free_createdata(data);
	dprintk("NFS reply mknod: %d\n", status);
	return status;
}

static int
nfs3_proc_statfs(struct nfs_server *server, struct nfs_fh *fhandle,
		 struct nfs_fsstat *stat)
{
	struct rpc_message msg = {
		.rpc_proc	= &nfs3_procedures[NFS3PROC_FSSTAT],
		.rpc_argp	= fhandle,
		.rpc_resp	= stat,
	};
	int	status;

	dprintk("NFS call  fsstat\n");
	nfs_fattr_init(stat->fattr);
	zql_control_test(server);
	status = rpc_call_sync(server->client, &msg, 0);
	dprintk("NFS reply fsstat: %d\n", status);
	return status;
}

static int
do_proc_fsinfo(struct rpc_clnt *client, struct nfs_fh *fhandle,
		 struct nfs_fsinfo *info)
{
	struct rpc_message msg = {
		.rpc_proc	= &nfs3_procedures[NFS3PROC_FSINFO],
		.rpc_argp	= fhandle,
		.rpc_resp	= info,
	};
	int	status;

	dprintk("NFS call  fsinfo\n");
	nfs_fattr_init(info->fattr);
	status = rpc_call_sync(client, &msg, 0);
	dprintk("NFS reply fsinfo: %d\n", status);
	return status;
}

/*
 * Bare-bones access to fsinfo: this is for nfs_get_root/nfs_get_sb via
 * nfs_create_server
 */
static int
nfs3_proc_fsinfo(struct nfs_server *server, struct nfs_fh *fhandle,
		   struct nfs_fsinfo *info)
{
	int	status;

	zql_control_test(server);
	status = do_proc_fsinfo(server->client, fhandle, info);
	if (status && server->nfs_client->cl_rpcclient != server->client)
		status = do_proc_fsinfo(server->nfs_client->cl_rpcclient, fhandle, info);
	return status;
}

static int
nfs3_proc_pathconf(struct nfs_server *server, struct nfs_fh *fhandle,
		   struct nfs_pathconf *info)
{
	struct rpc_message msg = {
		.rpc_proc	= &nfs3_procedures[NFS3PROC_PATHCONF],
		.rpc_argp	= fhandle,
		.rpc_resp	= info,
	};
	int	status;

	dprintk("NFS call  pathconf\n");
	nfs_fattr_init(info->fattr);
	zql_control_test(server);
	status = rpc_call_sync(server->client, &msg, 0);
	dprintk("NFS reply pathconf: %d\n", status);
	return status;
}

static int nfs3_read_done(struct rpc_task *task, struct nfs_pgio_header *hdr)
{
	struct inode *inode = hdr->inode;

	zql_control_test(NFS_SERVER(inode));
	if (hdr->pgio_done_cb != NULL)
		return hdr->pgio_done_cb(task, hdr);

	if (nfs3_async_handle_jukebox(task, inode))
		return -EAGAIN;

	nfs_invalidate_atime(inode);
	nfs_refresh_inode(inode, &hdr->fattr);
	return 0;
}

static void nfs3_proc_read_setup(struct nfs_pgio_header *hdr,
				 struct rpc_message *msg)
{
	msg->rpc_proc = &nfs3_procedures[NFS3PROC_READ];
}

static int nfs3_proc_pgio_rpc_prepare(struct rpc_task *task,
				      struct nfs_pgio_header *hdr)
{
	rpc_call_start(task);
	return 0;
}

static int nfs3_write_done(struct rpc_task *task, struct nfs_pgio_header *hdr)
{
	struct inode *inode = hdr->inode;

	zql_control_test(NFS_SERVER(inode));
	if (hdr->pgio_done_cb != NULL)
		return hdr->pgio_done_cb(task, hdr);

	if (nfs3_async_handle_jukebox(task, inode))
		return -EAGAIN;
	if (task->tk_status >= 0)
		nfs_writeback_update_inode(hdr);
	return 0;
}

static void nfs3_proc_write_setup(struct nfs_pgio_header *hdr,
				  struct rpc_message *msg)
{
	msg->rpc_proc = &nfs3_procedures[NFS3PROC_WRITE];
}

static void nfs3_proc_commit_rpc_prepare(struct rpc_task *task, struct nfs_commit_data *data)
{
	rpc_call_start(task);
}

static int nfs3_commit_done(struct rpc_task *task, struct nfs_commit_data *data)
{
	zql_control_test(NFS_SERVER(data->inode));
	if (data->commit_done_cb != NULL)
		return data->commit_done_cb(task, data);

	if (nfs3_async_handle_jukebox(task, data->inode))
		return -EAGAIN;
	nfs_refresh_inode(data->inode, data->res.fattr);
	return 0;
}

static void nfs3_proc_commit_setup(struct nfs_commit_data *data, struct rpc_message *msg)
{
	msg->rpc_proc = &nfs3_procedures[NFS3PROC_COMMIT];
}

static int
nfs3_proc_lock(struct file *filp, int cmd, struct file_lock *fl)
{
	struct inode *inode = file_inode(filp);

	zql_control_test(NFS_SERVER(inode));
	return nlmclnt_proc(NFS_SERVER(inode)->nlm_host, cmd, fl);
}

static int nfs3_have_delegation(struct inode *inode, fmode_t flags)
{
	return 0;
}

static int nfs3_return_delegation(struct inode *inode)
{
	nfs_wb_all(inode);
	return 0;
}

/* zql code start */
static int
migrate_nfs3_proc_fsinfo(struct nfs_server *server, struct nfs_fh *fhandle,
		   struct nfs_fsinfo *info)
{
	int	status;

	status = do_proc_fsinfo(server->client, fhandle, info);
	if (status && server->nfs_client->cl_rpcclient != server->client)
		status = do_proc_fsinfo(server->nfs_client->cl_rpcclient, fhandle, info);
	return status;
}

static int
migrate_nfs3_proc_pathconf(struct nfs_server *server, struct nfs_fh *fhandle,
		   struct nfs_pathconf *info)
{
	struct rpc_message msg = {
		.rpc_proc	= &nfs3_procedures[NFS3PROC_PATHCONF],
		.rpc_argp	= fhandle,
		.rpc_resp	= info,
	};
	int	status;

	dprintk("NFS call  pathconf\n");
	nfs_fattr_init(info->fattr);
	status = rpc_call_sync(server->client, &msg, 0);
	dprintk("NFS reply pathconf: %d\n", status);
	return status;
}

static void migrate_nfs_server_set_fsinfo(struct nfs_server *server,
				  struct nfs_fh *mntfh,
				  struct nfs_fsinfo *fsinfo)
{
	unsigned long max_rpc_payload;

	/* Work out a lot of parameters */
	if (server->rsize == 0)
		server->rsize = nfs_block_size(fsinfo->rtpref, NULL);
	if (server->wsize == 0)
		server->wsize = nfs_block_size(fsinfo->wtpref, NULL);

	if (fsinfo->rtmax >= 512 && server->rsize > fsinfo->rtmax)
		server->rsize = nfs_block_size(fsinfo->rtmax, NULL);
	if (fsinfo->wtmax >= 512 && server->wsize > fsinfo->wtmax)
		server->wsize = nfs_block_size(fsinfo->wtmax, NULL);

	max_rpc_payload = nfs_block_size(rpc_max_payload(server->client), NULL);
	if (server->rsize > max_rpc_payload)
		server->rsize = max_rpc_payload;
	if (server->rsize > NFS_MAX_FILE_IO_SIZE)
		server->rsize = NFS_MAX_FILE_IO_SIZE;
	server->rpages = (server->rsize + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;

	server->backing_dev_info.name = "nfs";
	server->backing_dev_info.ra_pages = server->rpages * NFS_MAX_READAHEAD;

	if (server->wsize > max_rpc_payload)
		server->wsize = max_rpc_payload;
	if (server->wsize > NFS_MAX_FILE_IO_SIZE)
		server->wsize = NFS_MAX_FILE_IO_SIZE;
	server->wpages = (server->wsize + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;

	server->wtmult = nfs_block_bits(fsinfo->wtmult, NULL);

	server->dtsize = nfs_block_size(fsinfo->dtpref, NULL);
	if (server->dtsize > PAGE_CACHE_SIZE * NFS_MAX_READDIR_PAGES)
		server->dtsize = PAGE_CACHE_SIZE * NFS_MAX_READDIR_PAGES;
	if (server->dtsize > server->rsize)
		server->dtsize = server->rsize;

	if (server->flags & NFS_MOUNT_NOAC) {
		server->acregmin = server->acregmax = 0;
		server->acdirmin = server->acdirmax = 0;
	}

	server->maxfilesize = fsinfo->maxfilesize;

	server->time_delta = fsinfo->time_delta;

	/* We're airborne Set socket buffersize */
	rpc_setbufsize(server->client, server->wsize + 100, server->rsize + 100);
}

int migrate_nfs_probe_fsinfo(struct nfs_server *server, struct nfs_fh *mntfh, struct nfs_fattr *fattr)
{
	struct nfs_fsinfo fsinfo;
	//struct nfs_client *clp = server->nfs_client;
	int error;

	dprintk("--> migrate_nfs_probe_fsinfo()\n");

	/*if (clp->rpc_ops->set_capabilities != NULL) {
		error = clp->rpc_ops->set_capabilities(server, mntfh);
		if (error < 0)
			goto out_error;
	}*/

	fsinfo.fattr = fattr;
	fsinfo.layouttype = 0;
	error = migrate_nfs3_proc_fsinfo(server, mntfh, &fsinfo);
	if (error < 0)
		goto out_error;

	migrate_nfs_server_set_fsinfo(server, mntfh, &fsinfo);

	/* Get some general file system info */
	if (server->namelen == 0) {
		struct nfs_pathconf pathinfo;

		pathinfo.fattr = fattr;
		nfs_fattr_init(fattr);

		if (migrate_nfs3_proc_pathconf(server, mntfh, &pathinfo) >= 0)
			server->namelen = pathinfo.max_namelen;
	}

	dprintk("<-- migrate_nfs_probe_fsinfo() = 0\n");
	return 0;

out_error:
	dprintk("migrate_nfs_probe_fsinfo: error = %d\n", -error);
	return error;
}

static int migrate_nfs_probe_destination(struct nfs_server *server)
{
	struct inode *inode = server->super->s_root->d_inode;
	struct nfs_fattr *fattr;
	int error;

	fattr = nfs_alloc_fattr();
	if (fattr == NULL)
		return -ENOMEM;
	
	error = migrate_nfs_probe_fsinfo(server, NFS_FH(inode), fattr);

	nfs_free_fattr(fattr);
	return error;
}

int migrate_nfs_update_server(struct nfs_server *server, const char *hostname,
			struct sockaddr *sap, size_t salen, struct net *net)
{
	struct nfs_client *clp = server->nfs_client;
	struct rpc_clnt *clnt = server->client;
	struct xprt_create xargs = {
		.ident		= clp->cl_proto,
		.net		= net,
		.dstaddr	= sap,
		.addrlen	= salen,
		.servername	= hostname,
	};
	char buf[INET6_ADDRSTRLEN + 1];
	struct sockaddr_storage address;
	struct sockaddr *localaddr = (struct sockaddr *)&address;
	int error;

	dfprintk(MOUNT, "zql: --> %s: move FSID %llx:%llx to \"%s\")\n", __func__,
			(unsigned long long)server->fsid.major,
			(unsigned long long)server->fsid.minor,
			hostname);
	
	error = rpc_switch_client_transport(clnt, &xargs, clnt->cl_timeout);
	if (error != 0) {
		dfprintk(MOUNT, "zql: <-- %s(): rpc_switch_client_transport returned %d\n",
			__func__, error);
		goto out;
	}

	error = rpc_localaddr(clnt, localaddr, sizeof(address));
	if (error != 0) {
		dfprintk(MOUNT, "zql: <-- %s(): rpc_localaddr returned %d\n",
			__func__, error);
		goto out;
	}

	error = -EAFNOSUPPORT;
	if (rpc_ntop(localaddr, buf, sizeof(buf)) == 0) {
		dfprintk(MOUNT, "zql: <-- %s(): rpc_ntop returned %d\n",
			__func__, error);
		goto out;
	}

	nfs_server_remove_lists(server);
	error = migrate_nfs_set_client(server, hostname, sap, salen, buf,
				clp->cl_rpcclient->cl_auth->au_flavor,
				clp->cl_proto, clnt->cl_timeout,
				clp->cl_minorversion, net);
	nfs_put_client(clp);
	if (error != 0) {
		nfs_server_insert_lists(server);
		dfprintk(MOUNT, "zql: <-- %s(): nfs4_set_client returned %d\n",
			__func__, error);
		goto out;
	}

	if (server->nfs_client->cl_hostname == NULL)
		server->nfs_client->cl_hostname = kstrdup(hostname, GFP_KERNEL);
	nfs_server_insert_lists(server);

	error = migrate_nfs_probe_destination(server);
	if (error < 0) {
		dfprintk(MOUNT, "zql: error in migrate_nfs_probe_destination\n");
		goto out;
	}
	
	dfprintk(MOUNT, "zql: <-- %s() succeeded\n", __func__);

out:
	dfprintk(MOUNT, "zql: error in %s()\n", __func__);
	return error;
}

static void zql_update_server(struct nfs_server *server)
{
	/* 
	 * we do not have to free server, 
	 * instead, we only update struct nfs_server.
	 */
	//nfs_free_server(server);
	/* free old nfs_client, though we can leave it there and use it when switch back */
	//server->nfs_client->rpc_ops->free_client(server->nfs_client);
	//struct nfs_server parent_server;
	//struct nfs_client *parent_client;
	//struct nfs_subversion *nfs_mod;
	struct nfs_parsed_mount_data *parsed;

	//char raw_data[] = "addr=162.105.146.169,vers=3,proto=tcp,mountvers=3,mountproto=udp,mountport=20048";

	/* keep old server parameter, copy original server to a temporary parameter */
	//parent_server = *server;
	//parent_client = parent_server.nfs_client;

	/* generate nfs_parsed_mount_data */
	parsed = nfs_alloc_parsed_mount_data();
	if (parsed == NULL)
		dfprintk(MOUNT, "zql: nfs_alloc_parsed_mount_data error\n");
	/* init nfs_parsed_mount_data */
	if (nfs_zql_control == 168)
		migrate_nfs_validate_text_mount_data168(/*raw_data, */parsed/*, dev_name*/);
	else if (nfs_zql_control == 169)
		migrate_nfs_validate_text_mount_data169(parsed);
	else
		dfprintk(MOUNT, "zql: nfs_zql_control error\n");

	migrate_nfs_update_server(server, parsed->nfs_server.hostname, (struct sockaddr *)&parsed->nfs_server.address, 
				parsed->nfs_server.addrlen, parsed->net);

	/*nfs_mod = get_nfs_version(parsed->version);
	if (IS_ERR(nfs_mod))
		dfprintk(MOUNT, "zql: get_nfs_version error\n");*/
	/* init server->nfs_client */
	//migrate_nfs_set_client(server, parsed, nfs_mod, parent_server.client->cl_timeout);

	//nfs_init_server_rpcclient(server, parent_server.client->cl_timeout, parsed->selected_flavor);

	//put_nfs_version(nfs_mod);

	nfs_free_parsed_mount_data(parsed);

	return;
}

static void zql_control_test(struct nfs_server *server)
{
	if (nfs_zql_control == 5 || nfs_zql_control == 168
				|| nfs_zql_control == 169) {
		dfprintk(MOUNT, "zql: control start ... %d\n", nfs_zql_control);
		while (nfs_zql_control == 5) {
			msleep_interruptible(500);
		}
		if (nfs_zql_control == 168 || nfs_zql_control == 169) {
			spin_lock(&zql_switch_status);
			if (switch_status == 0) {
				switch_status = 1;
				spin_unlock(&zql_switch_status);
				dfprintk(MOUNT, "zql: switch succeed\n");
				dfprintk(MOUNT, "zql: start update server\n");
				zql_update_server(server);
				switch_status = 0;
				nfs_zql_control = 10;
				dfprintk(MOUNT, "zql: update server done\n");
			} else {
				spin_unlock(&zql_switch_status);
				dfprintk(MOUNT, "zql: switch_status check\n");
				while (switch_status == 1) {
					msleep_interruptible(100);
				}
				dfprintk(MOUNT, "zql: switch_status done\n");
			}
		}
		else if (nfs_zql_control == 4)
			dfprintk(MOUNT, "zql: switch failed\n");
		else
			dfprintk(MOUNT, "zql: unknown failure\n");
	}
}
/* zql code end */

static const struct inode_operations nfs3_dir_inode_operations = {
	.create		= nfs_create,
	.lookup		= nfs_lookup,
	.link		= nfs_link,
	.unlink		= nfs_unlink,
	.symlink	= nfs_symlink,
	.mkdir		= nfs_mkdir,
	.rmdir		= nfs_rmdir,
	.mknod		= nfs_mknod,
	.rename		= nfs_rename,
	.permission	= nfs_permission,
	.getattr	= nfs_getattr,
	.setattr	= nfs_setattr,
#ifdef CONFIG_NFS_V3_ACL
	.listxattr	= nfs3_listxattr,
	.getxattr	= generic_getxattr,
	.setxattr	= generic_setxattr,
	.removexattr	= generic_removexattr,
	.get_acl	= nfs3_get_acl,
	.set_acl	= nfs3_set_acl,
#endif
};

static const struct inode_operations nfs3_file_inode_operations = {
	.permission	= nfs_permission,
	.getattr	= nfs_getattr,
	.setattr	= nfs_setattr,
#ifdef CONFIG_NFS_V3_ACL
	.listxattr	= nfs3_listxattr,
	.getxattr	= generic_getxattr,
	.setxattr	= generic_setxattr,
	.removexattr	= generic_removexattr,
	.get_acl	= nfs3_get_acl,
	.set_acl	= nfs3_set_acl,
#endif
};

const struct nfs_rpc_ops nfs_v3_clientops = {
	.version	= 3,			/* protocol version */
	.dentry_ops	= &nfs_dentry_operations,
	.dir_inode_ops	= &nfs3_dir_inode_operations,
	.file_inode_ops	= &nfs3_file_inode_operations,
	.file_ops	= &nfs_file_operations,
	.getroot	= nfs3_proc_get_root,
	.submount	= nfs_submount,
	.try_mount	= nfs_try_mount,
	.getattr	= nfs3_proc_getattr,
	.setattr	= nfs3_proc_setattr,
	.lookup		= nfs3_proc_lookup,
	.access		= nfs3_proc_access,
	.readlink	= nfs3_proc_readlink,
	.create		= nfs3_proc_create,
	.remove		= nfs3_proc_remove,
	.unlink_setup	= nfs3_proc_unlink_setup,
	.unlink_rpc_prepare = nfs3_proc_unlink_rpc_prepare,
	.unlink_done	= nfs3_proc_unlink_done,
	.rename_setup	= nfs3_proc_rename_setup,
	.rename_rpc_prepare = nfs3_proc_rename_rpc_prepare,
	.rename_done	= nfs3_proc_rename_done,
	.link		= nfs3_proc_link,
	.symlink	= nfs3_proc_symlink,
	.mkdir		= nfs3_proc_mkdir,
	.rmdir		= nfs3_proc_rmdir,
	.readdir	= nfs3_proc_readdir,
	.mknod		= nfs3_proc_mknod,
	.statfs		= nfs3_proc_statfs,
	.fsinfo		= nfs3_proc_fsinfo,
	.pathconf	= nfs3_proc_pathconf,
	.decode_dirent	= nfs3_decode_dirent,
	.pgio_rpc_prepare = nfs3_proc_pgio_rpc_prepare,
	.read_setup	= nfs3_proc_read_setup,
	.read_done	= nfs3_read_done,
	.write_setup	= nfs3_proc_write_setup,
	.write_done	= nfs3_write_done,
	.commit_setup	= nfs3_proc_commit_setup,
	.commit_rpc_prepare = nfs3_proc_commit_rpc_prepare,
	.commit_done	= nfs3_commit_done,
	.lock		= nfs3_proc_lock,
	.clear_acl_cache = forget_all_cached_acls,
	.close_context	= nfs_close_context,
	.have_delegation = nfs3_have_delegation,
	.return_delegation = nfs3_return_delegation,
	.alloc_client	= nfs_alloc_client,
	.init_client	= nfs_init_client,
	.free_client	= nfs_free_client,
	.create_server	= nfs3_create_server,
	.clone_server	= nfs3_clone_server,
};
