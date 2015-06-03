#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

MODULE_INFO(intree, "Y");

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x13ed5080, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x8b4b335b, __VMLINUX_SYMBOL_STR(get_acl) },
	{ 0xd056f914, __VMLINUX_SYMBOL_STR(forget_cached_acl) },
	{ 0x38d2dcfc, __VMLINUX_SYMBOL_STR(alloc_pages_current) },
	{ 0x7c7901e0, __VMLINUX_SYMBOL_STR(nfs_unlink) },
	{ 0x86cd9196, __VMLINUX_SYMBOL_STR(nfs_symlink) },
	{ 0xca1c3591, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0x97f0e3a8, __VMLINUX_SYMBOL_STR(generic_getxattr) },
	{ 0xaf5bf6ef, __VMLINUX_SYMBOL_STR(nfs_debug) },
	{ 0x1e3dff57, __VMLINUX_SYMBOL_STR(xdr_stream_pos) },
	{ 0x1a015ce2, __VMLINUX_SYMBOL_STR(nfs_refresh_inode) },
	{ 0x79330616, __VMLINUX_SYMBOL_STR(nfs_close_context) },
	{ 0x474896f1, __VMLINUX_SYMBOL_STR(nfs_free_client) },
	{ 0x754d539c, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0x48672dd5, __VMLINUX_SYMBOL_STR(nfs_try_mount) },
	{ 0x9469482, __VMLINUX_SYMBOL_STR(kfree_call_rcu) },
	{ 0x52d38cb6, __VMLINUX_SYMBOL_STR(posix_acl_access_xattr_handler) },
	{ 0xcb46de61, __VMLINUX_SYMBOL_STR(nfs_permission) },
	{ 0x7ab88a45, __VMLINUX_SYMBOL_STR(system_freezing_cnt) },
	{ 0xbf7fd2f5, __VMLINUX_SYMBOL_STR(schedule_timeout_killable) },
	{ 0x59183cf6, __VMLINUX_SYMBOL_STR(nfs_link) },
	{ 0x8508beb, __VMLINUX_SYMBOL_STR(xdr_inline_pages) },
	{ 0x79a1bfe5, __VMLINUX_SYMBOL_STR(rpc_restart_call) },
	{ 0x5496e120, __VMLINUX_SYMBOL_STR(nfs_instantiate) },
	{ 0x12900ed3, __VMLINUX_SYMBOL_STR(nfs_sops) },
	{ 0x14bf3e93, __VMLINUX_SYMBOL_STR(nfs_setattr_update_inode) },
	{ 0x3a875bd0, __VMLINUX_SYMBOL_STR(unregister_nfs_version) },
	{ 0x14f39c0b, __VMLINUX_SYMBOL_STR(generic_setxattr) },
	{ 0x8418835d, __VMLINUX_SYMBOL_STR(nfs_rmdir) },
	{ 0x7d11c268, __VMLINUX_SYMBOL_STR(jiffies) },
	{ 0xe993dbe5, __VMLINUX_SYMBOL_STR(xdr_reserve_space) },
	{ 0xfb7ee006, __VMLINUX_SYMBOL_STR(nfs_alloc_fattr) },
	{ 0xc5ef47d5, __VMLINUX_SYMBOL_STR(nfs_init_timeout_values) },
	{ 0x5b358776, __VMLINUX_SYMBOL_STR(rpc_delay) },
	{ 0xb606e716, __VMLINUX_SYMBOL_STR(nfs_fattr_init) },
	{ 0xe779d206, __VMLINUX_SYMBOL_STR(xdr_terminate_string) },
	{ 0xa8e2529b, __VMLINUX_SYMBOL_STR(nfs_setattr) },
	{ 0x2eb87eef, __VMLINUX_SYMBOL_STR(nfs_fs_type) },
	{ 0x348df4d6, __VMLINUX_SYMBOL_STR(rpc_call_sync) },
	{ 0xde56b523, __VMLINUX_SYMBOL_STR(rpc_call_start) },
	{ 0xe03be9bf, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0x8991b1d8, __VMLINUX_SYMBOL_STR(freezing_slow_path) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xe77eef94, __VMLINUX_SYMBOL_STR(register_nfs_version) },
	{ 0xf27f3959, __VMLINUX_SYMBOL_STR(rpc_bind_new_program) },
	{ 0xa1c76e0a, __VMLINUX_SYMBOL_STR(_cond_resched) },
	{ 0x47e9981c, __VMLINUX_SYMBOL_STR(nfs_zap_acl_cache) },
	{ 0x16305289, __VMLINUX_SYMBOL_STR(warn_slowpath_null) },
	{ 0x71e82856, __VMLINUX_SYMBOL_STR(nfs_getattr) },
	{ 0x60df1e3b, __VMLINUX_SYMBOL_STR(posix_acl_equiv_mode) },
	{ 0x3705d050, __VMLINUX_SYMBOL_STR(nfs_invalidate_atime) },
	{ 0x25e164c4, __VMLINUX_SYMBOL_STR(set_cached_acl) },
	{ 0xd8035c12, __VMLINUX_SYMBOL_STR(posix_acl_create) },
	{ 0xfc8c3d38, __VMLINUX_SYMBOL_STR(generic_removexattr) },
	{ 0xc09e435c, __VMLINUX_SYMBOL_STR(nfsacl_encode) },
	{ 0xdca3cc47, __VMLINUX_SYMBOL_STR(nfs_lookup) },
	{ 0xc063e95a, __VMLINUX_SYMBOL_STR(nfs_rename) },
	{ 0x68ec956c, __VMLINUX_SYMBOL_STR(nfs_file_operations) },
	{ 0x9e2e52cb, __VMLINUX_SYMBOL_STR(__free_pages) },
	{ 0xcc4c6431, __VMLINUX_SYMBOL_STR(nfs_get_client) },
	{ 0x87ddd648, __VMLINUX_SYMBOL_STR(nfs_revalidate_inode) },
	{ 0x77931102, __VMLINUX_SYMBOL_STR(nfs_mkdir) },
	{ 0x4482cdb, __VMLINUX_SYMBOL_STR(__refrigerator) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x6726bc4c, __VMLINUX_SYMBOL_STR(nfs_create) },
	{ 0x836c1b59, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0xc83b4d5b, __VMLINUX_SYMBOL_STR(posix_acl_from_mode) },
	{ 0x49ef8827, __VMLINUX_SYMBOL_STR(nfsacl_decode) },
	{ 0xee2a5c92, __VMLINUX_SYMBOL_STR(xdr_read_pages) },
	{ 0xe5919cb1, __VMLINUX_SYMBOL_STR(xdr_encode_opaque) },
	{ 0x1f2a9970, __VMLINUX_SYMBOL_STR(rpc_ntop) },
	{ 0x9a7b7438, __VMLINUX_SYMBOL_STR(nfs_post_op_update_inode) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0xea61f47c, __VMLINUX_SYMBOL_STR(nfs_init_client) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0x97c49149, __VMLINUX_SYMBOL_STR(nfs_create_server) },
	{ 0xf1868e4e, __VMLINUX_SYMBOL_STR(nfs_mknod) },
	{ 0xd86fadf3, __VMLINUX_SYMBOL_STR(posix_acl_default_xattr_handler) },
	{ 0xd4e5ea9, __VMLINUX_SYMBOL_STR(nfs_submount) },
	{ 0xf1dabee1, __VMLINUX_SYMBOL_STR(forget_all_cached_acls) },
	{ 0xe2fd700e, __VMLINUX_SYMBOL_STR(xdr_inline_decode) },
	{ 0x3f2b5189, __VMLINUX_SYMBOL_STR(nfs_wb_all) },
	{ 0x4ab5d41e, __VMLINUX_SYMBOL_STR(nfs_access_zap_cache) },
	{ 0x74c4fcc8, __VMLINUX_SYMBOL_STR(xdr_write_pages) },
	{ 0xfce87344, __VMLINUX_SYMBOL_STR(nfs_dentry_operations) },
	{ 0xe9cec2d5, __VMLINUX_SYMBOL_STR(nfs_alloc_client) },
	{ 0xcbd9cb6b, __VMLINUX_SYMBOL_STR(nfs_writeback_update_inode) },
	{ 0xa93bd088, __VMLINUX_SYMBOL_STR(nlmclnt_proc) },
	{ 0xe914e41e, __VMLINUX_SYMBOL_STR(strcpy) },
	{ 0x19fcb469, __VMLINUX_SYMBOL_STR(nfs_clone_server) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=nfs,sunrpc,nfs_acl,lockd";


MODULE_INFO(srcversion, "495ADC22AFB0250577D61F0");
