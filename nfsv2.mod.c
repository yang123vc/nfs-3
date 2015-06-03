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
	{ 0x7c7901e0, __VMLINUX_SYMBOL_STR(nfs_unlink) },
	{ 0x86cd9196, __VMLINUX_SYMBOL_STR(nfs_symlink) },
	{ 0xca1c3591, __VMLINUX_SYMBOL_STR(kmalloc_caches) },
	{ 0xaf5bf6ef, __VMLINUX_SYMBOL_STR(nfs_debug) },
	{ 0x1a015ce2, __VMLINUX_SYMBOL_STR(nfs_refresh_inode) },
	{ 0x79330616, __VMLINUX_SYMBOL_STR(nfs_close_context) },
	{ 0x474896f1, __VMLINUX_SYMBOL_STR(nfs_free_client) },
	{ 0x48672dd5, __VMLINUX_SYMBOL_STR(nfs_try_mount) },
	{ 0xcb46de61, __VMLINUX_SYMBOL_STR(nfs_permission) },
	{ 0x59183cf6, __VMLINUX_SYMBOL_STR(nfs_link) },
	{ 0x8508beb, __VMLINUX_SYMBOL_STR(xdr_inline_pages) },
	{ 0x5496e120, __VMLINUX_SYMBOL_STR(nfs_instantiate) },
	{ 0x12900ed3, __VMLINUX_SYMBOL_STR(nfs_sops) },
	{ 0x14bf3e93, __VMLINUX_SYMBOL_STR(nfs_setattr_update_inode) },
	{ 0x3a875bd0, __VMLINUX_SYMBOL_STR(unregister_nfs_version) },
	{ 0x8418835d, __VMLINUX_SYMBOL_STR(nfs_rmdir) },
	{ 0xe993dbe5, __VMLINUX_SYMBOL_STR(xdr_reserve_space) },
	{ 0xfb7ee006, __VMLINUX_SYMBOL_STR(nfs_alloc_fattr) },
	{ 0xb606e716, __VMLINUX_SYMBOL_STR(nfs_fattr_init) },
	{ 0xe779d206, __VMLINUX_SYMBOL_STR(xdr_terminate_string) },
	{ 0xa8e2529b, __VMLINUX_SYMBOL_STR(nfs_setattr) },
	{ 0x2eb87eef, __VMLINUX_SYMBOL_STR(nfs_fs_type) },
	{ 0x348df4d6, __VMLINUX_SYMBOL_STR(rpc_call_sync) },
	{ 0xde56b523, __VMLINUX_SYMBOL_STR(rpc_call_start) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xe77eef94, __VMLINUX_SYMBOL_STR(register_nfs_version) },
	{ 0x16305289, __VMLINUX_SYMBOL_STR(warn_slowpath_null) },
	{ 0x71e82856, __VMLINUX_SYMBOL_STR(nfs_getattr) },
	{ 0x3705d050, __VMLINUX_SYMBOL_STR(nfs_invalidate_atime) },
	{ 0x26884ff7, __VMLINUX_SYMBOL_STR(nfs_alloc_fhandle) },
	{ 0xdca3cc47, __VMLINUX_SYMBOL_STR(nfs_lookup) },
	{ 0xc063e95a, __VMLINUX_SYMBOL_STR(nfs_rename) },
	{ 0x68ec956c, __VMLINUX_SYMBOL_STR(nfs_file_operations) },
	{ 0x77931102, __VMLINUX_SYMBOL_STR(nfs_mkdir) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
	{ 0x6726bc4c, __VMLINUX_SYMBOL_STR(nfs_create) },
	{ 0x836c1b59, __VMLINUX_SYMBOL_STR(kmem_cache_alloc_trace) },
	{ 0x67f7403e, __VMLINUX_SYMBOL_STR(_raw_spin_lock) },
	{ 0xee2a5c92, __VMLINUX_SYMBOL_STR(xdr_read_pages) },
	{ 0xe5919cb1, __VMLINUX_SYMBOL_STR(xdr_encode_opaque) },
	{ 0x37a0cba, __VMLINUX_SYMBOL_STR(kfree) },
	{ 0xea61f47c, __VMLINUX_SYMBOL_STR(nfs_init_client) },
	{ 0x97c49149, __VMLINUX_SYMBOL_STR(nfs_create_server) },
	{ 0xf1868e4e, __VMLINUX_SYMBOL_STR(nfs_mknod) },
	{ 0xd4e5ea9, __VMLINUX_SYMBOL_STR(nfs_submount) },
	{ 0xe2fd700e, __VMLINUX_SYMBOL_STR(xdr_inline_decode) },
	{ 0x3f2b5189, __VMLINUX_SYMBOL_STR(nfs_wb_all) },
	{ 0x74c4fcc8, __VMLINUX_SYMBOL_STR(xdr_write_pages) },
	{ 0xfce87344, __VMLINUX_SYMBOL_STR(nfs_dentry_operations) },
	{ 0xe9cec2d5, __VMLINUX_SYMBOL_STR(nfs_alloc_client) },
	{ 0xcbd9cb6b, __VMLINUX_SYMBOL_STR(nfs_writeback_update_inode) },
	{ 0xa93bd088, __VMLINUX_SYMBOL_STR(nlmclnt_proc) },
	{ 0x19fcb469, __VMLINUX_SYMBOL_STR(nfs_clone_server) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=nfs,sunrpc,lockd";


MODULE_INFO(srcversion, "07BC4EA0D77D01B1EBC39B4");
