// SPDX-License-Identifier: GPL-2.0
/*
 * fdwatch - catch a file the moment someone creates it, even if the creator
 *           immediately unlinks it and execve()s away.
 *
 * WHY A KERNEL MODULE AND NOT A USERSPACE POLLER
 * ----------------------------------------------
 * A packer that drops a stage-2 does roughly:
 *
 *      mkstemp(path)                        create the file
 *      unlink(path)                         drop the name, keep the fd
 *      fcntl(fd, F_SETFD, FD_CLOEXEC)
 *      ftruncate(fd, 33 MB)                 declare the size
 *      write(fd, ...)                       the decrypted payload
 *      execve(path, ...)                    run it
 *
 * From userspace the interesting window is a fraction of a second wide, the
 * file has no name for most of it, and polling /proc/<pid>/fd loses the race
 * the moment the creator exits (and a 27k-fd snapshot on this device costs
 * ~220 ms, i.e. a whole attack window per poll).  The kernel does not have that
 * problem: at the instant the fd is installed we can take a reference on the
 * `struct file`, and that reference keeps the inode alive no matter what the
 * owner does afterwards - unlink it, close it, execve over itself.  The dump
 * then happens later, calmly, from a workqueue.
 *
 * THREE PROBES, THREE JOBS
 * ------------------------
 *   fd_install        the event layer.  Every newly installed fd whose file is
 *                     a regular file of size 0 with write permission - i.e. a
 *                     file that was just created or just truncated - is logged
 *                     with its basename, pid and comm.  Pure observation: no
 *                     reference is taken, so the cost stays a few instructions.
 *
 *   do_sys_ftruncate  the trigger.  ftruncate(fd, len) with len >= min_size_mb
 *                     is the sharpest signature of a dropping packer: declaring
 *                     a multi-megabyte size on a file nobody has written yet.
 *                     fdget() resolves the fd to a `struct file` right there
 *                     (atomic-safe) and the reference is kept.
 *
 *   vfs_write         the backstop, for a payload written in one big go without
 *                     an ftruncate first: count >= min_write_kb.
 *
 * A capture is `get_file()` plus a delayed work item.  The delay exists because
 * at trigger time the file is usually still empty - the payload is written
 * after the size is declared - so the worker retries, keeping the largest dump,
 * and stops once the file stops growing.
 *
 * WHAT THIS MODULE DOES NOT DO
 * ----------------------------
 * It never touches the writer, never changes a return value and never sleeps on
 * the probed path: each handler is a few loads, a spinlock and a
 * queue_delayed_work.  Allocation, file I/O and path formatting happen in the
 * workqueue.
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/build_bug.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/cred.h>
#include <linux/time.h>
#include <linux/timekeeping.h>
#include <linux/limits.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0) || \
    LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
#error "fdwatch targets Linux 5.15 (GKI android13-5.15 / android14-5.15) only"
#endif

#define FDW_VERSION "1.0.0"

/* ------------------------------------------------------------------ */
/* tunables                                                            */
/* ------------------------------------------------------------------ */

static char *dump_dir = "/data/local/tmp/fdcap";
module_param(dump_dir, charp, 0644);
MODULE_PARM_DESC(dump_dir, "directory captured files are written to (must exist)");

static bool capture_enabled = true;
module_param_named(enabled, capture_enabled, bool, 0644);

static unsigned int min_size_mb = 4;
module_param_named(min_size_mb, min_size_mb, uint, 0644);
MODULE_PARM_DESC(min_size_mb, "ftruncate() length that counts as a drop (MiB)");

static unsigned int min_write_kb = 256;
module_param_named(min_write_kb, min_write_kb, uint, 0644);
MODULE_PARM_DESC(min_write_kb, "single write() size that counts as a drop (KiB)");

static unsigned int max_dump_mb = 128;
module_param_named(max_dump_mb, max_dump_mb, uint, 0644);
MODULE_PARM_DESC(max_dump_mb, "largest file this module will dump (MiB)");

static bool log_fds = true;
module_param_named(log_fds, log_fds, bool, 0644);

static unsigned int slots = 8;
module_param_named(slots, slots, uint, 0444);
MODULE_PARM_DESC(slots, "concurrent captures in flight (1-32)");

#define FDW_MAX_SLOTS	32
#define FDW_POLLS	12
#define FDW_POLL_MS	400

/* ------------------------------------------------------------------ */
/* state                                                               */
/* ------------------------------------------------------------------ */

struct fdw_slot {
	struct delayed_work work;
	struct file *file;		/* reference held while armed */
	const struct cred *cred;	/* creds of whoever caused the drop */
	unsigned long ino;
	dev_t dev;
	pid_t pid;
	char comm[TASK_COMM_LEN];
	char name[64];
	const char *how;
	loff_t want;
	unsigned long best;
	unsigned int polls;
	bool busy;
};

static struct fdw_slot *fdw_slots;
static unsigned int fdw_nslots;
static DEFINE_SPINLOCK(fdw_lock);
static struct workqueue_struct *fdw_wq;
static bool fdw_stopping;

static atomic64_t fdw_events = ATOMIC64_INIT(0);
static atomic64_t fdw_captured = ATOMIC64_INIT(0);
static atomic64_t fdw_failed = ATOMIC64_INIT(0);
static atomic64_t fdw_dropped = ATOMIC64_INIT(0);

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

/* Wall-clock stamp for file names: YYYYMMDD-HHMMSS-uuuuuu */
static void fdw_ts(char *buf, size_t len)
{
	struct timespec64 ts;
	struct tm tm;

	ktime_get_real_ts64(&ts);
	time64_to_tm(ts.tv_sec, 0, &tm);
	scnprintf(buf, len, "%04d%02d%02d-%02d%02d%02d-%06ld",
		  (int)tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		  tm.tm_hour, tm.tm_min, tm.tm_sec,
		  (long)(ts.tv_nsec / 1000));
}

static void fdw_dentry_name(struct dentry *d, char *out, size_t outsz)
{
	const unsigned char *n;

	n = d ? d->d_name.name : NULL;
	if (!n)
		scnprintf(out, outsz, "?");
	else
		strscpy(out, (const char *)n, outsz);
}

/* The event layer: two dereferences and a compare in the common case. */
static void fdw_log_new_fd(unsigned int fd, struct file *file)
{
	struct inode *inode;
	char name[64];

	if (!log_fds || !file || !file->f_inode)
		return;
	inode = file->f_inode;
	if (!S_ISREG(inode->i_mode) || !(file->f_mode & FMODE_WRITE))
		return;
	/* freshly created / freshly truncated only */
	if (i_size_read(inode) != 0)
		return;

	fdw_dentry_name(file->f_path.dentry, name, sizeof(name));
	pr_info("new fd %u -> '%s' pid=%d comm=%s (size=0, writable)\n",
		fd, name, current->pid, current->comm);
	atomic64_inc(&fdw_events);
}

/*
 * Arm a capture for `file`; takes its own reference.  Probe context only:
 * spinlock + get_file + get_current_cred + queue_delayed_work, nothing that
 * can sleep.
 */
static bool fdw_arm(struct file *file, const char *how, loff_t want,
		    unsigned long delay_ms)
{
	struct inode *inode;
	struct fdw_slot *slot = NULL;
	unsigned long flags, i;
	unsigned long ino;
	dev_t dev;

	if (!file || !file->f_inode || !file->f_inode->i_sb)
		return false;
	inode = file->f_inode;
	ino = (unsigned long)inode->i_ino;
	dev = (dev_t)inode->i_sb->s_dev;

	spin_lock_irqsave(&fdw_lock, flags);
	/* already tracking this inode? then there is nothing to do */
	for (i = 0; i < fdw_nslots; i++) {
		if (fdw_slots[i].busy && fdw_slots[i].ino == ino &&
		    fdw_slots[i].dev == dev) {
			spin_unlock_irqrestore(&fdw_lock, flags);
			return true;
		}
	}
	for (i = 0; i < fdw_nslots; i++) {
		if (!fdw_slots[i].busy) {
			fdw_slots[i].busy = true;
			slot = &fdw_slots[i];
			break;
		}
	}
	spin_unlock_irqrestore(&fdw_lock, flags);

	if (!slot) {
		atomic64_inc(&fdw_dropped);
		pr_warn_ratelimited("all %u slots busy - dropped a capture\n",
				    fdw_nslots);
		return false;
	}

	slot->file = get_file(file);
	slot->cred = get_current_cred();
	slot->ino = ino;
	slot->dev = dev;
	slot->pid = current->pid;
	memcpy(slot->comm, current->comm, TASK_COMM_LEN);
	fdw_dentry_name(file->f_path.dentry, slot->name, sizeof(slot->name));
	slot->how = how;
	slot->want = want;
	slot->best = 0;
	slot->polls = 0;

	queue_delayed_work_on(WORK_CPU_UNBOUND, fdw_wq, &slot->work,
			      msecs_to_jiffies(delay_ms));
	return true;
}

/* ------------------------------------------------------------------ */
/* probes                                                              */
/* ------------------------------------------------------------------ */

/* void fd_install(unsigned int fd, struct file *file) */
static int fdw_p_fd_install(struct kprobe *p, struct pt_regs *regs)
{
	if (unlikely(!capture_enabled))
		return 0;
	fdw_log_new_fd((unsigned int)regs->regs[0],
		       (struct file *)regs->regs[1]);
	return 0;
}

static struct kprobe fdw_kp_fd_install = {
	.symbol_name = "fd_install",
	.pre_handler = fdw_p_fd_install,
};

/*
 * long do_sys_ftruncate(unsigned int fd, loff_t length, int small)
 *
 * fdget() is deliberate: it is the atomic half of the fd lookup and hands back
 * a reference that can be kept, which is exactly what lets the dump survive a
 * later unlink()/execve().
 */
static int fdw_p_ftruncate(struct kprobe *p, struct pt_regs *regs)
{
	unsigned int fd = (unsigned int)regs->regs[0];
	loff_t length = (loff_t)regs->regs[1];
	struct fd f;

	if (unlikely(!capture_enabled))
		return 0;
	if (length < (loff_t)min_size_mb * 1024 * 1024)
		return 0;

	f = fdget(fd);
	if (f.file) {
		fdw_arm(f.file, "ftruncate", length, FDW_POLL_MS);
		fdput(f);
	}
	return 0;
}

static struct kprobe fdw_kp_ftruncate = {
	.symbol_name = "do_sys_ftruncate",
	.pre_handler = fdw_p_ftruncate,
};

/*
 * ssize_t vfs_write(struct file *file, const char __user *buf,
 *                   size_t count, loff_t *pos)
 */
static int fdw_p_vfs_write(struct kprobe *p, struct pt_regs *regs)
{
	struct file *file = (struct file *)regs->regs[0];
	unsigned long count = (unsigned long)regs->regs[2];

	if (unlikely(!capture_enabled))
		return 0;
	if (count < (unsigned long)min_write_kb * 1024)
		return 0;
	fdw_arm(file, "vfs_write", (loff_t)count, FDW_POLL_MS);
	return 0;
}

static struct kprobe fdw_kp_vfs_write = {
	.symbol_name = "vfs_write",
	.pre_handler = fdw_p_vfs_write,
};

/* ------------------------------------------------------------------ */
/* the dump worker                                                     */
/* ------------------------------------------------------------------ */

static void fdw_index(const struct fdw_slot *slot, const char *path,
		      unsigned long bytes)
{
	char line[400];
	char idx[PATH_MAX];
	struct file *f;
	loff_t pos = 0;
	int n;

	n = scnprintf(line, sizeof(line),
		      "pid=%d comm=%s how=%s want=%lld size=%lu ino=%lu name=%s file=%s\n",
		      slot->pid, slot->comm, slot->how, (long long)slot->want,
		      bytes, slot->ino, slot->name, path);

	snprintf(idx, sizeof(idx), "%s/index.log", dump_dir);
	f = filp_open(idx, O_WRONLY | O_CREAT | O_APPEND | O_LARGEFILE, 0644);
	if (IS_ERR(f))
		return;
	kernel_write(f, line, (size_t)n, &pos);
	filp_close(f, NULL);
}

static void fdw_do_dump(struct fdw_slot *slot)
{
	struct inode *inode = slot->file->f_inode;
	const struct cred *old;
	struct file *out;
	loff_t size, pos = 0, w = 0;
	unsigned long cap;
	void *buf;
	char ts[40], path[PATH_MAX];
	ssize_t got, n;

	size = i_size_read(inode);
	cap = (unsigned long)max_dump_mb * 1024 * 1024;

	if (size <= 0)
		return;
	if ((unsigned long)size > cap) {
		pr_warn_ratelimited("'%s' is %lld bytes, over max_dump_mb=%uMiB - skipped\n",
				    slot->name, (long long)size, max_dump_mb);
		return;
	}
	if ((unsigned long)size <= slot->best)
		return;			/* no growth since the last poll */

	buf = vmalloc((size_t)size);
	if (!buf) {
		pr_warn_ratelimited("no memory for a %lld byte dump\n", (long long)size);
		return;
	}

	got = kernel_read(slot->file, buf, (size_t)size, &pos);
	if (got <= 0) {
		pr_warn_ratelimited("cannot read '%s' (%ld) - opened write-only?\n",
				    slot->name, (long)got);
		vfree(buf);
		return;
	}

	fdw_ts(ts, sizeof(ts));
	snprintf(path, sizeof(path), "%s/%s_%s_pid%d_%s_%lu.bin",
		 dump_dir, ts, slot->how, slot->pid,
		 slot->comm[0] ? slot->comm : "?", slot->ino);

	old = override_creds(slot->cred);
	out = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE, 0644);
	if (IS_ERR(out)) {
		revert_creds(old);
		atomic64_inc(&fdw_failed);
		pr_err("cannot create %s (%ld) - does %s exist?\n",
		       path, (long)PTR_ERR(out), dump_dir);
		vfree(buf);
		return;
	}
	n = kernel_write(out, buf, (size_t)got, &w);
	filp_close(out, NULL);
	revert_creds(old);
	vfree(buf);

	if (n == got) {
		slot->best = (unsigned long)got;
		atomic64_inc(&fdw_captured);
		pr_info("captured %ld bytes (%s) -> %s (pid=%d comm=%s name=%s)\n",
			(long)got, slot->how, path, slot->pid, slot->comm,
			slot->name);
		fdw_index(slot, path, (unsigned long)got);
	} else {
		atomic64_inc(&fdw_failed);
		pr_err("short write to %s: %ld of %ld\n", path, (long)n, (long)got);
	}
}

static void fdw_work(struct work_struct *work)
{
	struct fdw_slot *slot = container_of(to_delayed_work(work),
					     struct fdw_slot, work);

	fdw_do_dump(slot);
	slot->polls++;

	if (!fdw_stopping && slot->polls < FDW_POLLS) {
		queue_delayed_work_on(WORK_CPU_UNBOUND, fdw_wq, &slot->work,
				      msecs_to_jiffies(FDW_POLL_MS));
		return;
	}

	if (slot->file) {
		fput(slot->file);
		slot->file = NULL;
	}
	if (slot->cred) {
		put_cred(slot->cred);
		slot->cred = NULL;
	}
	/* Released last and under the lock, so the next probe cannot observe a
	 * half-cleared slot. */
	spin_lock_irq(&fdw_lock);
	slot->busy = false;
	spin_unlock_irq(&fdw_lock);
}

/* ------------------------------------------------------------------ */
/* init / exit                                                         */
/* ------------------------------------------------------------------ */

static int __init fdw_init(void)
{
	int ret;

	if (slots < 1 || slots > FDW_MAX_SLOTS)
		slots = 8;
	if (min_size_mb < 1)
		min_size_mb = 4;
	if (min_write_kb < 16)
		min_write_kb = 256;
	if (max_dump_mb < 1)
		max_dump_mb = 128;

	fdw_slots = kcalloc(slots, sizeof(*fdw_slots), GFP_KERNEL);
	if (!fdw_slots)
		return -ENOMEM;
	fdw_nslots = slots;

	fdw_wq = alloc_workqueue("fdwatch", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
	if (!fdw_wq) {
		kfree(fdw_slots);
		fdw_slots = NULL;
		return -ENOMEM;
	}

	ret = register_kprobe(&fdw_kp_ftruncate);
	if (ret) {
		pr_err("cannot probe do_sys_ftruncate (%d)\n", ret);
		goto err;
	}
	ret = register_kprobe(&fdw_kp_vfs_write);
	if (ret) {
		pr_err("cannot probe vfs_write (%d)\n", ret);
		unregister_kprobe(&fdw_kp_ftruncate);
		goto err;
	}
	ret = register_kprobe(&fdw_kp_fd_install);
	if (ret)
		pr_warn("cannot probe fd_install (%d) - the event log stays off\n",
			ret);

	pr_info("v%s armed: ftruncate>=%uMiB, write>=%uKiB, dump_dir=%s, %u slots\n",
		FDW_VERSION, min_size_mb, min_write_kb, dump_dir, fdw_nslots);
	return 0;

err:
	destroy_workqueue(fdw_wq);
	fdw_wq = NULL;
	kfree(fdw_slots);
	fdw_slots = NULL;
	fdw_nslots = 0;
	return ret;
}

static void __exit fdw_exit(void)
{
	unsigned int i;

	fdw_stopping = true;
	unregister_kprobe(&fdw_kp_fd_install);
	unregister_kprobe(&fdw_kp_vfs_write);
	unregister_kprobe(&fdw_kp_ftruncate);

	if (fdw_wq) {
		/* cancel first: a work item that re-arms itself would otherwise
		 * keep the queue busy forever */
		for (i = 0; i < fdw_nslots; i++)
			cancel_delayed_work_sync(&fdw_slots[i].work);
		drain_workqueue(fdw_wq);
		destroy_workqueue(fdw_wq);
		fdw_wq = NULL;
	}

	for (i = 0; i < fdw_nslots; i++) {
		if (fdw_slots[i].file)
			fput(fdw_slots[i].file);
		if (fdw_slots[i].cred)
			put_cred(fdw_slots[i].cred);
	}
	kfree(fdw_slots);
	fdw_slots = NULL;
	fdw_nslots = 0;

	pr_info("unloaded: fd-events=%lld captured=%lld failed=%lld dropped=%lld\n",
		(long long)atomic64_read(&fdw_events),
		(long long)atomic64_read(&fdw_captured),
		(long long)atomic64_read(&fdw_failed),
		(long long)atomic64_read(&fdw_dropped));
}

module_init(fdw_init);
module_exit(fdw_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Capture files at creation time by hooking the fd path");
MODULE_AUTHOR("inforcqb");
MODULE_VERSION(FDW_VERSION);

/*
 * filp_open / kernel_write / override_creds / revert_creds are exported as
 * EXPORT_SYMBOL_NS(.., ANDROID_GKI_VFS_EXPORT_ONLY); the Android build
 * stringifies that macro's expansion, so the long form has to be written out
 * literally here.
 */
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
