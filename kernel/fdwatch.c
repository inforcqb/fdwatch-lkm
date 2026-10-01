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
 * the moment the creator exits (a full snapshot of this device's 27k fds costs
 * ~220 ms - a whole attack window per poll).  The kernel does not have that
 * problem: at the instant the fd is installed we can take a reference on the
 * `struct file`, and that reference keeps the inode alive no matter what the
 * owner does afterwards - unlink it, close it, execve over itself.  The dump
 * then happens later, calmly, from a workqueue.
 *
 * PROBES
 * ------
 *   do_sys_ftruncate  the trigger.  ftruncate(fd, len) with len >= min_size_mb
 *                     is the sharpest signature of a dropping packer: declaring
 *                     a multi-megabyte size on a file nobody has written yet.
 *                     fdget() resolves the fd to a `struct file` right there
 *                     (atomic-safe) and its reference is kept.
 *
 *   vfs_write         the backstop, for a payload written in one big go with no
 *                     ftruncate first: count >= min_write_kb.
 *
 *   fd_install        the event layer: log every newly created regular file.
 *                     MEASURED DEAD on the target kernel - see the note on
 *                     fdw_cand_names[] below.
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
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0) || \
    LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
#error "fdwatch targets Linux 5.15 (GKI android13-5.15 / android14-5.15) only"
#endif

#define FDW_VERSION "1.3.0"

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

static unsigned int slots = 8;
module_param_named(slots, slots, uint, 0444);
MODULE_PARM_DESC(slots, "concurrent captures in flight (1-32)");

/*
 * Register a counter-only kprobe on each candidate symbol and print the hit
 * counts at unload.  This is not decoration: under CONFIG_LTO_CLANG_FULL a
 * symbol can be present in kallsyms, register_kprobe() can succeed, and the
 * handler still never runs because the kernel's own call sites were inlined or
 * cloned.  Measured on the target PJA110: do_sys_ftruncate and vfs_write fire,
 * fd_install stayed at zero hits through a whole test run - so the event layer
 * must not be built on fd_install without re-measuring.
 */
static bool scan_symbols;
module_param_named(scan, scan_symbols, bool, 0644);
MODULE_PARM_DESC(scan, "count hits per candidate hook point and report at unload");

#define FDW_MAX_SLOTS	32
#define FDW_POLLS	12
#define FDW_POLL_MS	400

/* ------------------------------------------------------------------ */
/* state                                                               */
/* ------------------------------------------------------------------ */

struct fdw_slot {
	struct delayed_work work;
	struct file *file;		/* reference held while armed */
	const struct cred *cred;
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

/*
 * Credentials of whoever loaded this module (normally root in the su/ksu
 * domain).  Held for the module's lifetime and used as the fallback when the
 * process that caused a drop is an ordinary app: an app cannot create files in
 * /data/local/tmp, and neither can the kworker's own kernel domain, so the
 * loader's credentials are the only ones that reliably can.
 */
static const struct cred *fdw_load_cred;

static atomic64_t fdw_captured = ATOMIC64_INIT(0);
static atomic64_t fdw_failed = ATOMIC64_INIT(0);
static atomic64_t fdw_dropped = ATOMIC64_INIT(0);
static atomic64_t fdw_partial = ATOMIC64_INIT(0);

/*
 * fd_install is reachable on this kernel (measured: 893 hits in a ten-second
 * run), but only a handful of those are "a regular file that was just
 * created".  These counters exist so that "the event log is silent" can be
 * told apart from "the probe never ran" - the distinction that a hit count
 * alone cannot make.
 */
static atomic64_t fdw_fd_hits = ATOMIC64_INIT(0);
static atomic64_t fdw_fd_reg = ATOMIC64_INIT(0);
static atomic64_t fdw_fd_pass = ATOMIC64_INIT(0);

static bool debug_fds;
module_param_named(debug_fds, debug_fds, bool, 0644);
MODULE_PARM_DESC(debug_fds, "log every fd_install (noisy; for measuring the filter)");

/* ---- hook-point reachability scan ---------------------------------- */

struct fdw_cand {
	const char *sym;
	struct kprobe kp;
	atomic64_t hits;
	bool live;
};

static struct fdw_cand fdw_cands[] = {
	{ .sym = "do_sys_ftruncate" },	/* capture trigger  */
	{ .sym = "vfs_write" },		/* capture backstop */
	{ .sym = "fd_install" },	/* event layer      */
	{ .sym = "get_unused_fd_flags" },
	{ .sym = "vfs_open" },
	{ .sym = "do_filp_open" },
	{ .sym = "path_openat" },
	{ .sym = "do_sys_openat2" },
	{ .sym = "ksys_openat" },
	{ .sym = "__arm64_sys_openat" },
	{ .sym = "__arm64_sys_openat2" },
	{ .sym = "__arm64_sys_ftruncate" },
	{ .sym = "ksys_write" },
	{ .sym = "vfs_truncate" },
	{ .sym = "vfs_unlink" },
	{ .sym = "do_unlinkat" },
};
#define FDW_NCANDS	ARRAY_SIZE(fdw_cands)

static int fdw_cand_hit(struct kprobe *p, struct pt_regs *regs)
{
	struct fdw_cand *c = container_of(p, struct fdw_cand, kp);

	atomic64_inc(&c->hits);
	return 0;
}

static void fdw_scan_register(void)
{
	unsigned int i;

	for (i = 0; i < FDW_NCANDS; i++) {
		fdw_cands[i].kp.symbol_name = fdw_cands[i].sym;
		fdw_cands[i].kp.pre_handler = fdw_cand_hit;
		fdw_cands[i].live =
			register_kprobe(&fdw_cands[i].kp) == 0;
	}
}

static void fdw_scan_unregister(void)
{
	unsigned int i;

	for (i = 0; i < FDW_NCANDS; i++) {
		if (!fdw_cands[i].live)
			continue;
		unregister_kprobe(&fdw_cands[i].kp);
		pr_info("reachability: %-26s hits=%lld\n", fdw_cands[i].sym,
			(long long)atomic64_read(&fdw_cands[i].hits));
	}
}

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

/*
 * The event layer: "a file is being opened".
 *
 * Hooked on vfs_open, NOT on fd_install.  Why, measured on the target kernel:
 *
 *   fd_install         912 hits in a ten-second run, of which ZERO were
 *                      regular files - every single one was an [eventfd],
 *                      [eventpoll], pipe, socket or anon_inode.  Under
 *                      CONFIG_LTO_CLANG_FULL, path_openat() got its fd_install
 *                      inlined, so the out-of-line symbol survives only for the
 *                      other callers (dup2, pipe, eventfd, epoll, ...).  The
 *                      probe is "reachable" and the event log is still empty:
 *                      a non-zero hit count is not evidence of coverage.
 *
 *   vfs_open            26460 hits, and it sits on the open(2) path after the
 *                      file object exists and before O_TRUNC is applied, which
 *                      is exactly the moment a new file can be recognised.
 */
static void fdw_log_new_open(const struct path *path, struct file *file)
{
	struct inode *inode;
	char name[64];
	umode_t mode;
	loff_t size;

	atomic64_inc(&fdw_fd_hits);
	if (!path || !path->dentry)
		return;
	inode = d_backing_inode(path->dentry);
	if (!inode)
		return;
	mode = inode->i_mode;
	size = i_size_read(inode);

	if (debug_fds) {
		fdw_dentry_name(path->dentry, name, sizeof(name));
		pr_info("vfs_open mode=%o f_mode=0x%x size=%lld pid=%d comm=%s name='%s'\n",
			mode, file ? file->f_mode : 0, (long long)size,
			current->pid, current->comm, name);
	}

	if (!S_ISREG(mode))
		return;
	atomic64_inc(&fdw_fd_reg);
	if (!file || !(file->f_mode & FMODE_WRITE))
		return;
	if (size != 0)
		return;

	atomic64_inc(&fdw_fd_pass);
	fdw_dentry_name(path->dentry, name, sizeof(name));
	pr_info("new file '%s' pid=%d comm=%s (size=0, opened for write)\n",
		name, current->pid, current->comm);
}

/* int vfs_open(const struct path *path, struct file *file) */
static int fdw_p_vfs_open(struct kprobe *p, struct pt_regs *regs)
{
	fdw_log_new_open((const struct path *)regs->regs[0],
			 (struct file *)regs->regs[1]);
	return 0;
}

static struct kprobe fdw_kp_vfs_open = {
	.symbol_name = "vfs_open",
	.pre_handler = fdw_p_vfs_open,
};

/*
 * Arm a capture for `file`; takes its own reference on both the file and the
 * caller's creds.  Probe context only: spinlock, get_file, get_current_cred,
 * queue_delayed_work - nothing that can sleep.
 */
static bool fdw_arm(struct file *file, const char *how, loff_t want,
		    unsigned long delay_ms)
{
	struct inode *inode;
	struct fdw_slot *slot = NULL;
	unsigned long flags, i, ino;
	dev_t dev;

	if (!file || !file->f_inode || !file->f_inode->i_sb)
		return false;
	inode = file->f_inode;
	ino = (unsigned long)inode->i_ino;
	dev = (dev_t)inode->i_sb->s_dev;

	spin_lock_irqsave(&fdw_lock, flags);
	for (i = 0; i < fdw_nslots; i++) {
		if (fdw_slots[i].busy && fdw_slots[i].ino == ino &&
		    fdw_slots[i].dev == dev) {
			spin_unlock_irqrestore(&fdw_lock, flags);
			return true;	/* already tracking this inode */
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

/* long do_sys_ftruncate(unsigned int fd, loff_t length, int small) */
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

/* ssize_t vfs_write(struct file *file, const char __user *buf,
 *                   size_t count, loff_t *pos) */
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
/* reading the captured file                                           */
/* ------------------------------------------------------------------ */

/*
 * Fallback for a file we may not read through its own `struct file`: either it
 * was opened write-only (FMODE_READ clear -> kernel_read() returns -EBADF) or
 * security_file_permission() refuses the read on the creds we happen to run
 * with.  The bytes are still in the page cache, and read_mapping_page() goes
 * straight to it without the file's permission checks.
 *
 * A full-page short read is normal here: the file may be growing while we read
 * it, and the next poll will pick up more.
 */
static ssize_t fdw_read_mapping(struct inode *inode, void *buf, size_t len)
{
	pgoff_t index = 0;
	size_t done = 0;

	while (done < len) {
		struct page *page;
		size_t chunk;

		page = read_mapping_page(inode->i_mapping, index, NULL);
		if (IS_ERR(page))
			break;
		chunk = min_t(size_t, PAGE_SIZE, len - done);
		memcpy((char *)buf + done, kmap(page), chunk);
		kunmap(page);
		put_page(page);
		done += chunk;
		index++;
	}
	return (ssize_t)done;
}

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
	bool via_mapping = false;
	const struct cred *creds[3];
	unsigned int nc, i;

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
		pr_warn_ratelimited("no memory for a %lld byte dump\n",
				    (long long)size);
		return;
	}

	/*
	 * Read as whoever caused the drop.  A kworker runs in the kernel
	 * SELinux domain, which has no business reading an app's database -
	 * measured: kernel_read() came back -EACCES until this was moved inside
	 * the credential override.
	 *
	 * FMODE_READ is checked first on purpose: __kernel_read() starts with
	 * WARN_ON_ONCE(!(file->f_mode & FMODE_READ)), so calling it on the
	 * write-only file that `dd`/`cp`/most packers create would put a
	 * WARNING in the kernel log on every poll.  Such a file goes straight to
	 * the page-cache path.
	 */
	if (slot->file->f_mode & FMODE_READ) {
		old = override_creds(slot->cred);
		got = kernel_read(slot->file, buf, (size_t)size, &pos);
		revert_creds(old);
	} else {
		got = 0;
	}
	if (got <= 0) {
		got = fdw_read_mapping(inode, buf, (size_t)size);
		via_mapping = true;
	}

	if (got <= 0) {
		pr_warn_ratelimited("cannot read '%s' (%ld)\n",
				    slot->name, (long)got);
		vfree(buf);
		return;
	}

	fdw_ts(ts, sizeof(ts));
	snprintf(path, sizeof(path), "%s/%s_%s_pid%d_%s_%lu.bin",
		 dump_dir, ts, slot->how, slot->pid,
		 slot->comm[0] ? slot->comm : "?", slot->ino);

	/*
	 * Which credentials to create the dump with.  Three candidates, tried in
	 * order, because none of them is right for every case:
	 *
	 *   1. the caller's - a root/su loader gets exactly the permissions it
	 *      would have on its own, which is the normal case;
	 *   2. the loader's - captured at module_init.  An ordinary app that
	 *      causes a drop cannot write /data/local/tmp at all (measured:
	 *      -EACCES on every capture), and the kworker's own kernel domain is
	 *      refused there by SELinux too, so the module remembers the
	 *      privileged credentials it was loaded with;
	 *   3. NULL, i.e. the kworker's own creds - last resort.
	 *
	 * open, write and close all happen under the same credentials: SELinux
	 * checks the write against current(), not against the file's opener.
	 */
	nc = 0;
	creds[nc++] = slot->cred;
	if (fdw_load_cred && fdw_load_cred != slot->cred)
		creds[nc++] = fdw_load_cred;
	creds[nc++] = NULL;

	out = ERR_PTR(-EACCES);
	n = -EACCES;
	for (i = 0; i < nc; i++) {
		old = creds[i] ? override_creds(creds[i]) : NULL;
		out = filp_open(path, O_WRONLY | O_CREAT | O_TRUNC | O_LARGEFILE,
				0644);
		if (IS_ERR(out)) {
			if (creds[i])
				revert_creds(old);
			continue;
		}
		w = 0;
		n = kernel_write(out, buf, (size_t)got, &w);
		filp_close(out, NULL);
		if (creds[i])
			revert_creds(old);
		break;
	}
	vfree(buf);

	if (IS_ERR(out)) {
		atomic64_inc(&fdw_failed);
		pr_err("cannot create %s (%ld) with any of %u credential sets - does %s exist and allow writes?\n",
		       path, (long)PTR_ERR(out), nc, dump_dir);
		return;
	}

	if (n == got) {
		slot->best = (unsigned long)got;
		atomic64_inc(&fdw_captured);
		if ((unsigned long)got < (unsigned long)size)
			atomic64_inc(&fdw_partial);
		pr_info("captured %ld/%lld bytes (%s%s) -> %s (pid=%d comm=%s name=%s)\n",
			(long)got, (long long)size, slot->how,
			via_mapping ? ",pagecache" : "", path, slot->pid,
			slot->comm, slot->name);
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
	spin_lock_irq(&fdw_lock);
	slot->busy = false;
	spin_unlock_irq(&fdw_lock);
}

/* ------------------------------------------------------------------ */
/* init / exit                                                         */
/* ------------------------------------------------------------------ */

static int __init fdw_init(void)
{
	unsigned int i;
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
	fdw_load_cred = get_current_cred();
	for (i = 0; i < fdw_nslots; i++)
		INIT_DELAYED_WORK(&fdw_slots[i].work, fdw_work);

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

	if (scan_symbols) {
		fdw_scan_register();
	} else if (register_kprobe(&fdw_kp_vfs_open)) {
		pr_warn("cannot probe vfs_open - the event log stays off\n");
	}

	pr_info("v%s armed: ftruncate>=%uMiB, write>=%uKiB, dump_dir=%s, %u slots%s\n",
		FDW_VERSION, min_size_mb, min_write_kb, dump_dir, fdw_nslots,
		scan_symbols ? " (symbol scan ON)" : "");
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
	unregister_kprobe(&fdw_kp_vfs_write);
	unregister_kprobe(&fdw_kp_ftruncate);
	if (scan_symbols)
		fdw_scan_unregister();
	else
		unregister_kprobe(&fdw_kp_vfs_open);

	if (fdw_wq) {
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

	if (fdw_load_cred) {
		put_cred(fdw_load_cred);
		fdw_load_cred = NULL;
	}

	pr_info("unloaded: captured=%lld partial=%lld failed=%lld dropped=%lld  vfs_open hits=%lld regular=%lld passed-filter=%lld\n",
		(long long)atomic64_read(&fdw_captured),
		(long long)atomic64_read(&fdw_partial),
		(long long)atomic64_read(&fdw_failed),
		(long long)atomic64_read(&fdw_dropped),
		(long long)atomic64_read(&fdw_fd_hits),
		(long long)atomic64_read(&fdw_fd_reg),
		(long long)atomic64_read(&fdw_fd_pass));
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
