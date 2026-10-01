# fdwatch-lkm

**在 fd 建立的那一刻把文件抓下来**——哪怕创建者马上 `unlink()` 掉名字、`write()` 完内容、再 `execve()` 覆盖自己。

配套工具：[`modcapture-lkm`](https://github.com/inforcqb/modcapture-lkm)（抓之后加载的所有 `.ko`）。

## 为什么必须做成内核模块

加壳器投放 stage-2 的典型流程：

```
mkstemp(path)                 建文件
unlink(path)                  删名字，只留 fd
fcntl(fd, F_SETFD, FD_CLOEXEC)
ftruncate(fd, 33 MB)          声明大小
write(fd, ...)                写解密后的 payload      ← P1 在 0x1fd3c2c/0x1fd43a4 实测
execve(path, ...)             跑起来
```

窗口只有**几百毫秒**，而且大部分时间里这个文件**没有名字**。用户态轮询 `/proc/<pid>/fd` 会输在起跑线上：本机实测一次 2.69 万 fd 的全量快照就要 **216 ms**——一整个攻击窗口，每轮。

内核不需要抢这个窗口：**在 fd 安装的瞬间对 `struct file` 取一个引用**，这个引用让 inode 一直活着，之后所有者干什么都不影响——`unlink`、`close`、`execve` 都不行。dump 可以慢慢在 workqueue 里做。

## 三个探针，三件事

| 探针 | 签名（入口寄存器） | 作用 |
|---|---|---|
| **`fd_install`** | `void fd_install(unsigned int fd, struct file *file)`<br>x0=fd, x1=file | **事件层**。凡是"刚创建的文件"（`S_ISREG` + `size==0` + 可写）就记一行：fd、basename、pid、comm。纯观察，**不取引用**，代价是几条指令。 |
| **`do_sys_ftruncate`** | `long do_sys_ftruncate(unsigned int fd, loff_t length, int small)`<br>x0=fd, x1=length | **触发层**。`ftruncate(fd, len)` 且 `len >= min_size_mb`——在没人写过的新文件上声明上兆大小，这是投放器**最锋利的特征**。这里 `fdget()` 拿引用（原子安全）。 |
| **`vfs_write`** | `ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)`<br>x0=file, x2=count | **兜底层**。不需要先 ftruncate、一次性写大块的那种：`count >= min_write_kb`。 |

命中 = `get_file()` + 一个 delayed work。延迟是必要的：触发时刻文件通常还是空的（payload 在声明大小之后才写），所以 worker 会**重试 12 次 × 400 ms**，只保留最大的那份，直到文件不再增长。

**不做什么**：不改写者的任何返回值、不阻塞被探的路径、不在探针里睡眠——处理函数只有几条 load、一个自旋锁、一次 `queue_delayed_work`。分配、文件 I/O、路径格式化全在 workqueue 里。

## 产物

```
/data/local/tmp/fdcap/<时间戳>_<如何触发>_pid<pid>_<comm>_<ino>.bin
/data/local/tmp/fdcap/index.log     每行一次捕获：how / want / size / ino / basename / pid / comm
```

`how` 是 `ftruncate` 或 `vfs_write`，也就是**它是被哪条特征抓到的**——这本身是很有用的判据。

> **加载前先建目录**：`adb shell su -c "mkdir -p /data/local/tmp/fdcap"`。模块不建目录（和 modcapture 一样），建不出来会在 dmesg 里明确报错。

## 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `dump_dir=` | `/data/local/tmp/fdcap` | 落盘目录（须已存在） |
| `enabled=` | `1` | 运行时开关 |
| `min_size_mb=` | `4` | ftruncate 触发阈值 |
| `min_write_kb=` | `256` | 单次写触发阈值 |
| `max_dump_mb=` | `128` | 超过就不 dump（只报警告） |
| `log_fds=` | `1` | 是否打 fd_install 事件日志 |
| `slots=` | `8` | 在途捕获上限（1–32） |

```sh
insmod fdwatch.ko min_size_mb=8 min_write_kb=512 dump_dir=/data/local/tmp/fdcap
```

## 构建 / 加载

CI（`.github/workflows/build-ddk.yml`）用 DDK 镜像 `ghcr.io/ylarod/ddk-min:<variant>-20260828`，
矩阵 **android13-5.15 / android14-5.15**；每个变体都会：

1. 去**目标内核树**里核对三个被探函数的原型（改了原型 → 读错寄存器 → 静默失效，所以按变体逐个查）；
2. 断言模块 import 的每个符号在该树里确实导出；
3. **断言产物的未定义符号里没有 `fd_install`/`do_sys_ftruncate`/`vfs_write`**——它们是 `register_kprobe()` 按名字解析的，一旦变成链接期依赖就说明实现回退了；
4. 断言 `.modinfo` 里有 `import_ns`（`filp_open`/`kernel_write`/`override_creds`/`revert_creds` 走 `ANDROID_GKI_VFS_EXPORT_ONLY`）。

```sh
adb push dist/fdwatch.ko-android13-5.15/fdwatch.ko /data/local/tmp/fdwatch.ko
adb shell su -c "mkdir -p /data/local/tmp/fdcap"
adb shell su -c "ksud insmod /data/local/tmp/fdwatch.ko"     # 见下
```

**加载方式**：和 modcapture 一样，这台设备（5.15.180-android13-8）的**内核不向模块导出 `filp_open`/`kernel_write`**，
普通 `insmod` 会报 `Unknown symbol filp_open (err -2)`，所以要用 `ksud insmod`。

## 已知限制

- **只抓能读的文件**。`kernel_read()` 需要 `FMODE_READ`；如果目标是 `O_WRONLY` 打开的（`mkstemp` 是 `O_RDWR`，所以正常投放器没问题），会打一条 `cannot read ... opened write-only?` 然后放弃。
- **持有 `struct file` 引用**最多 `slots × 5 s`。引用会让 inode 不被回收，这是刻意的（也正是能抓到已 unlink 文件的原因），但不要把它当长期缓存。
- **两个触发阈值都是启发式**。它们不改变任何行为，只会漏抓或误抓；误抓的代价是多写一个文件。
- **`fd_install` 日志只覆盖"新建的文件"**（`size==0`），覆盖写已有文件不会打日志。
- 本模块**不隐藏自己**。

## 实测（PJA110 / 5.15.180-android13-8-o-01179 / KernelSU，2026-10-01）

### 落点可达性（`scan=1`，一次十秒的采样）

**每个落点都真机数过命中。** 结果里有两条必须知道的事：

| 落点 | 命中 | 结论 |
|---|---|---|
| `path_openat` | 70169 | 可达 |
| `get_unused_fd_flags` | 70010 | 可达 |
| `__arm64_sys_openat` | 69181 | 可达 |
| `vfs_open` | 26460 | 可达 ← **事件层用它** |
| `vfs_write` | 1077 | 可达 ← 兜底触发 |
| **`fd_install`** | **893** | **看着可达，其实没用** —— 见下 |
| `do_sys_ftruncate` | 30 | 可达 ← 主触发 |
| `do_unlinkat` / `vfs_unlink` | 27 / 27 | 可达 |
| `do_filp_open` | 24 | 可达但很稀（大部分被内联） |
| `ksys_write` / `vfs_truncate` | **0** | **不可达，别用** |
| `__arm64_sys_openat2` | **0** | **不可达** |

### ★ `fd_install` 的教训：命中数非 0 ≠ 覆盖了你要的事件

第一版用 `fd_install` 做事件层，采样显示 **912 次命中**——看起来很健康。但把
`mode`/`f_mode`/`size` 也打进日志之后真相是：**912 次里 regular 文件是 0 个**，
全是 `[eventfd]`、`[eventpoll]`、pipe、socket、anon_inode。

原因：`CONFIG_LTO_CLANG_FULL` 把 `path_openat()` 里的 `fd_install` **内联**了，
外层符号只服务剩下的调用者（dup2、pipe、eventfd、epoll、socket…）。
所以「探针注册成功 + 命中计数在涨」完全可以是**一个和你无关的事件流**。

⇒ 换到 `vfs_open` 之后，同一次采样里 `regular` 从 **0 → 13689**。

### 端到端

```
captured=3  partial=0  failed=0  dropped=0
vfs_open hits=25611  regular=13689  passed-filter=122
```

抓到的是设备上真实的 28–34 MB 文件（`NtStartup_pool`、`thread_general` 这些进程在
`ftruncate` 大文件），内容成功落盘到 `/data/local/tmp/fdcap/`。

### 两个只在真机上才会暴露的坑（已修）

1. **`kernel_read()` 会打内核 WARNING**：它第一行就是
   `WARN_ON_ONCE(!(file->f_mode & FMODE_READ))`。而 `dd`/`cp`/多数投放器写文件用的是
   **只写**打开——每次轮询都在内核日志里留一条 `WARNING: CPU: .. at fs/read_write.c:429
   __kernel_read`。现在先用 `f_mode & FMODE_READ` 判断，只写的文件直接走页缓存路径。
2. **dump 写不出去（-13）**：镜像调用方凭据时，如果调用方是**普通 app**，
   它本身就没有 `/data/local/tmp` 的写权限；而回退到 kworker 自己的内核域，
   SELinux 对 `shell_data_file` 同样不放行。现在模块在 `module_init` 时
   **保存加载者（root/ksu）的凭据**作为第二候选，第三候选才是内核域。
   `open/write/close` 全程在同一套凭据下进行——SELinux 检查的是 `current()`，
   不是文件打开时的 `f_cred`。

### 仍未验证

- `vfs_write` 兜底在 `dd` 这类只写场景下**没有观察到触发**（3 次捕获全部来自
  `ftruncate`）。`vfs_write` 本身命中 1077 次、可达，所以要么是阈值/时序问题，
  要么 open+write 的路径还有更细的内联。主触发（`ftruncate`）不受影响。
