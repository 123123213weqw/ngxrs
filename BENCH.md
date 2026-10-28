# 基准测试记录

测试机：64 核 / 251 GB / Ubuntu 22.04 / kernel 6.8（单台物理机，同机对跑）。

基线：**nginx 1.28.0**，从源码编译到 `$HOME/nginx-baseline`（
`--with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_stub_status_module --with-http_gzip_static_module --with-threads`）。
若要在你自己的机器上复现，请用源码编译的 nginx 1.28 作为基线——发行版自带的
nginx 常常是多模块打包版（例如缺少 lualib 的 openresty 构建），可能起不来或行为不同。

## 当前结论（2026-10-28 复测，c=128，含对照组）

判据：**c≤128 吞吐 或 64 KB 尾延迟至少一项优于 nginx**。

做法：`bench/abba_raw.sh` 用 A/B/B/A 交错，每场景 6 个样本取中位数，
每个样本的完整 wrk 输出都存档以便审计（本轮两份都在 `bench/results/`）：

- `raw-20261028-160342.txt` — nginx 默认（`sendfile on`）
- `raw-20261028-161005.txt` — 对照组（nginx `sendfile off`）

各 36 个样本（3 场景 × 4 位置 × 3 轮）。

### c=128，nginx 默认（`sendfile on; tcp_nopush on`）

| 场景 | nginx | ngxrs | 比值 | nginx p99 | ngxrs p99 |
|---|---|---|---|---|---|
| 1 KB | 427,600 | 398,507 | 0.932 | 545 µs | 577 µs |
| **64 KB** | 188,775 | 189,236 | **1.002** | 39.35 ms | **749 µs** |
| 1 MB | 32,748 | 30,060 | 0.918 | 6.01 ms | 4.59 ms |

### c=128，对照组（nginx `sendfile off`）

| 场景 | nginx | ngxrs | 比值 | nginx p99 | ngxrs p99 |
|---|---|---|---|---|---|
| 1 KB | 466,770 | 401,894 | 0.861 | 506 µs | 577 µs |
| **64 KB** | 191,008 | 195,712 | **1.025** | 1.16 ms | **747 µs** |
| 1 MB | 18,945 | 30,402 | **1.605** | 15.04 ms | **4.57 ms** |

### 结论，以及必须注明的条件

- **判据是靠 64 KB 尾延迟满足的**：默认配置下 39.35 ms → 749 µs，
  对照组下 1.16 ms → 747 µs。**两种对照都占优**，所以这不只是
  「nginx 开了 `sendfile`」造成的；去掉那部分后仍剩约 **1.55×**。
- **64 KB 吞吐只能算持平**：默认 1.002、对照 1.025。上一轮记录的 1.049 没有复现，
  按实测应记为 1.00–1.03，**不能宣称明显更快的吞吐**。
- **1 KB 我们落后**（0.861–0.932），且 p99 也略差（577 µs vs 506–545 µs）。
  这个差距跨很多轮未定位；已排除定时器、内存分配、syscall 数、accept 模式。
- **1 MB 在对照组下 1.605×** 是 nginx 关掉 `sendfile` 后退化的结果
  （18,945 rps），不是我们的进步；默认配置下我们仍落后（0.918）。

复现：

```bash
CONNS=128 REPEAT=3 bash bench/abba_raw.sh                 # 默认配置
SENDFILE=off CONNS=128 REPEAT=3 bash bench/abba_raw.sh   # 对照
```

## 方法

`bench/bench.sh` 用同一份配置模板分别启动 nginx 与 ngxrs（仅端口不同），
root 指向同一目录、同一批文件：

```
worker_processes auto;
sendfile on; tcp_nopush on; tcp_nodelay on;
keepalive_timeout 65; keepalive_requests 1000000;
access_log off;
```

wrk：`-t8 -c512 -d10s --latency`，先 3 s 预热，重复 3 次取 Requests/sec 中位数。
两端都在同一台机器、同一时刻交替测，避免机器状态漂移。

## 结果（2026-10-18，第二轮）

`bench/ab.sh`：同一时刻两个服务都在跑，ABBA 交错（A B B A），每档 2 轮取中位数，
不带 `--latency`（避免客户端统计拖慢双方）。32 worker 对齐。

| 并发连接 | nginx 1.28 | ngxrs | 比值 |
|---|---|---|---|
| 128（t=24） | 636,846 | 672,818 | **1.056** |
| 1024（t=24） | 810,405 | 652,660 | 0.805 |

单 worker（`worker_processes 1`，c=64）：nginx 43,832 / ngxrs 45,288 → **1.033**。

64 KB / 1 MB 静态文件（`bench/bench.sh`，t=24 c=1024）：

| 场景 | nginx | ngxrs | 比值 | p99 |
|---|---|---|---|---|
| 64 KB | 372,749 | 357,024 | 0.958 | 28.59 ms → **6.32 ms** |
| 1 MB | 62,619 | 61,917 | 0.989 | 18.01 ms → 18.46 ms |

### TLS（`bench/tlsbench.sh`，TLS1.3，t=8 c=128，ABBA 3 轮）

| 目标 | rps | 比值 |
|---|---|---|
| nginx 1.28 | 355,795 | 1.000 |
| ngxrs | 336,679 | 0.946 |

## 测量方法上踩过的坑（重要）

1. **`ulimit -n` 必须适中。** 把 fd 上限提到 hard max（1048576）会让双方都掉速，
   而且我们掉得更多；把上限压到 1024 时，我们因 EMFILE 直接返回 500，
   wrk 会把它算成 1.0M rps 的“吞吐”——完全是假数据。现在 `bench/ab.sh`、
   `bench/bench.sh` 都会检查 `Non-2xx responses`，非 0 直接报错退出。
2. **`--latency` 会压低绝对值。** 客户端逐请求记录延迟在 800k rps 时成为瓶颈，
   吞吐对比不带 `--latency`，尾延迟单独测。
3. **这台 V100 是共享机**，别的租户在跑自己的 nginx 压测（load average 一度 30）。
   所以只能相信同一时间窗内的 A/B 比值，不能跨时段比绝对值。

## 这一轮做过的优化

1. 小文件（≤16 KB）把响应头和文件内容合并成一次 `write`，去掉第二个报文段；
   大文件仍走 `sendfile(2)`，并在 `tcp_nopush on` 时用 `TCP_CORK` 包住
   header+payload，避免 header 单独成包。
2. `Date` 头按秒缓存（thread-local），不再每请求 `gmtime_r` + 分配。
3. 线程模型改为每核一个 worker + 各自 `SO_REUSEPORT` 监听 + current_thread
   runtime，连接不再跨核迁移（对照实验：单 acceptor + mpsc 分发吞吐持平但
   p99 1 KB 从 1.2 ms 劣化到 2.95 ms，故未采用）。
4. 静态文件路径先 `metadata` 再 `open`，与 nginx 的 stat/open 次数一致；
   目录索引、ETag/Last-Modified 的计算与 nginx 对齐。

## 结论与下一步

- 大文件已基本追平（96–97%），且 p99 明显优于 nginx（64 KB 场景 12.6 倍）。
- 1 KB 仍有 ~6% 差距，热点在每请求的堆分配（响应头 `String`、ETag、
  Last-Modified 格式化）与 tokio 每请求 timer。下一步：把响应头渲染成
  `Vec<u8>` 直接写（零分配）、`Last-Modified` 用纯算术格式化、keepalive
  读超时改成连接级 deadline。
- 之后进入功能面：反向代理 / upstream / TLS / HTTP/2 / gzip / fastcgi / stream。

## Round 12 (this session) — after Vary/trailer/range work

Same host, same window, `bench/pair.sh` (ABBA interleaved) then `bench/bench.sh`
(t=8 c=128 d=10s repeat=3):

| scene | nginx 1.28 | ngxrs | ratio | avg latency |
|---|---|---|---|---|
| 1k.txt | 439,286 rps | 440,923 rps | **1.004×** | 540µs → 380µs |
| 64k.bin | 206,988 rps | 203,886 rps | 0.985× | 39.35ms → **703µs** |

The 1MB scene did not finish inside the run's timeout, so no number is claimed
for it this round. Note the 64k average latency gap: our sendfile path degrades
far less than nginx's under the same concurrency.

Static hot path was not touched this round (changes were proxy/cache/range
only), but the above numbers were re-measured rather than carried over.

## Round 13 (this session) — fresh run after intercept/limit_rate/trailer/range work

Same host, same config template, `bench/bench.sh` (t8, c512, 10s, medians).

| target | rps | p99 | ratio |
|---|---|---|---|
| nginx 1k | 447,235 | 1.28 ms | — |
| ngxrs 1k | 423,340 | 1.93 ms | 0.947 |
| nginx 64k | 203,045 | 30.62 ms | — |
| ngxrs 64k | 197,408 | **2.64 ms** | 0.972 |
| nginx 1m | 30,772 | 17.53 ms | — |
| ngxrs 1m | 29,666 | 17.42 ms | 0.964 |

`bench/ab.sh` ABBA at c=128 (T=32, 8s, 3 rounds): nginx 651,014 vs ngxrs 613,529 → **0.942**.

**Honest reading**: 1 KB throughput is still a few percent behind nginx (0.94–0.97×), and it
drifts with the host's other tenants, so cross-run absolutes are not comparable — only the
same-window ratio is. The defensible win is 64 KB tail latency: **p99 2.64 ms vs 30.62 ms
(11.6× better)** at essentially equal throughput. That is the "or tail latency" half of the
acceptance criterion; the throughput half is *not* met at 1 KB.

## 最新一轮：带 p99 的完整测量（wrk -t8 -c512 -d10s，ABBA，3 轮中位数）

**先说一个测量缺陷的修复**：此前几轮表格里的 `p99` 列一直是空的。
原因是 `bench/bench.sh` 的 `field()` 用 `index($0,k)==1` 匹配，而 wrk 输出每行都带
前导空格，所以 `"    Latency"` 永远不匹配；`99%` 那一行同理。空值被原样写进结果文件，
于是「尾延迟优于 nginx」这条验收标准**在好几轮里其实是不可验证的**。
现在 `field()` 会先剥掉前导空白，并且在任一字段解析失败时**直接报错退出**，
而不是写一个空单元格。顺带修了 `median()`：延迟值是混合单位的
（`602.00us` / `1.34ms`），`sort -g` 按数值比较会把 602 排到 1.34 前面，
现在统一换算成微秒再取中位数。

| 场景 | nginx 1.28 | ngxrs | 比值 | nginx p99 | ngxrs p99 |
|---|---|---|---|---|---|
| 1 KB | 440,678 | 418,558 | 0.950 | 1.30 ms | 1.68 ms |
| 64 KB | 198,007 | 193,870 | 0.979 | **30.46 ms** | **2.69 ms** |
| 1 MB | 30,136 | 29,035 | 0.963 | 17.48 ms | 17.72 ms |

**结论（不含糊）**：吞吐在三个场景都低于 nginx（0.95–0.98×）；
64 KB 的 p99 好 **11.3 倍**；1 KB 的 p99 反而更差（1.68 vs 1.30 ms），1 MB 基本持平。
所以「尾延迟优于 nginx」只在 64 KB 这个场景成立，不能推广。

### 并发扫描（1 KB，wrk -t8 -d5s，ABBA 两轮均值）

| 并发 | nginx | ngxrs | 比值 |
|---|---|---|---|
| 8 | 81,637 | 103,832 | **1.272** |
| 32 | 379,473 | 369,319 | 0.973 |
| 128 | 407,490 | 425,130 | **1.043** |
| 512 | 437,161 | 418,471 | 0.957 |
| 1024 | 433,532 | 393,335 | 0.907 |

低并发赢 27%，中并发（c=128）赢 4%，高并发输 4–9%。**比值随并发单调下降**，
说明我们的每连接开销比 nginx 增长得快。这一点机制上还没定位，不做猜测性修复。

### 被排除的假设（有对照实验）

上一轮猜测「每请求一次 tokio 定时器唤醒」是 1 KB 差距的来源。用现成的
`NGXRS_NO_IDLE_TIMER=1` 开关做 ABBA 对照（c=512，各 6 次）：

| 配置 | 中位数 rps |
|---|---|
| 定时器开 | 425,178 |
| 定时器关 | 426,487 |

差 0.3%，在噪声内。**该假设被排除**，后续不再重复验证。
另外确认了静态热路径上**没有**每请求 `tokio::spawn`（每连接一个任务，keepalive 循环在任务内），
1 KB 走的是「pread + 单次 write」，与 nginx 的「writev + sendfile」同为 2 个系统调用。

## 每请求分配次数：先测，再优化（本轮）

1 KB 静态请求每次分配多少？没有工具就直接量。加了 `--features alloc-count`
的全局计数分配器和一个 `/_alloc` 端点（默认构建完全不受影响），按阶段记账：

| 阶段 | 优化前 | 优化后 |
|---|---|---|
| 请求解析 | 10.0 | 10.0 |
| 派发（路由+内容+写出） | 25.0 | 14.0 |
| 访问日志 | 0.0 | 0.0 |
| **合计** | **47.0** | **24.0** |

砍掉的分配（都是纯浪费）：

- `split_head(&resp.raw)` **无条件**执行：`$sent_http_*` 是它唯一的消费者，
  而 `access_log` 关闭时 `log_access` 立刻返回。每个响应头两 `String`，
  一次请求约 12 次分配白烧。现在按「有没有 access log」门控。
- ETag 的 `format!("{:x}-{:x}")` 和 `http_date()` 每请求各一次分配：
  ETag 改成写进 40 字节栈缓冲，`Last-Modified` 只在 304 分支才生成。
- `Content-Length` / `Content-Range` 的 `to_string()` 换成手写 itoa。
- `extension()` 返回 `&str`，mime 查表用栈缓冲做小写化，不再分配。
- `conn.peer.ip().to_string()` 和 `conn.local_addr()...to_string()`
  每请求算一次，但它们在一条连接上恒定——提到连接作用域。

**结果：分配次数减半，吞吐没变。** 用「旧二进制 vs 新二进制」同时在线
对跑（ABBA，排除 nginx 与机器噪声）：

| 并发 | 旧 | 新 | 新/旧 |
|---|---|---|---|
| 128 | 421,282 | 427,381 | 1.014 |
| 512 | 417,186 | 418,622 | 1.003 |
| 1024 | 406,225 | 402,095 | 0.990 |

**结论：分配不是高并发差距的原因，该假设被排除。** 47 次/请求在 400k rps 下
约 19M 次/秒，glibc 的 tcache 完全吃得下。这些改动本身仍然保留——它们减少了
真实工作量、内存开销与尾延迟抖动——但不能算作性能修复，不应被当成那样宣传。

至此已用对照实验排除：每请求定时器（425,178 vs 426,487，0.3%）、
每请求 task spawn（代码中不存在）、系统调用数（两边都是 1 读 1 写）、
accept 模式、fd 上限、内存分配（本节）。`perf` 在本机被
`kernel.perf_event_paranoid=4` 挡住且无 root，无法取火焰图，
所以高并发那 5% 的机制**仍未定位**，不做猜测性修改。

### 当前可站住的性能结论

| 指标 | 结果 |
|---|---|
| 低并发 c=8 吞吐 | **1.27×** nginx |
| c=128 吞吐 | **1.06×** nginx |
| 64 KB p99 | **2.69 ms vs nginx 30.46 ms（11.3×）** |
| c=512 / c=1024 吞吐 | 0.94× / 0.95× nginx |
| 1 KB p99 | 1.68 ms vs nginx 1.30 ms（更差） |

即：**尾延迟在高并发大响应场景显著更好，吞吐在低/中并发更好，高并发略差。**
不能笼统说「比 nginx 快」。

## 更正：64 KB 尾延迟优势是 `sendfile` 的取舍，不是我们的设计优势

此前多轮把「64 KB p99 好 11 倍」当成验收标准里「尾延迟」那一半的证据。**这个归因是错的。**

同一台机器、同一份配置，只改 nginx 的 `sendfile`（其余 `tcp_nopush on; tcp_nodelay on;` 与
`worker_processes auto` 完全相同），wrk `-t8 -c512 -d5s`，各跑 2 轮：

| 服务 | sendfile | rps | p99 |
|---|---|---|---|
| nginx 1.28 | **on** | 210,668 / 206,111 | **32.56 / 29.88 ms** |
| nginx 1.28 | **off** | 188,635 / 194,453 | **2.97 / 2.97 ms** |
| ngxrs | — | 197,352 / 197,412 | **2.68 / 2.66 ms** |

结论：

- nginx 的 10 倍尾延迟差异来自 `sendfile on`，关掉它就消失（代价是约 7% 吞吐：210k → 190k）。
- 我们的 2.68 ms 只是「走缓冲写」这个工作点的结果，与 nginx 关掉 sendfile 后的 2.97 ms
  基本同一水平（好约 10%，吞吐高约 3.5%）。
- 所以**不能**说我们比 nginx 尾延迟好 11 倍。正确的说法是：我们默认处在
  nginx 需要显式配置才能到达的工作点上，且在该工作点上略好一点。

单 worker（`worker_processes 1`）时这个差异更极端，但方向一致：nginx p99 **1.08 s**，
ngxrs 24–40 ms，而 nginx 吞吐仍高约 24%（28.7k vs 21.8k）。

### 当前吞吐对照（`-t8 -d5s --latency`，同窗口）

| 场景 | nginx rps | ngxrs rps | 比值 | nginx p99 | ngxrs p99 |
|---|---|---|---|---|---|
| 1 KB c=512 | 459,762 | 424,529 | 0.923 | 1.29 ms | **2.63 ms（更差）** |
| 1 KB c=1024 | 448,261 | 420,519 | 0.938 | 2.41 ms | **4.19 ms（更差）** |
| 64 KB c=512 | 210,537 | 197,386 | 0.938 | 18.44 ms | 2.68 ms |
| 1 MB c=512 | 31,031 | 29,491 | 0.950 | 17.57 ms | 17.76 ms |
| 1 KB c=8 | 94,399 | 89,701 | 0.950 | — | — |

**在吞吐上我们没有任何场景超过 nginx**；c=8 曾经量到过的 1.27× 在后续轮次无法复现，
已从结论中撤下。1 KB 的 p99 我们明显更差，且原因未定位。

## 性能诊断：每请求 CPU 成本（本轮，带 ABBA 交错与 schedstat）

前面几轮一直用吞吐和 p99 判断，但都没有回答"差在哪里"。这台机器没有 `perf`
（`perf_event_paranoid=4`、无 root），所以改用两种可用的观测：

- `/proc/<pid>/task/<tid>/schedstat`：线程级 CPU 时间与运行队列等待。
- `src/prof.rs`（`NGXRS_PROF=1`）：请求内部分阶段线程 CPU 计时，`/_prof` 导出。

### 已经排除的

| 假设 | 证据 |
|---|---|
| 调度不公 | 运行队列等待两边都 ~0.2 µs/请求 |
| 连接反复重建 | 515 次 accept 服务 ~120 万请求，两边相同 |
| 响应字节不同 | 头 240 字节完全一致 |
| 系统调用更多 | 我们 6 次/请求，nginx 8 次（`strace -c`） |
| 阻塞线程池 | 请求路径上没有 `spawn_blocking`/`tokio::fs` |

### 主结论：是 CPU，而且随线程数放大

`/ret`（`return 200 "hello"`，完全不碰文件系统）每请求 CPU，
ABBA 交错、3 轮中位数，`-t4 -d3s`：

| worker 数 | nginx µs/请求 | ngxrs µs/请求 | 比值 |
|---|---|---|---|
| 1 | 14.3 | 18.9 | 1.32 |
| 2 | 15.2 | 19.2 | 1.26 |
| 4 | 15.2 | 19.1 | 1.26 |
| 8 | 20.6 | 23.4 | 1.14 |
| 16 | 24.6 | 36.8 | 1.50 |
| 32 | 25.1 | 59.3 | 2.36 |
| 64 | 24.8 | 67.2 | 2.71 |

**读法很重要**：从 8 个 worker 起 nginx 的吞吐已经封顶（~280k rps，8→64 worker
几乎不变），它**不再是 CPU 受限**；此时比较"每请求 CPU"是在拿一个饱和的服务器
比一个没饱和的。真正可比的是 ≤8 worker（双方都 CPU 受限）区间：
**ngxrs 的每请求 CPU 是 nginx 的 1.14–1.32 倍**。

之前几轮报过的"2.2 倍"来自 64 worker 的测量，是机器被 64+8 个线程压满
（含超线程兄弟核、共享租户）后的放大结果，不应作为"我们慢一倍"的结论。

### 已做的一个改动

`shutdown_notify().notified()` 原来建在**每请求**循环里。tokio 的 `Notify`
等待队列由互斥锁保护，等于每个请求都在所有 worker 之间争这把锁。改为
**每连接**注册一次。

效果：吞吐 +4%（`/ret` 243k → 254k，`/1k.txt` 236k → 239k），但每请求 CPU
比值在噪声范围内（±12%）没有明显改善。所以**不能**说这是主因，只能说它本来
就不该在热路径上。

验证：`http_keepalive_shutdown.t` 3/3、`proxy_available.t` 4/4、`http_keepalive.t`
21/23、`limit_conn.t` 10/10，全部与 nginx 一致（这几个正是依赖优雅停机语义的
用例集）；`bench/all.sh` 70/70。

### 仍未定位

1.14–1.32 倍的剩余差距在 8 worker 以下稳定存在，说明是**绝对效率**问题而非
争用：每请求 ~5 µs（约 15000 周期）花在我们有而 nginx 没有的东西上。候选是
tokio 的 park/unpark 与任务唤醒、每请求约 24 次堆分配、以及 `ServerVars` 等
per-request 结构体的构造。要定位需要能采样调用栈的剖析器，这台机器上没有。

## 框架地板校准：tokio 不是瓶颈，差距全在 HTTP 层

上一轮只知道"每请求 CPU 是 nginx 的 1.14–1.32 倍"，不知道钱花在哪。这轮做了一个
**地板校准**：`bench/floor.rs` 是一个最小 tokio 服务器（同款每连接一个 task、同款
每 worker 一个 current-thread runtime、同款 240 字节响应头 + 1024 字节体、SO_REUSEPORT），
只读请求头再写固定响应，不解析、不路由、不碰文件。

`bench/floorcmp.py`，`-t4 -c128 -d3s`，1 worker，ABBA 交错 3 轮取中位数：

| 端点 | nginx | 地板 | ngxrs | ngxrs−地板 | nginx−地板 |
|---|---|---|---|---|---|
| `/ret`（不碰文件） | 14.16 µs | 11.31 µs | 18.54 µs | **7.2 µs** | 2.85 µs |
| `/1k.txt`（静态） | 23.07 µs | 11.48 µs | 26.57 µs | 15.1 µs | 11.6 µs |

三条结论：

1. **tokio 不是问题**。最小 tokio 服务器是 nginx 的 **0.50 倍 CPU**（快一倍）。
   所以"Rust 异步框架开销大"这个假设被证伪。
2. **我们的文件服务比 nginx 更省**。从地板算增量：ngxrs 静态度量 8.0 µs，
   nginx 11.6 µs。文件路径（open/stat/read 或 sendfile）我们反而占优。
3. **全部赤字在 HTTP 请求层**：7.2 µs vs nginx 的 2.85 µs，多 4.4 µs。

这也解释了之前几个看似矛盾的比值：`/ret` 是 1.31、`/1k.txt` 是 1.15——因为静态
文件开销大，把 HTTP 层的差距**稀释**了。用比值看 HTTP 层会被掩盖，用"减去地板"
的绝对增量才看得清。

## 已定位的一个真实缺陷：location 匹配是线性的

`bench/locscale.py`：同样服务 `/ret`，只改配置里 `location` 的个数。

| 服务 | 2 个 | 20 个 | 200 个 | 增量 |
|---|---|---|---|---|
| nginx | 14.53 µs | 14.68 µs | 14.73 µs | **+0.20 µs** |
| ngxrs | 18.60 µs | 18.91 µs | 21.66 µs | **+3.06 µs** |

nginx 用前缀树，条数无关。我们的 `match_list` 对每个请求做**两趟全表线性扫描**
（先前缀、再正则），所以成本随 location 数线性增长。

这与基准配置无关（那里只有 2 个 location），但生产配置动辄几十上百个 location，
所以是真实缺陷。修法是把前缀 location 按长度降序预排序（首个命中即最长匹配，可
提前退出）+ 正则单独一张表；因为会改动 `Location` 列表顺序（`find_location`、
`locate_named`、auto_redirect 都依赖声明顺序），风险不小，本轮只测量不重构。

## 仍未定位

HTTP 层那 4.4 µs。已知它不在：tokio、文件 I/O、日志（`access_log off` 时
`log_access` 首行就返回）、`ServerVars`（纯引用结构体）、系统调用数量（6 vs 8）。
下一步候选：请求头解析、`finalize_response` 的过滤器链、响应头渲染。

## 四段归因：找到了 16 KB 的 memset，并推翻上一轮的结论

上一轮用"最小 tokio 地板"减出"HTTP 层多 4.4 µs"，但没定位到代码。这轮加了
`bench/skipcmp.py`：在解析完请求头之后立刻应答（`NGXRS_SKIP_AFTER_PARSE=1`，
返回与 `/ret` 同样的 200 + 5 字节体），于是四点可比：

```
floor     裸 tokio：读头 + 写固定响应
skip      ngxrs 解析完就应答 = 我们的解析器 + 连接循环
full      ngxrs 真正跑 location /ret
nginx     参照
skip - floor   = 解析器 + 连接循环
full - skip    = 路由 + 过滤器 + 渲染
```

1 worker、`-t4 -c128 -d3s`、交错取中位数：

| 点位 | 修复前 | 修复后 |
|---|---|---|
| nginx | 14.32 µs | 14.36 µs |
| floor | 11.01 µs | 10.99 µs |
| skip | 18.21 µs | **13.69 µs** |
| full | 18.74 µs | 17.90 µs |

### 缺陷：每次 read 都零初始化 16 KB 栈缓冲

```rust
async fn fill(&mut self) -> io::Result<usize> {
    let mut tmp = [0u8; 16 * 1024];      // 每次 read 都 memset 16 KB
    let n = self.stream.read(&mut tmp).await?;
```

注释写的是"避免把 16 KB 零填充进 self.buf"，但它在**栈上**照样零填充了 16 KB，
而且是在 keepalive 连接的**每个请求**上做一次，外加弄脏 256 条 cache line
（16 KB 已经超过 L1）。改成每连接一次的 staging 缓冲后：

- 解析器 + 连接循环：+7.21 µs → **+2.70 µs**
- 完整路径：18.74 µs → **17.90 µs**（−4.5% CPU）
- 1 worker c=64 的 `/1k.txt`：37,454 → **38,421 rps**，比值 0.881 → **0.901**

### 必须撤回的上一轮结论

上一轮我写"路由 + 过滤器 + 渲染只花 −0.27 µs，基本免费"。**那是测量假象。**
16 KB memset 被算进了 skip 变体，把 skip 抬到和 full 一样高，于是 full−skip 被压成 0。
memset 修掉之后真实数字是 **+4.21 µs**，它现在是最大的一项。

教训和之前几次同类：一个未归因的固定开销会**同时**扭曲基准差值和它的分解。
只有把被测量的路径本身拆到足够细，差值才可信。

### 顺带确认

`NGXRS_NO_IDLE_TIMER` 开关显示每请求的 keepalive 定时器重置是 **+0.00 µs**
（之前怀疑过它），可以排除。

## 当前分解（1 worker，修复后）

| 项 | 我们 | nginx |
|---|---|---|
| 解析器 + 连接循环（− floor） | +2.70 µs | — |
| 路由 + 过滤器 + 渲染 | +4.21 µs | — |
| **合计 − floor** | **+6.91 µs** | **+3.37 µs** |

解析器这一段我们已经**优于 nginx**（2.70 vs nginx 整个栈的 3.37）。赤字全部
转移到了路由/过滤器/渲染这一段，下一步从那里下手：`finalize_response` 每请求都做
`path.to_string()` + `query.to_string()` + `cur_loc.root.to_string_lossy().to_string()`
三次分配，并**重新做一次 location 匹配**（调用方 `handle_conn_inner` 已经算过 `loc`）。

## 分阶段归因：把"路由/渲染"再拆开

上一轮把赤字定位到"路由+过滤器+渲染 +4.21 µs"，但那一整段太粗。这轮把它拆成
可测量的阶段停点（`NGXRS_STOP_STAGE=N`，N=1 解析后、N=2 URL 规范化后），
配合 `bench/skipcmp.py`：

| 阶段（1 worker，−floor） | 时间 |
|---|---|
| 解析器 + 连接循环 | +2.63 µs |
| `parse_target`（URL 规范化） | +0.86 µs |
| location 匹配之后的一切 | +3.57 µs |
| **合计** | **+7.06 µs**（nginx 全栈 +3.37） |

## 本轮修掉的：`parse_target` 里的无谓分配

三处，都是每请求一次：

1. `absolute_form_to_origin` 对每个请求 `raw[..8].to_ascii_lowercase()` 造一个
   8 字节 String，然后对 origin-form（99.9% 的请求）立刻丢弃。改成按字节不区分
   大小写比较。
2. `percent_decode` 无论如何都 `Vec::with_capacity` + 转 String；没有 `%` 时直接返回输入。
3. `normalize_path` 无论路径多简单都建 `Vec<&str>` 再 join；无 `..`/`//`/`/./` 时直接返回输入。

`parse_target` 段：**1.00 µs → 0.86 µs**。

### 这里踩了一个真坑

第 1 项第一版写成 `head.len() == want.len()`，而 `http://` 是 7 字节、`https://` 是
8 字节，我却拿 8 字节的头去比 7 字节的前缀，于是**所有 absolute-form 请求都失效**。
单元测试 `absolute_form_with_query` / `targets` 立刻抓到了。改成
`head.len() >= want.len() && head[..want.len()]` 后通过。

## 一次失败的重构（已回退，未造成损害）

本轮先试图把 `finalize_response` 里每请求的
`path.to_string()` + `query.to_string()` + `root.to_string_lossy().to_string()`
和**第二次 location 匹配**去掉。改法是让 `cur_path`/`cur_query` 变成 `&str`
借用、把重定向后的值存进 `Option<(String,String)>`、`cur_loc` 变成
`Option<&LocCfg>` 回落到调用方已算出的 `loc`。

结果：`finalize_response` 主体改完了，但 12 个调用点、`render_resolved_state`
的签名也被我用一个批量替换改到了，出现 35 个编译错误，其中 12 个是"把参数加到了
错误的函数上"。**已 `git checkout` 全部回退**，回到干净可编译状态。

这次和之前一次批量脚本事故是同一类错误：**不要用文本批量替换去改跨函数的签名**。
而且事后看，这三个分配总共约 150 ns，根本解释不了 4.21 µs——即使改对也不会有效果。
正确的做法是本轮采用的办法：先用阶段停点测出钱花在哪，再动手。

## 顺带发现一个此前从未测量过的缺口

跑 URL 相关用例时第一次带上 `autoindex.t`：**12/18（nginx 18/18）**。
失败的 6 条是符号链接目录、超长名字、以及 HTML 转义/UTF-8 长名的三组转义。
我用 `git stash` 回到改动前的二进制重跑，**同样是 12/18**，所以是既有缺口，
不是本轮引入的。记入待办。

## 2026-10-28 — c=128 ABBA，含 `SENDFILE=off` 对照组（本轮新原始数据）

两次独立运行，各自 `REPEAT=3`、ABBA 交错，原始 wrk 输出逐样本保留：

```
默认（nginx sendfile on） : bench/results/raw-20261028-210446.txt
对照（SENDFILE=off）      : bench/results/raw-20261028-211248.txt
```

| 场景 | 条件 | nginx rps | ngxrs rps | 比值 | nginx p99 | ngxrs p99 |
|---|---|---|---|---|---|---|
| 1 KB | 默认 | 436,361 | 398,648 | **0.914** | 538 µs | 581 µs |
| 64 KB | 默认 | 189,693 | 194,828 | **1.027** | **39.33 ms** | **747 µs** |
| 1 MB | 默认 | 32,793 | 30,060 | **0.917** | 5.84 ms | 4.66 ms |
| 1 KB | 对照 | 442,164 | 399,489 | **0.903** | 518 µs | 615 µs |
| 64 KB | 对照 | 188,175 | 194,161 | **1.032** | **1.18 ms** | **750 µs** |
| 1 MB | 对照 | 18,327 | 29,971 | 1.635 | 13.51 ms | 4.64 ms |

### 怎么读这张表

- **64 KB 是唯一站得住的优势，而且两种条件都成立**：吞吐 1.027 / 1.032，
  尾延迟 747 µs vs 39.33 ms（默认）与 750 µs vs 1.18 ms（对照）。
  对照条件下 nginx 已经关掉 `sendfile`，所以这不是拿它的可调参数当自己的优势——
  在同等 `sendfile` 设置下 64 KB 的 p99 仍然是我们的 1/1.6。
- **1 KB 落后约 9%，且 p99 也更差**（581 µs vs 538 µs）。这一项跨多轮没有改善。
- **1 MB 默认落后 8%**；对照组的 1.635 是 **nginx 自己退化**（32.8k → 18.3k），
  不是我们变快——我们的 30.1k → 30.0k 基本没动。这一格不能算作优势。
- `sendfile` 对 nginx 的影响只出现在大响应（1 MB 退化 44%、p99 从 5.84 ms 涨到 13.51 ms），
  与早前"关掉 sendfile 后 nginx 的 64 KB p99 从 30 ms 掉到 ~3 ms"的观察一致：
  那条 11 倍差距主要来自 nginx 的默认取值，已被撤回，此处不再重复。

### 判据

验收要求"吞吐**或** 64 KB 尾延迟至少一项优于 nginx"。按上表：**64 KB 两项都优于 nginx，
且默认与对照两种情况都成立**。1 KB 与 1 MB 吞吐不占优，如实记录。

## 2026-10-29 — ABBA c=128，默认与 SENDFILE=off 对照

原始输出：`bench/results/raw-20261029-011710.txt`（默认）、
`bench/results/raw-20261029-012418.txt`（对照）。各 `REPEAT=3`，A/B/B/A。

| 场景 | 条件 | nginx rps | ngxrs rps | 比值 | nginx p99 | ngxrs p99 |
|---|---|---|---|---|---|---|
| 1k.txt | 默认 | 397,325 | 386,208 | **0.972** | 585 µs | 530 µs |
| 64k.bin | 默认 | 193,262 | 185,970 | **0.962** | **39.30 ms** | **789 µs** |
| 1m.bin | 默认 | 32,650 | 30,003 | **0.919** | 6.15 ms | 4.59 ms |
| 1k.txt | 对照 | 429,561 | 388,362 | **0.904** | 507 µs | 539 µs |
| 64k.bin | 对照 | 181,347 | 192,680 | **1.062** | **1.22 ms** | **768 µs** |
| 1m.bin | 对照 | 18,236 | 30,495 | 1.672 | 15.60 ms | 4.57 ms |

读法：

- **吞吐仍落后**：1k 0.972/0.904、64k 0.962、1m 0.919（默认）。
- **64 KB 是唯一站得住的优势**：尾延迟 39.30 ms → 0.79 ms；对照条件下 nginx 关掉
  `sendfile` 后 p99 降到 1.22 ms，我们 0.77 ms 仍低约 1.6×，所以这不是把它的可调参数
  当成我们的优势。
- **1m 对照的 1.672 不算优势**：那是 nginx 自己从 32.6k 掉到 18.2k 的退化，
  我们 30.0k → 30.5k 基本没动。

## 2026-10-29 (2) — ABBA c=128，本轮改动后

原始输出：`bench/results/raw-20261029-023019.txt`（默认）、
`raw-20261029-023642.txt`（对照）。`REPEAT=3`，A/B/B/A。

| 场景 | 条件 | nginx rps | ngxrs rps | 比值 | nginx p99 | ngxrs p99 |
|---|---|---|---|---|---|---|
| 1k.txt | 默认 | 404,730 | 395,098 | **0.976** | 605 µs | 621 µs |
| 64k.bin | 默认 | 191,918 | 192,060 | **1.001** | **39.32 ms** | **753 µs** |
| 1m.bin | 默认 | 32,713 | 30,314 | **0.927** | 6.04 ms | 4.61 ms |
| 1k.txt | 对照 | 435,782 | 399,222 | **0.916** | 516 µs | 584 µs |
| 64k.bin | 对照 | 186,082 | 190,442 | **1.023** | **1.21 ms** | **759 µs** |
| 1m.bin | 对照 | 17,394 | 30,477 | 1.752 | 14.37 ms | 4.52 ms |

与此前一致：吞吐仍落后（1k 0.976/0.916、64k 1.001、1m 0.927），
**64 KB 尾延迟在两种条件下都占优**（39.32 ms → 0.75 ms；对照 1.21 ms → 0.76 ms，
即去掉 sendfile 因素后仍是 1.6×），1m 对照的 1.752 是 nginx 自身退化，不算优势。
本轮代码改动只在 stream（access / ssl_alpn），未触及 HTTP 热路径，数字吻合这一点。
