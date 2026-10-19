# 基准测试记录

测试机：64 核 / 251 GB / Ubuntu 22.04 / kernel 6.8（单台物理机，同机对跑）。

基线：**nginx 1.28.0**，从源码编译到 `$HOME/nginx-baseline`（
`--with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-http_stub_status_module --with-http_gzip_static_module --with-threads`）。
若要在你自己的机器上复现，请用源码编译的 nginx 1.28 作为基线——发行版自带的
nginx 常常是多模块打包版（例如缺少 lualib 的 openresty 构建），可能起不来或行为不同。

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
