# nginx 兼容矩阵

图例：`✅` 已实现并测过 · `🟡` 部分实现/有已知差异 · `⬜` 未实现

对照基线：**nginx 1.28.0**（V100 上源码编译，`$HOME/nginx-baseline/sbin/nginx`）。
所有数字都来自同一台机器上 ngxrs 与 nginx 的 **A/B 逐断言比对**，不是单边通过率。

## 一、验收判据与当前状态

判据只有一条：**「nginx 通过而 ngxrs 不通过」的断言数必须为 0**（在下方声明清单上）。
绝对通过率没有意义——nginx-tests 里的套件会因为 Test::Nginx 版本、`-V` 特性门控、
参考构建的编译选项而在两边一起失败，那种失败不构成我们的缺陷。

| 项 | 命令 | 当前结果 |
|---|---|---|
| 声明清单 A/B | `bash bench/declared.sh` | **PASS** — 135 文件，WORSE=0 TRUNC=0（nginx 2142 / ngxrs 2147，130 个逐断言一致、5 个更优） |
| 自有差分套件 | `bash bench/all.sh` | **PASS** — 70/70（19 静态 + 28 功能 + 9 TLS/H2 + 14 fastcgi/uwsgi/scgi/grpc/stream） |
| 单元测试 | `cargo test --release` | **PASS** — 175 passed |
| 性能 | `CONNS=128 REPEAT=3 bash bench/abba_raw.sh` | 见 `BENCH.md`；c=128 吞吐与 64 KB 尾延迟均优于 nginx，条件见该文件 |

## 一之二、2026-10-27 轮：范围纠偏、realip 信任判定、auth_basic

三条都是同机 A/B 实测，不是推断。

### 1. 声明范围此前按「nginx 默认构建」写，与参考二进制不符

`~/nginx-baseline/sbin/nginx -V` 的 configure 参数里有
`--with-http_realip_module --with-http_auth_request_module --with-http_slice_module
--with-http_sub_module --with-http_secure_link_module --with-http_dav_module
--with-http_stub_status_module --with-http_gzip_static_module --with-threads
--with-stream --with-stream_ssl_module --with-stream_realip_module
--with-mail --with-mail_ssl_module`。这些模块**在范围内**，此前却被当成「默认构建没有」
排除掉了。按修正后的范围跑 20 个此前从未计分的文件：

| 结果 | 文件 |
|---|---|
| SAME（12） | `realip.t` 10/10、`realip_remote_addr.t` 6/6、`realip_remote_port.t` 6/6、`auth_request_satisfy.t` 20/20、`auth_request_set.t` 8/8、`sub_filter_merge.t` 3/3、`stub_status.t` 36/36、`limit_req.t` 8/8、`limit_req_delay.t` 6/6、`limit_conn.t` 10/10、`limit_conn_complex.t` 6/6 |
| WORSE（8，共 42 断言） | `slice.t` 23、`secure_link.t` 6、`limit_req2.t` 5、`realip_hostname.t` 2、`auth_basic.t` 2、`sub_filter_multi.t` 2、`auth_request.t` 1、`sub_filter.t` 1 |

其中 12 个持平的文件里 6 个（`realip_remote_addr/port`、`auth_request_satisfy/set`、
`limit_req*`、`limit_conn*`）已加入声明清单——它们本来就是通过状态，只是从未被计分。
声明清单 **76 → 83 文件**。

`bench/nginxtests.sh` 里那张 `SKIP_ALWAYS` 表是死代码：定义了却从未被引用，
而且名单里 `realip auth_request limit_req limit_conn secure_link sub` 全都已实现。
已删除，改为指向 `bench/declared.txt`。

### 2. realip：`$remote_addr` 可被任意客户端伪造（已修）

修复前，只要某个 location 配了**任意** `set_real_ip_from`，非 `X-Forwarded-For` 的
头（默认 `X-Real-IP`）就不做信任判定，直接采信。同机 A/B（静态文件，peer 127.0.0.1，
`set_real_ip_from 192.0.2.0/24`，带 `X-Real-IP: 192.0.2.1`）：

```
nginx : X-IP: 127.0.0.1      ngxrs(修前): X-IP: 192.0.2.1
```

`$remote_addr` 是 `allow`/`deny`、`limit_req`/`limit_conn` 的键和 `access_log` 的内容，
所以这是一个可绕过访问控制的问题。nginx 在 `ngx_http_realip_handler` 里先做
`ngx_cidr_match(c->sockaddr, ...)` 再取值；现在同样先判 peer 是否受信。

同一处补齐了另外两种取值形式（`realip_hostname.t` 由 4/6 → 6/6）：

- `set_real_ip_from <hostname>`：配置期用 `getaddrinfo` 解析（等价
  `ngx_inet_resolve_host`）；解析失败按 nginx 的报错文本写进告警，不再静默丢弃。
- `set_real_ip_from unix:`：unix socket 的 peer 没有地址（`$remote_addr` 是 `unix:`），
  单独用 `realip_from_unix` 记，只有显式写了 `unix:` 才信任。

修后同一组 A/B：`/u`(不受信) 127.0.0.1、`/t`(受信) 192.0.2.1、`/h`(主机名) 192.0.2.1、
`/none`(未配置) 127.0.0.1，四项与 nginx 逐字节一致。

### 3. auth_basic：`$apr1$` 与变量路径（已修，27/27）

- `$apr1$`（Apache `htpasswd -m` 的默认格式）此前落到 `crypt(3)`，而本机 libxcrypt
  不认这个前缀（`crypt("password","$apr1$salt$...")` 返回 `*0`），nginx 则自带
  `ngx_crypt_apr1`。现在在 `src/auth.rs` 内实现 apr1（含所需的最小 MD5），
  以 `auth_basic.t` 的向量 `$apr1$salt$Xxd1irWT9ycqoYxGFn4cb.` 与 RFC 1321 向量做单测。
- `auth_basic_user_file $arg_f`：原样存成路径，永远打不开。现在配置期先把相对路径
  锚到配置前缀、请求期再展开变量。同一处也顺带修正了**静态相对路径**的解析。

### 仍有的偏差（下一轮）

- `auth_request.t` 19/22：子请求打到 `fastcgi_pass` location 时返回 500 而非上游状态。
  `fastcgi::handle` 直接写连接，子请求需要缓冲版 `Response`，属于重构而非补丁，未在本轮动。
- `slice.t` 23 条：`ngx_http_slice_module` 未实现。
- `secure_link.t` 6 条、`limit_req2.t` 5 条、`sub_filter.t` 1 条 / `sub_filter_multi.t` 2 条：未实现或语义差异。

## 一之三、2026-10-27 第二轮：sub_filter 语义、limit 空键与 dry run、配置文本编码

### 1. 配置里所有非 ASCII 文本都被写成乱码（已修）

`$var` 展开函数在拷贝字面量时逐字节 `push(b as char)`，把每个字节当成一个 Latin-1 码点，
再按 UTF-8 编码输出。`模様`（`E6 A8 A1 E6 A7 98`）因此变成 `æ¨¡æ§˜`（`C3 A6 C2 A8 ...`）。

后果不只是难看：`sub_filter 模様 替换` 里的模式在进程内是乱码，永远匹配不到真正的
UTF-8 body。同机 A/B（`sub_filter 模様 zast1`，body 来自 `$arg_a`）：

```
nginx : ТЕКСТzast1ТЕКСТ      ngxrs(修前): ТЕКСТ模様ТЕКСТ（未替换）
```

修了 9 处展开器：`http/mod.rs` 的 `expand_vars` / `expand_captures` /
`expand_captures_args` / `ServerVars::expand` / `limit_key`，以及 `ssi.rs`、`proxy.rs`（2 处）、
`fastcgi.rs`、`uwsgi_scgi.rs`、`cache.rs`、`cookie.rs`。做法是把字面量整段按 `&str` 切片拷贝
（`$` 是 ASCII，切片边界必然合法），比逐字节 push 还快。SSI 的 `escape_entity` 改为按字符遍历。

顺带把 `ssi.t` 从 30/32 拉到 **32/32**。

### 2. sub_filter 的匹配模型是错的（已修，2 个文件全平）

原实现把多条规则当成独立流水线依次全局替换。nginx 不是这样：

- **每个位置取最长匹配**（模式按长度降序排好，`ngx_http_sub_match` 取第一个命中的）。
  `sub_filter_multi.t` 的 "partial match" 就是这一点：`aabb -> +` 与 `aaabb -> -` 处理
  `aabbaaabbaabb`，nginx 给 `+-+`，流水线模型给 `+a++`。
- **`sub_filter_once on` 是按模式计**，不是按请求计：每个模式各替换一次后置位。
  `aabyyzaab`（`aab`/`yyz`）→ `+-aab`。
- **替换结果不会被再次扫描**：`sub_filter a b; sub_filter b c;` 处理 `a` 得 `b`（实测 nginx）。
  旧单测断言的是 `c`，那是错的，已按实测改正。

同时补上：`sub_filter` 现在**也作用于代理响应**。此前 `wants_buffered` 只看 `ssi` 与 `gzip`，
代理响应直接流式写 socket，`sub_filter` 完全没跑（`sub_filter.t` 的 `/lm` 用例即此）；
现在有 `sub_filter` 的 location 走缓冲取回，WebSocket 升级仍走流式。
另外按 nginx 的 header filter 语义，过滤器一装上就清 `Content-Length` / `Accept-Ranges`，
并按 `sub_filter_last_modified` 决定「丢两个验证器」还是「留 Last-Modified + 弱化 ETag」。

`sub_filter_buffering` 此前是未识别指令，现在会解析（nginx 默认 on，我们始终缓冲）。

结果：`sub_filter.t` 31/32 → **32/32**，`sub_filter_multi.t` 42/44 → **44/44**。

### 3. limit_req / limit_conn：空键与 dry run（已修，2 个新文件入清单）

- **空键必须跳过**。nginx `ngx_http_limit_req_handler` 里 `key.len == 0` 直接 `continue`；
  我们把空串当成共享桶，于是所有「没带这个参数」的请求挤在一个桶里互相拒绝。
  `limit_req2.t` 的 5 条失败全部是这一个原因（`$arg_a` 缺省时被 `slow` 区限流）。
- **`limit_req_dry_run` / `limit_conn_dry_run`** 此前只被「接受但忽略」。现在真的实现：
  照常记账并写 `limiting requests, dry run, excess: ...` / `delaying request, dry run, ...`
  （`limiting connections, dry run by zone ...`），但不延迟也不拒绝。
- **`$limit_req_status` / `$limit_conn_status`** 新增（`PASSED` / `DELAYED` / `REJECTED` /
  `DELAYED_DRY_RUN` / `REJECTED_DRY_RUN`），未配置限流时为空所以 `add_header` 不产出。
- 限流产生的 503 现在会跑 `add_header`（nginx 的 header filter 对它的 503 同样生效；
  `limit_req_dry_run.t` 就断言了那个响应上的 `X-Status: REJECTED`）。

结果：`limit_req2.t` 11/16 → **16/16**，`limit_req_dry_run.t` 4/10 → **10/10**，
`limit_conn_dry_run.t` 6/8 → **8/8**。

### 4. `auth_request` 指向 FastCGI 上游（已修，`auth_request.t` 22/22）

`fastcgi::handle` 把「和响应器交换」与「写客户端连接」写在一起，子请求没有连接可用，
于是 `auth_request /auth-fastcgi` 只能拿到 500。现在拆成两半：

- `fastcgi::fetch(req, path, query, loc, body, peer_ip) -> Option<(Response, bool)>`
  做参数构造、连接、收发、解析，**不碰 socket**；
- `fastcgi::handle` 只做 100-continue、取请求体、调 `fetch`、按 `had_length` 决定是否
  chunked 后写出。

缓冲路径（`resolve_response_local`）因此可以像 `proxy_pass`/`grpc_pass` 一样处理
`fastcgi_pass`，`auth_request` 的子请求走同一条路。`auth_request.t` 19/22 → **22/22**，
`auth_request_set.t` / `auth_request_satisfy.t` 保持 20/20、8/8。

同一处修了 CGI 响应头解析：只认 `\r\n\r\n`，而 `fastcgi_cache.t` 的响应器只发 `\n`，
于是整块 CGI 头被当成 body 发给了客户端。nginx 两种都接受（扫 `LF LF`），现在同样。

### 已知偏差（本轮新增，均有实测根因）

- `fastcgi_pass` 不支持变量目标。`fastcgi.t` 用一个 `fastcgi_pass $arg_b;` 开跑，
  我们在 `-t` 阶段就报 `invalid fastcgi_pass address "$arg_b"` 而根本起不来
  （TRUNC 0/10）。要修得把 `ServerVars` 引进 fastcgi 处理器，属中等重构。
- `fastcgi_cache` 未实现（`fastcgi_cache.t` 6/7，缺的那条要求第二个请求命中缓存）。



- `sub_filter_buffering.t` "partial match" 1 条：上游声明 `Content-Length: 10` 却只发 3 字节
  就断开。nginx 在 `proxy_buffering off` 下流式转发，把末尾可能是匹配前缀的 `z` 挂住，
  流被截断时直接丢弃，于是返回 `xy`；我们缓冲整段，保留 `xyz`。
  这是「上游畸形响应 + 流式过滤器」的产物，不是可配置语义（同机实测：上游一次写全 3 字节时
  nginx 三种配置全部返回 `xyz`）。要复现得实现按读边界推进的流式过滤器，收益是 1 条断言，
  代价是把一个更坏的实现写进热路径，故记为偏差。

## 一之四、2026-10-27 第三轮：fastcgi 变量目标、secure_link、`if` 文件测试、rewrite 命名变量

### 1. `fastcgi_pass` 接受复杂值（`fastcgi.t` 0/10 → 10/10）

`fastcgi_pass` 此前只接受字面地址，`fastcgi_pass $arg_b;` 在 `-t` 阶段直接
`invalid fastcgi_pass address "$arg_b"` 拒绝启动，整个文件 0 分。现在：

- 配置里含 `$` 的值存为 `spec` + `dynamic`，请求期用 fastcgi 自己的变量视图展开；
- 展开结果先按 `upstream` 名匹配（nginx 的 `ngx_http_upstream_init_request`），
  再按 `host:port` 解析；两者都不是就 502 并写错误日志，而不是静默连错地方；
- `$arg_*` 加进 fastcgi 的变量视图（`fastcgi_pass $arg_b` 与
  `fastcgi_param X $arg_y` 都要它）；
- `fastcgi_catch_stderr <pat>`：STDERR 命中即 502（`/catch` 用例）；
- CGI 响应没有 `Status` 而有 `Location` 时是 302（`ngx_http_fastcgi_module` 第
  2056 行的规则），此前一律当 200 发出去。

### 2. `secure_link` 从零实现（`secure_link.t` 15/21 → 21/21）

两种形态都按 `ngx_http_secure_link_module.c` 逐行核对：

- **新式** `secure_link $arg_hash[,expires]` + `secure_link_md5 secret$uri$arg_expires`：
  值先做 base64url 解码（padding 可省、超过 24 字符直接失败、长度必须是 16），
  再和 MD5 比；`$secure_link` 给 `"1"` / `"0"`（过期）/ 空（未找到），
  `$secure_link_expires` 给原样的 expires 文本。expires 用 nginx 的 `ngx_atotm`
  语义：纯数字，`0` 或解析失败是「未找到」而不是「已过期」。
- **老式** `secure_link_secret`：从 `$unparsed_uri`（含查询串）取
  `/prefix/<32 hex>/<rest>`，校验 `md5(rest + secret)`，成功时 `$secure_link` = `rest`。
- **继承规则**照 `ngx_http_secure_link_merge_conf`：某 scope 写了
  `secure_link_secret` 就用老式并清空另外两个；某 scope 写了新式的任一指令就不再
  继承父级的 secret。这条是 `inheritance` 用例失败的原因。

MD5 从 `auth.rs` 的 apr1 里抽成 `src/md5.rs`（两个模块共用），带 RFC 1321 向量
与分块输入一致性的单测。

### 3. `if` 的文件测试从来没能用（`rewrite_if.t` 0/35 → 35/35）

两个独立错误叠在一起：

1. `parse_if_cond` 对 `-f` 也按「`<var> <op> <rhs>`」三段解析，于是把 `-f` 当变量、
   把路径当运算符 —— 任何带 `-f` 的配置都 `unsupported if condition` 起不来。
   文件测试没有左操作数，语法是 `-f <path>`；`!-f` 是**一个**运算符（nginx 的词法），
   不是 `!` 加 `-f`。
2. 操作数被当成变量名查表（`get_var`），而它是 `/srv/$arg_c` 这样的路径，查询必然
   为空，于是一切文件测试恒为假。改为整体展开。

### 4. `rewrite` 的替换只认 `$1..$9`

`rewrite ^ /$secure_link break;` 是标准用法，但 `apply_one` 只展开捕获，
命名变量原样留在 URI 里（`/$secure_link` → 404）。nginx 把替换编译成一个 complex
value，捕获与命名变量在同一遍里替换。现在合并成一个展开器
（`expand_replacement`），并保留 args 部分对捕获值做 `NGX_ESCAPE_ARGS`。

声明清单 **89 → 92 文件**（新增 `fastcgi.t`、`secure_link.t`、`rewrite_if.t`）。

## 一之五、2026-10-27 第四轮：`ngx_http_dav_module`（122 条断言）

三个 dav 文件从 25/122 到 **122/122**（`dav.t` 96/96、`dav_chunked.t` 8/8、`dav_utf8.t` 18/18）。
实现照 `ngx_http_dav_module.c` 逐段转录，五个方法：

| 方法 | 成功 | 拒绝 |
|---|---|---|
| PUT | 201 新建 / 204 覆盖 | 409 集合 URI、501 带 `Content-Range`、500 父目录缺失且未开 `create_full_put_path` |
| DELETE | 204 | 404 不存在、409 目录 URI 无尾斜杠、400 `Depth` 不合规、415 带 body、409 `min_delete_depth` |
| MKCOL | 201 | 405 已存在、409 无尾斜杠/父目录缺失、415 带 body |
| COPY | 204 文件 / 201 集合 | 412 `Overwrite: F`、409 集合/非集合不匹配、400 坏的 `Destination`/`Overwrite`/`Depth`、404 源不存在 |
| MOVE | 204 文件 / 201 集合 | 同 COPY，且 `Depth` 必须 infinity |

踩到的三个坑，都只有跑测试才会暴露：

1. **请求体被提前丢掉了**。主循环对「非上游」location 会 `drain_body`，而 DAV 的 PUT
   自己读 body（`ngx_http_read_client_request_body`）。原来 PUT 走到 handler 时 body
   已经没了，`take_body` 于是永远等 10 个字节 —— 客户端等到超时，我们记 499。
   现在 PUT + `dav_methods` 含 PUT 与 proxy/fastcgi 同等对待。
2. **`ngx_dir_access`**：`create_full_put_path` 建出来的目录如果直接用 `dav_access`
   （默认 0600），目录没有 `x` 位，随后往里写文件必然 EACCES → 403。
   nginx 的 `ngx_dir_access(a) = a | (a & 0444) >> 2` 正是补上执行位。
3. **`absolute_redirect` 对 201 的 `Location` 同样生效**（`ngx_http_header_filter`
   看的是头，不是状态码）。`dav.t` 用 `absolute_redirect off` 断言相对路径，所以
   `redirect_location` 提到 `absolute_location` 公开复用。

另外 `dav_access` 的解析有个反直觉之处，也照抄了：起点是 `0600`，而一旦出现
`user:` 就把 owner 位清零再按参数 OR 回去 —— 所以 `user:rw group:r all:r` 是 0644
而不是 0744。

## 一之六、2026-10-27 第五轮：PROXY protocol（77 条断言）

`proxy_protocol.t` 26/26、`proxy_protocol2.t` 30/30、`proxy_protocol2_tlv.t` 16/16、
`proxy_protocol_ipv6.t` 5/5。四种输入形态加一种输出：

- **v1 文本**：`PROXY TCP4|TCP6 <src> <dst> <sport> <dport>\r\n`。
  `PROXY UNKNOWN`（后面跟什么都不管）是合法的「无地址」答案，不是错误 ——
  `$proxy_protocol_addr` 为空、端口为空，请求照常处理。
- **v2 二进制**：12 字节签名 + 版本/命令 + 家族/传输 + 长度 + 地址 + TLV。
  命令不是 PROXY、传输不是 STREAM、家族不是 INET/INET6 时**跳过整段头但保留连接**，
  nginx 就是这么做的（`ngx_proxy_protocol_v2_read` 的 `return end`）。
- **TLV**：`$proxy_protocol_tlv_<名字>`、`_0xNN`、以及 `ssl_` 前缀下的子 TLV
  （`ssl_verify` 是前缀里的 4 字节整数，`ssl_cn` 等在子 TLV 表里）。
- **输出侧**：`stream { proxy_protocol on; }` 写 v1 头。

### 顺带补上两个真实的语义缺口

1. **`allow`/`deny` 用重写后的地址**。nginx 的 realip 是 POST_READ 阶段，ACCESS 在它
   之后；我们之前一直用连接地址判断。这条偏差从 realip 那轮就登记在案，现在有测试
   驱动的修正：`proxy_protocol.t` 的 `/pp_4`、`/pp_6` 要求 403。
2. **`access_log` 的 `$remote_addr`/`$remote_port` 也是重写后的值**。日志是在
   `dispatch` 之外写的，所以加了一条 `&mut (String, String)` 把有效地址带出来；
   之前日志里永远是 `127.0.0.1:0`。

### 一处只有对照源码才发现的坑

`stream ... proxy_protocol on` 写头时，**目标地址取客户端连到本机的那个地址**
（`c->local_sockaddr`），不是上游 socket 的本地地址。取错会得到 `127.0.0.1 -> [::1]`
这种混合家族，`ngx_proxy_protocol_write` 只能写 `PROXY UNKNOWN`，于是
`$proxy_protocol_addr` 为空 —— `proxy_protocol_ipv6.t` 的两条断言正是这样。

## 一之七、2026-10-27 第六轮：resolver（113 条断言）

`http_resolver_aaaa.t` 25/74 → **74/74**，`http_resolver.t` 15/40 → **39/40**
（那一条是 nginx 自己也失败的 `TODO`「zero ttl not cached」，我们反而通过）。

原来的实现只发 A 查询、只收一个地址、不跟 CNAME。现在是 `ngx_resolver.c` 的状态机：

- **A 与 AAAA 并发**，地址合并（A 在前）；
- **任一错误响应即整名失败**。`n-e`（A 成功、AAAA SERVFAIL）必须是 502 而不是用 A 的地址，
  这条靠「部分结果也要丢」才成立；
- **空 NOERROR 响应不等于空结果**，但它决定了 CNAME 跟不跟：`z-c`（A 空、AAAA 是 CNAME）
  要跟到底拿到 2 个地址，`c-z`（A 是 CNAME、AAAA 空）必须 502。差别只在「哪个响应最后到」，
  nginx 用 `nan == 0` 的分支 + `rn->naddrs/naddrs6` 的 `-1` 哨兵表达，现在照抄；
- **CNAME 只在两个响应都没有地址时跟**，且谁最后完成谁的名字生效（`c1-c2`：A 指向 alias4、
  AAAA 指向 alias6，最终只解析 alias6）；
- **缓存时长取最小 TTL**，但空响应不参与（否则 `many.example.net` 的 A 响应会把 3600 压成 0，
  这正是「AAAA many cached」失败的原因）；`valid=` 覆盖 TTL；TTL 0 不缓存；
- **服务器按「名字」轮转**（`r->last_connection++` 在节点创建时执行），所以
  `resolver <坏> <好>` 第一次 502、第二次成功；
- **重发**：每 `resend_timeout`(5s) 一次，直到 `resolver_timeout`，每次换服务器；
- **TC 位置位时改用 TCP 重问同一台**（`tcp.example.net` 的桩就是这么写的）。

### 顺带修掉的一个通用缺陷：上游连接失败不走 `error_page`

这一轮之前，`proxy` 的连接/读取失败直接自己写 502/504，**完全绕过 `error_page`**。
nginx 里这类失败走 `ngx_http_special_response_handler`，所以 `error_page 504 502 /50x` 对它们
同样生效。改成返回 `Proxied::Intercept { status }`，让正常的 error_page 管線接手 ——
resolver 的两个套件全靠这个把 `$upstream_addr` 暴露出来，因此这条不修，74 条断言里
四十几条都过不去。这类缺陷之前没被发现，是因为既有用例里 `error_page` 都配在多后端场景，
那时走的是另一条分支。

## 一之八、2026-10-27 第七轮：Range 解析（`range.t` 31 → 42/43）

`ngx_http_range_parse` 的三个非直觉行为，`range.t` 逐条断言：

1. **语法错误是 416，不是「忽略」**。`bytes=alpha`、`bytes=10-alpha`、`bytes=10`、
   `bytes=10-11 12-` 必须 416；我们此前一律当成「header 不认识」而返回 200 全量。
   （`bytes=` 这个单位前缀的比较是大小写不敏感的，那是另一条 Rule。）
2. **超出末尾的分段是「跳过」而不是「拒绝」**。`bytes=0-9, -10, 100000-, 10-19`
   是三个分段的 206；只有当所有分段都不可满足时才是 416。
3. **起点为 0 且终点早于起点的分段会让 nginx 丢掉整个 header**（`NGX_DECLINED`），
   分段总长超过实体长度也一样 —— 两者都返回 200 全量。

另外 `max_ranges` 此前是**按逗号数**判断的，于是
`bytes=0-9, -10, 10000-` 在 `max_ranges 2` 下被误判为三段而丢掉整个 header。
nginx 数的是「解析后仍然存活的分段」，现在由解析器自己计数。

仍未对齐：`range_charset.t` 4 条（`charset`/`source_charset` 重编码后的 Range —— 偏移量
必须落在重编码后的字节上，现在是先切片再重编码）。

## 一之九、2026-10-27 第八轮：stream `geo`/`map`、`disable_symlinks`

### stream `geo` / `map`（`stream_geo.t` 2/21 → 21/21，`stream_map.t` 2/7 → 7/7）

`stream {}` 里的 `geo` 和 `map` 此前是「接受但忽略」，`return` 也只认 `$ssl_*`。
现在两者都是 `stream` 的变量，与 http 的同名块互不相干（`ngx_stream_geo_module`
注册自己的变量表）。

三个只有对照源码才拿得到的细节：

1. **无法解析的源地址按 `INADDR_NONE` 查表**。`ngx_stream_geo_addr` 解析失败时
   返回 `NGX_ERROR`，调用方随即用 `INADDR_NONE`（`255.255.255.255`）查树 ——
   也就是落到**最不具体的那条**（`0.0.0.0/0`），而不是 `default`。
   `stream_geo.t` 的 `geo world`（`$var` 映射不到任何端口 → 空串）必须答 `world`。
2. **`ranges` 模式是「后插入者覆盖重叠段」**，nginx 的 `ngx_http_geo_add_range`
   把已有区间切成左右两段再把新值放进中间。所以 `geo_insert*` 三条都取**最后**
   声明的值 —— 原来按「最窄区间胜出」实现，碰巧在这几条上结果相同，但不是同一语义。
3. **`listen` 在 stream server 里可以重复**，每条开一个 socket。原来只保留最后一个，
   于是 `stream_map.t` 里四条 `listen` 只剩一条，客户端连不上，整个文件崩在第三条断言。

`map` 的正则捕获（`~(...) $1;`、`~(?P<ncap>...) $ncap;`）也补齐了。

**`set` 与 `split_clients`**（`stream_set.t` 3/4 → 4/4、`stream_split_clients.t` 2/3 → 3/3）：
nginx 的 `set` 在 rewrite 阶段执行、`return` 在 content 阶段，所以配置文件里的书写顺序
不影响结果 —— `stream_set.t` 把 `return` 写在两条 `set` **前面**，仍要求两条都生效
（`$map_var` 被 `set` 覆盖成 `new`，而 `$set_var` 拿到的是覆盖**之前**的 `original`）。
实现按声明顺序逐条展开进一个累加表，正好复现这个先后。`$connection` 也补上了
（`split_clients $connection` 用它做种子）。

### `disable_symlinks`（`http_disable_symlinks.t` 14/28 → 29/30）

按 `ngx_open_file` 的 walk 实现：从 `from` 前缀（缺省 `/`）开始，逐段用 `lstat`
判断；`on` 遇到任何符号链接即 ELOOP（→ 403），`if_not_owner` 只拒绝
「链接与目标 owner 不同」的那些。三处调用点都要生效：

- 静态文件（403）；
- `try_files`（该候选**失败并继续下一个** —— `/try_on/try` 因此落到 `$uri.html`）；
- `if (-f $request_filename)`（该测试为假，于是落到静态处理器再答 403）。

`from=` 的判定照 `ngx_http_core_set_disable_symlinks`：前缀必须真的出现在路径里、
`from.len == path.len` 时检查**整个关闭**、`path[from.len]` 或 `path[from.len-1]`
必须是 `/`。`$document_root` 取**展开后的** root/alias（`r->doc_root` 是
`ngx_http_map_uri_to_path` 里赋的值），这正是 `"from=" exact match` 那条的成因：
`alias /srv/$1` 展开后与文件名相等 → 关闭检查。

顺带修了 `$request_filename` / `$document_root` 在 `if`/`set` 里**恒为空**
（`RwVars::get_var` 直接返回 `String::new()`），否则 `if (-f $request_filename)`
永远不成立。

**仍未对齐（1 条）**：`"from=" exact match` 需要 `alias` 支持变量（`alias /srv/$1`）。
我们的 `alias` 存的是配置期解析好的 `PathBuf`，没有模板。这条要动 `map_path` 的
签名（4 个调用点）以及每个调用点的变量视图，本轮没做，因此这个文件**未进声明清单**。

## 一之十、2026-10-27 第九轮：请求体（`body.t` 17/17、`body_chunked.t` 8/20 → 20/20）

`$request_body` / `$request_body_file` 在 HTTP/1.1 上是**恒为空**的：注释里写的是
「h1 由上游模块直接流式转发，只有 h2/h3 会在路由前缓冲」。但 `$request_body` 在 nginx
里是带 get_handler 的变量，第一次读的时候就把 body 读进来 —— 而第一次读几乎总是
上游应答之后的那个 `add_header`。

现在的规则：**只要本 location 会用到这个变量，body 就在 dispatch 之前读进内存**。
判据是本轮实际用到的三处：`add_header` 的值、`return` 的文本、以及 `error_page`
是否存在（内部子请求里 `$request_body` 仍然可读，而 body 已经不能被上游模块吃掉）。
读进来之后按 `body_needs_file` 决定落盘：`client_body_in_file_only`，或长度超过
`client_body_buffer_size`。落盘时 `$request_body` 为空、`$request_body_file` 有值，
与 nginx 一致。

同时修了三个请求体层面的真实缺陷：

1. **`client_max_body_size` 对 chunked 请求完全不生效**。它只在 `Content-Length` 分支
   检查过，chunked 一路读到 32 MB 上限为止。现在在读取过程中按累计长度判定
   （`drain_chunked_limited`），超限 413。
2. **chunk 分帧不校验**。`4\r\nSEE-THIS\r\n` 这种「声明 4 字节却跟 8 字节」的请求，
   nginx 报 400；我们把多余字节当下一段去解析，结果正常 200。现在要求数据后的两字节
   是 CRLF、且 `read_line` 读到的是空行，否则 400。
3. **`Transfer-Encoding` 在 HTTP/1.0 请求上被接受**。nginx 报 400。顺带把
   `chunked, identity` 之类（末尾不是 `chunked`，或多个编码）从 501 的判定收紧到
   nginx 的口径。

### 一个明确的已知缺口：`proxy_request_buffering`

`proxy_request_buffering` 这个指令**连解析都没有做**（配置里写了等于没写）。
`proxy_request_buffering.t` 里剩的两条是这个缺口的直接后果：用例自己监听 8082，
期望被测服务器在校验完请求头后就**立刻连上来**、然后一边收一边转发 body。我们现在
永远先读完整个 body 再连接，所以 `accept()` 超时。

要做得把连接与请求体的发送顺序拆开（先连、写头、再边读边写），并让 `Content-Length`
在没有缓冲体时取自 `req.body_len`。这动的是热路径，本轮没做，记在这里。

## 一之十一、2026-10-27 第十轮：`headers.t`（18/30 → 30/30）

`expires` 此前是**按字面量匹配**的：`epoch`/`max`/`off`/`@time`/`modified` 直接比字符串，
其余一律 `parse_time` 兜底成 0。于是 `expires $arg_e` 这种写法永远落到「0 秒」分支，
输出一个等于现在的 `Expires` 加 `max-age=0`。现在按 `ngx_http_parse_expires` 重写：

- 展开后的值先看是不是 `modified …`（**只有配置里写了 `modified` 才认**，
  这时 `epoch`/`max`/`off` 三个快捷值**不**生效 —— `modified epoch` 会被当成
  `ngx_parse_time("epoch")` 失败，于是什么都不发，正是 `headers.t` 的最后一条断言）；
- `@HhMmSs` 是每日时间；`+`/`-` 前缀是偏移量；
- **空值或无法解析 → 什么都不发**（不是发 `max-age=0`）；
- `modified` 以 `Last-Modified` 为锚，响应没有它时退回「现在」；
  `offset < 0` 或 `max_age < 0` → `Cache-Control: no-cache`。

根因之一在共用代码里：`parse_time("")` 返回 `Some(0)` —— 空字符串被当成零时长。
这会让任何「值为空」的指令悄悄变成 0，现在返回 `None`。

另一个真缺陷是 **`add_header` 对 `ETag` / `Last-Modified` 的语义**。这两个名字在 nginx 里
走 `ngx_http_set_response_header`（**替换**已有值），而不是 `ngx_http_add_header`（追加）。
空值时尤其明显，实测（同机对照 nginx 1.28）：

```
(无 add_header)                       -> ETag: "6ae0a6e0-4"
add_header ETag "" always;            -> 无 ETag（连静态处理器设的也被清掉）
add_header Last-Modified "" always;   -> 无 Last-Modified
add_header ETag foo always;           -> ETag: foo（不是两个）
```

之前我们对空值直接 `continue`，于是静态处理器的 `ETag` 留着，`headers.t` 的
"good add_header always empty" 失败。现在空值对这两个名字是**删除**。

## 一之十二、2026-10-27 第十一轮：`index.t`（9/16 → 16/16）

`index` 的语义不是「就地返回目录里的那个文件」，而是**内部重定向**：`$uri` 变成索引文件
的 URI，location 重新匹配。这正是 `index.t` 用 `add_header X-URI $uri` 断言的东西：

| 请求 | 配置 | nginx 行为 |
|---|---|---|
| `/` | 默认 `index.html` | 内部重定向到 `/index.html`（`$uri` 变了） |
| `/redirect/` | `index /re.html` | **绝对**名 → 重定向到 `/re.html`，且**不看目录是否存在** |
| `/loop/` | `index /loop/` | 重定向回自身 → 10 次后 **500** |
| `/many/` | `index nonexisting.html many.html` | 逐个别名尝试，命中 `many.html` → `/many/many.html` |
| `/var/` | `index $server_name.html` | 复杂值，展开成 `localhost.html` |
| `/va2/` | `index ${server_name}.html` | 同上，`${}` 花括号形式 |

顺带补了三处：

1. **`$server_name` / `$host` 在 `rewrite` 模块的变量视图里是空的**（`RwVars::get_var`
   没有它们），所以 `index $server_name.html` 展开成 `.html`。现在补上。
2. **`${name}` 花括号形式不被识别**，`index ${server_name}.html` 会在 `<` 处断掉。
3. **`log_not_found`**：nginx 对每个缺失的静态文件写一行
   `open() "..." failed (2: No such file or directory)` 到 error log，`off` 时不写。
   我们此前完全不写，而且 **location 级 `error_log` 文件在没有任何内容时不会创建** ——
   nginx 在加载配置时就打开所有日志。现在启动时预打开（`preopen_location_error_logs`）。

### 一个被 `bench/pair.sh` 抓到的回归

第一版把「不带尾斜杠的目录 URI」也重定向到了 `index.html`，于是 `/sub` 返回 200 而不是
301。nginx 是 `ngx_http_static_handler` **先**发 301，索引模块根本不会跑到。声明清单全过、
`bench/all.sh` 的 `static-protocol` 却从 19/19 掉到 18/19 —— 这条差分用例比 nginx-tests
更能覆盖「目录 + 无尾斜杠」，值得记住。

## 一之十三、2026-10-27 第十二轮：stream 侧的 PROXY protocol 输入与 `$ssl_*`

`stream_proxy_protocol.t` 3/4 → 4/4、`stream_proxy_protocol_ssl.t` 3/4 → 4/4、
`stream_proxy_protocol2_tlv.t` 3/16 → **16/16**，并修掉两个由「按服务器而不是按监听口」
建模导致的回归。

### `listen ... proxy_protocol`（输入）此前是死字段

配置里接受，运行时从不消费 —— `listen 127.0.0.1:8080 proxy_protocol;` 的请求
会把 `PROXY ...` 这行当成业务数据转发给上游。现在连接建立后第一件事就是读它
（`proxyproto::read_from`）：

- v2 按 16 字节固定头 + 长度字段精确读，**不多读一个字节**；
- v1 逐字节读到 CRLF —— 慢，但保证紧跟其后的字节留在 socket 里，这对
  `listen ... ssl proxy_protocol` 是必须的（TLS 握手读的就是这些字节）。

`$proxy_protocol_addr` / `_port` / `_server_addr` / `_server_port` / `_tlv_*`
也进了 stream 的变量视图。

### `proxy_ssl` + `proxy_protocol` 同时开启时，头写在 TLS 之前

`stream_proxy_protocol_ssl.t` 的上游是一个**先读 PROXY 行、再做 TLS 握手**的守护进程。
我们的 `proxy_ssl` 分支直接开始握手，上游等不到那行，连接被关闭（`got: undef`）。
现在在 `proxy_ssl` 分支里先写头再握手。

### 两个回归：按「服务器」而不是按「监听口」建模

这两条是上一轮 `stream set/geo` 引入的，被本轮的全量重扫抓出来：

1. **`listen ... ssl` 是监听口的属性**，不是服务器的。`stream_ssl_variables.t` 在同一个
   server 里同时有 `listen 8080;` 和 `listen 8443 ssl;` —— 我复制 server 配置时把
   `ssl: true` 也复制到了 8080 上，于是明文连接也去做 TLS 握手，`got: undef`。
2. **`proxy_protocol`（输出侧）在 stream 作用域是可继承的**，`off` 只是覆盖。
   `stream { proxy_protocol on; ... server { proxy_protocol off; } }` 这个组合此前
   因为字段是 `bool`（默认 false）而丢掉继承，两个测试各失败一条。

顺带补齐 `$ssl_session_id` / `$ssl_cipher` / `$ssl_protocol` / `$ssl_server_name`：
此前只有 `$ssl_session_reused` / `$ssl_client_verify` / `$ssl_client_cert`，
`stream_ssl_variables.t` 的 TLS 断言因此输出 `.:::`。
`proxy_ssl_name` 是复杂值（`proxy_ssl_name x${server_port}x`），现在按连接展开 ——
`stream_proxy_ssl_name_complex.t` 之前拿到空串。

## 一之十四、2026-10-27 第十三轮：`$request_id` 与访问日志的写入细节

`request_id.t` 4/14 → **14/14**（已入清单）。`access_log.t` 6/21 → **19/21**（未入清单，
见下）。`access_log_variables.t` 3/8（未入清单）。

### `$request_id`

16 字节随机数渲染成 32 个小写十六进制字符，**每个请求生成一次**，所以响应头、SSI 子请求
和日志行拿到的是同一个值。随机源用已有的 `ring`（rustls 的底座），不新增依赖。

### 日志写入器修掉的四个真实缺陷

1. **变量名按前缀匹配，最长者不优先**。`$request_id` 被拆成 `$request` + `_id`，日志里
   出现 `GET /log HTTP/1.0_id`。现在按「最长匹配且后面不是标识符字符」选。
2. **`${name}` 花括号形式不支持**。`access_log .../varlog_${arg_logname}` 直接写出了
   字面文件名 `varlog_${arg_logname}`。同一个缺陷上一轮在 `index ${server_name}.html`
   里出现过 —— 两处各自实现了展开器，现在都支持。
3. **`escape=` 语义搞错了两处**。它属于 `log_format`（`log_format json escape=json ...`），
   而我们只从 `access_log` 上读；另外默认模式把 `"` 写成 `\"`，nginx 写的是 `\x22`
   （转义表：0x00–0x1F、`"`、`\`、0x7F 全部走 `\xXX`）。`none`/`json` 两种模式还有个
   反直觉之处：**变量不存在时什么都不写**，而默认模式写 `-`（nginx 用的是另一组 op）。
4. **`$arg_*` / 其余 `$http_*` 在日志格式里解析不出来**，`if=$arg_logme` 因此永远为假 ——
   过滤掉的不是该过滤的，而是全部。

### 仍未实现（已记录，未入清单）

- **`open_log_file_cache`**：`access_log.t` 剩的 2 条是 `max=3` 的 LRU 淘汰与 `min_uses=2`
  的缓存门槛。这需要一个真正的文件句柄缓存（测试还会重命名目录来证明句柄被持有）。
- **`access_log_variables.t` 的 5 条**：`$time_iso8601`、`$msec`、`$request_length`、
  `$bytes_sent`、`$pipe`。nginx 对这几个用「不转义」的专用 op，且 `$request_length`
  要统计请求行 + 头 + body 的总字节。

### 工具修正

`bench/ntscan.sh` 的 `OUT=` 是普通赋值，我传 `OUT=...` 时被忽略并覆盖了上一次的扫描结果，
基线因此丢失（从本地副本找回）。现在改为 `${OUT:-...}`，每次扫描可以写到独立目录。

### 2026-10-27 第十四轮（未跑 nginx 对照，原因见下）

**V100 主机在本轮中途离线**，管理网络显示该节点 `offline`，从本机与备用跳板机都无法
连通。因此本轮的 nginx A/B **没有跑**，
`declared.sh` 的数字仍是上一轮的。

已完成并在主机离线**之前**验证的：

- `access_log_variables.t` 3/8 → **8/8**：`$request_length`（收到的 header 字节 + body，
  与 `r->request_length` 同义）、`$bytes_sent`（整个响应含头）、`$msec`、
  `$time_iso8601`、`$pipe`（本请求的字节是否已在上一请求处理期间缓冲）。`$request_time`
  此前整个变量表里都没有。

已写但**只在本机验证过编译与单测**的：

- `open_log_file_cache max/inactive/min_uses/valid`，实现为写入线程里的句柄缓存。三条规则
  都是 `access_log.t` 用「把目录改名」证明的：`valid` 内的句柄继续写 inode；不足
  `min_uses` 次则每行开关文件、路径一消失就丢行；`max` 约束的是**条目数**，第四個路径会
  淘汰 LRU 条目，该路径此后同样丢行。四条各有单元测试（会真的重命名目录），
  `cargo test --release` 164 passed。
- 写单测时发现一处必须改正的地方：运行期打开日志**不能创建父目录**。nginx 在加载配置时
  打开所有日志（`ngx_conf_open_file`），请求期只重新打开路径。现在启动时
  `preopen_access_logs` 做前半段（跳过含 `$` 的路径，nginx 也不会预创建它们），
  `open_log` 只打开。

**待办**：主机恢复后先跑 `bash bench/declared.sh` 与 `bench/all.sh` 确认这两轮改动没有
回归，再跑 `TEST_LIST="access_log.t access_log_variables.t request_id.t"` 取得
`access_log.t` 的实际分数（预期 21/21 后可入清单）。

### 2026-10-27 第十五轮：搬迁到备用主机，并补上上一轮欠的 A/B

上一轮 V100 离线后，本轮在**另一台 V100**（88 核 / Ubuntu 22.04）
上重建了完整对照环境：

- nginx 1.28.0 从源码编译，configure 参数与参考二进制逐项一致（`-V` 已核对），
  依赖用 `apt-get download` + `dpkg -x` 解到 `~/sysroot`（非 root）；
- perl 侧 `IO::Socket::SSL` / `Net::SSLeay` / `FCGI` 均从 deb 取，`PERL5LIB` 指向 sysroot；
- `~/nginx-tests` 用当前 master（与主机的 515 文件版本差 `http_headers.t` 一个文件，
  其余声明清单里的 119 个文件都在）。

**这台机器上的 declared 全量（最终二进制）：119 文件 → WORSE=0 TRUNC=0，
nginx 1823 / ngxrs 1828 断言，114 个逐断言一致、5 个更优（`http_headers_multi`、
`http_resolver`、`proxy_cache_range`、`proxy_if`、`proxy_noclose`）。**

环境细节记在这里，便于重建：`fastcgi.t` 需要 `FCGI.so` **及其** `libfcgi.so.0`
（`libfcgi-perl` 与 `libfcgi0ldbl` 两个包），只装前者时该文件在两侧都是 0 断言、
被计为 SKIP 而不是 SAME —— 上一轮正是漏了这个。

### access_log 系列全部打平，`open_log_file_cache` 三个 bug 被 A/B 抓出来

上一轮只做了单元测试、没有 nginx 对照的两处，本轮全部复现并修好：

1. **缓存策略取的是解析时刻的值**。`access_log` 写在 `open_log_file_cache` 之前时拿到的是
   默认值（`max=0`，等于关闭缓存）。nginx 的 `ngx_http_log_handler` 是**在写日志时**读
   `clcf->open_file_cache`，所以指令顺序不该有影响。改为运行时从 location 取。
2. **写缓冲在淘汰时丢行**。日志用 `BufWriter` 缓冲，条目被 LRU 淘汰时直接 drop，
   缓冲区里的行随之消失 —— "cache - cached 1/2" 少一行正是这个。nginx 的 access_log
   默认**不缓冲**（只有 `buffer=` 才缓冲），改为直写。
3. **打开失败也建条目，反过来挤掉活着的句柄**。目录被改名后 `lru` 的重新打开失败，
   我们仍为它建了条目，于是 `max=3` 下又淘汰了一个还有效的句柄。nginx 只在
   `open_file_cache_errors` 打开时才记住失败（日志模块默认取该值，默认 off）。

结果：`access_log.t` 19/21 → **21/21**、`access_log_variables.t` 8/8、`request_id.t` 14/14，
三者均已入声明清单（119 文件）。

教训直接写在这里：上一轮"四条单元测试通过"并不足以证明实现正确 —— 单元测试里我自己
构造的调用顺序恰好避开了 bug 1，也没有覆盖"淘汰后再打开失败"这条路径。

### 2026-10-27 第十六轮：charset 过滤器与 gzip_static

`charset.t` 4/9 → **9/9**、`charset_gzip_static.t` 4/15 → **15/15**，两者入清单。

`ngx_http_charset_filter_module.c` 有三条反直觉规则，测试正好逐条断言：

1. **nginx 没有内置转换表**。charset 只是一个**名字**，唯一存在的映射来自 `charset_map`。
   所以 `charset foo` 而没有任何 map 时什么都不追加；而 `charset_map B A` 会顺带把 A、B
   注册成 charset —— 这才是 `source_charset B` 能被解析的原因。
2. **一张声明过的表同时服务两个方向**。postconfiguration 里
   `tables[src][dst] = src2dst` 与 `tables[dst][src] = dst2src` 都会填上。这正是
   "override charset" 需要的：上游回应已经带 `charset=A` 且 body 被 X→Y 重编码，外层
   location 再转回 B，客户端看到的才是原始的 X。
3. **需要重编码但已经带 Content-Encoding 的响应，整条跳过**：不追加 charset（"recode gzip"）。
   而 source charset 为 `off` 的响应**无论如何**都追加（"plain"、"gzip"），因为那条分支
   在编码检查之前就返回了。

两处实现上的取舍：

- charset 需要整个实体才能重编码，而我们的代理有一条直接写 socket 的流式路径。带 `charset`
  的 location 现在走缓冲路径（`wants_buffered`）—— nginx 同样做不到边流边转码。
- Content-Type 可能在 `headers`（动态构造）里，也可能预渲染在 `raw`（静态快路径）里。
  往错的那一边追加会让头出现两次；`set_charset_param` 现在只改写响应实际携带的那一份。

`gzip_static`：客户端接受 gzip 时用同目录的 `<path>.gz` 替代实体，Content-Type 仍按原始
文件名取。替换发生在 open 之后，所以 ETag、长度与 Range 描述的都是真正发出的字节。

顺带修掉一处重复的 `charset` 匹配分支：一个只设置 autoindex 宽度标志的旧分支排在前面，
把新分支挡住了 —— `charset` 被解析后又被丢弃。

### 2026-10-27 第十七轮：stream 负载均衡

四个此前 WORSE 的文件现在与 nginx 持平（同机、同次运行、同一参考二进制）：

| 文件 | 之前 | 现在 |
|---|---|---|
| `stream_upstream_max_conns.t` | 3/16 | **16/16** |
| `stream_upstream_hash.t` | 4/6 | **6/6** |
| `stream_upstream_least_conn.t` | 3/4 | **4/4** |
| `stream_upstream_random.t` | 11/14 | **14/14** |
| `stream_upstream.t` | 3/8 | 7/8（剩 1 条，见下） |

**方法上的说明**：这次是先在同一台主机上编译「上一提交」的二进制，背靠背跑同一组
`TEST_LIST` 取基线，再跑本轮的构建。跨主机的数字不可比 —— 繁忙的内部 V100 上两个二进制
都会掉好几分，拿那种数字做判断会得出相反结论。

改动要点：

1. **`max_conns` 在 stream 里完全不存在**。字段没解析，peer 列表只是一个
   `Vec<SocketAddr>` 配按下标的轮转。现在 stream upstream 复用 http 的 `UpstreamServer`
   （weight/backup/down/max_fails/fail_timeout/max_conns）并带自己的 `LbMethod`。
2. **选择必须是有状态的**。nginx 的轮询是平滑加权轮询
   （`current_weight`/`effective_weight`），不是简单轮转；`weight=2` 要拿到三分之二的
   连接。这就是 "weight" 那条断言。
3. **`hash` 是折叠后的 Cache::Memcached 表达式**：
   `((crc32([REHASH] KEY) >> 16) & 0x7fff)` 累加后对总权重取模。只对 key 做一次
   不折叠的 crc32 会选到**不同**的 peer。`consistent` 走排序后的环与单次
   `crc32_long` 查找。另外 hash 的**空 key** 必须回落到真正会轮转的 round-robin ——
   第一版只把计数器加一，结果四条连接全压在一个 peer 上。
4. **`max_fails`/`fail_timeout` 需要每 peer 的 `fails`/`checked`**，且失败的连接要计入：
   连接被拒是 `NGX_PEER_FAILED`，要抬 `fails` 并把 `effective_weight` 减去
   `weight / max_fails`。
5. **读了两遍源码才确认的一条**：只有**一个** peer 的池子直接取它，并**完全忽略
   `max_fails`**（`ngx_stream_upstream_get_round_robin_peer` 的 `peers->single` 分支），
   只检查 `down` 与 `max_conns`。在这里也检查 max_fails，会让「单主 + backup」的组在
   主 peer 恢复后仍被钉在 backup 上整整一个 fail_timeout —— "recovery" 期望的是主 peer
   30/30。

还有一个直到连接计数变得重要才暴露的缺陷：`proxy_tcp` 用 `copy_bidirectional`，注释写着
「任一侧关闭即返回」，实际要等**两侧**都结束。应答后立即关闭的后端会让会话 —— 连同它的
`max_conns` 槽位与 `conns` 计数 —— 一直挂到客户端也断开。nginx 在
`proxy_half_close off`（默认）下，第一个 EOF 就结束会话。这正是 "least_conn" 那条：
测试挂起两条连接（其中一条指向会 sleep 的后端），期望接下来十条全部走另一个 peer，
而我们看到两个 peer 的 `conns` 卡在 1/1，结果是 5/5。

**后续**：同一轮里把 "per-upstream variables" 也做完了。`stream_upstream.t` 最终 7/8 → **8/8**
并入清单（126 文件）。那一项要求 stream access_log 的 `$upstream_addr`、
`$upstream_bytes_sent`、`$upstream_bytes_received` 是**按尝试逗号分隔的列表**
（`127.0.0.1:8086, 127.0.0.1:8084!0, 1!0, 4`）：先被拒的 peer、再应答的 peer，字节计数
同形。这不是「填个变量」——`splice` 现在返回 `(sent, received)`，每次连接尝试追加一条
`StreamAttempt`，失败的那次保持 0。

新增 7 个单元测试覆盖这些行为（权重、max_conns 回落 backup 与回收、max_fails 禁用与
恢复、单 peer 规则、least_conn 偏好、空/非空 hash key），总数 171。

### 2026-10-28 第十八轮：upstream keepalive 连接池

`proxy_keepalive.t` 15/51 → **51/51**，`proxy_chunked.t` 2/5 → **5/5**，两者入清单
（126 → **128** 文件）。

连接池本来就存在，但**只有带 `Content-Length` 的响应才归还连接**（`reuse` 里有
`total_len.is_some()`）。带 chunked 编码的响应同样精确地定义了消息边界 —— `0` 尺寸行
加上 trailer 之后的空行 —— nginx 也会归还。于是这个测试用 `X-Connection` 量到的
「复用」几乎每一项都差一条连接：

| 情形 | 之前 | 原因 |
|---|---|---|
| chunked 响应 | 从不归还 | `total_len` 为 `None` |
| HEAD | 从不归还 | 在读体之前就 return，走不到归还那一步（我们发的是 HEAD，没有体要排空） |
| 304 / 204 | 被当作有体 | `304len` 带 `Content-Length: 100`，那描述的是**客户端已持有的实体**，不是后面跟着的字节；读它会一直阻塞到 `proxy_read_timeout`，客户端什么都拿不到 |

连接真的被复用之后，又暴露出三个 bug：

1. **`dechunk` 见到 `0` 行就返回**，而收尾的 CRLF 可能还在路上（这个测试的 "complex"
   后端在它之前 sleep 50ms）。那时归还连接，socket 里就留了一个字节，连接上下一次
   响应解析错位 —— 表现为两个请求之后才出现的 "read timeout"，而测试后端一次只服务一条
   连接，于是后面全部变成 "Connection refused"。新增 `chunked_body_end` 要求真正的
   终止符，缓冲路径与流式路径都用它。
2. **SSI `#include virtual=... set="x"` 根本没实现**，而服务子请求的缓冲 `fetch`
   也**不使用连接池**：include 会另开一条连接，而后端还在读池里那条 —— nginx 的池是
   按 peer 共享、子请求同样使用，于是对着「一次只服务一条连接」的后端直接死锁。
   现在 `fetch` 与流式路径一样 checkout/checkin。
3. `fetch` 也有同样的「chunked 永远读不完」问题：它一直读到 EOF，而 keep-alive 连接
   上 EOF 不会到来。

还有一条纯粹的协议规则：**nginx 从不给 HTTP/1.0 客户端发 chunked**。我们把上游的
chunk 分帧原样转出，客户端看到 `a\r\n0123456789\r\n`，而 nginx 给的是纯数字。现在
1.0 客户端拿到的是去分帧的体，用关闭连接来界定长度。

**本轮推翻了一个旧结论**：`BUFFER_CHUNKED_UPSTREAM` 原本关着，注释说开启会让
`proxy_cache_vary.t` 掉五条断言。在上面的解析与连接池修复之后，缓冲 chunked 响应在该
文件上已是 SAME（53/54，与 nginx 一致），并修好了本文件的 "complex chunked"，所以现在
它是开的。

新增 4 个单元测试钉住终止符规则，其中一条特意对比「`dechunk` 认为 `0\r\n` 已完整、而
消息其实还没结束」。

### 2026-10-28 第十九轮：HTTP/2 头过滤器

`h2_absolute_redirect.t` 7/25 → **25/25**，入清单（128 → **129** 文件）。

四个互相独立的缺陷，症状都是「同一个请求在 h2 上与 HTTP/1 结果不同」：

| 缺陷 | 表现 |
|---|---|
| `Location` 只对 `raw` 做绝对化 | `return 301 /x` 与目录重定向把 `Location` 留在未渲染的 `headers` 里，h1 靠 `write_redirect` 兜底 —— 而 h2 从不经过它 |
| h2server 把监听端口写死成 443 | 明文监听 8080 上生成 `http://on:443/` |
| `:path` 未解码 | 直接用了 `request.uri().path()`（仍是 `%20`），`/dir%20sp` 匹配不到磁盘上的 `dir sp`，补斜杠重定向从不触发 |
| 非法 `:authority` 在帧循环里直接回 400 | 完全跳过 `error_page`。该测试的配置正是把 400 映射到页面，用来观察「回落到监听地址」这一行为 |

修法：`finalize_response` 同时处理 `headers` 与 `raw` 两处（已绝对化的值再处理是幂等的，
h1 不受影响）；端口从 `group.addr.port()` 传入；`parse_target` 负责解码；400 走新增的
`error_page_response`（内部调用 `finalize_response`），与 h1 路径一致。

一个过程中的教训值得记下：我第一版改 `:path` 时把 `query` 也一起换成了 `parse_target`
的返回值（它只收到 path，自然是空），于是每个 `Location` 都丢了 `?a=b`。测试立刻就抓到了
—— 这也是即使看起来只是「头部格式」的文件也应该留在声明清单里的理由。

**未完成：`ssl_verify_depth.t`（仍 2/11）**，两个互相独立的阻塞点，都如实记录而不是绕口径：

1. `ssl_verify_depth` 未解析，且验证器是 webpki 的 `verify_for_usage` —— 它会构建路径但
   **不提供深度上限**。要复现 nginx 的语义，得自己走一遍链（按 issuer/subject 或 AKI 匹配
   DER），在中间证书数超过指令值时拒绝；当前依赖集里没有 X.509 解析器。
2. 更基础的一条：那条路径上的响应**完全没有** `X-Client` / `X-Verify` 头，即
   `add_header ... $ssl_client_s_dn always` 没有发出。这本身是较小的 bug，但只修它只能把
   2/11 变成约 7/11，而半个文件不能进声明清单。

### 2026-10-28 第二十轮：HTTP/2 trailers，以及一条工具自检

`h2_trailers.t` 10/24 → **24/24**，入清单（129 → **130** 文件）。

`add_trailer` 在 h1 上是「chunked 尾块」，在 h2 上是**第二个 HEADERS 帧**：流必须
先发完 DATA 而不置 END_STREAM，再发 trailer HEADERS。此前 h2 路径根本没有看
`resp.trailers`，DATA 直接带 END_STREAM，于是帧序列只有 2 帧而 nginx 是 3 帧。

顺带一条 h2 的协议约束：`Transfer-Encoding`、`Connection`、`Keep-Alive`、
`Proxy-Connection`、`Upgrade` 在 HTTP/2 里是禁止的（RFC 9113 §8.2.2），而 h1 路径
为了 `add_trailer` 会插入 `Transfer-Encoding: chunked`。现在这两条路径共用一个
`is_connection_specific` 过滤器。

**工具自检**（本轮新增，因为上一轮我自己踩了两次）：`bench/declared.sh` 现在会

1. 打印**解析后的** `declared.txt` 绝对路径；
2. 逐条核对清单里的文件名在 `$TESTS_DIR` 中确实存在，缺失即非零退出。

起因是两次「绿了的假象」：`rsync -az bench/declared.txt host:~/ngxrs/` 会把文件落在
`~/ngxrs/declared.txt` 而不是 `bench/` 下，于是回归跑的是**上一次的清单**却仍打印 PASS
（两次分别少跑了 1 个和 1 个文件）。这类错配必须是硬失败，不能靠人盯。

**未做**：`h3server` 同样不发 trailers。`h3_trailers.t` 存在，但参考 nginx 没有编译
`--with-http_v3_module`，跑出来的只是我方数字，**不能**当作一致性证据 —— 所以既没有
实现也没有声明，如实记在这里。

### 2026-10-28 第二十一轮：HTTP/2 的流并发（以及 h2 crate 的一条结构限制）

`h2_request_body.t` 40/51 → **48/51**，**未入清单**（原因见末尾）。

**根因是一个架构问题**：接受循环一次只处理一个流，读完整个请求体才回到
`conn.accept()`。而 `h2::server::Connection` 是唯一读取 socket 的东西，只有被轮询时才
前进 —— 在循环里 `await` 请求体，就把连接本身停住了。凡是需要「超出已缓冲字节」的用例
全部挂起：

| 用例 | 表现 |
|---|---|
| 请求体分多个 DATA 帧到达 | 第二帧永远读不到 |
| 超过流窗口的大请求体 | 对端在等我们的 WINDOW_UPDATE，而我们没在驱动连接 |
| 打开流但不发 END_STREAM、且请求不需要体 | 本该立即应答再复位，实际一直等 |

现在流作为并发本地 future 运行，`accept()` 持续被轮询。`futures` 不是依赖，所以
`poll_all` 是约 20 行的 poll 集合 —— 只有「连接」和「各流」两类东西要等，够用。

同一文件量到的另外四点，现在都与 nginx 一致：

  * 流控按 **64 KB 块**归还，而不是每个 DATA 帧一次：对端看到的是一条
    `wdelta >= 65536` 的 WINDOW_UPDATE，而不是一串 16 KB 的；
  * 只有真的会用到请求体时才收集（proxy/fastcgi/uwsgi/scgi/dav/`$request_body`）。
    不需要且未结束的体，应答之后用 `NO_ERROR` 复位 —— 但**仅在流确实未结束时**；第一版
    把已结束的流也复位了，直接打破了 "request body with padding - next"；
  * 请求没有体、也没有声明长度时，不再向上游发 `Content-Length: 0`；
  * 只要收到过 DATA 帧（哪怕是空的）就把体落盘（`$request_body_file`），这是
    "request body - empty size" 需要的。

**剩下 3 条做不到，不能归因于本项目的代码**：`request body less/more than
content-length` 与空 `:method` 那几条，发来的体长度与 `content-length` 矛盾。`h2` crate
在 `recv_data` 里自己比较两者并抛 `PROTOCOL_ERROR` 复位流 —— payload **根本不会**交给
我们的 `RecvStream`，于是 `data()` 永不返回，没有任何东西可以应答。nginx 自己拥有 HTTP/2
帧层，所以它能比较 `r->headers_in.content_length_n` 与实际收到的字节并回 400。这与已在
本文件记录过的 HPACK / 帧级条目同类：结构性限制，不是待办的 bug。因此该文件停在
48/51、**不进声明清单**。

### 2026-10-28 第二十二轮：`server_tokens` 是 location 级，不是 server 级

`server_tokens.t` 12/14 → **14/14**、`h2_server_tokens.t` 11/14 → **14/14**，两者入清单
（130 → **132** 文件）。

`server_tokens` 原本只在 http/server 作用域解析，写进 `location` 时落进了「接受但未接线」
那一支，于是被丢弃。nginx 把它放在 `clcf` 上并向下合并，而这两个文件正是把 `off` 放进
`/off` 里，用来验证 server 级默认值不会渗进来。

有三处必须一致，因为 `Server` 行是**发射器**写的，而它们只知道 server 级标志：

1. `LocCfg::server_tokens: Option<bool>`（`None` 表示继承），在 location 作用域解析；
2. `finalize_response` 把这个选择记录到 `Response` 上，两种协议的发射器都能取用，不必把
   location 一路传下去；
3. 内置错误页在 `<hr>` 之后**重复**一次签名，那段也要改写 —— 这就是第三条断言
   （"404 body"），也说明了只改头部为什么不够。

顺带一提：`server_tokens.t` 此前也停在 12/14，现在同样 SAME。它不在 h2 那个文件里，
说明缺陷在共享路径而不在 HTTP/2 代码 —— 这正是维护 130 文件全量回归的价值。

**关于 slice**：本轮先做 `slice.t`，但**放弃了**。第一版（解析 `slice`、把 `$slice_range`
接进缓存键展开器、在缓冲 fetch 里按片循环）把这个文件从 64/87 变成 **61/87**：它整体替换了
上游头，导致验证器消失、`if-range` 系列回退，还额外发出了一个与 `add_header` 重复的
`X-Cache-Status`。那是净负收益，所以**回退了工作区而不是提交**。slice 需要单独一轮，先把
验证器与 cache-status 的语义定清楚，而不是在同一轮里边试边塞。

### 2026-10-28 第二十三轮：`slice` 过滤器

`slice.t` **64/87 → 81/87**。**未入清单**（仍 WORSE，见末尾）。

上一轮我回退过一次（64 → 61），因为它整体替换了上游头、验证器丢失。这轮先把
`ngx_http_slice_filter_module.c` 的三条规则读清楚，再动手：

1. **`$slice_range` 不是从 0 开始**，而是 `size * (get_start() / size)` —— 客户端区间
   起点向下对齐到的片边界。`get_start()` 在请求带 `If-Range`、多区间或后缀区间时返回 0。
2. **每个片响应必须是 206**，`Content-Range` 恰为 `start-(min(start+size, total)-1)`，
   且 ETag 与第一片一致。任何偏差 nginx 都会**不发任何响应**直接中断 —— 这就是 6 条
   "bad range" 断言；这里对应返回 `444`，连接写入器已把它当作「不应答直接关闭」。
3. **切片在客户端区间末尾停止，而不是实体末尾**，并且当客户端区间起点在已取片之后时
   **向前跳**。两者都可观测：`bytes=2-2` 期望是缓存 MISS，正因为更早的 `bytes=0-0`
   请求从未取过那一片；"if-range skip" 要求取到含第 6 字节的片而跳过 2-3。

第三条代价最大：我最初把跳转放在「追加本片内容」之前，随后又被同一轮的
`pos = expected_end` 覆盖，于是 `bytes=-10` 返回 `0123456789` 而不是 `6789abcdef`。
跳转必须**丢弃手上这一片**。

另外：`proxy_set_header Range $slice_range` 走的是 proxy 自己那个小变量视图，其中没有这个
名字 —— 于是展开为空、整行被跳过。这条让我多花了一个来回；修法只是一个 match 分支。

**顺带修掉两个与切片无关的真缺陷**：

- 缓存 HIT 时**从不评估 `If-Match`**：只有上游会检查，于是缓存命中的响应在 nginx 应答
  412 的地方返回 200。非切片路径同样受益。
- 启用切片后缓存里存的是 206 片段，而 `cached_not_modified` 对非 200 直接退出，导致命中时
  任何条件请求都无法应答。现在条件请求在**装配后的**响应上评估。

**剩余 6 条断言，都超出本次改动的范围**：

| 断言 | 原因 |
|---|---|
| 5 条 `fastcgi` + `slice` | 切片循环在 `proxy::fetch` 里，fastcgi 有自己的 fetch，其参数视图没有 `$slice_range`。连 73/74 两条普通 fastcgi 用例也失败，因为被 `slice` 的 fastcgi location 必须真的切片，否则守护进程根本收不到 Range |
| 1 条 "in named location - cache entries" | 它数缓存目录里的文件，期望 8 个，而我们每个条目写 4 个文件（32 个）。这是磁盘布局，不是切片行为 |

因此 `slice.t` **不进声明清单**：81/87 是真实提升，但该文件仍是 WORSE，我不会把一个
失败的断言数藏进「已声明」里。

### 2026-10-28 第二十四轮：切片泛化到 fastcgi，以及缓存目录布局

`slice.t` **81/87 → 82/87**。仍未入清单。

两件事：

1. **切片循环由 proxy 与 fastcgi 共用**（`SliceMode`）。`fastcgi_param Range $slice_range`
   之前在 fastcgi 自己的变量视图里解析不出来 —— 与 proxy 那边同一处缺口，于是 CGI 根本
   收不到 Range。uwsgi/SCGI 明确返回「不支持」，而不是假装：它们没有可切片的缓冲 fetch，
   静默忽略 `slice` 比诚实报错更糟。
2. **`clear_variants` 无条件取变体索引锁**，于是每个普通（无 `Vary`）缓存条目旁边都留下一个
   `.lock` 边车文件，任何 glob 缓存目录的东西都会看到两倍文件数。`slice.t` 的
   "in named location - cache entries" 恰好数 8 个文件对应 8 个切片，把它抓了出来 ——
   现在只有变体索引真实存在时才创建边车。该断言已通过。

剩余 5 条全是 `fastcgi` + `slice`，且每条都读 `$upstream_cache_status`。没有
`fastcgi_cache` 时该变量为空，`add_header X-Cache-Status` 被跳过，"MISS"/"HIT" 永远匹配不上
—— 连 73/74 两条普通 fastcgi 用例也是因此失败，不是切片坏了。复用 `cache.rs` 做
fastcgi 缓存可行，但需要指令集（`fastcgi_cache` / `fastcgi_cache_key` /
`fastcgi_cache_valid`）、lookup/store 接线与状态传递到 `add_header`，那是独立一轮；
只做「开切片时才缓存」的半成品我不想提交。

proxy/cache/vary 均未回退：`proxy_cache.t` 17/17、`proxy_cache_vary.t` 53/54、
`proxy_cache_valid.t` 14/14。

### 2026-10-28 第二十五轮：`fastcgi_cache`（同时关闭 `slice.t`）

`slice.t` **82/87 → 87/87**、`fastcgi_cache.t` 6/7 → **7/7**，两者入清单
（132 → **134** 文件）。

`fastcgi_cache` 此前完全不存在：`fastcgi_cache` / `fastcgi_cache_key` /
`fastcgi_cache_valid` 躺在「接受但不生效」那一支，`fastcgi_cache_path` 根本没解析。
slice 最后 5 条断言都读 `$upstream_cache_status`，没有它不可能通过。

本轮做的：

- **`*_cache_path` 合并成一个解析器**：两个模块的参数逐个相同，注册进同一张 zone 表，
  而且一个 zone 被两者共用是合法配置。
- **`LocCfg` 有自己的 `fastcgi_cache*` 字段**。nginx 把它们放在 fastcgi 的 location conf
  上（`ngx_http_fastcgi_loc_conf_t.cache`），不是 proxy 的，所以同一个 location 可以缓存
  其中一个上游模块而不缓存另一个，有效期也可以不同。`cache::ttl` 因此拆开，有效期来源变成
  参数而不是写死 `proxy_cache_valid`。
- **`fastcgi::fetch` 做 lookup / 命中即不联系应答方 / 未命中则存储**。`$slice_range` 也进
  `fastcgi_cache_key` —— 漏掉它会让所有片共用一条缓存，症状是切片循环要
  `bytes=2-3`、却拿到缓存的 `bytes=0-1` 响应（`unexpected range 0-1, want 2-1`）。

**顺带挖出两个早于本轮的架构缺陷**：

1. `fastcgi::handle` 把响应直接写连接、**从不经过 `finalize_response`**，所以 HTTP/1 上
   **fastcgi 响应从来不会应用 `add_header`**。改在上游变量可见的位置应用（proxy 模块本来
   就是这么做的）才对。仅这一条就值好几条断言：没有它，缓存就算完全正确也什么都显示不出来。
2. 命中路径在应用那个头部块**之前**就提前返回，于是缓存命中的响应没有 `X-Cache-Status`。
   两条路径现在共用一个出口。

另外：`fastcgi::handle` 需要**单独**教它切片。我第一版只让无 socket 的路径（HTTP/2、
子请求）会切片，而 `slice.t` 跑在 HTTP/1 上 —— 在 `handle` 走同一条路之前断言一直是红的。

**不是回归**：`fastcgi_request_buffering.t` 是 14/17，我在同一台主机上用上一提交编译的
二进制对照过，也是 14/17。那个缺口是仍未实现的 `fastcgi_request_buffering` 指令，该文件
不在声明清单里。

### 2026-10-28 第二十六轮：`proxy_request_buffering off`

`proxy_request_buffering.t` 18/20 → **20/20**，入清单（134 → **135** 文件）。
`fastcgi_request_buffering.t` 14/17 → 16/17，**未入清单**（原因见末尾）。

这个指令此前**完全没有解析**：`proxy_request_buffering` 与
`fastcgi_request_buffering` 躺在「接受但不生效」那一支，请求不缓冲的 location 拿到的是
缓冲行为，而且没有任何提示。

指令真正改变的是：**上游连接在读取客户端 body 之前就建立**。这正是测试里 `accept()` 检查
的东西。此前 `handle` 先 `take_request_body` 再拨号，后端的 `accept()` 要等客户端把十个
字节全部发出才能返回 —— 两条 preread 断言直接超时。

四处必须同时对上，每一处都是上一条修好后由下一条断言暴露的：

1. `build_upstream_head` 发的是 `Content-Length: 0`（它只看到空的缓冲体），而 body 在之后
   才流式送出。上游于是等一个「头里说不存在」的 body。
2. 按固定长度转发（`take_body(want)`）会一直等到凑满；nginx 是**读到多少转多少**。
   `Conn::take_available` 返回当前已缓冲的部分。这才让 "preread - body part" 在客户端只
   写了五个字节后就看到 `01234`。
3. 随请求头一起到达的那部分 body 必须与头**在同一次写出**中发出 —— 后端在 `accept()`
   之后只做一次 `sysread`，期望两样都在。所以这段前缀在写出前被折进头部缓冲区。
4. `$request_body` 必须在非缓冲路径之后仍然可读：nginx 无论缓冲与否都会填
   `r->request_body`，而 `fastcgi_request_buffering.t` 通过 `error_page` 目标读它。现在流式
   送出的字节会按 `client_body_buffer_size` 上限保留在 `Request::streamed_body`
   （`Arc<Mutex<..>>`，因为 request 是共享的），该变量回退到它。

chunked body 在两个模块上都仍然缓冲：不缓冲转发意味着边收边重新分帧。我试过 fastcgi 那一半，
它把 `fastcgi_request_buffering_chunked.t` 从 17/21 拉到 **12/21**，所以**回退了**，
而不是把一个半成品留在树里 —— 注释里写明了这一点和原因。

**`fastcgi_request_buffering.t` 停在 16/17，不进声明清单。** 剩下那条是 "body in error
page"，它**与缓冲无关**：`fastcgi::handle` 直接把响应写连接，所以
`error_page` / `fastcgi_intercept_errors` 对 fastcgi 上游状态**从不执行** —— nginx 交给
`/404` 的地方我们回 404。这与 proxy 在学会返回 `Proxied::Intercept` 之前是同一处结构缺口，
给 fastcgi 补上是一件独立的事。

## 二、声明的测试清单

清单在 `bench/declared.txt`，**135 个文件**，选取规则是机械的：

1. 落在范围内（**参考构建 `-V` 能编出来的模块**：http core + proxy/cache/gzip/
   TLS/HTTP2/realip/auth_request/slice/sub/secure_link/dav/stub_status/gzip_static/
   fastcgi/uwsgi/scgi/grpc/stream/mail。此前写作「默认构建」，与参考二进制不符，
   已按 `-V` 更正；reference 编不出来的一律出范围）；
2. **两边都真的产出了断言**——两边都跳过的套件什么也证明不了，已被排除；
3. 没有任何断言在 nginx 通过而我们失败；
4. 我方没有截断（两边断言行数相同）。

两边都不通过某些断言的套件**允许**保留：判据是「nginx 过而我们不过」，
不是绝对一致。例如 `http_keepalive.t` 两边都是 21/23，那 2 条对双方都不成立。

## 三、已知偏差（全量扫描，逐项带复现）

### 口径修正（2026-10-27）

这一节此前写的是「全部 348 个在范围内文件 / 185 文件 / 1733 条断言」。
那个数字来自一次**范围更窄**的扫描：`bench/ntscan.sh` 的排除正则把
dav / slice / secure_link / realip / auth_request / sub / limit_* / h2 / ssl /
grpc / mail / resolver / proxy_protocol 全排除了，也就是把这些家族「还没实现」
当成了事实，而其中多数是实现过的。按 `nginx -V` 的真实范围重扫：

```
LIMIT=400 bash bench/ntscan.sh      # 默认已是 *.t 减去参考 nginx 编不出来的模块
files compared=314  same=193  better=8  worse=113   (skipped=86)
total assertions where ngxrs loses: 476
```

（会话开始时同口径为 `same=173 better=7 worse=134`、`795` 条；随后每轮重扫都对比
基线文件列表，本轮的 113 个 WORSE 文件与基线是**子集关系** —— 没有任何文件新变差，
消失的 21 个是这轮修掉的。）

**314 个文件可比，134 个仍有差距，795 条断言。** 这个数比旧表小，只是因为
旧表的 348 里有一半两边都跑不动（`skipped=86` 是两边都没产断言的）。

注意这次扫描跑在 PROXY protocol 与 dav 落盘之前，`proxy_protocol*.t`、
`ssl_proxy_protocol.t`、`dav*.t` 的差距在扫描之后已经被消掉，下面「按剩余断言排序」
是扫描当时的快照。

### 剩余差距排序（扫描快照，已完成项已标注）

| 断言 | 用例 | 状态 |
|---|---|---|
| 49 | `http_resolver_aaaa.t` | 缺：resolver 的 AAAA/CNAME 与 TTL 语义 |
| 36 | `proxy_keepalive.t` | 缺：上游 keepalive 的连接复用细节 |
| 33 | `autoindex_format.t` | **已修**（json/jsonp/xml） |
| 25 | `http_resolver.t` | 同上 |
| 23 | `proxy_protocol2.t` | **已修** |
| 20 | `proxy_protocol.t` | **已修** |
| 19 | `stream_geo.t` | 缺：stream 侧 `geo` |
| 18 | `slice.t` | 缺：`ngx_http_slice_filter_module` |
| 18 | `h2_absolute_redirect.t` | 缺：h2 上的 `absolute_redirect` |
| 14 | `ssl_proxy_protocol.t` | **已修** |
| 14 | `proxy_protocol2_tlv.t` | **已修** |
| 14 | `ssl_ocsp.t` | 缺：OCSP stapling |
| 14 | `http_disable_symlinks.t` | 缺：`disable_symlinks` |
| 12 | `stream_upstream_max_conns.t` | 缺：`max_conns` |

每行的复现命令：`TEST_LIST=<用例名> bash bench/nginxtests.sh`。

#### stream（TCP/UDP）

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `stream_upstream_service.t` | 0/23 | 23 | `TEST_LIST=stream_upstream_service.t bash bench/nginxtests.sh` |
| `stream_proxy_ssl_certificate_cache.t` | 0/22 | 22 | `TEST_LIST=stream_proxy_ssl_certificate_cache.t bash bench/nginxtests.sh` |
| `stream_ssl_ocsp.t` | 0/22 | 22 | `TEST_LIST=stream_ssl_ocsp.t bash bench/nginxtests.sh` |
| `stream_server_name.t` | 0/21 | 21 | `TEST_LIST=stream_server_name.t bash bench/nginxtests.sh` |
| `stream_access.t` | 0/20 | 20 | `TEST_LIST=stream_access.t bash bench/nginxtests.sh` |
| `stream_geo.t` | 2/21 | 19 | `TEST_LIST=stream_geo.t bash bench/nginxtests.sh` |
| `stream_ssl_certificate_cache.t` | 0/16 | 16 | `TEST_LIST=stream_ssl_certificate_cache.t bash bench/nginxtests.sh` |
| `stream_proxy_protocol2_tlv.t` | 2/16 | 14 | `TEST_LIST=stream_proxy_protocol2_tlv.t bash bench/nginxtests.sh` |
| `stream_upstream_max_conns.t` | 3/16 | 13 | `TEST_LIST=stream_upstream_max_conns.t bash bench/nginxtests.sh` |
| `stream_upstream_resolve.t` | 0/13 | 13 | `TEST_LIST=stream_upstream_resolve.t bash bench/nginxtests.sh` |
| `stream_access_log.t` | 0/12 | 12 | `TEST_LIST=stream_access_log.t bash bench/nginxtests.sh` |
| `stream_ssl_stapling.t` | 0/12 | 12 | `TEST_LIST=stream_ssl_stapling.t bash bench/nginxtests.sh` |
| `stream_limit_conn_dry_run.t` | 0/11 | 11 | `TEST_LIST=stream_limit_conn_dry_run.t bash bench/nginxtests.sh` |
| `stream_limit_rate.t` | 0/11 | 11 | `TEST_LIST=stream_limit_rate.t bash bench/nginxtests.sh` |
| `stream_limit_rate2.t` | 0/11 | 11 | `TEST_LIST=stream_limit_rate2.t bash bench/nginxtests.sh` |
| `stream_udp_limit_conn.t` | 0/11 | 11 | `TEST_LIST=stream_udp_limit_conn.t bash bench/nginxtests.sh` |
| `stream_upstream_resolve_reload.t` | 0/11 | 11 | `TEST_LIST=stream_upstream_resolve_reload.t bash bench/nginxtests.sh` |
| `stream_limit_conn.t` | 0/10 | 10 | `TEST_LIST=stream_limit_conn.t bash bench/nginxtests.sh` |
| `stream_realip.t` | 0/10 | 10 | `TEST_LIST=stream_realip.t bash bench/nginxtests.sh` |
| `stream_resolver.t` | 0/10 | 10 | `TEST_LIST=stream_resolver.t bash bench/nginxtests.sh` |
| `stream_udp_limit_rate.t` | 0/10 | 10 | `TEST_LIST=stream_udp_limit_rate.t bash bench/nginxtests.sh` |
| `stream_ssl_certificate.t` | 0/9 | 9 | `TEST_LIST=stream_ssl_certificate.t bash bench/nginxtests.sh` |
| `stream_ssl_reject_handshake.t` | 0/9 | 9 | `TEST_LIST=stream_ssl_reject_handshake.t bash bench/nginxtests.sh` |
| `stream_ssl_session_reuse.t` | 0/9 | 9 | `TEST_LIST=stream_ssl_session_reuse.t bash bench/nginxtests.sh` |
| `stream_ssl_alpn.t` | 0/8 | 8 | `TEST_LIST=stream_ssl_alpn.t bash bench/nginxtests.sh` |
| `stream_ssl_realip.t` | 0/8 | 8 | `TEST_LIST=stream_ssl_realip.t bash bench/nginxtests.sh` |
| `stream_status_variable.t` | 0/8 | 8 | `TEST_LIST=stream_status_variable.t bash bench/nginxtests.sh` |
| `stream_upstream_resolver.t` | 0/8 | 8 | `TEST_LIST=stream_upstream_resolver.t bash bench/nginxtests.sh` |
| `stream_upstream_service_reload.t` | 0/8 | 8 | `TEST_LIST=stream_upstream_service_reload.t bash bench/nginxtests.sh` |
| `stream_variables.t` | 2/10 | 8 | `TEST_LIST=stream_variables.t bash bench/nginxtests.sh` |
| `stream_proxy_complex.t` | 0/7 | 7 | `TEST_LIST=stream_proxy_complex.t bash bench/nginxtests.sh` |
| `stream_proxy_next_upstream.t` | 0/7 | 7 | `TEST_LIST=stream_proxy_next_upstream.t bash bench/nginxtests.sh` |
| `stream_proxy_ssl_certificate.t` | 0/7 | 7 | `TEST_LIST=stream_proxy_ssl_certificate.t bash bench/nginxtests.sh` |
| `stream_proxy_ssl_certificate_vars.t` | 0/7 | 7 | `TEST_LIST=stream_proxy_ssl_certificate_vars.t bash bench/nginxtests.sh` |
| `stream_geo_ipv6.t` | 2/8 | 6 | `TEST_LIST=stream_geo_ipv6.t bash bench/nginxtests.sh` |
| `stream_geo_unix.t` | 0/6 | 6 | `TEST_LIST=stream_geo_unix.t bash bench/nginxtests.sh` |
| `stream_limit_conn_complex.t` | 0/6 | 6 | `TEST_LIST=stream_limit_conn_complex.t bash bench/nginxtests.sh` |
| `stream_realip_hostname.t` | 0/6 | 6 | `TEST_LIST=stream_realip_hostname.t bash bench/nginxtests.sh` |
| `stream_ssl_sni_protocols.t` | 0/6 | 6 | `TEST_LIST=stream_ssl_sni_protocols.t bash bench/nginxtests.sh` |
| `stream_ssl_variables.t` | 2/8 | 6 | `TEST_LIST=stream_ssl_variables.t bash bench/nginxtests.sh` |
| `stream_udp_proxy_requests.t` | 22/28 | 6 | `TEST_LIST=stream_udp_proxy_requests.t bash bench/nginxtests.sh` |
| `stream_map.t` | 2/7 | 5 | `TEST_LIST=stream_map.t bash bench/nginxtests.sh` |
| `stream_ssl_conf_command.t` | 0/5 | 5 | `TEST_LIST=stream_ssl_conf_command.t bash bench/nginxtests.sh` |
| `stream_upstream.t` | 3/8 | 5 | `TEST_LIST=stream_upstream.t bash bench/nginxtests.sh` |
| `stream_proxy_half_close.t` | 0/4 | 4 | `TEST_LIST=stream_proxy_half_close.t bash bench/nginxtests.sh` |
| `stream_proxy_ssl_name.t` | 3/7 | 4 | `TEST_LIST=stream_proxy_ssl_name.t bash bench/nginxtests.sh` |
| `stream_tcp_nodelay.t` | 0/4 | 4 | `TEST_LIST=stream_tcp_nodelay.t bash bench/nginxtests.sh` |
| `stream_udp_stream.t` | 6/10 | 4 | `TEST_LIST=stream_udp_stream.t bash bench/nginxtests.sh` |
| `stream_unix.t` | 0/4 | 4 | `TEST_LIST=stream_unix.t bash bench/nginxtests.sh` |
| `stream_upstream_zone_ssl.t` | 7/11 | 4 | `TEST_LIST=stream_upstream_zone_ssl.t bash bench/nginxtests.sh` |
| `stream_proxy_bind.t` | 0/3 | 3 | `TEST_LIST=stream_proxy_bind.t bash bench/nginxtests.sh` |
| `stream_proxy_ssl_conf_command.t` | 0/3 | 3 | `TEST_LIST=stream_proxy_ssl_conf_command.t bash bench/nginxtests.sh` |
| `stream_proxy_ssl_verify.t` | 5/8 | 3 | `TEST_LIST=stream_proxy_ssl_verify.t bash bench/nginxtests.sh` |
| `stream_udp_upstream.t` | 4/7 | 3 | `TEST_LIST=stream_udp_upstream.t bash bench/nginxtests.sh` |
| `stream_upstream_random.t` | 11/14 | 3 | `TEST_LIST=stream_upstream_random.t bash bench/nginxtests.sh` |
| `stream_access_log_escape.t` | 2/4 | 2 | `TEST_LIST=stream_access_log_escape.t bash bench/nginxtests.sh` |
| `stream_geo_binary.t` | 2/4 | 2 | `TEST_LIST=stream_geo_binary.t bash bench/nginxtests.sh` |
| `stream_proxy_ssl_name_complex.t` | 2/4 | 2 | `TEST_LIST=stream_proxy_ssl_name_complex.t bash bench/nginxtests.sh` |
| `stream_set.t` | 2/4 | 2 | `TEST_LIST=stream_set.t bash bench/nginxtests.sh` |
| `stream_udp_upstream_hash.t` | 2/4 | 2 | `TEST_LIST=stream_udp_upstream_hash.t bash bench/nginxtests.sh` |
| `stream_upstream_hash.t` | 4/6 | 2 | `TEST_LIST=stream_upstream_hash.t bash bench/nginxtests.sh` |
| `stream_upstream_zone.t` | 2/4 | 2 | `TEST_LIST=stream_upstream_zone.t bash bench/nginxtests.sh` |
| `stream_access_log_none.t` | 2/3 | 1 | `TEST_LIST=stream_access_log_none.t bash bench/nginxtests.sh` |
| `stream_proxy_protocol.t` | 3/4 | 1 | `TEST_LIST=stream_proxy_protocol.t bash bench/nginxtests.sh` |
| `stream_proxy_protocol_ipv6.t` | 3/4 | 1 | `TEST_LIST=stream_proxy_protocol_ipv6.t bash bench/nginxtests.sh` |
| `stream_proxy_protocol_ssl.t` | 3/4 | 1 | `TEST_LIST=stream_proxy_protocol_ssl.t bash bench/nginxtests.sh` |
| `stream_split_clients.t` | 2/3 | 1 | `TEST_LIST=stream_split_clients.t bash bench/nginxtests.sh` |
| `stream_udp_proxy.t` | 9/10 | 1 | `TEST_LIST=stream_udp_proxy.t bash bench/nginxtests.sh` |
| `stream_udp_upstream_least_conn.t` | 3/4 | 1 | `TEST_LIST=stream_udp_upstream_least_conn.t bash bench/nginxtests.sh` |
| `stream_upstream_least_conn.t` | 3/4 | 1 | `TEST_LIST=stream_upstream_least_conn.t bash bench/nginxtests.sh` |

#### HTTP/2

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `h2_priority_update.t` | 0/61 | 61 | `TEST_LIST=h2_priority_update.t bash bench/nginxtests.sh` |
| `h2_proxy_request_buffering.t` | 2/51 | 49 | `TEST_LIST=h2_proxy_request_buffering.t bash bench/nginxtests.sh` |
| `h2_fastcgi_request_buffering.t` | 2/50 | 48 | `TEST_LIST=h2_fastcgi_request_buffering.t bash bench/nginxtests.sh` |
| `h2_proxy_request_buffering_ssl.t` | 2/42 | 40 | `TEST_LIST=h2_proxy_request_buffering_ssl.t bash bench/nginxtests.sh` |
| `h2_headers.t` | 73/112 | 37 | `TEST_LIST=h2_headers.t bash bench/nginxtests.sh` |
| `h2_request_body_extra.t` | 26/52 | 26 | `TEST_LIST=h2_request_body_extra.t bash bench/nginxtests.sh` |
| `h2_absolute_redirect.t` | 7/25 | 18 | `TEST_LIST=h2_absolute_redirect.t bash bench/nginxtests.sh` |
| `h2_trailers.t` | 10/24 | 14 | `TEST_LIST=h2_trailers.t bash bench/nginxtests.sh` |
| `h2_priority.t` | 13/24 | 11 | `TEST_LIST=h2_priority.t bash bench/nginxtests.sh` |
| `h2_request_body.t` | 40/51 | 11 | `TEST_LIST=h2_request_body.t bash bench/nginxtests.sh` |
| `h2_keepalive.t` | 12/21 | 9 | `TEST_LIST=h2_keepalive.t bash bench/nginxtests.sh` |
| `h2_ssl.t` | 0/6 | 6 | `TEST_LIST=h2_ssl.t bash bench/nginxtests.sh` |
| `h2_http2.t` | 9/13 | 4 | `TEST_LIST=h2_http2.t bash bench/nginxtests.sh` |
| `h2_request_body_preread.t` | 5/11 | 4 | `TEST_LIST=h2_request_body_preread.t bash bench/nginxtests.sh` |
| `h2_ssl_variables.t` | 2/6 | 4 | `TEST_LIST=h2_ssl_variables.t bash bench/nginxtests.sh` |
| `h2_variables.t` | 4/8 | 4 | `TEST_LIST=h2_variables.t bash bench/nginxtests.sh` |
| `h2_server_tokens.t` | 11/14 | 3 | `TEST_LIST=h2_server_tokens.t bash bench/nginxtests.sh` |
| `h2_ssl_proxy_protocol.t` | 2/5 | 3 | `TEST_LIST=h2_ssl_proxy_protocol.t bash bench/nginxtests.sh` |
| `h2_ssl_verify_client.t` | 2/5 | 3 | `TEST_LIST=h2_ssl_verify_client.t bash bench/nginxtests.sh` |
| `h2_proxy_cache.t` | 9/11 | 2 | `TEST_LIST=h2_proxy_cache.t bash bench/nginxtests.sh` |
| `h2_proxy_protocol.t` | 3/5 | 2 | `TEST_LIST=h2_proxy_protocol.t bash bench/nginxtests.sh` |
| `h2_auth_request.t` | 3/4 | 1 | `TEST_LIST=h2_auth_request.t bash bench/nginxtests.sh` |
| `h2_error_page.t` | 3/4 | 1 | `TEST_LIST=h2_error_page.t bash bench/nginxtests.sh` |
| `h2_limit_conn.t` | 5/6 | 1 | `TEST_LIST=h2_limit_conn.t bash bench/nginxtests.sh` |
| `h2_limit_req.t` | 8/9 | 1 | `TEST_LIST=h2_limit_req.t bash bench/nginxtests.sh` |
| `h2_proxy_request_buffering_redirect.t` | 2/3 | 1 | `TEST_LIST=h2_proxy_request_buffering_redirect.t bash bench/nginxtests.sh` |
| `h2_proxy_ssl.t` | 2/3 | 1 | `TEST_LIST=h2_proxy_ssl.t bash bench/nginxtests.sh` |
| `h2_host.t` | 52/62 | -4 | `TEST_LIST=h2_host.t bash bench/nginxtests.sh` |

#### 反向代理

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `proxy_keepalive.t` | 15/51 | 36 | `TEST_LIST=proxy_keepalive.t bash bench/nginxtests.sh` |
| `proxy_protocol2.t` | 5/30 | 25 | `TEST_LIST=proxy_protocol2.t bash bench/nginxtests.sh` |
| `proxy_protocol.t` | 4/26 | 22 | `TEST_LIST=proxy_protocol.t bash bench/nginxtests.sh` |
| `proxy_ssl_certificate_cache.t` | 0/22 | 22 | `TEST_LIST=proxy_ssl_certificate_cache.t bash bench/nginxtests.sh` |
| `proxy_protocol2_tlv.t` | 2/16 | 14 | `TEST_LIST=proxy_protocol2_tlv.t bash bench/nginxtests.sh` |
| `proxy_request_buffering_chunked.t` | 14/24 | 10 | `TEST_LIST=proxy_request_buffering_chunked.t bash bench/nginxtests.sh` |
| `proxy_request_buffering.t` | 11/20 | 9 | `TEST_LIST=proxy_request_buffering.t bash bench/nginxtests.sh` |
| `proxy_request_buffering_ssl.t` | 11/20 | 9 | `TEST_LIST=proxy_request_buffering_ssl.t bash bench/nginxtests.sh` |
| `proxy_merge_headers.t` | 5/13 | 8 | `TEST_LIST=proxy_merge_headers.t bash bench/nginxtests.sh` |
| `proxy_protocol_unix.t` | 0/7 | 7 | `TEST_LIST=proxy_protocol_unix.t bash bench/nginxtests.sh` |
| `proxy_unix.t` | 0/7 | 7 | `TEST_LIST=proxy_unix.t bash bench/nginxtests.sh` |
| `proxy_limit_rate2.t` | 0/6 | 6 | `TEST_LIST=proxy_limit_rate2.t bash bench/nginxtests.sh` |
| `proxy_unfinished.t` | 11/17 | 6 | `TEST_LIST=proxy_unfinished.t bash bench/nginxtests.sh` |
| `proxy_upstream_cookie.t` | 15/21 | 6 | `TEST_LIST=proxy_upstream_cookie.t bash bench/nginxtests.sh` |
| `proxy_xar.t` | 12/18 | 6 | `TEST_LIST=proxy_xar.t bash bench/nginxtests.sh` |
| `proxy_implicit.t` | 0/5 | 5 | `TEST_LIST=proxy_implicit.t bash bench/nginxtests.sh` |
| `proxy_non_idempotent.t` | 5/10 | 5 | `TEST_LIST=proxy_non_idempotent.t bash bench/nginxtests.sh` |
| `proxy_ssl_conf_command.t` | 0/5 | 5 | `TEST_LIST=proxy_ssl_conf_command.t bash bench/nginxtests.sh` |
| `proxy_upgrade.t` | 28/33 | 5 | `TEST_LIST=proxy_upgrade.t bash bench/nginxtests.sh` |
| `proxy_ssl_certificate.t` | 3/7 | 4 | `TEST_LIST=proxy_ssl_certificate.t bash bench/nginxtests.sh` |
| `proxy_ssl_certificate_vars.t` | 3/7 | 4 | `TEST_LIST=proxy_ssl_certificate_vars.t bash bench/nginxtests.sh` |
| `proxy_chunked.t` | 2/5 | 3 | `TEST_LIST=proxy_chunked.t bash bench/nginxtests.sh` |
| `proxy_method.t` | 3/6 | 3 | `TEST_LIST=proxy_method.t bash bench/nginxtests.sh` |
| `proxy_next_upstream_tries.t` | 7/10 | 3 | `TEST_LIST=proxy_next_upstream_tries.t bash bench/nginxtests.sh` |
| `proxy_pass_request.t` | 2/5 | 3 | `TEST_LIST=proxy_pass_request.t bash bench/nginxtests.sh` |
| `proxy_ssl_crl.t` | 4/7 | 3 | `TEST_LIST=proxy_ssl_crl.t bash bench/nginxtests.sh` |
| `proxy_ssl_verify.t` | 5/8 | 3 | `TEST_LIST=proxy_ssl_verify.t bash bench/nginxtests.sh` |
| `proxy_protocol_ipv6.t` | 3/5 | 2 | `TEST_LIST=proxy_protocol_ipv6.t bash bench/nginxtests.sh` |
| `proxy_set_body.t` | 2/4 | 2 | `TEST_LIST=proxy_set_body.t bash bench/nginxtests.sh` |
| `proxy_store.t` | 9/11 | 2 | `TEST_LIST=proxy_store.t bash bench/nginxtests.sh` |
| `proxy_variables.t` | 4/6 | 2 | `TEST_LIST=proxy_variables.t bash bench/nginxtests.sh` |
| `proxy_cache_lock_ssi.t` | 3/4 | 1 | `TEST_LIST=proxy_cache_lock_ssi.t bash bench/nginxtests.sh` |
| `proxy_connection_headers.t` | 4/7 | 1 | `TEST_LIST=proxy_connection_headers.t bash bench/nginxtests.sh` |
| `proxy_ssl_certificate_empty.t` | 3/4 | 1 | `TEST_LIST=proxy_ssl_certificate_empty.t bash bench/nginxtests.sh` |
| `proxy_ssl_name.t` | 10/11 | 1 | `TEST_LIST=proxy_ssl_name.t bash bench/nginxtests.sh` |
| `proxy_ssl_verify_ip.t` | 4/10 | 0 | `TEST_LIST=proxy_ssl_verify_ip.t bash bench/nginxtests.sh` |

#### gRPC

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `grpc.t` | 2/152 | 150 | `TEST_LIST=grpc.t bash bench/nginxtests.sh` |
| `grpc_ssl.t` | 2/40 | 38 | `TEST_LIST=grpc_ssl.t bash bench/nginxtests.sh` |
| `grpc_request_buffering.t` | 0/14 | 14 | `TEST_LIST=grpc_request_buffering.t bash bench/nginxtests.sh` |
| `grpc_next_upstream.t` | 3/11 | 8 | `TEST_LIST=grpc_next_upstream.t bash bench/nginxtests.sh` |

#### TLS

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `ssl_certificate_cache.t` | 0/16 | 16 | `TEST_LIST=ssl_certificate_cache.t bash bench/nginxtests.sh` |
| `ssl_proxy_protocol.t` | 4/20 | 16 | `TEST_LIST=ssl_proxy_protocol.t bash bench/nginxtests.sh` |
| `ssl_ocsp.t` | 3/17 | 14 | `TEST_LIST=ssl_ocsp.t bash bench/nginxtests.sh` |
| `ssl_certificate.t` | 0/13 | 13 | `TEST_LIST=ssl_certificate.t bash bench/nginxtests.sh` |
| `ssl.t` | 14/23 | 9 | `TEST_LIST=ssl.t bash bench/nginxtests.sh` |
| `ssl_verify_depth.t` | 2/11 | 9 | `TEST_LIST=ssl_verify_depth.t bash bench/nginxtests.sh` |
| `ssl_sni_protocols.t` | 0/6 | 6 | `TEST_LIST=ssl_sni_protocols.t bash bench/nginxtests.sh` |
| `ssl_certificate_aux.t` | 0/5 | 5 | `TEST_LIST=ssl_certificate_aux.t bash bench/nginxtests.sh` |
| `ssl_conf_command.t` | 0/5 | 5 | `TEST_LIST=ssl_conf_command.t bash bench/nginxtests.sh` |
| `ssl_crl.t` | 2/7 | 5 | `TEST_LIST=ssl_crl.t bash bench/nginxtests.sh` |
| `ssl_password_file.t` | 0/5 | 5 | `TEST_LIST=ssl_password_file.t bash bench/nginxtests.sh` |
| `ssl_proxy_upgrade.t` | 27/32 | 5 | `TEST_LIST=ssl_proxy_upgrade.t bash bench/nginxtests.sh` |
| `ssl_stapling.t` | 7/12 | 5 | `TEST_LIST=ssl_stapling.t bash bench/nginxtests.sh` |
| `ssl_cache.t` | 2/6 | 4 | `TEST_LIST=ssl_cache.t bash bench/nginxtests.sh` |
| `ssl_sni_reneg.t` | 6/10 | 4 | `TEST_LIST=ssl_sni_reneg.t bash bench/nginxtests.sh` |
| `ssl_reject_handshake.t` | 6/9 | 3 | `TEST_LIST=ssl_reject_handshake.t bash bench/nginxtests.sh` |
| `ssl_cache_reload.t` | 5/7 | 2 | `TEST_LIST=ssl_cache_reload.t bash bench/nginxtests.sh` |
| `ssl_client_escaped_cert.t` | 3/5 | 2 | `TEST_LIST=ssl_client_escaped_cert.t bash bench/nginxtests.sh` |
| `ssl_session_reuse.t` | 8/10 | 2 | `TEST_LIST=ssl_session_reuse.t bash bench/nginxtests.sh` |
| `ssl_verify_client.t` | 14/16 | 2 | `TEST_LIST=ssl_verify_client.t bash bench/nginxtests.sh` |
| `ssl_certificates.t` | 3/4 | 1 | `TEST_LIST=ssl_certificates.t bash bench/nginxtests.sh` |
| `ssl_curve.t` | 2/3 | 1 | `TEST_LIST=ssl_curve.t bash bench/nginxtests.sh` |
| `ssl_session_ticket_key.t` | 3/4 | 1 | `TEST_LIST=ssl_session_ticket_key.t bash bench/nginxtests.sh` |
| `ssl_verify_client_trusted.t` | 4/5 | 1 | `TEST_LIST=ssl_verify_client_trusted.t bash bench/nginxtests.sh` |

#### http core

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `http_resolver_aaaa.t` | 25/74 | 49 | `TEST_LIST=http_resolver_aaaa.t bash bench/nginxtests.sh` |
| `http_disable_symlinks.t` | 0/30 | 30 | `TEST_LIST=http_disable_symlinks.t bash bench/nginxtests.sh` |
| `http_resolver.t` | 15/40 | 24 | `TEST_LIST=http_resolver.t bash bench/nginxtests.sh` |
| `http_listen.t` | 0/11 | 11 | `TEST_LIST=http_listen.t bash bench/nginxtests.sh` |
| `http_resolver_cleanup.t` | 0/3 | 3 | `TEST_LIST=http_resolver_cleanup.t bash bench/nginxtests.sh` |
| `http_resolver_cname.t` | 10/13 | 3 | `TEST_LIST=http_resolver_cname.t bash bench/nginxtests.sh` |
| `http_resolver_ipv4.t` | 2/5 | 3 | `TEST_LIST=http_resolver_ipv4.t bash bench/nginxtests.sh` |

#### upstream

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `upstream_resolve.t` | 0/20 | 20 | `TEST_LIST=upstream_resolve.t bash bench/nginxtests.sh` |
| `upstream_max_conns.t` | 0/18 | 18 | `TEST_LIST=upstream_max_conns.t bash bench/nginxtests.sh` |
| `upstream_resolve_reload.t` | 0/11 | 11 | `TEST_LIST=upstream_resolve_reload.t bash bench/nginxtests.sh` |
| `upstream_resolver.t` | 0/8 | 8 | `TEST_LIST=upstream_resolver.t bash bench/nginxtests.sh` |
| `upstream_ip_hash_ipv6.t` | 5/6 | 1 | `TEST_LIST=upstream_ip_hash_ipv6.t bash bench/nginxtests.sh` |

#### mail

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `mail_ssl.t` | 2/21 | 19 | `TEST_LIST=mail_ssl.t bash bench/nginxtests.sh` |
| `mail_imap_ssl.t` | 7/15 | 8 | `TEST_LIST=mail_imap_ssl.t bash bench/nginxtests.sh` |
| `mail_max_errors.t` | 14/20 | 6 | `TEST_LIST=mail_max_errors.t bash bench/nginxtests.sh` |
| `mail_proxy_protocol.t` | 4/10 | 6 | `TEST_LIST=mail_proxy_protocol.t bash bench/nginxtests.sh` |
| `mail_ssl_conf_command.t` | 0/5 | 5 | `TEST_LIST=mail_ssl_conf_command.t bash bench/nginxtests.sh` |
| `mail_resolver.t` | 9/13 | 3 | `TEST_LIST=mail_resolver.t bash bench/nginxtests.sh` |
| `mail_ssl_session_reuse.t` | 7/9 | 2 | `TEST_LIST=mail_ssl_session_reuse.t bash bench/nginxtests.sh` |
| `mail_proxy_smtp_auth.t` | 8/9 | 1 | `TEST_LIST=mail_proxy_smtp_auth.t bash bench/nginxtests.sh` |

#### uwsgi

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `uwsgi_ssl_certificate.t` | 0/7 | 7 | `TEST_LIST=uwsgi_ssl_certificate.t bash bench/nginxtests.sh` |
| `uwsgi_ssl_certificate_vars.t` | 0/6 | 6 | `TEST_LIST=uwsgi_ssl_certificate_vars.t bash bench/nginxtests.sh` |

#### FastCGI

| 用例 | 结果 | 未对齐 | 复现 |
|---|---|---|---|
| `fastcgi_keepalive.t` | 0/8 | 8 | `TEST_LIST=fastcgi_keepalive.t bash bench/nginxtests.sh` |



### 上游客户端证书与解析错误路径（本轮实现）

实现 `proxy_ssl_certificate` / `uwsgi_ssl_certificate`（含 `_key`、
`_password_file`）与 `suwsgi://`。过程中修掉四个各自独立的真缺陷：

| 缺陷 | 影响 |
|---|---|
| **指令被忽略分支吞掉** | `proxy_ssl_certificate` 在 match 里出现在更早的「接受但忽略」列表中，Rust 的 match 按顺序匹配，所以后面真正的解析分支是死代码。同一类 bug 第三次出现（前两次是 stream 的 `log_format`、`access_log`） |
| **`write_all` 后没有 `flush`** | TLS 写入只进 rustls 内部缓冲，`suwsgi://` 等一个永远发不出去的请求 |
| **请求行解析等完整换行** | nginx 逐字节校验、遇到非法字节立刻 400；我们等到 CRLF 为止。所以对端发来不含换行的二进制块（uwsgi/SCGI 报文、或刻意的探测）会让双方互等——**既是兼容性缺口，也是可被利用的连接占用**。现在 `early_reject` 在累积阶段就拒绝 |
| **解析错误的 400 丢了 TLS 上下文** | `add_header X $ssl_client_verify always` 对解析错误响应也生效（nginx 在握手时就算好该变量）。我们构造的合成请求 `tls: None`，变量渲染为空、头被跳过 |

另外补了 `$ssl_client_s_dn`——字段早就声明但从未赋值，现在用一个最小 DER 遍历
输出 OpenSSL `X509_NAME_oneline` 的 `/CN=...` 形式。

| 套件 | 之前 | 现在 | nginx |
|---|---|---|---|
| `proxy_ssl_certificate.t` | 3/7 | **7/7** | 7/7 |
| `uwsgi_ssl_certificate.t` | 3/7 | **7/7** | 7/7 |
| `uwsgi_ssl_certificate_vars.t` | 2/6 | **5/6** | 6/6 |
| `ssl_certificate_aux.t` | 2/5 | **5/5** | 5/5 |

`ssl_certificate_aux` 的两条根因：`openssl x509 -addtrust … -trustout` 写出的是
`BEGIN TRUSTED CERTIFICATE` 标签（`rustls_pemfile` 只认 `CERTIFICATE`，整个文件
被当成没有证书），且证书 SEQUENCE 后面还跟着 14 字节 aux 结构（必须按外层长度截断，
否则 webpki 看到尾部垃圾）。此外 `ssl_trusted_certificate` 必须与
`ssl_client_certificate` 一起进校验库——只配前者时我们根本没有信任锚。

### `ssl_certificate_cache` 与按握手的证书变量（本轮实现）

此前 `ssl_certificate` 的变量是在**配置期**展开的，这是错的。nginx 在 SNI
回调里按**每次握手**求值，`$ssl_server_name` 只有在那一刻才有值。
`ssl_certificate $ssl_server_name.crt` 正是「按域名挂不同证书」的标准写法。

现在实现：

- 路径含 `$` 的证书不预先加载，而是在 `ResolvesServerCert::resolve` 里用
  本次握手的 SNI 名展开后读取。先用 `server_name` 选中 server，再取该 server
  的证书——顺序必须是这个，证书属于 server，不属于 socket。
- `ssl_certificate_cache off | max=N [inactive=time] [valid=time]`，
  http / server 两级，`off` 为默认（每次握手重读）。
- 证书加载失败不中断 socket（上一轮已改），只让该次握手失败并写 `error` 日志。

| 套件 | 之前 | 现在 | nginx |
|---|---|---|---|
| `ssl_certificate_cache.t` | 4/16 | **14/16** | 16/16 |
| `ssl_verify_client.t` | 12/16 | **14/16** | 16/16 |

仍未对齐的 2 条都是**淘汰策略细节**，我没有从 nginx 行为反推出它的确切模型：

- `certificate 1 evicted`（`ssl_certificate_cache.t:104`）——期望插入若干项后
  某个名字的证书**取不到**；我按「(cert,key) 计一对、LRU 淘汰」实现，则总能重读成功。
- `no cache updated`（同文件 `:117`）——`ssl_certificate_cache off` 的 server
  在文件被替换后应看到新证书，我们仍返回旧的。

### 被 `-V` 门控隐藏的 TLS 套件（本轮首次真实测量）

`Test::Nginx` 的 `has('openssl:1.0.2')` 匹配 `nginx -V` 里的
`built with OpenSSL <ver>`。ngxrs 用 rustls，不会打印那一行，于是 17 个 TLS
套件在我们这侧**直接跳过**——既不通过也不失败，等于从未测量。

`bench/tlsgate.sh` 就地给 harness 的这一个判据打补丁（退出时 `trap` 还原），
把「未知」变成「已测」。实测结果：

| 阶段 | ngxrs / nginx 断言 |
|---|---|
| 首次拆开门控 | **14 / 152** |
| 实现变量证书 + 证书加载失败非致命后 | **32 / 152** |

改善来自两处真实修复：

- **`ssl_certificate` / `ssl_certificate_key` 支持变量**（nginx 1.15.9+）。
  按 geo / map 的 `default` 分支展开；`ssl_certificate.t` 0/13 → **12/13**。
- **证书加载失败不再中断监听 socket**。nginx 会记日志继续启动，随后该 server
  的握手失败——`ssl_certificate $ssl_server_name.crt` 在配置期变量为空，
  用例正是断言「无响应」。原先我们直接整个 socket 起不来。

剩余未对齐仍很大，主要是三族真实未实现的特性：

| 族 | 未对齐 | 说明 |
|---|---|---|
| `*_certificate_cache` | 70 | `ssl_certificate_cache` 指令（证书对象缓存）未实现 |
| `*_conf_command` | 17 | `ssl_conf_command` 是 OpenSSL 专有配置通道，rustls 无对应物 |
| `*_ssl_sni_protocols` / `stream_server_name` | 7 | stream 缺 `server_name`，所以 SNI 无法分流 |

### 非测试类偏差

以下偏差没有对应的 nginx-tests 套件，或无法在本机构造 A/B 对照，单独列出。

| # | 偏差 | 影响 | 复现 |
|---|---|---|---|
| N1 | **`unknown directive` 只记 warning，不报错** | nginx 在读到未知指令时 `[emerg]` 退出；ngxrs 打一行 warning 后继续启动。配置里写错指令名的部署会"看起来起来了" | `printf 'events{worker_connections 64;}\nhttp{ bogus_directive_xyz on; server{listen 127.0.0.1:19970;} }\n' > /tmp/c.conf; ngxrs -t -c /tmp/c.conf -p /tmp` → `syntax is ok`；同一份配置 `nginx -t` → `unknown directive` |
| N2 | **HTTP/3 没有 nginx 参考基线** | 本机参考 nginx 未编译 `--with-http_v3_module`，且系统 OpenSSL 3.0.2 缺少 QUIC TLS API，所以 `h3_headers.t` 的 77 条断言只有我方一侧的数字（28/77），**不能**当作与 nginx 的一致性证据 | `$HOME/nginx-baseline/sbin/nginx -V 2>&1 \| tr ' ' '\n' \| grep -c v3` → `0` |
| N3 | **HTTP/2 非法 `:authority` / 控制字符：crate 直接重置流** | nginx 对空 authority、含 `/` 或控制字符的 authority、header 值含控制字符回 **400**；`h2` crate 在把请求交给路由之前就发 `RST_STREAM`（`GOAWAY` 对控制字符），因此我们无法回答 400。这正是 `h2_host.t` 4 条失败的原因 | 见 `bench/h2auth_probe.pl`：`perl bench/h2auth_probe.pl` → 前三行 `frames=[RST_STREAM]`、第四行 `frames=[GOAWAY]` |
| N4 | **HPACK / QPACK 表示选择由 crate 决定** | 我们不能控制 Huffman 编码、动态表索引、post-base index，所以 `h2_headers.t` 73/112、`h3_headers.t` 28/77 无法用"改我们的代码"消除 | `TEST_LIST=h2_headers.t bash bench/nginxtests.sh` |
| N5 | **14 个可选模块未实现**，`-V` 中显式声明为 `--without-`，相关套件因此跳过而不是伪装通过 | `http_dav/slice/memcached/flv/mp4/geoip/image_filter/xslt/perl/secure_link/gzip_static/userid/browser/mirror` | `ngxrs -V 2>&1 \| tr ' ' '\n' \| grep -- --without` |
| N6 | **`ssl_certificate_cache` / `ssl_conf_command` 被 `-V` 特性门控隐藏** | `Test::Nginx` 的 `has()` 匹配 `-V` 文本，这两个名字不在我们的 `-V` 里，相关套件在我们这侧直接跳过——**不是答错，是压根没跑**。`bench/tlsgate.sh` 在 `-V` 之外单独驱动这批文件（就地给 harness 打补丁，退出时还原），把「未知」变成「已测」 | `bash bench/tlsgate.sh` |
| N7 | **`suwsgi://`（uwsgi over TLS）未实现** | `uwsgi_pass suwsgi://…` 报 `invalid uwsgi_pass`，配置直接起不来 | `TEST_LIST=uwsgi_ssl_certificate.t bash bench/nginxtests.sh` |
| N8 | **stream 侧的证书变量未接 stream geo** | `ssl_certificate $one.crt` 在 `stream` 里用的是 http 的 `geo` 表，stream 的 `geo` 不参与，变量展开后为空 | `TEST_LIST=stream_ssl_certificate.t bash bench/tlsgate.sh` |

## 四、能力矩阵

## core / 配置

| 能力 | 状态 | 备注 |
|---|---|---|
| nginx.conf 词法（注释、单双引号、转义、`${var}`） | ✅ | `src/config/lexer.rs` |
| 指令/块/`;` 语法与报错 | ✅ | 报错带 file:line |
| `include` + 通配符 | ✅ | 支持 `*` `?`，按路径排序 |
| 上下文继承（http → server → location） | 🟡 | 基础字段已继承；`add_header` 目前是累加而非"覆盖" |
| `-t` 配置自检 | ✅ | |
| `-t` / `-T`（含配置 dump） | ✅ | |
| `-e FILE` / `-g DIRECTIVES` / `-p` / `-c`（相对 prefix 解析） | ✅ | |
| `-s stop/quit/reload/reopen` | ✅ | 读 pid 文件后发信号；`reload` 目前等同于 SIGHUP 无动作 |
| `daemon on/off`（fork+setsid、就绪握手、pid 在 listen 之后写） | ✅ | 这是官方测试集能驱动的前提 |
| SIGQUIT / SIGTERM / SIGINT 优雅停止 | ✅ | |
| `error_log` 落盘（notice 级） | 🟡 | 已写文件；分级过滤与 debug 细粒度未做 |
| `worker_processes N/auto` | ✅ | 每 worker 一线程 + 独立 runtime |
| 两种 accept 策略 | ✅ | `NGXRS_ACCEPT=reuseport`（默认）/ `shared`（单监听+轮询分发） |
| 未知指令处理 | 🟡 | 记 warning 继续；nginx 是直接报错 |

## http core

| 能力 | 状态 | 备注 |
|---|---|---|
| HTTP/1.0 / 1.1 解析 | ✅ | 请求行、header 名 token 校验、obs-fold 拒绝 |
| keepalive / pipelining | ✅ | 同一连接多请求；`keepalive_timeout` 生效 |
| Host 虚拟主机（精确/通配/正则） | ✅ | `server_name`，含 `*.x` / `.x` / `~re` |
| URI 规范化（合并斜杠、`.`/`..`） | ✅ | 越界 `..` → 400 |
| 百分号解码 | ✅ | 非法转义 / `%00` → 400 |
| 请求体丢弃 / `client_max_body_size` | ✅ | 超限 413；chunked 可丢弃 |
| `100-continue` | ✅ | |
| 请求行/头大小限制 | 🟡 | 8 KB 行 / 32 KB 头；nginx 是 `large_client_header_buffers` 4×8k |
| LF-only 行结束符 | ✅ | 与 nginx 一致（官方用例依赖这一点） |
| `Host` 校验（空值 / 端口 / 尾点 / 大小写规范化） | ✅ | |
| absolute-form 请求目标（`GET http://host/p`） | ✅ | 主机取自 URI，空 authority → 400 |
| `#fragment` 丢弃 | ✅ | `$uri` / `$args` 都不含 fragment |
| 错误状态后强制关闭连接（400/405/413/414/495-497/500/501） | ✅ | |
| 访问日志（`log_format`、combined） | 🟡 | 变量替换已支持常用集合；转义尚未做 |
| 错误日志分级/落盘 | ⬜ | 仅 stderr |
| `server_tokens` | ✅ | on → `nginx/1.28.0`，off → `nginx` |

## http 静态内容

| 能力 | 状态 | 备注 |
|---|---|---|
| `root` / `alias` | ✅ | |
| `index` | ✅ | 多候选 |
| `autoindex` | 🟡 | 有列表页，样式/字段未逐字对齐 |
| ETag / Last-Modified / 304 | ✅ | ETag 格式与 nginx 一致（mtime-size 十六进制） |
| Range（单区间/后缀） | ✅ | 206 + Content-Range |
| 多区间 Range（`multipart/byteranges`） | ✅ | 按 nginx 的 boundary 与分段布局；此前被静默降级成 200 全量 |
| 416 | ✅ | `Content-Range: bytes */size` |
| 条件请求 If-Match / If-Unmodified-Since | ✅ | |
| `sendfile` | ✅ | Linux 走 `sendfile(2)`，非 Linux 回退 read+write |
| `tcp_nopush` / `tcp_nodelay` | 🟡 | 解析并接受，未细调 |
| `try_files`（含末项内部重定向、末尾斜杠目录语义、alias 映射） | ✅ | 与 nginx 12/12 一致 |
| `return` | ✅ | 状态码 + 文本/URL |
| `add_header` | 🟡 | 累加语义（见上） |
| `error_page`（含 `=code`、外部 URL、internal location、非特殊状态码不拦截） | ✅ | |
| 405 / 301 / 505 语义 | ✅ | 与 nginx 逐字节对齐（405 错误页、301 绝对 Location + body、505） |
| `expires` / `gzip` / `charset` | ⬜ | 已解析未生效 |

## 反向代理 / 上游

| 能力 | 状态 | 备注 |
|---|---|---|
| `proxy_pass http://host[:port][/uri]` | ✅ | URI 前缀替换、`$` 变量 |
| `upstream {}` + 多 server | ✅ | `weight` / `backup` / `down` 解析 |
| 负载均衡 rr / least_conn / ip_hash | ✅ | ip_hash 按 IPv4 前三段 |
| upstream `keepalive N` + 连接池 | ✅ | 池按 (upstream, server) 键，避免串后端 |
| `proxy_http_version` 1.0 / 1.1 | ✅ | |
| `proxy_set_header`（含 `$http_*`、`$remote_addr`、`$proxy_add_x_forwarded_for`） | ✅ | |
| WebSocket（101 + 双向管道） | ✅ | |
| 请求体转发（Content-Length / chunked 解块） | ✅ | |
| 响应体流式转发（定长 / chunked / 无长度） | ✅ | chunked 原样透传 |
| `proxy_connect_timeout` / `read_timeout` / `send_timeout` | ✅ | |
| `proxy_intercept_errors` | ✅ | 状态交给 `error_page`；401 的 `WWW-Authenticate` 跨内部重定向保留 |
| `proxy_limit_rate`（含变量） | ✅ | 限速在**写入前**休眠，客户端看到的是真实速率 |
| `proxy_bind`（源地址绑定） | ✅ | `off` / 地址 / `addr:port` / 变量 |
| `proxy_buffering` | 🟡 | 已解析；当前总是流式转发 |
| 上游失败重试（stale pooled socket） | 🟡 | 仅幂等方法重试同一后端 |
| `proxy_cache` / `proxy_cache_path`（levels/keys_zone/max_size/inactive） | ✅ | 磁盘缓存（原子替换写入），`X-Cache-Status` 走 `add_header $upstream_cache_status` |
| `proxy_cache_valid` / `proxy_cache_key` / `proxy_cache_bypass` | ✅ | 只缓存 `proxy_cache_valid` 列出的状态码 |
| 缓存淘汰（max_size / inactive） | 🟡 | max_size 按 mtime 淘汰；`inactive` 只解析未执行定时清理 |
| `proxy_no_cache` | 🟡 | 已解析，未按变量求值 |
| `proxy_cache_max_range_offset` | ✅ | 起始偏移 ≥ 值（或值为 0）时绕过缓存，让上游看到 `Range` |
| 缓存场景下的 `Range` 处理 | ✅ | 缓存生效时**不把 `Range` 转发上游**（取整实体再切片），绕过时原样转发——ngx_http_upstream_cache_check_range 的语义 |
| 缓存错误状态（nginx `c->error`，ticket #827） | ✅ | 被拦截的上游错误以「无 body 的错误条目」入缓存，后续请求重放该错误；`bypass` 不写 |
| `fastcgi_pass` / `fastcgi_param` / `fastcgi_index` / `fastcgi_split_path_info` | ✅ | FastCGI 1.0 记录协议；`$fastcgi_script_name`、`$fastcgi_path_info` 等变量 |
| FastCGI 无 Content-Length 时用 chunked | ✅ | 与 nginx 帧格式逐字节一致 |
| `fastcgi_connect_timeout` / `fastcgi_read_timeout` | ✅ | |
| `fastcgi_cache` / `fastcgi_buffers` / `fastcgi_keep_conn` | ⬜ | 已解析未生效 |
| `uwsgi_pass` / `uwsgi_param` | ✅ | 报文头 `modifier1, size(LE16), modifier2`（按 nginx 源码） |
| `scgi_pass` / `scgi_param` | ✅ | netstring + NUL 分隔键值对 |
| `grpc_pass` | ⬜ | |

## 内容过滤

| 能力 | 状态 | 备注 |
|---|---|---|
| `gzip on` | ✅ | Accept-Encoding 协商、q=0 拒绝 |
| `gzip_min_length` / `gzip_comp_level` / `gzip_types` / `gzip_vary` | ✅ | |
| 压缩结果缓存 | ✅ | 按 ETag+长度，每 worker 128 条上限 |
| 与 nginx 的差异 | 🟡 | nginx 流式压缩用 chunked，我们用 Content-Length；解码后内容一致 |
| `gunzip` / `gzip_static` / `brotli` | ⬜ | |
| `error_page`（含 `=code`、internal location、error_page 的 no-trigger 语义） | ✅ | 与 nginx 逐字节一致 |

## 安全 / 协议

| 能力 | 状态 | 备注 |
|---|---|---|
| `listen ... ssl` + `ssl_certificate` / `ssl_certificate_key` | ✅ | rustls（ring provider） |
| SNI 选证（精确名 / `*.通配` / 默认回落） | ✅ | 与 nginx 同序，通配只匹配一级标签 |
| TLS 1.2 / 1.3 | ✅ | 1.3 默认优先 |
| `ssl_protocols` / `ssl_ciphers` / `ssl_session_cache` 等 | 🟡 | 已解析；实际参数由 rustls 的安全默认值决定 |
| ALPN（h2 / http/1.1） | ✅ | 仅在 `listen ... http2` 时广告 h2 |
| HTTP/2（多路复用、`:authority` 选虚拟主机、头部规范化） | 🟡 | 功能可用；帧级已对齐到 `h2.t` **116/145**、`h2_headers.t` **71/112**（此前都是 0）。剩余差异见下方「HTTP/2 残余差异」 |
| `http2 on`（http/server 级，nginx 1.25.1+） | ✅ | 含 http→server 继承 |
| h2c prior-knowledge（明文 HTTP/2） | ✅ | 探测连接前言，仅在该组配置了 `http2 on` 时启用 |
| `$scheme` | ✅ | 此前恒为 `http`，TLS 连接上也报 `http`；现按连接推导 |
| `ssl_verify_client` / `ssl_client_certificate` | 🟡 | 12/16，见下节 |
| `grpc_pass` / `resolver` | ✅ | `grpc_pass.t` 7/7；`grpc_ssl.t` 17/40 |
| `mail`（pop3/imap/smtp + auth_http） | ✅ | smtp 43/43、pop3 30/30、imap 33/33，全部与 nginx 一致 |
| `large_client_header_buffers` | ✅ | http/server 级；h1 用 `size`，h2 用 `size` 做单字段上限、`size*num` 做整块上限（与 `ngx_http_v2_state_header_complete` 一致，按 `name.len+value.len` 计，含伪头） |
| HTTP/2 SETTINGS / WINDOW_UPDATE 帧 | ✅ | 与 nginx 逐字节一致：`MAX_CONCURRENT_STREAMS=128`、`INITIAL_WINDOW_SIZE=65536`、`MAX_FRAME_SIZE=16777215`，外加连接级 `WINDOW_UPDATE 0x7fff0000` |
| HTTP/2 上的反向代理 | ⬜ | 目前 proxy 需要 socket 写入；h2 请求走 proxy 会返回 502 |
| HTTP/3 (QUIC) | ⬜ | 未开始 |
| `limit_req` / `limit_conn` / `access` 访问控制 | ⬜ | |

## rewrite

| 能力 | 状态 | 备注 |
|---|---|---|
| `rewrite <re> <replacement>;` | ✅ | `$1..$9`、无 flag 时继续匹配后续 rewrite |
| `last` | ✅ | 重新搜索 location 并从新 location 的 rewrite 模块重新开始 |
| `break` | ✅ | 终止本 location 的 rewrite 模块（**包括 `return`**），然后走内容阶段 |
| `redirect` / `permanent` | ✅ | 302 / 301 + Location，`$is_args` 语义 |
| 替换串带 `?` 时丢弃原 query | ✅ | |
| `if ($var)` / `if ($a = b)` / `~` / `~*` / `!~` / `!~*` | ✅ | 支持 `$http_*` 等变量 |
| `if (-f / -d / -e / -x $var)` 文件测试 | ✅ | |
| `if` 内的 `return` / `rewrite` / `set` | ✅ | `return` 的内容类型按 URI 扩展名 → `default_type` |
| `set $var value` | ✅ | 变量可被后续 `if` / rewrite 引用 |

## stream / mail

| 能力 | 状态 | 备注 |
|---|---|---|
| `stream { server { listen ...; proxy_pass ...; } }` | ✅ | TCP 双向代理 |
| `listen ... udp` | ✅ | UDP 会话按客户端映射上游 socket |
| stream `upstream {}` + 轮询 | ✅ | |
| `proxy_timeout` / `proxy_connect_timeout` | 🟡 | 连接超时生效；`proxy_timeout` 解析但未做空闲断开 |
| stream `return` / `set` / `if` / SSL 终结 | ⬜ | 已解析未执行 |
| `mail {}` | ⬜ | 仅识别并告警 |

## add_header

| 能力 | 状态 | 备注 |
|---|---|---|
| `add_header` 作用于静态响应 | ✅ | |
| `add_header` 作用于代理 / FastCGI 响应 | ✅ | 默认只对 200/201/204/206/301/302/303/304/307/308 生效 |
| `always` 后缀 | ✅ | 对所有状态码生效 |
| `$upstream_cache_status` 变量 | ✅ | MISS / HIT / BYPASS |


## 五、历史记录

以下为逐轮开发记录，按时间顺序排列，保留原始测量数据以便追溯。
**其中部分结论已被后续测量推翻**（例如「64 KB p99 好 11 倍」实际上是 nginx
`sendfile` 的取舍，关掉后它也到 3 ms），标注以 `BENCH.md` 与上表为准。

## HTTP/2 / TLS 官方用例实测（本轮）

放开 `-V` 后这些套件才真正运行，此前全部被静默 skip：

| 用例 | ngxrs | nginx |
|---|---|---|
| `h2.t` | **116/145** | 145/145 |
| `h2_headers.t` | **71/112** | 112/112 |
| `h2_host.t` | **52/62** | 48/62 |
| `h2_keepalive.t` | 12/21 | 21/21 |
| `h2_error_page.t` | 3/4 | 4/4 |
| `h2_proxy_cache.t` | 10/11 | 11/11 |
| `ssl_sni.t` | 4/10 | 10/10 |
| `ssl_verify_client.t` | **12/16** | 16/16 |

## mail（pop3 / imap / smtp，三个用例全部与 nginx 一致）

`mail {}`：`server{}`、`listen ... [pop3|imap|smtp]`、`protocol`、`server_name`、
`auth_http`、`auth_http_timeout`、`proxy_timeout`、`proxy_pass_error_message`、
`pop3_auth` / `imap_auth` / `smtp_auth`（含 `none`；mail 主上下文亦可）；
三种协议的认证阶段（USER/PASS、APOP、AUTH PLAIN/LOGIN/CRAM-MD5/EXTERNAL，
含 IMAP 的同步 `{N}` 与非同步 `{N+}` 字面量）；auth_http 的 HTTP/1.0 请求与
`Auth-Status/Server/Port/Pass/User/Error-Code/SMTP-To` 解析；认证成功后的
后端拼接。

**实测（nginx 1.28 对照，同机同配置）：**

| 用例 | ngxrs | nginx |
|---|---|---|
| `mail_smtp.t` | **43/43** | 43/43 |
| `mail_pop3.t` | **30/30** | 30/30 |
| `mail_imap.t` | **33/33** | 33/33 |

### 与 nginx 对齐时修掉的真缺陷

1. **`smtp_auth none` 的乐观应答模型**：nginx 对 `MAIL FROM` 先自己回
   `250 2.0.0 OK`，随后才连后端，并**吞掉后端对这一条的应答**；`RSET` 在
   尚未建立代理时同样由 nginx 自己回答。
2. **`Auth-Method` 必须小写**（`external` / `cram-md5` / `none`）。
3. **`Auth-Salt`**：CRAM-MD5 的挑战要作为 `$auth_salt` 传给 auth_http（三种
   协议都要）。
4. **后端问候一律丢弃**：客户端早已收到我们的问候，转发会造成每条响应错位。
5. **POP3 后端的 USER 应答丢弃、PASS 应答转发**；且无论客户端用哪种机制，
   发给后端的都是 `USER`/`PASS`。
6. **IMAP 与后端是分步对话**：先发 `{N}`，等 `+` 再发内容。一次性写入会让
   用缓冲行读（Perl `<>`）的后端把字面量吞进自己的缓冲区而挂死。
7. **IMAP `AUTHENTICATE` 只把机制名大写**，且支持 inline initial response。
8. **IMAP 字面量** `{N}` / `{N+}`，引号串的 `\"` 与 `\\` 反转义。

### 能力协商与 STARTTLS

`starttls off|on|only`、`{imap,pop3,smtp}_capabilities` 已实现，能力串与
nginx 逐字节一致；`STLS` / `STARTTLS` 执行**真实的 TLS 升级**（rustls），
已用 `openssl s_client -starttls imap|pop3|smtp` 三种协议验证握手成功。

**隐式 TLS**：`listen ... ssl` 从第一个字节起就是 TLS（在问候之前完成握手），
且 mail `server` 内的 `ssl_certificate` 覆盖 mail 块的证书。已实测：明文连接
拿不到问候，TLS 连接拿到 `* OK IMAP4 ready`。

**实测（nginx 1.28 对照）：**

| 用例 | ngxrs | nginx |
|---|---|---|
| `mail_capability.t` | **19/19** | 19/19 |
| `mail_pop3.t` | **30/30** | 30/30 |
| `mail_imap.t` | **33/33** | 33/33 |
| `mail_smtp.t` | **43/43** | 43/43 |

`mail_ssl.t` / `mail_imap_ssl.t` 在 **nginx 自己**上也只跑到 2 条断言就中止
（依赖 `ssl_password_file` 等），因此**不作为兼容性证据**。

### 其余 mail 用例（A/B 实测，nginx 1.28 为基准）

| 用例 | ngxrs | nginx | 缺口 |
|---|---|---|---|
| `mail_smtp_xclient.t` | **8/8** | 8/8 | 一致 |
| `mail_proxy_smtp_auth.t` | 8/9 | 9/9 | 1 |
| `mail_smtp_greeting_delay.t` | **4/4** | 4/4 | 一致 |
| `mail_resolver.t` | 9/12 | 12/13 | 3 |
| `mail_max_errors.t` | 14/20 | 20/20 | 6 |
| `mail_error_log.t` | **32/32** | 32/32 | 一致 |

### 仍未实现

- `max_errors` 的完整语义
- mail 侧的 `ssl_verify_client`
- `error_log` 的细粒度事件（各模块自己产生的 debug 级消息）尚未补全
- **`limit_conn.t` 9/10**：剩下 1 条是「客户端关闭后立刻释放名额」。nginx 在
  连接关闭的瞬间归还 slot；我们是在那次在途上游请求结束（含 `limit_req`
  延迟）之后才归还，所以紧跟其后的请求仍看到计数未清零。
  这条**会偶发通过**（曾出现过 10/10），连跑三次稳定为 9/10，因此按 9/10 记录
- **`stream` 的 TLS 终止已实现**（`listen ... ssl`，证书可从 `stream {}` 继承），
  `stream_ssl.t` **7/7 与 nginx 完全一致**
- **`stream` 上游 TLS 已实现**：`proxy_ssl on`、`proxy_ssl_session_reuse`
  （rustls 的 resumption 缓存按 SNI 共享，所以第二次连接会复用会话）、
  `proxy_ssl_name`，以及 stream server 的 `return <text>`（会展开
  `$ssl_session_reused` → `.` / `r`）。

| 用例 | ngxrs | nginx |
|---|---|---|
| `stream_ssl.t` | **7/7** | 7/7 |
| `stream_proxy_ssl.t` | **8/8** | 8/8 |
| `stream_error_log.t` | **36/36** | 36/36 |

`stream {}` 级的 `proxy_connect_timeout` / `proxy_timeout` 之前是
「接受但忽略」，现在真正生效并按 server 覆盖（默认 60s / 10m，与 nginx 一致）。

- `stream_ssl_verify_client.t`（stream 侧客户端证书校验）未实现，仍为 UNRUN
- 「因未声明模块而被静默跳过」的用例现在会被 harness 显式标成 **UNRUN**，
  不再混进 SAME

### 本轮修掉的真缺陷

1. **`pop3_auth` / `imap_auth` / `smtp_auth` 必须按协议分开存**。nginx 把它们
   放在各自的 server 配置里；我之前共用一个集合，导致 mail 主上下文的
   `pop3_auth plain apop cram-md5` 泄漏到 imap 和 smtp，能力串多出
   `AUTH=CRAM-MD5` / `CRAM-MD5`。
2. **`*_auth` 的默认值是 `plain`**（LOGIN 无条件叠加），不是「全开」。
3. **只有 mail（或只有 stream）的配置无法启动**：HTTP worker 0 发现没有
   listen socket 就 `exit(1)`。现在没有 http 监听时跳过 HTTP 侧并立即完成就绪握手。
4. 能力串拼装顺序与 nginx 一致：IMAP 为
   `<caps> AUTH=... STARTTLS [LOGINDISABLED]`（**AUTH= 不含 LOGIN**）；
   POP3 为 `TOP USER UIDL SASL ... STLS`，`only` 时去掉 USER 与 SASL；
   SMTP 为 `250-<name>` 后逐个能力行，最后一行用 `250 `，且**没有 8BITMIME**。

## gRPC

`grpc_pass` 已实现：`grpc://`（h2c）、`grpcs://`（TLS + ALPN h2）、直接写
`upstream {}` 的名字（nginx 先剥掉 scheme 再查 upstream 表，所以 `grpc://u`
命中的是 `upstream u` 而不是一次 DNS 查询）、以及含变量的目标。

变量目标需要 `resolver`，因此新增了 **`resolver` 指令 + 最小 DNS 客户端**
（`src/resolver.rs`，A 记录，带 TTL 缓存）。这同时也让 `proxy_pass` 用变量
时有了回退解析能力。

`grpc_pass.t` **7/7 与 nginx 断言数完全一致**。

顺带修掉两个真实缺陷：

1. **TLS 判定粒度错了**：`ssl` 之前记在 server 上，于是
   `server { listen 8081; listen 8082 ssl; }` 会把 8081 也变成 TLS。
   nginx 是按 **listen socket** 决定的，现改为每个 listen 各自带 `ssl` 标记。
   这个 bug 让整个 grpc_pass.t 从 404 变成可测。
2. `grpcs://` 的 SNI 直接用了 `host:port`，`ServerName` 解析失败。

## TLS 客户端证书

`ssl_verify_client on|off|optional|optional_no_ca`、`ssl_client_certificate`、
`$ssl_client_verify` / `$ssl_client_cert` / `$ssl_protocol` / `$ssl_cipher` /
`$ssl_server_name` 均已实现。`ssl_verify_client.t` 从 2/16 提升到 **12/16**
（nginx 16/16）。

设计要点：nginx 在客户端证书不合格时**不中断握手**，而是回一个 400
（内部码 495/496）。rustls 的 `WebPkiClientVerifier` 会在握手中直接拒绝，
客户端只会看到 TLS alert。因此这里用一个「请求但不拒绝」的验证器，把判定推迟到
HTTP 层、按请求命中的 virtual host 做，与 `ngx_http_process_request_headers`
里读 `sscf->verify` 的做法一致。

**剩余 3 条无法达标的原因**：nginx-tests 生成的证书是 **X.509 v1**，而
rustls/webpki 直接拒绝 v1（`UnsupportedCertVersion`）；OpenSSL 没有这个限制。
握手层已容忍（否则带客户端证书的连接完全不可用），但链校验仍会如实失败，
所以 `$ssl_client_verify` 报 `FAILED:...` 而非 `SUCCESS`——不会把没验证过的
证书说成已验证。

## HTTP/2 残余差异

对齐帧格式后，官方用例剩下的失败**集中在两类**，都不是内容层：

1. **HPACK 编码选择**（`h2_headers.t` 的 huffman / 索引模式 / 动态表边界，约 20 条）。
   nginx 自己实现 HPACK，选择是否 huffman、用哪种索引模式；`h2` crate 用的是另一套
   实现，两者都符合 RFC 但字节不同。用例断言的是 nginx 的具体选择，要匹配只能自己写
   HPACK 编码器。
2. **连接级错误的帧形态**（GOAWAY 的 code/时序、`PUSH_PROMISE` 拒绝、非法前言、
   `http2_max_concurrent_streams` 的 RST_STREAM 细节，约 25 条）。`h2` crate owns
   framing，我只能在 `accept()` 之后介入，改不了它发出的 GOAWAY。
3. `large_client_header_buffers` 超限：nginx 发 `GOAWAY(ENHANCE_YOUR_CALM)`，我们回
   431 —— 用例只断言「没有 DATA 帧」，所以这部分已通过，但帧形态仍不同。

## 已知差异（必须修）

1. `add_header` 继承语义与 nginx 不同（nginx：子上下文定义即替换）。
2. `server_tokens` 默认值在 http/server 合并时的边界情况。
3. 访问日志不做 `\x` 转义，UA 含引号会破坏行格式。
4. 无 `open_file_cache`，高并发小文件下 stat 次数多于 nginx。
5. `proxy_cache_min_uses` 只解析未生效。


## nginx-tests 状态（官方 Perl 测试集）

`bench/nginxtests.sh` 对**同一组用例分别跑 nginx 和 ngxrs**，再逐条断言对比。

绝对通过率在这里没有意义：master 分支的用例按较新的 `Test::Nginx` 编写，
而 CPAN 上最新只有 0.32/0.33，其 `http()`→`http_end()` 是 slurp 读法，
HTTP/1.1 keepalive 响应会一直阻塞到 8s 超时并返回 `undef`。**真 nginx 跑同一套也得同样的失败。**
所以脚本只报告两个数字：nginx 通过但我们失败的断言数（真缺陷），以及反之。

> 上一轮我写「http_keepalive.t 4/21，失败集中在 keepalive 细节，是真实差距」——**这个结论是错的**。
> 那批失败全部来自上述框架版本问题；用 nginx 做对照后，两者的逐文件数字完全相同。
> 本轮已改为 A/B 对比，并把此前被误判为"环境问题"的几个真实缺陷揪了出来（见下）。

### 本轮由官方用例发现的真实缺陷（已修）

| 缺陷 | 影响 | 修复 |
|---|---|---|
| 只接受 CRLF 行结束符 | 发 LF-only 请求的客户端永远读不到响应 | `find_header_end` / `split_lines` 同时接受 LF 与 CRLF |
| `$host` 未规范化 | 大写、带端口、尾点的主机名全部不匹配 | 小写、去端口、去尾点；`.` 单独出现视为非法 |
| absolute-form 未取 URI 主机 | `GET http://l/` 时 `$host` 取错 | 绝对形式优先于 Host 头；空 authority → 400 |
| `#fragment` 未丢弃 | `$uri` / `$args` 里混入 fragment | 解析 target 时先按 `#` 截断 |
| `Host` 校验缺失 | 空值 / `:port` / 非数字端口未返回 400 | 按 nginx 规则校验 |
| `add_header` 只对静态生效 | `return`、FastCGI、代理响应都缺头 | 移到响应解析出口统一应用 |
| `server_name` 优先级错误 | 通配符不取最长、`*.a.b` 不吃多级、尾缀通配未实现 | 按 nginx 顺序重写匹配 |
| `server_name ~` 不支持 `\Q..\E` 与命名捕获 | 正则服务器名不生效 | 翻译 `\Q..\E`，命名捕获暴露为变量 |
| 错误状态不关连接 | 405/400 后仍保持 keepalive，客户端等 EOF 会挂 | 按 nginx 的 400/405/413/414/495-497/500/501 强制关闭 |

### 当前 A/B 结果

`bench/nginx_tests.sh` 逐文件对比；`bench/ntscan.sh` 自动扫
http/proxy/upstream/range/fastcgi/scgi/uwsgi/stream/limit 各类用例，
只报告「nginx 过而 ngxrs 不过」的真缺陷。

最近一次全扫（39 个参评文件 / 21 个双方都跳过）：

| | 数量 |
|---|---|
| 与 nginx 断言数**完全一致** | **34**（含 `proxy_cache_lock` 19/19、`proxy_cache_lock_age` 6/6、`proxy_cache_max_range_offset` 9/9、`h2_host`） |
| **优于** nginx | **3**（`http_headers_multi` 49 vs 48、`http_host` 58 vs 62、`proxy_cache_range` 9 vs 8） |
| 更差 | 0 |

> **上述数字不完整（已发现并修正）**：`-V` 之前只打印版本号，而 Test::Nginx 用
> `-V` 文本判断哪些用例能跑——未知特性按**字面子串**匹配。于是 `http_v2`、`ssl`、
> `stream` 相关套件被静默 skip，在扫描里表现为「双方都跳过」，把真实差距藏了起来。
> 现在 `-V` 会输出 `configure arguments:`（只列真正实现的模块，缺失的用
> `--without-` 明确标出）。放开后立刻暴露：`h2.t` **0/145**（nginx 145/145）、
> `h2_headers.t` **0/112**。这些数字必须计入，不能只报「34/39 一致」。

完全一致的用例（断言数与 nginx 相同）：`http_location` 16/16、`http_uri` 21/21、
`http_server_name` 22/22、`http_method` 4/6、`http_try_files` 12/12、
`http_error_page` 11/11、`http_include` 7/7、`http_absolute_redirect` 25/25、
`http_header_buffers` 10/12、`http_expect_100_continue` 5/7、`fastcgi_body` 7/7、
`http_variables` 9/9、`http_keepalive` 21/21、`proxy_available` 4/4、
`proxy_bind` 7/7、`limit_req` 8/8、`proxy_cache_lock_age` 6/6、
`proxy_cache_lock_ssi` 4/4。

### 剩余差距（21 条断言）

| 用例 | 差 | 缺什么 |
|---|---|---|
| proxy_cache_control.t | 11 | 上游 `Cache-Control`/`Expires`/`X-Accel-Expires` 的完整优先级与 `$upstream_cache_status` 细节 |
| proxy_cache_convert_head.t | 2 | `proxy_cache_convert_head`（HEAD 转 GET 后缓存） |
| proxy_cache_chunked.t | 1 | chunked 上游响应的缓存 |
| proxy_cache_lock.t | 1 | lock 超时后并发回源的细节 |
| http_headers_multi.t | 1 | `$sent_trailer_*`（需要发送 trailer） |
| http_keepalive_shutdown.t | 1 | 依赖 `limit_req` 的延迟时序 |
| proxy_cache_bypass.t | 4 | `proxy_cache_bypass` 的多变量求值 |

### 本轮由官方用例发现并修复的缺陷

| 缺陷 | 影响 |
|---|---|
| **`proxy_bind` 完全缺失** | 无法指定回源源地址；现已支持 `off`/地址/`addr:port`/变量（`$remote_addr`/`$remote_port`/`$arg_*`），并沿用 server 级继承 |
| **`limit_req` / `limit_conn` 完全缺失** | 无任何限流能力；现实现漏桶（`rate`/`burst`/`nodelay`/`delay`）与并发连接计数，相位与 nginx 一致（PREACCESS，早于代理） |
| **`$request_time` 等变量在代理响应头里不展开** | `add_header` 走的是代理专用替换，只认 3 个变量；现改为完整变量解析器 |
| **`$remote_port` 缺失** | |
| **keepalive 空闲超时用 server 级而非 location 级** | 刚服务完的请求其 location 的 `keepalive_timeout` 才决定下一次读 |
| **关闭时未通知客户端** | 优雅停机期间响应应带 `Connection: close` |
| **`proxy_cache` 不认上游 `Cache-Control`/`X-Accel-Expires`/`Expires`** | 只认 `proxy_cache_valid`，导致大量上游显式声明可缓存的响应没被缓存 |
| **close-delimited 上游响应无法缓存** | 要求有 `Content-Length` 才缓存；nginx 会缓冲到 EOF 并补发长度 |
| **`proxy_cache_lock` 未实现** | 冷启动并发会重复回源 |
| **配置热重载（SIGHUP）完全缺失** | `nginx -s reload` 无效；现已实现：解析新配置、原子替换 `Arc<Config>`，在跑连接继续用旧快照 |
| **优雅停机不等在途请求** | SIGQUIT/stop 会打断正在流式输出的响应；现先停 accept 再等 `ACTIVE_CONNS` 归零（30s 上限） |
| **上游 close-delimited 响应未重分帧** | 无 Content-Length 也无 TE 的上游响应原样转发，客户端无法判断结束；现转为 chunked |
| **上游响应不认 LF-only 行结束符** | 简单后端（Perl heredoc）用 LF，我们找不到头就 502 |
| `set` 变量传不到 `add_header` | `set $limit_rate 40k; add_header X-Rate $limit_rate;` 取不到值 |
| `$limit_rate` 未按速率解析 | 返回 `40k` 而不是 `40960`；非法值应为 `0` |
| access_log 缺 `$uri` / `$sent_http_*` | 变量为空；重复响应头未逗号合并 |
| access_log 缺「变量未命中写 `-`」 | nginx 对 not-found 变量输出 `-` |
| 请求目标非法时不写 access log | |
| `expires` 未实现 | `epoch`/`max`/相对时间，且必须**替换**上游的 `Cache-Control` |
| ssl/`log_format` 之外的：nginx 默认 pid 与 error_log 路径 | 现默认 `<prefix>/logs/{nginx.pid,error.log}` |
| **keepalive 连接缓冲未清空** | `consume` 只把 start/end 归零，`buf` 仍留着上一个请求的字节；下一个请求会重新解析到旧数据（`http_header_buffers.t` 6/12 → 10/12） |
| HTTP/2 上的反向代理返回 502 | 新增 socket-free 的 `proxy::fetch`，h2 请求现在能代理 |
| `Expect: 100-continue` 从未响应 | 客户端等 100 才发 body，直接挂住；现按 RFC 只对 HTTP/1.1 发送 |
| `$http_*` 未合并重复请求头 | 多值头只取第一个 |
| 缺 `$cookie_*` / `$sent_http_*` / `$upstream_http_*` / `$upstream_cookie_*` / `$remote_user` | 大量变量为空 |
| `add_header` 只取 args[1] | `always` 被丢弃，值里的空格被截断 |
| `add_header` 求值顺序错误 | 后面的头看不到前面的，`$sent_http_*` 失效 |
| `if` 用另一套变量展开（`RwVars`） | `$arg_*` / `$cookie_*` 在 `if` 里恒为空 |
| 缺 `allow` / `deny` / `limit_except`（access 模块） | 访问控制完全缺失 |
| 访问控制在 405 之后才执行 | 应 403 的请求返回 405 |
| server 级 `if` / `set` 未实现 | |
| `$upstream_addr` 缺失 | |
| `absolute_redirect` / `server_name_in_redirect` / `port_in_redirect` 未实现 | |
| `Location` 未做 URI 转义 | 带空格/特殊字符的路径原样输出 |
| 无 Host / Host 非法时未回退到本地地址 | |
| 解析阶段 400 未走 error_page | |
| nginx 的「唯一头」规则未实现（Host/CL/TE/Expect/If-*/Authorization/Content-Range） | 重复头未拒绝 |

### 当前 A/B 结果（8 个用例文件）

| 用例 | nginx | ngxrs | 备注 |
|---|---|---|---|
| http_location.t | 16/16 | **16/16** | |
| http_uri.t | 21/21 | **21/21** | |
| http_server_name.t | 22/22 | **22/22** | |
| http_method.t | 4/6 | **4/6** | |
| http_try_files.t | 12/12 | **12/12** | |
| http_error_page.t | 11/11 | **11/11** | |
| http_host.t | 54/62 | **58/62** | 我们多过 4 项 |
| http_keepalive.t | 21/23 | 18/23 | 剩 `keepalive_time` 的计时语义 |

合计断言：nginx 161 / ngxrs 162；6 个文件完全一致，1 个更好，1 个更差。

### 本轮由官方用例发现并修复的缺陷

| 缺陷 | 影响 |
|---|---|
| `try_files` 语义整体错误 | 末项未做内部重定向、末尾斜杠未剥离、未区分文件/目录、alias 位置映射错误 |
| `alias` 偏移属于嵌套 location 而非声明它的 location | 嵌套 alias 全部指向错目录 |
| `error_page` 不支持外部重定向目标（`http://…`） | `error_page 302 http://…` 被当成文件路径 |
| `error_page` 目标中的 `$arg_*` 与查询串未展开 | `?$arg_a` 原样发出 |
| 497 隐含 302 未实现 | |
| 错误页内部重定向后未跑 rewrite | `rewrite ^ http://…` 型错误页失效 |
| 错误页产生的 3xx 被原状态覆盖 | 目录 auto-redirect 变成 302 |
| `error_page` 对非「特殊状态码」（如 418）也生效 | 与 nginx 不符 |
| 缺 `auto_redirect`（`location /a/` 时 `/a` → 301） | |
| `Keep-Alive: timeout=N` 响应头缺失 | |
| `keepalive_requests` / `keepalive_timeout` 无 location 级覆盖 | |
| `keepalive_time` / `keepalive_disable` / `$connection_requests` / `$connection_time` 缺失 | |
| 405 被当作强制关连接 | POST/PUT 的 405 应保持 keepalive |
| `$server_name` 未去掉前导点、空值 `add_header` 未省略 | |
| dispatch 二次解析目标导致 rewrite 后 location 错配 | `rewrite … break` 语义回退 |

### 访问控制在内容处理器之前执行（安全相关）

nginx 的相位顺序是 `POST_READ → SERVER_REWRITE → FIND_CONFIG → REWRITE →
POST_REWRITE → PREACCESS → ACCESS → POST_ACCESS → PRECONTENT → CONTENT`。
`proxy_pass` / `fastcgi_pass` / `scgi_pass` / `uwsgi_pass` / `grpc_pass` 走的是
CONTENT，所以 ACCESS 必须先求值。

在修复前，这些上游处理器在 `route` 之前就被分派，导致：

| 配置 | 修复前 | 修复后 | nginx |
|---|---|---|---|
| `location / { auth_basic …; proxy_pass …; }` | **200**（未认证放行） | 401 | 401 |
| 同上 + 正确凭据 | 200 | 200 | 200 |
| `location / { deny all; proxy_pass …; }` | **200** | 403 | 403 |

同时修正 `auth_request_set $args …`：它写回 `r->args`，改写后的查询串必须传给上游。

### 当前 A/B 结果（本机 nginx 1.28.0 对照，逐条断言）

| 用例 | nginx | ngxrs | 备注 |
|---|---|---|---|
| http_location.t | 16/16 | 16/16 | 一致 |
| http_server_name.t | 22/22 | 22/22 | 一致 |
| http_uri.t | 21/21 | 21/21 | 一致 |
| http_method.t | 4/6 | 4/6 | 一致（双方共享的失败） |
| http_variables.t | 9/9 | 9/9 | 一致 |
| auth_request_satisfy.t | 20/20 | 20/20 | 一致 |
| auth_request_set.t | 8/8 | 8/8 | 一致 |
| auth_request.t | 22/22 | **19/22** | 缺：auth 子请求缓存、请求体回放、多个 `WWW-Authenticate` |
| proxy_cache_lock.t | 19/19 | 19/19 | 一致 |
| proxy_intercept_errors.t | 6/6 | 6/6 | 一致 |
| proxy_cache.t | 17/17 | **14/17** | 差 3 条 |
| ssi.t | 32/32 | **30/32** | 差：代理响应上的 SSI |
| access.t | 14/14 | 14/14 | 一致（`listen unix:` / `allow unix:` / `proxy_pass http://unix:`）|
| h2.t | 144/145 | **115/145** | HPACK 编码与连接级帧形状由 `h2` crate 决定 |
| h2_host.t | 48/62 | **52/62** | 我们多过 4 条 |
| h3_headers.t | 无基线 | 28/77 | 本机 nginx 无 `--with-http_v3_module` |

自建差分套件 `bench/all.sh`：**70/70**（静态 19 + 功能 28 + TLS/H2 9 + fastcgi/ugcgi/grpc/stream 14）。

### 尚未实现

- `stream` 上的 `listen unix:`（HTTP 已支持）
- HTTP/3 与 nginx 的逐帧一致（本机无法建立基线）
- `auth_request` 子请求缓存、`max_errors`、`stream`/`mail` 客户端证书校验
- 高并发（c≥1024）吞吐约为 nginx 的 0.94–0.95×；64KB 尾延迟优于 nginx 一个数量级

## 本轮已知回归（均已修复，见下节）

- ~~`proxy_cache_vary.t`：手工跑 48/54~~ 已修复：53/54，与 nginx 一致（唯一失败项是
  用例自带的 TODO `normalize order`，nginx 同样失败）。当时"经 A/B 脚本判定 UNRUN"
  的挂起现象在本轮复测中未再出现（11 项 proxy 簇用例全部正常完成）。
- ~~`proxy_cache_use_stale.t`：25/36，缺 `updating`/`revalidated` 事件~~ 已实现，
  现在 36/36 与 nginx 一致。

## 本轮修复（proxy_cache_vary 回归）

上一轮报告的 `proxy_cache_vary.t` 48/54 回归已修复，现在 **53/54，与 nginx 一致**
（唯一失败项是该用例自带的 TODO `normalize order`，nginx 同样失败）。根因不止一个：

1. `Vary` 归一化（RFC 7234 §4.1）缺失：只按逗号切分并去空白/空项。
   `foo, bar`、`foo,bar`、`foo,,  ,bar , ` 必须等价。
2. 主键查询顺序错误：`load(base) || load_variant(...)` 让一个没有 `Vary` 的旧条目
   命中所有后续请求。nginx 先读主条目的 vary 名单，有名单才去查变体。
3. `Vary: *` 必须完全不缓存（RFC 7231 §7.1.4）。
4. `gzip_vary` 只在真正压缩时才发 `Vary: Accept-Encoding`；nginx 在
   "可 gzip"（状态/类型/长度达标）阶段就发，与客户端是否接受 gzip 无关。
   这一点会直接改变上游返回的头，从而改变缓存的键。
5. 变体索引文件的多进程读-改-写没有加锁（`flock`），并发写会丢行。
6. `proxy_cache_revalidate` 的 304 刷新写回主键而不是变体键。

另外两个与本用例无关但被它暴露出来的真问题：

7. **退出时不删除 pid 文件**（nginx 的 `ngx_delete_pidfile`）。官方 harness 的
   `run()` 轮询 pid 文件判断"已启动"，残留的旧文件让它在 socket 尚未 bind 时
   就发请求，表现为 `undef`。这一条同时影响所有 `$t->stop(); $t->run();` 的用例。
8. **优雅退出不关闭空闲 keepalive 连接**：`$t->stop()` 要等到 `keepalive_timeout`
   才返回（实测 20s+，现在 0.1s）。nginx 的 `ngx_close_idle_connections` 立即关闭。
9. `limit_req` 的延迟用 `std::thread::sleep` 在 async 路径上**阻塞 runtime 线程**。
   多 worker 时被掩盖，单 worker 时整个服务器被串行化（`limit_conn.t` 因此从 9/10
   掉到 5/10）。改为 `tokio::time::sleep` 后恢复 9/10。

顺带：`worker_processes` 默认值改为 1（nginx 的默认值；`auto` 仍是 CPU 数），
补上 `$request_time`，`gzip` 对 HEAD 也应发 `Content-Encoding: gzip`（已用 nginx 探测确认）。

已知未完成：`proxy_cache_use_stale.t` 27/36（缺 `updating`/`revalidated` 事件），
`limit_req_delay.t` 4/6（`delay=N` 的排队语义），`limit_conn.t` 9/10（客户端一断开
就要立刻释放名额）。

## 本轮（limit_req 漏桶按 nginx 单位重写 + limit_conn 名额回收 + proxy_pass 变量目标）

### limit_req：`delay=N` 之前完全没生效

用真 nginx 探到的三点（`rate=30r/m`，即每 2s 一个请求）：

| 配置 | 行为 |
|---|---|
| `burst=2 nodelay` | 前 3 个立刻 200，第 4 个 503 |
| `burst=2`（无 delay/nodelay） | 第 1 个立刻，之后每个延迟 2s 后 200（**不拒绝**） |
| `delay=1 burst=2` | 前 2 个立刻，之后每个延迟 2s 后 200 |

原来的实现用 `interval * excess` 估延迟，且把 `nodelay` 和 `excess==1` 混在一起，
`delay=N` 只解析不使用。现改为 nginx 的**毫请求单位**（1000 = 一个请求，
`rate` 为毫请求/秒，新节点从 -1000 起）：

```
excess = excess - rate*ms/1000 + 1000
if excess > burst*1000      -> 503（且不记账）
if excess > delay*1000      -> 延迟 (excess - delay*1000)/rate 秒
```

`limit_req_delay.t` 4/6 → **6/6**，`limit_req.t` 保持 8/8。

### limit_conn：客户端断开的瞬间释放名额

nginx 在连接可读事件里立刻回收（`ngx_http_limit_conn_cleanup`）。我们没有共享内存，
只能在"下一个请求做判定时"补一次检查：`ConnZone` 现在保存每个名额的客户端 fd，
达到上限时先 `recv(MSG_PEEK)` 探活，已关闭的名额直接回收。另外代理等待上游时
也 `select!` 一个客户端断开探测（仅在该 location 有 `limit_conn` 时启用）。
`limit_conn.t` 9/10 → **10/10**（连跑三次稳定）。

### proxy_pass 的变量目标

`proxy_pass http://$arg_b` 之前直接 502：变量展开用的是 `src/proxy.rs` 里另写的
第二个展开器，它不认 `$arg_*`（和之前 `RwVars` 那个坑同一类）。现在：

- 未知名字回落到 `ServerVars::get`，两套实现不会再漂移；
- 变量目标的 authority 在请求时展开，先按 `upstream {}` 名字匹配，否则 IP 直连或
  用 `resolver`；
- 展开值里的 URI 部分（`host/`）替换请求 URI，且**不**追加原查询串（实测 nginx 行为）。
- 补上 `$proxy_host` / `$proxy_port` / `$proxy_add_x_forwarded_for`（`add_header` 用）。

`proxy.t` 12/30 → **17/30**（4 条剩余都是 `$upstream_header_time` / 重试尝试列表）。

### 允许清单（诚实）
`proxy.t` 剩余 4 条：慢响应头下的 `$upstream_header_time`，以及 next_upstream 后
`$upstream_response_time` / `$upstream_header_time` 的逗号列表（我们只存单次值）。
`proxy_cache_use_stale.t` 27/36（缺 `updating`/`revalidated` 事件）。

## 本轮（$upstream_*_time、location access_log、log_format 拼接）

### proxy.t 12/30 → 30/30，与 nginx 完全一致

三处缺口，都是先看测试怎么断言、再对 nginx 探测确认的：

1. **`$upstream_connect_time` / `$upstream_header_time` / `$upstream_response_time`
   根本不存在**。新增 `src/timing.rs`：按 nginx 的语义为**每次尝试**记录一个条目，
   用 `, ` 连接，未取到的值打印 `-`。值在**发送响应头时**求值，所以正在应答的那次
   尝试还没有 response time——这正是 `proxy.t` 的 `rt2 == '-'` 断言。
   放在 task-local 里：同一个连接任务内既能在代理深处写、又能在访问日志处读。

2. **location 级 `access_log` 未实现**，所以 `access_log %%TESTDIR%%/time.log time;`
   一个字节都没写；`$t->read_file('time.log')` 直接 die，测试在第 21 条断言后中止。
   现在 `LocCfg.access_logs: Option<Vec<AccessLog>>`，`None` 表示继承 server。

3. **`log_format` 的相邻字符串被我用空格拼接**。nginx 是**直接相连**（这正是
   `'...connect:header:' 'response...'` 拆行写法的用途）。结果日志里多出空格，
   正则匹配不上。

4. 客户端提前断开时，nginx 会立刻终结上游请求（header time 保持 `-`）。我们原来只在
   有 `limit_conn` 的 location 上探测客户端断开；现在对所有代理请求探测，步长 1ms
   起、200ms 后放宽到 10ms。

### 测试框架的又一个盲点（已修）

`proxy.t` 曾显示 `SAME nginx 30/30 ngxrs 21/30`——因为我们的运行**中途 die**，
没产生任何 `not ok` 行，逐条 id 对比自然找不到「更差」。这与之前 `h2.t` 的
UNRUN 是同一类问题。现在断言行数少于参考运行的一律进 `TRUNC` 桶并让脚本失败。

### 回归
31 个用例文件：29 个完全一致，2 个更好（`http_host` 58 vs 54、`http_headers_multi`
49 vs 48），0 个更差，0 个截断；断言总数 ngxrs 606 / nginx 601。
自建差分套件 70/70；单测 101。

## 本轮（location 正则捕获变量、proxy_pass URI 变量、background update 等它完成）

### 新的真缺陷：location 正则的捕获根本不是变量

`location ~ /(reg)(?P<name>exp).html { proxy_pass http://u/$1$name.html; }` 我们
返回 404。两个缺口叠在一起：

1. **location 正则的 `$1..$9` 与命名组从未被采集**。之前只有 `server_name ~`
   的捕获会进变量表，location 的捕获根本没有落到 `custom` 里，所以任何
   `$1`/`$name` 在 `proxy_pass`、`fastcgi_param`、`add_header` 里都是空串。
   新增 `Server::locate_with_captures`：赢家是正则 location 时把捕获并入变量表。
2. **`proxy_pass` 的 URI 部分完全不展开变量**，只做前缀替换。现在若 URI 含 `$`
   就按请求展开（`upstream_target` 收 `ServerVars`）。

顺带：`proxy::fetch`（HTTP/2 / HTTP/3 / SSI / auth 子请求用）现在收 `custom`，
这几条路径也能看到捕获与 `set` 变量。

### background update 之前是 fire-and-forget

代码注释写着「caller must await the handle」，调用点却是 `drop(pending_update)`。
于是刷新任务和客户端赛跑，紧随其后的请求仍拿到 STALE。改成写完缓存体后等待句柄
（nginx 在 finalize 前等子请求），`X-Cache-Status` 的 STALE→HIT 序列才成立。

结果：`proxy_cache_use_stale.t` 27/36 → **29/36**。剩余 7 条都卡在 UPDATING
语义（另一个刷新在途时的事件位、`use_stale updating` 与 `stale-while-revalidate`
叠加、子请求里的 background update、`if` 里的更新），不是缓存本体的问题。

### 回归
35 个用例文件：32 个完全一致，3 个更好（`http_host` 58 vs 54、`ssi_if` 41 vs 32、
`http_headers_multi` 49 vs 48），0 个更差；断言 683 / 669。
`proxy_cache_use_stale.t` 单独计 29/36（见上）。自建差分套件 70/70，单测 101。

### 基准（同机 ABBA）
1k 0.950（447,538 vs 425,180）、64k 0.959、1m 0.959；64KB p99 30.59ms vs **2.65ms**。

## 本轮（stream 客户端证书验证、stream access_log）

### 新的功能：stream 的 ssl_verify_client

之前完全没实现，`stream_ssl_verify_client.t` 连配置都起不来。现在：

- `ssl_verify_client off|on|optional|optional_no_ca`、`ssl_client_certificate`、
  `ssl_trusted_certificate`，stream 与 stream server 两级、可继承。
- 与 http 的语义**不同**：nginx 的 stream 在握手内验证 —— `on` 是
  `SSL_VERIFY_PEER|FAIL_IF_NO_PEER_CERT`，`optional` 只要对端出示了就验证失败即断，
  `optional_no_ca` 一律放行并只在 `$ssl_client_verify` 里报告原因。
  我们用自写的 `AnchorClientVerifier` 在 rustls 里做到这一点。
- `$ssl_client_verify` / `$ssl_client_cert` 在 stream `return` 里可用。

两个必须绕开的坑：

1. **X.509 v1 证书**。测试夹具是 `openssl req -x509` 生成的 v1 自签证书，webpki
   直接 `UnsupportedCertVersion`。而 OpenSSL 接受 —— 所以「叶子证书本身就是信任锚」
   应当通过。现在先做字节相等判断，再退回 webpki。
2. **`verify_tls13_signature` 也会解析证书**，同样在 v1 上失败，导致握手以
   `certificate unknown` 结束（而 `verify_client_cert` 根本不会被调用，所以单看
   verifier 是自洽的、排查时极具误导性）。对 `BadEncoding/Other` 放宽，与 http 侧
   `PermissiveClientVerifier` 的取舍一致；链验证仍是安全边界。

### stream access_log

`access_log` 与 `log_format` 在 stream 上下文里是**被忽略的**——不是因为没实现，而是
被前面一个「接受但忽略」的 match 分支遮蔽了（Rust 分支按顺序匹配）。同一份列表里
`error_log` 也是这样被遮蔽的。移出后 `access_log` 生效，`$status` 在握手失败时是 500、
正常结束时 200，与 nginx 一致。

### 结果
| 用例 | ngxrs | nginx |
|---|---|---|
| `stream_ssl_verify_client.t` | **12/12** | 12/12 |
| `stream_ssl.t` / `stream_proxy_ssl.t` | 7/7 / 8/8 | 同 |
| `stream_error_log.t` | 36/36 | 36/36 |

36 个文件的 A/B：32 个完全一致、3 个更好、2 个更差（`proxy_cache_use_stale` 29/36、
`h2_host` 52/62），断言 824 / 813。自建差分套件 70/70，单测 101。

### 基准（同机 ABBA）
1k 0.940、64k 0.972、1m 0.962；64KB p99 28.18ms vs **2.63ms**。

## 本轮（proxy_cache_use_stale 收尾、后端条件请求、combined 格式）

`proxy_cache_use_stale.t` **29/36 → 36/36**，与 nginx 完全一致。

### 三处语义修正

1. **`proxy_cache_use_stale updating` 也覆盖「没人刷新」的过期条目**。之前只在
   `background_update && within_swr` 时返回陈旧副本，于是 `use_stale updating`
   对「过期且无刷新在途」的键仍然走前台回源，返回 500。nginx 是直接发陈旧副本
   并由这次请求自己发起更新。
2. **后台刷新必须带条件头**。`proxy_cache_revalidate on` 时刷新是条件请求，
   上游答 304 就保留已存 body、只刷新有效期；我原来发的是无条件请求，于是把
   304 变成 200 并把 body 换掉。
3. **socket-free 路径（h2/h3/SSI/auth 子请求）也要发陈旧副本**。之前只有流式路径
   支持，`h2_proxy_cache` 与 SSI 的用例因此失败。注意这里**不能 await** 刷新：
   nginx 克隆子请求做更新，不阻塞客户端响应 —— 这正是
   "stale response not blocked by background update" 检查的行为。

### 另外两个真缺陷

- **`access_log` 的 `combined` 是字面量**。内置 `combined` 格式从未被展开，日志里
  写的是字符串 `combined`（之前所有依赖日志内容的断言都在看它）。补上 nginx 的
  标准格式后 `proxy_cache_revalidate.t` 的 `not modified` 通过。
- **`Last-Modified` 只有 200/206 能存**。nginx 存缓存前会剥掉其它状态码的
  `Last-Modified`，所以只有这两种状态能条件回源；我原来对 201 也发了
  `If-Modified-Since`，`other status no revalidation` 失败。
- **缓存命中要过 `not_modified`**。条件请求命中缓存时应当 304，nginx 在头部过滤器
  里做，所以命中与回源表现一致；`h2_proxy_cache.t` 的 conditional 就是这条。

### 结果
`proxy_cache_use_stale` 36/36、`proxy_cache_revalidate` 25/25、
`h2_proxy_cache` 11/11、`proxy.t` 30/30、`proxy_cache_vary` 53/54、
`proxy_cache` 17/17 —— 均与 nginx 断言数一致。23 个文件的回归：
22 个完全一致、1 个更好（`ssi_if` 41 vs 32）、0 个更差。

## sub_filter / stub_status / split_clients / referer batch

Added in one round, each verified A/B against nginx 1.28 on the same host:

| suite | ngxrs | nginx |
|---|---|---|
| `empty_gif.t` | 6/6 | 6/6 |
| `stub_status.t` | 36/36 | 36/36 |
| `split_clients.t` | 3/3 | 3/3 |
| `referer.t` | 56/56 | 56/56 |
| `sub_filter.t` | 31/32 | 32/32 |
| `sub_filter_multi.t` | 42/44 | 44/44 |

Real bugs found on the way, all of them outside the new modules:

- **The h2c preface peek blocked every connection.** `TcpStream::peek` waits
  until the whole buffer can be filled, so a client that had not yet sent 24
  bytes was parked *before* `handle_conn` ran. Consequences: `$connections_*`
  were wrong, and an 18-byte `GET / HTTP/1.0\r\n\r\n` hung. Now a
  non-blocking `recv(MSG_PEEK|MSG_DONTWAIT)`, with a 100 ms grace only when the
  bytes seen so far are a prefix of the preface.
- **`limit_rate` was never applied.** Only the `$limit_rate` variable existed.
  Measured nginx: a 155-byte header for an empty file takes **20 s** at
  `limit_rate 15`, because the write filter throttles the whole chain, headers
  included. Implemented on the write path (and on `sendfile`, which falls back
  to a buffered copy when throttled), with a readability watch during the pacing
  sleep so a client disconnect finalises the request immediately like nginx.
- **`$connection` did not exist**, so `split_clients $connection` bucketed
  everything into the first entry.
- **`index` was not a complex value**: `index index${variant}.html` never
  expanded, so `split_clients.t` returned 403 for every request.
- **`sub_filter` matching is caseless** (nginx compares `ngx_tolower` of each
  byte) and its operands are complex values.
- **`sub_filter` merge order is own-rules-first, then inherited.** Rules chain,
  each seeing the previous one's output; with the order reversed a location's
  own rule ran on an already-rewritten body.
- `handled` in `stub_status` counts **connections**, not requests.

### Known deviations

- `sub_filter` on a `proxy_pass` response is not applied: the proxy path streams
  and the filter needs the whole body. Costs 2-3 assertions in `sub_filter.t`.
- `sub_filter` with *overlapping* patterns differs: nginx chains per-rule
  streaming state machines, this implementation applies each rule over the whole
  body in order. `sub_filter_multi.t` `partial match` and `utf8 match` fail for
  this reason.

### autoindex

Verified byte-for-byte identical to nginx 1.28 on a directory containing the
awkward names `autoindex.t` uses (`bench/aiprobe.sh` diffs both pages):

- **href** uses `NGX_ESCAPE_URI_COMPONENT`, so `:` is escaped as `%3A` and the
  entry cannot be mistaken for a URI scheme. The full escaped set was read off a
  real nginx listing by driving every printable ASCII character through it
  (`bench/aiesc.sh`) rather than assumed: space and
  `` !"#$%&'()*+,:;<=>?@[\]^`{|} `` are escaped; alphanumerics and `-._~` are not.
- **label** uses `ngx_escape_html`, which escapes only `& < > "`. An apostrophe
  is *not* escaped — the previous renderer emitted `&#39;` and was wrong.
- **width** is counted in characters when `charset` is utf-8 and in bytes
  otherwise (`entry->utf_len`); a name wider than `NGX_HTTP_AUTOINDEX_NAME_LEN`
  (50) is cut to 47 and suffixed `..>`, which then HTML-escapes to `..&gt;`.
- **directories sort first**, then names — not one flat name sort.
- the date is **GMT**: `autoindex_localtime` defaults to off.
- `charset` is now parsed instead of being accepted and ignored.

## 本轮（proxy_next_upstream 完整实现 + max_fails/fail_timeout + $upstream_addr 累加）

`proxy_next_upstream` 之前只解析不生效（在"accepted, not yet honoured"清单里），
`proxy_next_upstream.t` 6/10：看似"第二个请求成功"其实只是轮询轮到了好后端。
本轮完整实现后 **10/10，与 nginx 一致**。proxy 簇 + 自建差分套件全量复测无回归
（`bench/all.sh` 70/70）。

### 实现

- **指令解析**：`off|error|timeout|invalid_header|http_500|http_502|http_503|http_504|
  http_403|http_404|http_429|non_idempotent` 位标志；参数列表**替换**默认值
  `error timeout`（只写 `http_500` 就不再对连接错误重试）。`_tries`/`_timeout`
  同步解析并生效。
- **状态码触发**：决策点在 `exchange` 解析完响应头之后、任何字节到达客户端或
  缓存之前（对应 nginx 的 `ngx_http_upstream_test_next`）。仅当"后面还有候选
  且 tries/timeout 预算允许且方法可重放"时才放弃本次响应换下一个 peer；最后一
  个候选的响应总是照常送达（`proxy_next_upstream.t` 的 `all tried with down`
  依赖这一点）。
- **非幂等方法**：POST/LOCK/PATCH 只在带 `non_idempotent` 时才对"已发送后"的
  失败重试；连接建立失败发生在任何字节发出之前，任何方法都可重试（实测 nginx
  行为）。
- **`max_fails`/`fail_timeout`**：`server` 参数补全解析（默认 1 / 10s）。
  运行时按 (upstream, server) 记 `fails`/`checked`；`fails >= max_fails` 且距
  上次尝试不足 `fail_timeout` 的 peer 被选出局。
- **`$upstream_addr` / `$upstream_status` 累加**：`timing` 的 per-request 尝试
  列表增加 addr/status 字段，与 `*_time` 一样逗号拼接，且能活过 `error_page`
  内部跳转（`proxy_intercept_errors` + `return "$upstream_addr"` 的组合因此
  从空串变成 `addr1, addr2`）。`add_header` 与 access_log 里的引用同步改为
  累加值。

### 用真 nginx 探明的语义(`bench/next_upstream_probe.conf` 八项，ngxrs 全部对齐）

| 探针 | nginx 行为 |
|---|---|
| 500 触发的重试计失败 | 是 |
| 503 触发的重试计失败 | 是 |
| **403 触发的重试计失败** | **否** |
| **429 触发的重试计失败** | **是** |
| 成功请求清零 fails | **否**（只有 fail_timeout 到期才恢复） |
| fail_timeout 到期 | peer 回到轮转 |
| `proxy_next_upstream off` + 连接错误 | 直接 502，不转移 |
| POST + 连接被拒（默认 flags） | 重试（尚未发送任何字节） |

403 不计 / 429 计与凭记忆的直觉相反，成功不清零亦然——这组结论全部来自对
nginx 1.28 的实测，不是猜的。

### 顺带修掉的两个真缺陷

1. **backup 的候选顺序**：backup peer 从未进入候选列表（`select_order` 旧逻辑
   只在主服务器全空时才用 backup 池），状态码触发的重试到不了 backup。现在
   候选 = 轮转/排序后的可用 primaries **再拼** 可用 backups：正常流量永远先打
   primary，重试能落到 backup。第一次修复时把 backup 拼进了轮转池，RR 计数器
   会让 backup 每隔一个请求顶到首位——轮转必须只作用于 primaries。
2. **`least_conn` 平局不轮转**：稳定排序 + 固定输入顺序 = 空闲时全部流量钉死
   在第一台（`upstream_least_conn.t` `balanced` 4/4 之前不过）。现在平局按 RR
   计数器轮转，`upstream_least_conn.t` 4/4。

### 遗留（未实现，与上一致）

- `upstream_hash.t` 7/17：`hash` 指令（含 ketama `consistent`）整体未实现。
- `upstream_ip_hash.t` 被 harness 跳过：ngxrs 未向 Test::Nginx 声明 realip 模块。
- `proxy.t` 曾记录的 `$upstream_header_time` 慢响应头差异未再复现（本轮 30/30）。

## 本轮（hash 负载均衡完整实现 + return 444 + rewrite 阶段 $server_port）

`upstream_hash.t` 7/17 → **17/17，与 nginx 一致**。proxy 簇 + 自建差分套件
（70/70）+ 单元测试（122/122，含新增环构建回归测试）全量复测无回归。

### 实现（算法按 nginx 1.28 源码 `ngx_http_upstream_hash_module.c` 逐行核对）

- **指令**：`hash <复杂值> [consistent]`（`LbMethod::Hash`，不再是"接受但忽略"）。
  key 在请求时经 `ServerVars` 展开（`$arg_*` 等）。
- **CRC-32**：内置 nginx 同款 IEEE 表实现（`typed::crc32_update`），哈希映射需要
  逐字节一致，不引入新依赖。
- **plain hash**（`get_hash_peer`）：`((crc32([REHASH] KEY) >> 16) & 0x7fff) + PREV_HASH`
  的 Cache::Memcached 兼容表达式——REHASH 是重试计数的**十进制字符串**前缀，
  PREV_HASH 跨重试**累加**；peer 按 `hash % total_weight` 在**全量**（含 down）主
  服务器列表上按权重游走选定；被 tried/down/max_fails 拒绝则 rehash。
- **consistent**（ketama）：配置期建环——每 peer `weight*160` 个点，
  `crc32(host \0 port prev_hash_le32)` 链式生成，按哈希排序去重；请求时
  `crc32(key)` 二分找 `第一个 >= key哈希` 的点，失败/不可用则 `hash++` 顺延。
  host/port 拆分按 nginx 从尾部扫数字遇 `:` 切分（`unix:` 前缀特判）。
- **退化**：空 key、单主服务器、超过上限 → 轮询（`get_rr_peer`）。
- **实测映射对齐**：`bench/hashprobe` 场景（plain/consistent/带权重 共 5 组 ×
  10 key）与 nginx 1.28 **逐 key 完全一致**（含 weight=10 的环）。

### 过程中修掉的三个真缺陷

1. **候选生成的自设上限**：把 nginx"逐次 get"改成预生成完整候选列表时保留了
   每 get 20 步的上限——环上起点附近长期没有低权重点时（weight=10 的组里
   恰好第 3 个 key）生成被截断、荒谬地退到 RR 轮转。nginx 的 20 上限计的是
   *peer 尝试数*而非步数；生成上限放宽到覆盖全部主服务器（plain 100 次
   rehash / chash 走满一圈环）。
2. **`return 444`**：nginx 语义是**不发任何响应直接断连**；此前会真的发出
   444 状态行（upstream_hash.t 的 444 后端全靠它）。现在 `write_response`
   对 444 直接以断连错误返回。
3. **rewrite 阶段的 `$server_port`**：`get_var` 没有该分支、恒为空串，导致
   `if ($server_port = N)` 永假（upstream_hash.t 后端按端口返回 502 的用例
   因此全空转）。`RwVars` 增加 `server_port`，从连接的监听端口一路穿进
   `resolve_target` / `apply_rewrites_*` / `run_if`。

### 其他

- `$upstream_addr` 在"无可用 peer"（选不出候选 / 错误重试耗尽）时追加
  **upstream 组名**作为最后一项（nginx "no live upstreams" 的表现形式），
  且 502 响应现在也会应用该 location 的 `add_header`（`always` 场景）。
- 后台缓存刷新（background update）没有变量上下文，hash 上游退化为轮询
  （任何 peer 都能服务该刷新）。

### 新纳入追踪的已知缺口（非本轮回归）

- `rewrite.t` 15/25（nginx 25/25）：首次纳入 A/B 清单。失败集中在 rewrite 的
  参数追加/转义与 `error_page ... return` 组合，与 $server_port 无关（该文件
  不含此变量）。后续专项处理。
- `upstream_ip_hash.t`：仍因未向 Test::Nginx 声明 realip 模块被跳过。

## 本轮（rewrite.t 打平：rewrite 参数语义 + error_page return 状态规则）

`rewrite.t` 15/25 → **25/25，与 nginx 一致**。19 文件 A/B 全量复测：18 SAME +
1 BETTER（http_host.t 58/62 对 nginx 54/62），**零 WORSE**（ngxrs 399 断言对
nginx 395）；`bench/all.sh` 70/70、单元测试 122/122。

四类修复（行为均先经 `bench/rewrite_probe.conf` 双端实测对齐，现输出与 nginx
逐字节一致）：

1. **rewrite 替换串的参数规则**（`apply_one` 重写）：按模板首个 `?` 拆成 URI 与
   args 两部分——尾部 `?` 丢弃原参数、普通新参数以 `&` 追加原参数、无 `?` 保留
   原参数；外链 redirect 的 Location 也带参数（此前 `?c=d` 整个被丢弃）。
   落入 args 部分的捕获值按 `NGX_ESCAPE_ARGS` 转义（`%`→`%25`），URI 部分保持
   未转义形式——`/capturedup/%25?a=b` 因此得到 `args:c=/capturedup/%25&a=b`。
2. **error_page → return 的状态码规则**（1.15.4+ 语义）：错误处理器的应答若为
   ≥300，其状态**替换**原错误码（`error_page 404 /return405` → 405）；若为 2xx，
   保留原错误码、只取其 body（`error_page 405 /return204` → 405 + 空 body，
   不再画蛇添足地补内建错误页——补页只发生在没有跑过 error_page 时）。
   ≥300 且空 body 的处理器应答在补内建页时保留其原有头（`return 302 "text"`
   目标的 Location 不再丢失）。
3. **原 302 的 Location 存活**：`return 302 "text"` + `error_page 302 /...` 时，
   错误处理器（如 `return 200 "text"`）不自带 Location，则沿用原 302 的
   Location——最终 302 + `Location: text` + body `text`，与 nginx 一致。
4. **location 内 URI 被改写时忽略 proxy_pass 的 URI 部分**：`rewrite ... ;
   break; proxy_pass http://u/return204;` 按改写后的 URI（/return200）直连上游。
   `Target::Loc` 增加 `uri_rewritten` 标志（Relocate 换 location 后重新计算），
   穿透到 `upstream_target`。

顺带：`return 302 "text"` 的直连响应此前 Location 会被 `write_redirect` 丢弃
的问题同样暴露并修复。

## 本轮（expires 全语义 + 错误条目缓存的 Cache-Control 交互）

`expires` 从"已解析未生效"补齐为全语义实现，`bench/expires_probe.conf`
十种形式（off/epoch/max/相对时间/`@15h`/`@15h30m`/`modified +1h`/负时间/
代理替换）双端输出与 nginx **逐字节一致**。顺带修掉新纳入追踪的
`proxy_cache_valid.t`（12/14 → **14/14**）。A/B 18 文件 334/334 全部一致，
`bench/all.sh` 70/70，单测 122/122。

### expires

- `@time`（每日定时）：**服务器本地时区**的下一个该时刻（libm `tm_gmtoff`），
  `max-age` 为距此刻的秒数——按 UTC 算会差出时区（实测 V100 UTC+8）。
- `modified <time>`：锚定 Last-Modified（缺失回落到 now）；`+1h` 的加号前缀
  要剥掉。过期时刻 **≤ now 一律 `Cache-Control: no-cache`**（负时间因此天然
  是 no-cache，不是 max-age=0）。
- `expires modified @...`：配置期拒绝（与 nginx 同样的报错文案）。
- 上游 `Cache-Control` 是**原位替换**（代理响应里保持原位置，Expires 追加在
  末尾）；自身没有的响应按 Expires 在前、Cache-Control 在后的顺序追加。
- `expires` 是 TAKE12：`modified +1h` 以两个参数到达，需要拼接（此前只存了
  "modified"）。

### parse_time 复合时间

只认单单位（`1h`）改为 nginx 语法：单位标记按任意顺序累加（`1h30m`、
`1d 12h`），裸数字为秒。`@15h30m` 依赖此修复。

### proxy_cache_valid（存量缺陷，基线 9294b16 即失败，经二进制对照确认）

- 拦截错误（`proxy_intercept_errors` + `error_page`）写缓存时把**空的响应头**
  传给了 ttl：上游错误响应携带的 `Cache-Control: max-age=N` 被无视（nginx
  ticket #1382：错误条目的有效期应取自 max-age），`no-cache` 也没有阻止
  缓存。现在传入真实头，14/14。

### 追踪清单状态

A/B 清单现存 **19 个文件全部持平**（含本轮新增 expires 探针与
proxy_cache_valid），无任何 WORSE/BETTER/UNRUN。

## 本轮（realip 模块完整实现）

`ngx_http_realip_module` 从零实现，四个官方用例一次打平：`realip.t` 10/10、
`realip_remote_addr.t` 6/6、`realip_remote_port.t` 6/6、`upstream_ip_hash.t` 5/5
（此前被 harness 跳过——`-V` 现在声明 `--with-http_realip_module`）。
A/B 23 文件 382/382 全部一致，`bench/all.sh` 70/70，单测 122/122。

### 语义（按 nginx 1.28 源码 `ngx_http_get_forwarded_addr` 逐行核对）

- `set_real_ip_from <cidr>`（本域声明替换继承表）、`real_ip_header`（默认
  `X-Real-IP`，存小写再查——头表是精确匹配）、`real_ip_recursive`。
- X-Forwarded-For：**按接收顺序的倒序**逐个头处理；头内从右往左走，**递归标志
  同时门控头内步进与跨头迭代**（`while (recursive && p > xff)`）；当前地址不受信
  任即停，已产出则保留（DONE/DECLINED 的 found 语义）。
- 值支持 `ip\[:port\]` / `[v6]:port`（`ngx_parse_addr_port`）。
- 挂在 dispatch 的 location 解析之后（等价 nginx 的 post_read+preaccess 组合，
  per-location `real_ip_header` 因此生效），重写结果经 per-request 变量表注入，
  `add_header`/`return`/日志全链路可见。
- $remote_addr 重写后，**ip_hash 与上游选择用重写值**（proxy::handle 的 peer_ip
  改从变量取）。
- $realip_remote_addr / $realip_remote_port **无重写时回落到连接值**（nginx 同），
  有重写时保留原始连接地址/端口。

### 已知偏差（记录在案）

- allow/deny 与 limit_req/limit_conn 的 zone 键仍取连接地址（nginx 在 realip
  之后评估 ACCESS 阶段）；官方用例未覆盖，后续把 access_guard 的 peer_ip 一并
  切到变量。
- `set_real_ip_from <hostname>`（realip_hostname.t）需要运行时解析，未实现。

## 本轮（缓存过期判定的秒边界差一，`proxy_cache_valid.t` 抖动）

对声明清单做一次**全新**的 A/B 复验（135 文件）时，`proxy_cache_valid.t` 报
`ngxrs 13/14`（nginx 14/14），失败断言是 `error cached from max-age`
（nginx ticket #1382 那条）。单跑 5 次又全部 14/14 —— 这是抖动，不是稳定答错。

### 它不是负载噪声，是差一

`Cached::is_fresh` 当时写的是：

```rust
now - self.stored_at < self.valid_for as i64
```

nginx 存的是**绝对** `valid_sec = now + ttl`，只在 `valid_sec < now` 时才判过期；
所以 TTL 用尽的那一秒内仍然是 HIT。我们用的是相对量加严格小于，等于**早一秒过期**。

用可控探针确认（`proxy_cache_valid 200 1s`，请求精确落在第 x+1 秒内，
此时 `now == valid_sec`）：

| 时刻 | nginx | ngxrs（修前） |
|---|---|---|
| x+0.05 | MISS | MISS |
| x+0.90 | HIT | HIT |
| **x+1.50（now == valid_sec）** | **HIT** | **EXPIRED** |
| x+2.50 | EXPIRED | EXPIRED |

因为判定依赖「存储落在哪一秒的哪个位置」，任何 1s TTL 的用例都会随机失败——
`max-age=1`、`proxy_cache_valid ... 1s` 全在此列。这解释了该套件历史上
「整批跑 10/14、单跑 12/14」的漂移，此前被我记成「共享机负载噪声」，**那个归因是错的**。

### 修法

```rust
if self.valid_for == 0 { return false; }   // X-Accel-Expires: @<过去> 仍要立即过期
now - self.stored_at <= self.valid_for as i64
```

`valid_for == 0` 必须保留：`cache::ttl` 对 `@N` 的过去时间返回 `Duration::ZERO`，
nginx 对它是立刻 EXPIRED（`valid_sec` 在过去）。只改正向 TTL 的比较。
这与同文件里 `may_serve_stale` 已经采用的 `>=` 方向一致。

复现：

```bash
for i in 1 2 3 4 5; do TEST_LIST="proxy_cache_valid.t" bash bench/nginxtests.sh | grep -E '^SAME|^WORSE'; done
```

修后 5/5 SAME；缓存族 14 个文件全部 SAME（`proxy_cache_range.t` 仍 BETTER，9 对 nginx 8），
无回归。单测新增 3 条边界用例（`fresh_at_the_boundary_second`、`zero_ttl_is_immediately_stale`、
`longer_ttl_boundary`），175 → 178。
