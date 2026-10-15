# ADR-036：`remote-share/1` 线格式约定与内容寻址残余风险的接受

- **状态**：已采纳
- **日期**：2026-10-15（P3/P4 收尾；记录随最终代码状态而非早期草案）
- **范围**：设备文件共享控制面 ALPN 的帧格式约定、`DenyCode` 错误面、BlobTicket 寻址
  方式，以及规格 §19「按 digest 寻址的跨会话可读性」的处置。不决定 P5 之后的
  daemon 路由、出站 client 与 UI 形状。
- **相关文件**：[`remote_share.rs`](../../../crates/uc-sync-protocol/src/remote_share.rs)（opcode 帧与
  `DenyCode` 全集）、[`tests/golden_vectors.rs`](../../../crates/uc-sync-protocol/tests/golden_vectors.rs)（字节级回归）、
  [`serve_adapter.rs`](../../../crates/uc-infra-p2p/src/network/iroh/remote_share/serve_adapter.rs)（域→线映射与 §5.3 审计发射）、
  [`ports/blob/transfer.rs`](../../../crates/uc-core/src/ports/blob/transfer.rs)（`BlobTicket`/`fetch_to_path`/`publish_reader`）、
  [`remote_share/transfer.rs`](../../../crates/uc-application/src/remote_share/transfer.rs)（编排与进度上报）、
  产品仓规格 `docs/specs/2026-10-12-device-file-share-spec.md` §8、§12、§15、§19

## 背景

P1 落地的控制面 codec 是 postcard 裸枚举：未知变体直接解码失败并掉连接，不满足规格 §15
「未知操作码必须回 `unsupported_request`」；`DenyCode` 也低于规格 §12 要求的全集。P4 又把
清单项的 blob 凭据、传输关联键与导出票据放上同一条线。这些是同一处取舍：

- 线上格式在功能未发布前允许直接修改（`/1` 不变），发布后任何字节变化必须升版本；
- 「能拿到内容」的边界究竟画在哪——blob 服务按内容寻址服务任何持 digest 的已准入成员，
  这决定了 `Export` 票据的真实授权强度。

## 决定

1. **帧格式：显式 opcode + 按 op 的 postcard payload。** Body 为
   `postcard(u32 opcode) ++ postcard(payload)`；未知 opcode 解码为 `ShareRequest::Unknown`，
   由 serve 适配器应答 `Denied{UnsupportedRequest}` 而非掉连接。回复侧同法。
   `DenyCode` 扩至规格 §12 全集（locked/unsupported/unsupported_request/suspended/revoked/
   denied/reserved_name/not_found/conflict/root_gone/quota/too_large/too_many_entries/io/
   cancelled/too_late/interrupted），枚举判别式只增不改。golden 向量钉住全部代表帧的精确字节。

2. **字节寻址用 `BlobTicket` 字节，不是裸 digest。** `WireStageEntry.ticket` 与
   `Exported.ticket` 携带的是 `BlobTransferPort::issue_ticket` 产出的完整票据（含发布方
   endpoint 地址与 hash），持有者凭它 `fetch`/`fetch_to_path` 即可定位字节来源；规格 §8 中
   「digest」的措辞按此订正。目录项 ticket 为空；文件项缺 ticket 即拒绝 `StageUpload`。

3. **传输关联键由客户端选择。** `StageUpload.transfer_id`（16 字节）是上传方选定的随机 id，
   同时是 `transfer-progress/1` 反向帧的关联键——持有方按它回报拉取进度，上传方按它聚合父任务。

4. **§19 裁定：接受残余风险，不加盐、不建 digest 白名单。** blob 服务当前只按 ALPN 与会话
   门控，不按请求授权：任何已准入 Space 成员只要知道 digest 即可拉取对应内容。理由：

   - 能算出某文件 digest 的实体本就持有相同字节，拉取不提供新内容；
   - 残余仅为「经旁路得知 digest 但不持字节」的存在性预言机与带宽占用；
   - 加盐会破坏内容寻址的去重收益且需自定义字节层，白名单机制成本与边际威胁不成比例。

   导出票据另以 `TagReason::RemoteShareExport` 命名标签短时持有（TTL 清扫），防 GC 竞态，
   不改变上述寻址属性。

5. **`peer_device_id` 审计字段按匿名 `peer_ref` 落实。** 规格 §5.3 要求每次 serve 操作
   记录对端、op、根与 `blake3(rel)` 截断值；本仓观测合同禁止设备身份进入任何输出。
   落点：serve 适配器把原始节点身份挂进内存观测上下文，序列化层分配每 run 匿名
   `peer_ref`；变更/传输类操作记 `remote_share.serve.op` 诊断记录（op、root_id、
   rel 的 blake3 截断指纹、结果码），高频只读操作只留模块级 `uc_debug!`。

## 后果

- 未知操作码在协议上是可应答错误而非连接失败，新旧两端可安全交错；扩展只能经新 opcode。
- `DenyCode` 与域错误是两张表：适配器是全量映射的唯一位置（`StagingNotFound`→`NotFound`、
  `IsADirectory`/`NotADirectory`→`Denied` 两处刻意塌缩有注释与测试钉住）。
- 持 ticket 即持内容：票据字节视同内容本身处理——只走加密通道、不进日志与持久化
  （`Debug` 脱敏与字段目录在编译期挡住两处意外）。
- 若将来要收紧寻址授权，兼容演进路径是在 blob 服务侧加按 digest 的授权登记，
  不需改本线格式。

## 未验证项

- Windows/macOS 上 cap-std 手工逐段路径的符号链接行为未实测（P9 真机验收前记「跳过」）。
- `peer_ref` 匿名编号与 collector 可视化在真实双机记录链路上的呈现未端到端验证。
