# 使用 `ExitNodes` 强制固定客户端 RP 的代码改动说明

本文说明为了让 Tor 客户端在配置了：

```torrc
StrictNodes 1
ExitNodes 45.61.184.51
```

之后，除了普通出口电路以外，连 onion service 时使用的客户端
rendezvous point（RP）也固定到该节点，所做的两处代码改动。

## 改动目标

目标行为是：

- 普通客户端出口电路使用 `ExitNodes` 指定的节点
- 客户端 hidden-service rendezvous 电路也使用同一个节点作为 RP

如果没有下面两处改动，RP 仍然可能落到随机节点上。

---

## 改动一：在 `circuitbuild.c` 中强制 RP 从 `ExitNodes` 里选择

文件：`src/core/or/circuitbuild.c`

### 改动目的

客户端 RP 电路对应的 purpose 是 `CIRCUIT_PURPOSE_C_ESTABLISH_REND`。

这类电路虽然“末跳”逻辑上就是 RP，但它属于 internal circuit，不会天然复用普通
`C_GENERAL` 的 exit 选择语义。因此需要显式把 RP 选择绑定到 `ExitNodes`。

### 关键代码片段 1：新增从 routerset 中选 RP 的辅助函数

```c
/* BORING TEST */
/* Pick a node from a configured routerset, but still enforce the normal
 * suitability checks for this circuit position and purpose. */
static const node_t *
choose_good_exit_server_from_routerset(const routerset_t *pick_from,
                                       const routerset_t *exclude_set,
                                       router_crn_flags_t flags)
{
  const node_t *node = NULL;
  smartlist_t *live_nodes = smartlist_new();

  tor_assert(pick_from);

  routerset_get_all_nodes(live_nodes, pick_from, exclude_set, 1);
  SMARTLIST_FOREACH_BEGIN(live_nodes, const node_t *, live_node) {
    if (!router_can_choose_node(live_node, flags)) {
      SMARTLIST_DEL_CURRENT(live_nodes, live_node);
    }
  } SMARTLIST_FOREACH_END(live_node);

  if (smartlist_len(live_nodes) <= MAX_SANE_RESTRICTED_NODES) {
    node = smartlist_choose(live_nodes);
  } else {
    node = node_sl_choose_by_bandwidth(live_nodes, NO_WEIGHTING);
  }

  smartlist_free(live_nodes);
  return node;
}
/* BORING TEST */
```

这段代码的作用是：

- 从 `ExitNodes` 里收集所有在线节点
- 再用正常的 relay 适配规则过滤一次
- 最后从过滤后的节点中选出一个可用 RP

这一步支持你在 `torrc` 里直接写 IP，例如：

```torrc
ExitNodes 45.61.184.51
```

### 关键代码片段 2：在 `C_ESTABLISH_REND` 分支中强制使用 `ExitNodes`

```c
case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
  /* For these three, we want to pick the exit like a middle hop,
   * since it should be random. */
  tor_assert_nonfatal(is_internal);
  /* We want to avoid picking certain nodes for HS purposes. */
  flags |= CRN_FOR_HS;
  /* BORING TEST */
  /* If ExitNodes is configured, force the client rendezvous point to be
   * chosen from that set as well, including IP-based routerset entries. */
  if (TO_CIRCUIT(circ)->purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND &&
      options->ExitNodes) {
    const node_t *node = choose_good_exit_server_from_routerset(
        options->ExitNodes, options->ExcludeExitNodesUnion_, flags);
    if (!node) {
      log_warn(LD_CIRC,
               "No nodes in ExitNodes%s seem usable as a rendezvous "
               "point: can't choose a rendezvous point.",
               options->ExcludeExitNodesUnion_ ?
               ", except possibly those excluded by your configuration, " :
               "");
    }
    return node;
  }
  /* BORING TEST */
  FALLTHROUGH;
```

这段修改后，客户端 RP 电路在配置了 `ExitNodes` 时，不再随机挑 RP，而是：

- 只从 `ExitNodes` 中选
- 同时仍然遵守 `ExcludeExitNodesUnion_`

### 额外修正：让 RP 的排除检查与普通出口一致

```c
case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
case CIRCUIT_PURPOSE_C_REND_READY:
case CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED:
case CIRCUIT_PURPOSE_C_REND_JOINED:
  /* BORING TEST */
  /* Rendezvous points now follow the same exit exclusion set as normal
   * exits so diagnostics match the enforced selection behavior. */
  description = "chosen rendezvous point";
  rs = options->ExcludeExitNodesUnion_;
  /* BORING TEST */
  break;
```

这部分主要是让 RP 的告警和诊断逻辑与普通 exit 保持一致。

---

## 改动二：在 `circuituse.c` 中禁止复用已有内部电路

文件：`src/core/or/circuituse.c`

### 改动目的

仅仅修改 `circuitbuild.c` 还不够。

原因是客户端 `Hs_client_rend` 电路有时不会重新完整建路，而是直接复用一条已经打开的
internal circuit（也就是 cannibalize）。一旦发生这种复用，原来那条电路的末跳会被直接继承，
这样就会绕过上面新增的 RP 选择逻辑，导致最终 RP 仍然是随机节点。

### 关键代码片段

```c
static int
circuit_should_cannibalize_to_build(uint8_t purpose_to_build,
                                    int has_extend_info,
                                    int onehop_tunnel)
{
  const or_options_t *options = get_options();

  ...

  /* BORING TEST */
  /* A client rendezvous circuit with ExitNodes configured must be built with
   * a freshly chosen final hop, otherwise cannibalizing an existing internal
   * circuit would keep its random endpoint and bypass the forced RP choice. */
  if (purpose_to_build == CIRCUIT_PURPOSE_C_ESTABLISH_REND &&
      options->ExitNodes) {
    return 0;
  }
  /* BORING TEST */

  return 1;
}
```

这段代码的效果是：

- 当正在构建的是 `CIRCUIT_PURPOSE_C_ESTABLISH_REND`
- 且用户配置了 `ExitNodes`
- 就禁止复用已有内部电路

这样 Tor 就必须新建一条 RP 电路，而新电路就会进入前面在 `circuitbuild.c`
中修改过的 RP 选择路径。

---

## 为什么这两处缺一不可

### 只有改动一，不够

如果只改 `circuitbuild.c`：

- 新建的 RP 电路会按 `ExitNodes` 选
- 但如果 Tor 复用了旧内部电路，末跳仍然可能是旧的随机节点

也就是说，逻辑正确，但可能根本没有机会执行。

### 只有改动二，也不够

如果只改 `circuituse.c`：

- Tor 会老老实实新建 RP 电路
- 但新建电路时，RP 还是没有被明确绑定到 `ExitNodes`

也就是说，保证了“会重建”，但没有保证“重建后选对 RP”。

### 两者合起来才完整

完整链路是：

1. `circuituse.c` 禁止在 `C_ESTABLISH_REND + ExitNodes` 情况下复用旧内部电路
2. `circuitbuild.c` 在新建 RP 电路时，强制从 `ExitNodes` 中选 RP

这样才能真正保证客户端 RP 固定到你指定的节点。

---

## 最终结果

这两处修改完成后，理论上的行为应当是：

- 普通出口电路固定到 `ExitNodes`
- 客户端 `Hs_client_rend` 电路的最终 RP 也固定到 `ExitNodes`
- 不再因为内部电路复用而偷偷落到随机 RP

如果运行中仍然看到 RP 没落到指定节点，那么下一步就该继续检查：

- 是否存在其他客户端 HS 建路路径绕过了这两处逻辑
- 是否是控制端/上层工具展示的电路类型与实际 purpose 不一致
- 是否运行的二进制不是当前源码重新编译出来的版本
