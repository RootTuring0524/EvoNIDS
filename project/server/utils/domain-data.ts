import type {
  AgentAnalysis,
  AlertDetail,
  AnomalyProfile,
  AutoEncoderOutput,
  DatasetRecord,
  RagEvidence,
  RiskFusion,
  RuleDetail,
  StructuredRule,
  TransformerOutput,
} from '../../shared/types/security'
import { alerts, rules } from './mock-data'

type EvidenceInput = Pick<RagEvidence, 'id' | 'title' | 'sourceType' | 'sourceId' | 'excerpt' | 'purpose' | 'matchedKeywords'> &
  Partial<Pick<RagEvidence, 'relevance' | 'trust' | 'updatedAt' | 'allowed' | 'usedByAgent' | 'promptInjectionRisk' | 'vectorScore' | 'keywordScore' | 'rerankScore'>>

function evidence(input: EvidenceInput): RagEvidence {
  const relevance = input.relevance ?? 90
  return {
    relevance,
    trust: input.trust ?? 'high',
    updatedAt: input.updatedAt ?? '2026-07-10',
    allowed: input.allowed ?? true,
    usedByAgent: input.usedByAgent ?? true,
    promptInjectionRisk: input.promptInjectionRisk ?? 'none',
    vectorScore: input.vectorScore ?? Math.min(0.99, relevance / 100),
    keywordScore: input.keywordScore ?? Math.max(0.5, relevance / 100 - 0.06),
    rerankScore: input.rerankScore ?? relevance / 100,
    ...input,
  }
}

interface ScenarioEvidenceInput {
  prefix: string
  attack: string
  techniqueId: string
  techniqueSourceType?: RagEvidence['sourceType']
  techniqueTitle: string
  techniqueExcerpt: string
  historyId: string
  historyTitle: string
  historyExcerpt: string
  ruleId: string
  ruleTitle: string
  ruleExcerpt: string
  supportType?: RagEvidence['sourceType']
  supportId: string
  supportTitle: string
  supportExcerpt: string
  keywords: string[]
}

function scenarioEvidence(input: ScenarioEvidenceInput): RagEvidence[] {
  return [
    evidence({
      id: `${input.prefix}-EV-01`, title: input.techniqueTitle, sourceType: input.techniqueSourceType ?? 'MITRE ATT&CK', sourceId: input.techniqueId,
      excerpt: input.techniqueExcerpt, purpose: `确认 ${input.attack} 的攻击阶段与关键行为`, matchedKeywords: [input.techniqueId, ...input.keywords], relevance: 97,
    }),
    evidence({
      id: `${input.prefix}-EV-02`, title: input.historyTitle, sourceType: '历史告警', sourceId: input.historyId,
      excerpt: input.historyExcerpt, purpose: `比较同类 ${input.attack} 的历史行为与处置结果`, matchedKeywords: input.keywords, relevance: 94,
    }),
    evidence({
      id: `${input.prefix}-EV-03`, title: input.ruleTitle, sourceType: '已验证规则', sourceId: input.ruleId,
      excerpt: input.ruleExcerpt, purpose: '核对现有规则覆盖范围与阈值', matchedKeywords: input.keywords, relevance: 95,
    }),
    evidence({
      id: `${input.prefix}-EV-04`, title: input.supportTitle, sourceType: input.supportType ?? '处置手册', sourceId: input.supportId,
      excerpt: input.supportExcerpt, purpose: '生成调查、验证与处置建议', matchedKeywords: input.keywords, relevance: 88,
    }),
    evidence({
      id: `${input.prefix}-EV-99`, title: `外部未验证的 ${input.attack} 说明`, sourceType: '协议知识', sourceId: `EXT-${input.prefix}-UNTRUST`,
      excerpt: '来源包含试图改变 Agent 安全策略的指令，已净化并隔离。', purpose: '低可信来源，不提供给 Agent', matchedKeywords: input.keywords,
      relevance: 46, trust: 'low', allowed: false, usedByAgent: false, promptInjectionRisk: 'blocked', vectorScore: 0.62, keywordScore: 0.48, rerankScore: 0.46,
    }),
  ]
}

export const ragEvidence: RagEvidence[] = [
  evidence({
    id: 'EVIDENCE-102', title: 'Network Service Scanning', sourceType: 'MITRE ATT&CK', sourceId: 'ATTACK-T1046', relevance: 98,
    excerpt: '对手可能扫描 IP 地址块中的服务端口，以识别可用于后续攻击的服务。', updatedAt: '2026-06-28',
    purpose: '映射攻击阶段并确认扫描行为的关键观测量', matchedKeywords: ['port scan', 'service discovery', 'T1046'], vectorScore: 0.94, keywordScore: 0.91, rerankScore: 0.98,
  }),
  evidence({
    id: 'EVIDENCE-107', title: 'ALT-65108 · 低速分布式端口探测', sourceType: '历史告警', sourceId: 'ALT-65108', relevance: 93,
    excerpt: '源主机在 60 秒内访问 54 个端口，SYN 比例 0.76；旧规则因目的端口阈值过高未命中。', updatedAt: '2026-05-19',
    purpose: '对比相似异常并识别现有规则覆盖缺口', matchedKeywords: ['60 秒', 'SYN ratio', 'threshold'], vectorScore: 0.91, keywordScore: 0.84, rerankScore: 0.93,
  }),
  evidence({
    id: 'EVIDENCE-123', title: 'short_window_port_sweep v2', sourceType: '检测规则', sourceId: 'RULE-DEP-0018', relevance: 96,
    excerpt: 'destination_port_count_60s > 90 AND syn_ratio > 0.75 AND flow_duration < 1.5', updatedAt: '2026-04-11',
    purpose: '判断当前异常是否为已部署规则的变体并生成修复基线', matchedKeywords: ['destination_port_count_60s', 'syn_ratio', 'flow_duration'], vectorScore: 0.95, keywordScore: 0.89, rerankScore: 0.96,
  }),
  evidence({
    id: 'EVIDENCE-131', title: '失败规则：宽松 SYN 扫描阈值', sourceType: '失败规则', sourceId: 'RULE-REJ-0009', relevance: 74,
    excerpt: '将端口阈值降至 20 后，对服务网格健康检查产生 3.8% 误报；需联合目标 IP 数量约束。', updatedAt: '2026-03-08',
    purpose: '约束修复阈值并提示潜在误报来源；复核完成前不提供给 Agent', matchedKeywords: ['false positive', 'threshold', 'service mesh'], trust: 'medium', usedByAgent: false, promptInjectionRisk: 'review', vectorScore: 0.78, keywordScore: 0.61, rerankScore: 0.74,
  }),
  evidence({
    id: 'EVIDENCE-119', title: '横向扫描处置手册 v4', sourceType: '处置手册', sourceId: 'PB-RECON-004', relevance: 88,
    excerpt: '先确认源资产是否属于授权扫描器，再按目标范围、连接成功率和后续登录行为判断处置级别。', updatedAt: '2026-07-02',
    purpose: '补充调查步骤与遏制建议', matchedKeywords: ['授权扫描器', '处置', '横向扫描'], usedByAgent: false,
  }),
  evidence({
    id: 'EVIDENCE-145', title: 'Suricata TCP SYN 扫描规则样例', sourceType: 'Snort / Suricata', sourceId: 'SURICATA-EX-2001219', relevance: 82,
    excerpt: '按源地址聚合 SYN-only 连接，并在滑动时间窗内统计唯一目的端口。', purpose: '参考网络检测引擎可表达的字段和窗口语义', matchedKeywords: ['Suricata', 'SYN', 'by_src'], usedByAgent: false,
  }),
  evidence({
    id: 'EVIDENCE-146', title: 'CAPEC-300 · Port Scanning', sourceType: 'CVE / CWE / CAPEC', sourceId: 'CAPEC-300', relevance: 79,
    excerpt: '端口扫描通过系统化探测可达端口识别潜在攻击面，应结合速率与目标范围判断。', purpose: '补充攻击模式分类语义', matchedKeywords: ['CAPEC-300', 'port scanning'], usedByAgent: false,
  }),
  evidence({
    id: 'EVIDENCE-147', title: '已验证规则：distributed_port_scan v5', sourceType: '已验证规则', sourceId: 'RULE-VAL-0031', relevance: 86,
    excerpt: '跨目标端口统计需排除 CMDB 登记扫描器，并在回放中同时评估内部服务发现流量。', purpose: '对照已通过回放的规则设计约束', matchedKeywords: ['validated', 'CMDB', 'port count'],
  }),
  evidence({
    id: 'EVIDENCE-140', title: '外部来源：端口扫描绕过技巧', sourceType: '协议知识', sourceId: 'EXT-UNTRUST-204', relevance: 49,
    excerpt: '来源包含要求忽略安全策略的非知识性指令，内容已被净化并隔离。', updatedAt: '2025-11-22',
    purpose: '低可信来源，不提供给 Agent', matchedKeywords: ['scan evasion'], trust: 'low', allowed: false, usedByAgent: false,
    promptInjectionRisk: 'blocked', vectorScore: 0.67, keywordScore: 0.52, rerankScore: 0.49,
  }),
]

function transformer(input: Omit<TransformerOutput, 'modelVersion' | 'inferenceMs' | 'pretrainingTask'> & { inferenceMs?: number }): TransformerOutput {
  return {
    modelVersion: 'flow-transformer-v2.8.4', inferenceMs: input.inferenceMs ?? 14.8, pretrainingTask: 'Masked Feature Modeling', ...input,
  }
}

function autoEncoder(input: Omit<AutoEncoderOutput, 'modelVersion' | 'inferenceMs' | 'trainedOn'> & { inferenceMs?: number }): AutoEncoderOutput {
  return { modelVersion: 'flow-ae-v1.9.2', inferenceMs: input.inferenceMs ?? 8.2, trainedOn: 'normal_traffic', ...input }
}

const profileDefaults: AnomalyProfile = {
  flow_id: '', timestamp: '', src_ip: '', src_port: 0, dst_ip: '', dst_port: 0, protocol: 'TCP', service: 'Unknown', flow_duration: 0,
  forward_packet_count: 0, backward_packet_count: 0, forward_bytes: 0, backward_bytes: 0, packets_per_second: 0, bytes_per_second: 0,
  syn_ratio: 0, ack_ratio: 0, rst_ratio: 0, destination_port_count_60s: 0, destination_ip_count_60s: 0, flow_count_60s: 0,
  average_packet_size: 0, transformer_prediction: '', transformer_confidence: 0, autoencoder_reconstruction_error: 0,
  autoencoder_anomaly_score: 0, final_risk_score: 0, suspected_attack_type: '',
}

function profile(
  values: Partial<AnomalyProfile>,
  transformerOutput: TransformerOutput,
  autoEncoderOutput: AutoEncoderOutput,
  fusion: RiskFusion,
): AnomalyProfile {
  return {
    ...profileDefaults,
    ...values,
    transformer_prediction: transformerOutput.prediction,
    transformer_confidence: transformerOutput.confidence,
    autoencoder_reconstruction_error: autoEncoderOutput.reconstructionError,
    autoencoder_anomaly_score: autoEncoderOutput.anomalyScore,
    final_risk_score: fusion.finalScore,
  }
}

interface AgentInput {
  runId: string
  hypothesis: string
  patternDecision: AgentAnalysis['patternDecision']
  summary: string
  recommendation: string
  rag: RagEvidence[]
  comparisonResult: string
  ruleResult: string
  validationResult: string
}

function agent(input: AgentInput): AgentAnalysis {
  const evidenceIds = input.rag.filter((item) => item.allowed && item.usedByAgent && item.promptInjectionRisk === 'none').map((item) => item.id)
  return {
    displayModel: 'DeepSeek V4 Pro', runId: input.runId, state: 'completed', hypothesis: input.hypothesis,
    patternDecision: input.patternDecision, summary: input.summary, recommendation: input.recommendation, evidenceIds,
    steps: [
      { id: 'S1', label: '读取结构化攻击画像', state: 'completed', tool: 'profile_reader', durationMs: 42, result: '画像字段通过契约校验，模型输出与 Flow 统计一致。' },
      { id: 'S2', label: '检索安全知识与历史规则', state: 'completed', tool: 'hybrid_rag_search', durationMs: 186, result: `完成可信度与 Prompt Injection 过滤，向 Agent 提供 ${evidenceIds.length} 条证据。` },
      { id: 'S3', label: '攻击假设与模式判断', state: 'completed', tool: 'pattern_comparator', durationMs: 324, result: input.comparisonResult },
      { id: 'S4', label: '生成或选择检测策略', state: 'completed', tool: 'rule_json_builder', durationMs: 418, result: input.ruleResult },
      { id: 'S5', label: '提出验证与处置建议', state: 'completed', tool: 'validation_planner', durationMs: 96, result: input.validationResult },
    ],
  }
}

function alert(id: string) {
  const item = alerts.find((row) => row.id === id)
  if (!item) throw new Error(`Unknown alert ${id}`)
  return item
}

const portTransformer = transformer({
  prediction: 'Unknown', confidence: 0.71, isKnownClass: false,
  topK: [{ label: 'Port Scan', probability: 0.71 }, { label: 'Infiltration', probability: 0.14 }, { label: 'Benign', probability: 0.08 }],
  abnormalFeatures: [
    { field: 'destination_port_count_60s', value: '76', contribution: 0.32 },
    { field: 'syn_ratio', value: '0.82', contribution: 0.27 },
    { field: 'flow_duration', value: '0.58s', contribution: 0.18 },
  ],
})
const portAe = autoEncoder({
  reconstructionError: 0.93, threshold: 0.64, anomalyScore: 0.91, exceedsThreshold: true,
  deviatingFeatures: [
    { field: 'destination_port_count_60s', observed: 76, baseline: 4.2, deviation: 17.1 },
    { field: 'syn_ratio', observed: 0.82, baseline: 0.16, deviation: 4.1 },
    { field: 'average_packet_size', observed: 72, baseline: 614, deviation: 0.88 },
  ],
})
const portFusion: RiskFusion = {
  finalScore: 88, transformerWeight: 0.35, autoEncoderWeight: 0.5, contextAdjustment: 8, agreement: 'partial', lean: 'unknown_anomaly',
  explanation: 'Transformer 仅以 0.71 置信度接近 Port Scan，未进入已知类阈值；AutoEncoder 明确超过异常阈值。结合未授权资产和 60 秒扫描范围，风险上调 8 分。',
}
const portAgent = agent({
  runId: 'AGENT-RUN-0716-0284', hypothesis: '当前流量是已部署端口扫描规则 RULE-DEP-0018 的低阈值变体，而不是全新攻击族。',
  patternDecision: 'rule_variant', summary: '单一源地址在 60 秒内访问 76 个端口与 18 台资产，SYN 比例 0.82。分类通道置信度不足，但异常通道显著偏离正常基线。',
  recommendation: '修复旧规则：将端口阈值从 90 调整为 50，同时加入目标 IP 数量与短连接约束；完成正常流量回放后再由分析师确认部署。',
  rag: ragEvidence, comparisonResult: '与 RULE-DEP-0018 条件相似度 0.91，判定为已有规则变体。',
  ruleResult: '生成 RULE-CAND-0042 v1，包含 3 项联合条件并保留父规则关系。',
  validationResult: '建议回放 30 天正常流与三类扫描攻击，重点观察服务网格误报。',
})

const ddosRag = scenarioEvidence({
  prefix: 'DDOS', attack: 'DDoS SYN Flood', techniqueId: 'ATTACK-T1498.001', techniqueTitle: 'Direct Network Flood',
  techniqueExcerpt: '攻击者可能从大量来源直接向目标发送高频网络报文，耗尽链路或服务处理能力。',
  historyId: 'ALT-74219', historyTitle: 'ALT-74219 · 支付边界 SYN Flood', historyExcerpt: '2,106 个源在 35 秒内将 PPS 推高至基线 24 倍，边界限速后恢复。',
  ruleId: 'SIG-DDOS-4401', ruleTitle: '已验证规则：multi_source_syn_flood v8', ruleExcerpt: 'source_cardinality_60s > 500 AND syn_ratio > 0.9 AND packets_per_second > 12000',
  supportId: 'PB-DDOS-002', supportTitle: 'DDoS 边界清洗处置手册', supportExcerpt: '确认目标服务容量后执行边界限速、上游清洗与源分布留证。', keywords: ['SYN flood', 'PPS', 'multi-source'],
})
const ddosTransformer = transformer({
  prediction: 'DDoS', confidence: 0.99, isKnownClass: true,
  topK: [{ label: 'DDoS', probability: 0.99 }, { label: 'DoS', probability: 0.008 }, { label: 'Port Scan', probability: 0.002 }],
  abnormalFeatures: [{ field: 'packets_per_second', value: '24,568', contribution: 0.48 }, { field: 'syn_ratio', value: '0.96', contribution: 0.31 }, { field: 'source_cardinality_60s', value: '1,842', contribution: 0.16 }],
})
const ddosAe = autoEncoder({
  reconstructionError: 1.42, threshold: 0.64, anomalyScore: 0.99, exceedsThreshold: true,
  deviatingFeatures: [{ field: 'packets_per_second', observed: 24568, baseline: 860, deviation: 27.6 }, { field: 'flow_count_60s', observed: 98640, baseline: 3120, deviation: 30.6 }],
})
const ddosFusion: RiskFusion = { finalScore: 98, transformerWeight: 0.5, autoEncoderWeight: 0.35, contextAdjustment: 3, agreement: 'consistent', lean: 'dual_confirmed', explanation: '分类与异常通道一致确认 DDoS，且已部署 SYN Flood 规则直接命中；关键支付网关资产使风险上调 3 分。' }
const ddosAgent = agent({
  runId: 'AGENT-RUN-0716-0285', hypothesis: '这是已知的多源 DDoS SYN Flood，已部署规则 SIG-DDOS-4401 完整覆盖。', patternDecision: 'known_match',
  summary: '1,842 个源在 40 秒内将支付网关 PPS 推升至基线 28.6 倍；Transformer 与 AutoEncoder 一致报警。',
  recommendation: '沿用已部署规则，无需生成新规则；维持边界限速并核查上游清洗策略。', rag: ddosRag,
  comparisonResult: '与历史 SYN Flood 和 SIG-DDOS-4401 高度一致，判定为已知规则直接命中。',
  ruleResult: '复用 SIG-DDOS-4401 v8，不创建重复候选规则。', validationResult: '持续监测限速效果，并对上游清洗切换进行可用性验证。',
})

const c2Rag = scenarioEvidence({
  prefix: 'C2', attack: 'Botnet C2', techniqueId: 'ATTACK-T1071.001', techniqueTitle: 'Web Protocols for Command and Control',
  techniqueExcerpt: '攻击者可能利用 HTTPS 等常见 Web 协议隐藏命令控制通信。',
  historyId: 'ALT-70318', historyTitle: 'ALT-70318 · TLS 周期心跳 C2', historyExcerpt: '受感染主机每 45 至 49 秒建立小流量 TLS 会话，SNI 与证书 SAN 不一致，隔离后停止。',
  ruleId: 'RULE-C2-0012', ruleTitle: '已验证规则：periodic_tls_beacon v4', ruleExcerpt: 'interval_jitter < 0.03 AND bytes_per_flow < 8192 AND tls_sni_san_match == false',
  supportType: '协议知识', supportId: 'PROTO-TLS-017', supportTitle: 'TLS 心跳与证书身份核验', supportExcerpt: '低抖动周期连接、稳定小包长和 SNI/SAN 错配组合具有较高 C2 指示性。',
  keywords: ['TLS beacon', '47 seconds', 'SNI SAN'],
})
const c2Transformer = transformer({
  prediction: 'Botnet', confidence: 0.62, isKnownClass: false,
  topK: [{ label: 'Botnet', probability: 0.62 }, { label: 'Benign', probability: 0.21 }, { label: 'Infiltration', probability: 0.09 }],
  abnormalFeatures: [{ field: 'beacon_interval_jitter', value: '1.8%', contribution: 0.29 }, { field: 'tls_sni_san_match', value: 'false', contribution: 0.24 }, { field: 'bytes_per_flow', value: '4,832', contribution: 0.18 }],
})
const c2Ae = autoEncoder({
  reconstructionError: 0.88, threshold: 0.64, anomalyScore: 0.94, exceedsThreshold: true,
  deviatingFeatures: [{ field: 'connection_periodicity', observed: 0.98, baseline: 0.12, deviation: 7.17 }, { field: 'bytes_per_flow', observed: 4832, baseline: 48620, deviation: 0.9 }],
})
const c2Fusion: RiskFusion = { finalScore: 96, transformerWeight: 0.3, autoEncoderWeight: 0.5, contextAdjustment: 12, agreement: 'partial', lean: 'unknown_anomaly', explanation: 'Botnet 分类置信度较低，但周期性、小流量、TLS 身份错配和历史 C2 相似性使异常通道高度可信，目标信誉与关键资产上下文上调 12 分。' }
const c2Agent = agent({
  runId: 'AGENT-RUN-0716-0283', hypothesis: '这是周期抖动更小的 TLS C2 心跳，属于 RULE-C2-0012 的间隔变体。', patternDecision: 'rule_variant',
  summary: '主机每 47 秒建立一次约 4.8 KB 的 TLS 会话，SNI/SAN 错配；与历史 C2 告警 ALT-70318 高度相似。',
  recommendation: '隔离源资产并保留 PCAP；为周期抖动与 SNI/SAN 错配生成联合修复规则，回放合法更新代理流量。', rag: c2Rag,
  comparisonResult: '与真实历史 C2 案例 ALT-70318 相似度 0.94，判定为现有 C2 规则变体。',
  ruleResult: '生成 C2-CAND-0017，收紧周期抖动并保留小流量和证书错配条件。', validationResult: '回放合法软件更新代理、遥测客户端和三类 TLS C2 样本。',
})

const sshRag = scenarioEvidence({
  prefix: 'SSH', attack: 'SSH Brute Force', techniqueId: 'ATTACK-T1110.001', techniqueTitle: 'Password Guessing',
  techniqueExcerpt: '攻击者可能反复尝试密码以获得账户访问权限。', historyId: 'ALT-72881', historyTitle: 'ALT-72881 · SSH 口令喷洒',
  historyExcerpt: '固定源地址在 10 分钟内对 38 台服务器产生 312 次认证失败，未观察到成功登录。',
  ruleId: 'EVO-2026-0716-12', ruleTitle: '已验证候选：横向 SSH 口令喷洒', ruleExcerpt: 'destination_port == 22 AND auth_failures_5m > 120 AND destination_ip_count_60s > 20',
  supportId: 'PB-CRED-006', supportTitle: 'SSH 暴力尝试处置手册', supportExcerpt: '核查堡垒机授权、禁用涉事凭据，并保留认证日志与源主机进程信息。',
  keywords: ['SSH', 'authentication failure', 'T1110.001'],
})
const sshTransformer = transformer({
  prediction: 'Brute Force', confidence: 0.96, isKnownClass: true,
  topK: [{ label: 'Brute Force', probability: 0.96 }, { label: 'Port Scan', probability: 0.03 }, { label: 'Benign', probability: 0.01 }],
  abnormalFeatures: [{ field: 'authentication_failures_5m', value: '286', contribution: 0.46 }, { field: 'destination_ip_count_60s', value: '43', contribution: 0.25 }, { field: 'destination_port', value: '22', contribution: 0.18 }],
})
const sshAe = autoEncoder({
  reconstructionError: 0.72, threshold: 0.64, anomalyScore: 0.83, exceedsThreshold: true,
  deviatingFeatures: [{ field: 'authentication_failures_5m', observed: 286, baseline: 3.2, deviation: 88.4 }, { field: 'destination_ip_count_60s', observed: 43, baseline: 1.8, deviation: 22.9 }],
})
const sshFusion: RiskFusion = { finalScore: 87, transformerWeight: 0.55, autoEncoderWeight: 0.3, contextAdjustment: 2, agreement: 'consistent', lean: 'known_attack', explanation: 'Flow Transformer 明确分类为 SSH Brute Force，异常通道同步超过阈值；源主机无运维权限使风险上调 2 分。' }
const sshAgent = agent({
  runId: 'AGENT-RUN-0716-0282', hypothesis: '固定源对多台服务器执行 SSH 口令喷洒，行为被已知类别和候选规则共同覆盖。', patternDecision: 'known_match',
  summary: '8 分钟内对 43 台资产产生 286 次认证失败，目标端口固定为 22，未发现授权运维记录。',
  recommendation: '继续验证 EVO-2026-0716-12，立即隔离源主机并检查是否存在成功登录。', rag: sshRag,
  comparisonResult: '行为与历史 SSH 口令喷洒一致，Transformer 置信度 0.96。',
  ruleResult: '关联正在验证的 EVO-2026-0716-12，不创建重复候选。', validationResult: '回放堡垒机批量运维流量，并核查认证成功事件。',
})

function contextualDetail(input: {
  alertId: string
  flowId: string
  timestamp: string
  srcIp: string
  srcPort: number
  dstIp: string
  dstPort: number
  protocol: string
  service: string
  suspected: string
  prediction: string
  confidence: number
  known: boolean
  reconstructionError: number
  anomalyScore: number
  threshold?: number
  finalScore: number
  lean: RiskFusion['lean']
  agreement: RiskFusion['agreement']
  rag: RagEvidence[]
  agent: AgentAnalysis
  ragQuery: string
  relatedRule: AlertDetail['relatedRule']
  metrics?: Partial<AnomalyProfile>
}): AlertDetail {
  const t = transformer({
    prediction: input.prediction, confidence: input.confidence, isKnownClass: input.known,
    topK: [{ label: input.prediction, probability: input.confidence }, { label: 'Benign', probability: Math.max(0.01, 1 - input.confidence - 0.08) }, { label: 'Unknown Anomaly', probability: 0.08 }],
    abnormalFeatures: [
      { field: 'packets_per_second', value: String(input.metrics?.packets_per_second ?? 0), contribution: 0.31 },
      { field: 'bytes_per_second', value: String(input.metrics?.bytes_per_second ?? 0), contribution: 0.24 },
      { field: 'flow_count_60s', value: String(input.metrics?.flow_count_60s ?? 0), contribution: 0.18 },
    ],
  })
  const ae = autoEncoder({
    reconstructionError: input.reconstructionError, threshold: input.threshold ?? 0.64, anomalyScore: input.anomalyScore,
    exceedsThreshold: input.reconstructionError > (input.threshold ?? 0.64),
    deviatingFeatures: [
      { field: 'packets_per_second', observed: input.metrics?.packets_per_second ?? 0, baseline: 48, deviation: Math.max(0, (input.metrics?.packets_per_second ?? 0) / 48 - 1) },
      { field: 'bytes_per_second', observed: input.metrics?.bytes_per_second ?? 0, baseline: 18200, deviation: Math.max(0, (input.metrics?.bytes_per_second ?? 0) / 18200 - 1) },
    ],
  })
  const fusion: RiskFusion = {
    finalScore: input.finalScore, transformerWeight: input.known ? 0.55 : 0.32, autoEncoderWeight: input.known ? 0.3 : 0.5,
    contextAdjustment: input.lean === 'normal' ? 0 : 4, agreement: input.agreement, lean: input.lean,
    explanation: input.lean === 'normal'
      ? '分类通道判定为正常，重构误差位于阈值内；上下文证据解释了触发原因，不升级为高危告警。'
      : `分类通道输出 ${input.prediction}，异常通道分数为 ${input.anomalyScore.toFixed(2)}；结合资产和历史上下文形成最终风险。`,
  }
  return {
    alert: alert(input.alertId), transformer: t, autoEncoder: ae, fusion,
    profile: profile({
      flow_id: input.flowId, timestamp: input.timestamp, src_ip: input.srcIp, src_port: input.srcPort, dst_ip: input.dstIp, dst_port: input.dstPort,
      protocol: input.protocol, service: input.service, suspected_attack_type: input.suspected, ...input.metrics,
    }, t, ae, fusion),
    rag: input.rag, agent: input.agent, ragQuery: input.ragQuery, relatedRule: input.relatedRule,
  }
}

const exfilRag = scenarioEvidence({
  prefix: 'EXFIL', attack: 'Abnormal Outbound Connection', techniqueId: 'ATTACK-T1041', techniqueTitle: 'Exfiltration Over C2 Channel',
  techniqueExcerpt: '攻击者可能通过已有外连通道传输收集的数据。', historyId: 'ALT-69840', historyTitle: 'ALT-69840 · 数据库非窗口外传',
  historyExcerpt: '数据库主机在非备份窗口向首次出现的 ASN 传输大量加密数据。', ruleId: 'RULE-OUT-0021', ruleTitle: '已验证规则：db_abnormal_egress v3',
  ruleExcerpt: 'asset_role == database AND outbound_bytes_ratio > 8 AND destination_first_seen == true', supportId: 'PB-EXFIL-003', supportTitle: '数据外传调查手册',
  supportExcerpt: '核查变更、业务所有人、目标信誉和主机进程后再执行阻断。', keywords: ['database', 'outbound', 'first seen'],
})
const exfilAgent = agent({ runId: 'AGENT-RUN-0716-0279', hypothesis: '数据库主机在非备份窗口产生异常加密外传，属于现有规则未覆盖的新目的地变体。', patternDecision: 'rule_variant', summary: '出站字节量为基线 12.4 倍，目标 ASN 首次出现，AutoEncoder 明显超过正常阈值。', recommendation: '暂停该目的地连接，核查数据库导出任务和源主机进程，并修复目的地首次出现条件。', rag: exfilRag, comparisonResult: '与历史数据库外传案例相似度 0.89，现有规则缺少首次出现 ASN 条件。', ruleResult: '建议修复 RULE-OUT-0021，增加 destination_first_seen 与备份窗口排除。', validationResult: '回放合法备份、数据仓库同步和历史外传流量。' })

const scanRag = scenarioEvidence({
  prefix: 'SCAN', attack: 'Port Scan', techniqueId: 'ATTACK-T1046', techniqueTitle: 'Network Service Scanning', techniqueExcerpt: '服务扫描用于识别网络中开放端口和可用服务。',
  historyId: 'ALT-64012', historyTitle: 'ALT-64012 · Nmap SYN 扫描', historyExcerpt: '单一源地址在 10 秒内探测 1,024 个端口并被边界规则阻断。',
  ruleId: 'SIG-2200451', ruleTitle: '已验证规则：ET SCAN Nmap SYN Scan', ruleExcerpt: 'flags:S; threshold by_src count 20 seconds 10; authorized_scanner == false',
  supportId: 'PB-RECON-004', supportTitle: '授权扫描器核验流程', supportExcerpt: '将源主机与 CMDB 授权扫描器列表比对后决定阻断或关闭。', keywords: ['Nmap', 'SYN scan', 'T1046'],
})
const scanAgent = agent({ runId: 'AGENT-RUN-0716-0277', hypothesis: '这是已知 Nmap SYN 扫描，SIG-2200451 已命中并完成临时阻断。', patternDecision: 'known_match', summary: '源地址探测 1,024 个端口，SYN/ACK 比率 18.7，行为与已部署规则完全一致。', recommendation: '保留现有规则，核查源资产是否为漏登的授权扫描器。', rag: scanRag, comparisonResult: '规则与模型均指向已知 Port Scan，未发现新变体。', ruleResult: '复用 SIG-2200451，不生成候选规则。', validationResult: '核查 CMDB 授权扫描器登记并关闭临时阻断。' })

const dnsRag = scenarioEvidence({
  prefix: 'DNS', attack: 'DNS Tunneling', techniqueId: 'ATTACK-T1071.004', techniqueTitle: 'DNS for Command and Control', techniqueExcerpt: '攻击者可能将命令或数据编码进 DNS 查询与响应。',
  historyId: 'ALT-68114', historyTitle: 'ALT-68114 · 高熵 TXT 隧道', historyExcerpt: '平均子域长度 52，TXT 占比 71%，熵值 4.9，最终确认为数据隧道。',
  ruleId: 'EVO-2026-0715-08', ruleTitle: '候选规则：高熵 DNS 子域外传', ruleExcerpt: 'subdomain_length > 38 AND entropy > 4.5 AND txt_query_ratio > 0.4',
  supportType: '协议知识', supportId: 'PROTO-DNS-009', supportTitle: 'DNS 标签长度与 TXT 查询基线', supportExcerpt: '企业 DNS 基线需排除 CDN、DKIM 和合法遥测域名。', keywords: ['DNS', 'TXT', 'entropy'],
})
const dnsAgent = agent({ runId: 'AGENT-RUN-0716-0276', hypothesis: '高熵长子域与异常 TXT 比例符合 DNS 隧道规则变体。', patternDecision: 'rule_variant', summary: '子域平均长度 47.3、熵值 4.81，Transformer 与 AutoEncoder 给出部分一致证据。', recommendation: '继续验证 EVO-2026-0715-08，并增加合法 CDN 与遥测域名排除。', rag: dnsRag, comparisonResult: '与历史 DNS 隧道相似度 0.87，候选规则仍需降低误报。', ruleResult: '关联 EVO-2026-0715-08，不新建重复规则。', validationResult: '重点回放 DKIM、CDN 和安全产品遥测域名。' })

const rdpRag = scenarioEvidence({
  prefix: 'RDP', attack: 'Authorized Remote Administration', techniqueId: 'ATTACK-T1021.001', techniqueTitle: 'Remote Desktop Protocol', techniqueExcerpt: 'RDP 可用于远程服务，也可能是合法运维活动。',
  historyId: 'CHG-20260716-118', historyTitle: '已批准变更：夜间数据库维护', historyExcerpt: '用户Root在变更窗口内从合规终端发起 RDP，会话目标与工单一致。',
  ruleId: 'EXC-RDP-008', ruleTitle: '已验证例外：批准变更窗口', ruleExcerpt: 'approved_change == true AND endpoint_compliant == true AND destination_in_ticket == true',
  supportId: 'PB-RDP-001', supportTitle: '远程运维核验手册', supportExcerpt: '确认变更单、终端合规和目标范围后可将告警关闭为已解释行为。', keywords: ['RDP', 'change ticket', 'compliant'],
})
const rdpAgent = agent({ runId: 'AGENT-RUN-0716-0271', hypothesis: '该 RDP 会话由已批准变更解释，不构成攻击。', patternDecision: 'benign', summary: '源终端通过 EDR 合规检查，操作者、目标与维护工单一致。', recommendation: '维持关闭状态，将变更单证据保留在审计记录中。', rag: rdpRag, comparisonResult: '四条可信证据一致支持合法运维解释。', ruleResult: '不生成攻击规则，沿用已验证变更窗口例外。', validationResult: '无需攻击回放；保留会话与变更单关联审计。' })

const saasRag = scenarioEvidence({
  prefix: 'SAAS', attack: 'Normal SaaS Traffic', techniqueId: 'KB-NET-SAAS', techniqueSourceType: '协议知识', techniqueTitle: 'Microsoft SaaS 网络归属', techniqueExcerpt: '目标地址属于已登记 Microsoft 服务网络，TLS 身份与资产访问模式一致。',
  historyId: 'BASELINE-SAAS-24', historyTitle: '资产组 SaaS 访问基线', historyExcerpt: '24 台终端在补丁窗口后出现相同目标，流量规模与时间分布一致。',
  ruleId: 'EXC-SAAS-014', ruleTitle: '已验证例外：企业 SaaS 目标', ruleExcerpt: 'destination_owner == Microsoft AND tls_identity_valid == true AND peer_group_consistent == true',
  supportId: 'PB-SAAS-002', supportTitle: '新 SaaS 目标核验流程', supportExcerpt: '核对网络归属、证书、资产群组一致性与采购登记。', keywords: ['Microsoft', 'SaaS', 'baseline'],
})
const saasAgent = agent({ runId: 'AGENT-RUN-0716-0268', hypothesis: '这是新出现但已验证的正常 SaaS 通信。', patternDecision: 'benign', summary: '目标归属 Microsoft，24 台同组终端行为一致，模型均位于正常分布。', recommendation: '关闭告警并将目标纳入 SaaS 基线，无需创建检测规则。', rag: saasRag, comparisonResult: '网络归属、TLS 身份和同组资产行为均支持正常结论。', ruleResult: '不生成攻击规则，更新 SaaS 资产基线。', validationResult: '监测未来 7 天流量规模变化。' })

const dosRag = scenarioEvidence({
  prefix: 'DOS', attack: 'DoS', techniqueId: 'ATTACK-T1499.002', techniqueTitle: 'Service Exhaustion Flood',
  techniqueExcerpt: '单一来源也可能通过大量并发或半开连接耗尽服务端连接池与工作线程。',
  historyId: 'ALT-71902', historyTitle: 'ALT-71902 · HTTP 半开连接耗尽', historyExcerpt: '单一外部地址在 60 秒内建立 16,800 条半开连接，限速后服务响应恢复。',
  ruleId: 'SIG-DOS-3302', ruleTitle: '已验证规则：single_source_connection_exhaustion v6', ruleExcerpt: 'source_cardinality_60s == 1 AND half_open_connections_60s > 12000 AND syn_ratio > 0.9',
  supportId: 'PB-DOS-005', supportTitle: '单源连接耗尽处置手册', supportExcerpt: '核对服务容量后执行源地址限速、连接池保护，并保留服务可用性指标。',
  keywords: ['DoS', 'half-open', 'connection exhaustion'],
})
const dosAgent = agent({
  runId: 'AGENT-RUN-0716-0264', hypothesis: '这是已知的单源 HTTP 连接耗尽 DoS，已部署规则 SIG-DOS-3302 完整覆盖。', patternDecision: 'known_match',
  summary: '单一外部地址在 60 秒内建立 18,420 条半开连接，SYN 比例 0.95，两个检测通道一致报警。',
  recommendation: '沿用已部署限速规则，核查连接池与上游代理容量；无需生成重复候选规则。', rag: dosRag,
  comparisonResult: '与历史 DoS 案例和 SIG-DOS-3302 阈值完全一致。', ruleResult: '复用 SIG-DOS-3302 v6，不创建新规则。',
  validationResult: '持续观察限速后的可用性，并复核合法压测来源白名单。',
})

const webRag = scenarioEvidence({
  prefix: 'WEB', attack: 'Web Attack', techniqueId: 'ATTACK-T1190', techniqueTitle: 'Exploit Public-Facing Application',
  techniqueExcerpt: '攻击者可能利用面向互联网的应用输入点探测或利用服务端漏洞。',
  historyId: 'ALT-73551', historyTitle: 'ALT-73551 · 登录接口 SQL 注入探测', historyExcerpt: '同一来源对登录参数发送 42 个布尔型 SQL 变形 payload，WAF 全部阻断且无成功响应。',
  ruleId: 'RULE-WEB-0074', ruleTitle: '已验证规则：login_boolean_sqli_probe v3', ruleExcerpt: 'endpoint == /login AND sqli_boolean_pattern == true AND request_count_60s > 20',
  supportId: 'PB-WEB-003', supportTitle: 'Web 注入调查与取证手册', supportExcerpt: '关联 WAF、应用访问日志和数据库审计，确认是否存在绕过或成功响应。',
  keywords: ['SQL injection', '/login', 'boolean payload'],
})
const webAgent = agent({
  runId: 'AGENT-RUN-0716-0261', hypothesis: '这是已知 Web Attack 类别中的布尔型 SQL 注入探测，现有应用规则已经覆盖。', patternDecision: 'known_match',
  summary: '登录接口在 60 秒内收到 37 次变形 SQL payload，Transformer 置信度 0.93，WAF 未记录成功放行。',
  recommendation: '保留现有阻断策略，核查应用与数据库日志确认无成功利用；无需生成重复候选规则。', rag: webRag,
  comparisonResult: '与 ALT-73551 和 RULE-WEB-0074 的请求结构高度一致。', ruleResult: '复用 RULE-WEB-0074 v3，不创建新规则。',
  validationResult: '回放合法登录失败、自动化测试与已知 SQL 注入样本，确认无误报回归。',
})

const botnetRag = scenarioEvidence({
  prefix: 'BOTNET', attack: 'Botnet', techniqueId: 'ATTACK-T1105', techniqueTitle: 'Ingress Tool Transfer',
  techniqueExcerpt: '受控主机可能通过既有命令通道周期性拉取任务配置或附加工具。',
  historyId: 'ALT-72604', historyTitle: 'ALT-72604 · 僵尸网络任务拉取', historyExcerpt: '受感染终端每 5 分钟从同一基础设施簇拉取 4 至 9 KB 加密任务载荷，隔离后停止。',
  ruleId: 'RULE-BOTNET-0011', ruleTitle: '已验证规则：periodic_botnet_task_pull v5', ruleExcerpt: 'interval_seconds BETWEEN 285 AND 315 AND payload_bytes < 10240 AND destination_cluster == botnet_infra',
  supportId: 'PB-BOTNET-004', supportTitle: '僵尸网络感染主机处置手册', supportExcerpt: '隔离终端、提取任务载荷与进程树，并在阻断基础设施前保存 DNS、TLS 和主机证据。',
  keywords: ['Botnet', 'task pull', 'infrastructure cluster'],
})
const botnetAgent = agent({
  runId: 'AGENT-RUN-0716-0258', hypothesis: '该终端已经加入已知僵尸网络，并通过 TLS 周期性拉取任务配置。', patternDecision: 'known_match',
  summary: '主机按 5 分钟周期从已知基础设施簇拉取约 6.8 KB 加密载荷，Transformer 以 0.95 置信度判定 Botnet。',
  recommendation: '立即隔离源终端并提取进程树和任务载荷；复用现有规则，不由 Agent 直接部署新规则。', rag: botnetRag,
  comparisonResult: '与 ALT-72604 的周期、载荷规模和目标基础设施簇一致。', ruleResult: '复用 RULE-BOTNET-0011 v5，不生成重复候选。',
  validationResult: '关联 EDR 进程树、DNS 与 TLS 会话，确认不存在合法管理代理误命中。',
})

export const alertDetails: Record<string, AlertDetail> = {
  'ALT-78435': {
    alert: alert('ALT-78435'), transformer: portTransformer, autoEncoder: portAe, fusion: portFusion,
    profile: profile({
      flow_id: 'FLOW-20260716-00842', timestamp: '2026-07-16T14:33:04+08:00', src_ip: '192.168.10.23', src_port: 49152,
      dst_ip: '10.0.0.8', dst_port: 445, protocol: 'TCP', service: 'SMB', flow_duration: 0.58, forward_packet_count: 94,
      backward_packet_count: 11, forward_bytes: 6892, backward_bytes: 668, packets_per_second: 181.03, bytes_per_second: 13034.48,
      syn_ratio: 0.82, ack_ratio: 0.09, rst_ratio: 0.06, destination_port_count_60s: 76, destination_ip_count_60s: 18,
      flow_count_60s: 130, average_packet_size: 72, suspected_attack_type: 'Port Scan Variant',
    }, portTransformer, portAe, portFusion),
    rag: ragEvidence, agent: portAgent, ragQuery: '低置信度 Unknown + 60 秒 76 个端口 + SYN 0.82 + 短连接',
    relatedRule: { recordId: 'EVO-2026-0716-14', ruleId: 'RULE-CAND-0042', label: '候选修复规则' },
  },
  'ALT-78436': {
    alert: alert('ALT-78436'), transformer: ddosTransformer, autoEncoder: ddosAe, fusion: ddosFusion,
    profile: profile({
      flow_id: 'FLOW-20260716-00911', timestamp: '2026-07-16T14:34:22+08:00', src_ip: 'multiple:1842', src_port: 0,
      dst_ip: '10.8.2.10', dst_port: 443, protocol: 'TCP', service: 'HTTPS', flow_duration: 40.2, forward_packet_count: 986400,
      backward_packet_count: 1240, forward_bytes: 63129600, backward_bytes: 79360, packets_per_second: 24568, bytes_per_second: 1570368,
      syn_ratio: 0.96, ack_ratio: 0.01, rst_ratio: 0.02, destination_port_count_60s: 1, destination_ip_count_60s: 1,
      flow_count_60s: 98640, average_packet_size: 64, suspected_attack_type: 'DDoS SYN Flood',
    }, ddosTransformer, ddosAe, ddosFusion),
    rag: ddosRag, agent: ddosAgent, ragQuery: '1,842 个源 + PPS 24,568 + SYN 0.96 + 支付网关',
    relatedRule: { recordId: null, ruleId: 'SIG-DDOS-4401', label: '已部署命中规则' },
  },
  'ALT-78431': {
    alert: alert('ALT-78431'), transformer: c2Transformer, autoEncoder: c2Ae, fusion: c2Fusion,
    profile: profile({
      flow_id: 'FLOW-20260716-00831', timestamp: '2026-07-16T14:32:08+08:00', src_ip: '10.24.16.37', src_port: 51842,
      dst_ip: '185.225.73.44', dst_port: 443, protocol: 'TLS', service: 'HTTPS', flow_duration: 1.22, forward_packet_count: 10,
      backward_packet_count: 8, forward_bytes: 2236, backward_bytes: 2596, packets_per_second: 14.75, bytes_per_second: 3960.66,
      syn_ratio: 0.06, ack_ratio: 0.78, rst_ratio: 0, destination_port_count_60s: 1, destination_ip_count_60s: 1,
      flow_count_60s: 2, average_packet_size: 268, suspected_attack_type: 'Botnet C2',
    }, c2Transformer, c2Ae, c2Fusion),
    rag: c2Rag, agent: c2Agent, ragQuery: '47 秒周期 TLS 心跳 + 小流量 + SNI/SAN 错配 + 可疑外部地址',
    relatedRule: { recordId: null, ruleId: 'C2-CAND-0017', label: '建议候选修复规则' },
  },
  'ALT-78428': {
    alert: alert('ALT-78428'), transformer: sshTransformer, autoEncoder: sshAe, fusion: sshFusion,
    profile: profile({
      flow_id: 'FLOW-20260716-00828', timestamp: '2026-07-16T14:29:51+08:00', src_ip: '10.18.4.92', src_port: 42017,
      dst_ip: '10.18.8.47', dst_port: 22, protocol: 'TCP', service: 'SSH', flow_duration: 0.48, forward_packet_count: 8,
      backward_packet_count: 4, forward_bytes: 1080, backward_bytes: 780, packets_per_second: 25, bytes_per_second: 3875,
      syn_ratio: 0.17, ack_ratio: 0.58, rst_ratio: 0.08, destination_port_count_60s: 1, destination_ip_count_60s: 43,
      flow_count_60s: 286, average_packet_size: 155, suspected_attack_type: 'SSH Brute Force',
    }, sshTransformer, sshAe, sshFusion),
    rag: sshRag, agent: sshAgent, ragQuery: '固定源 + 目标端口 22 + 8 分钟 286 次认证失败 + 43 台资产',
    relatedRule: { recordId: 'EVO-2026-0716-12', ruleId: 'EVO-2026-0716-12', label: '验证中的候选规则' },
  },
  'ALT-78422': contextualDetail({
    alertId: 'ALT-78422', flowId: 'FLOW-20260716-00822', timestamp: '2026-07-16T14:24:16+08:00', srcIp: '10.32.6.15', srcPort: 44318,
    dstIp: '104.21.44.19', dstPort: 443, protocol: 'TLS', service: 'HTTPS', suspected: 'Abnormal Outbound Connection', prediction: 'Infiltration',
    confidence: 0.68, known: false, reconstructionError: 0.89, anomalyScore: 0.92, finalScore: 84, lean: 'unknown_anomaly', agreement: 'partial',
    rag: exfilRag, agent: exfilAgent, ragQuery: '数据库资产 + 出站字节基线 12.4 倍 + 非备份窗口 + 首次目标 ASN',
    relatedRule: { recordId: null, ruleId: 'RULE-OUT-0021', label: '待修复已有规则' },
    metrics: { flow_duration: 4.62, forward_packet_count: 326, backward_packet_count: 44, forward_bytes: 684291, backward_bytes: 12840, packets_per_second: 80.09, bytes_per_second: 150894, ack_ratio: 0.82, destination_port_count_60s: 1, destination_ip_count_60s: 1, flow_count_60s: 3, average_packet_size: 1884 },
  }),
  'ALT-78417': contextualDetail({
    alertId: 'ALT-78417', flowId: 'FLOW-20260716-00817', timestamp: '2026-07-16T14:19:03+08:00', srcIp: '172.19.4.61', srcPort: 52014,
    dstIp: '10.12.0.18', dstPort: 0, protocol: 'TCP', service: 'Multi-port', suspected: 'Port Scan', prediction: 'Port Scan', confidence: 0.97,
    known: true, reconstructionError: 0.78, anomalyScore: 0.86, finalScore: 68, lean: 'known_attack', agreement: 'consistent', rag: scanRag, agent: scanAgent,
    ragQuery: '1,024 个端口 + SYN/ACK 18.7 + 边界已阻断', relatedRule: { recordId: 'SIG-2200451', ruleId: 'SIG-2200451', label: '已部署命中规则' },
    metrics: { flow_duration: 9.8, forward_packet_count: 1128, backward_packet_count: 61, forward_bytes: 72192, backward_bytes: 3904, packets_per_second: 121.3, bytes_per_second: 7764, syn_ratio: 0.94, ack_ratio: 0.05, rst_ratio: 0.01, destination_port_count_60s: 1024, destination_ip_count_60s: 61, flow_count_60s: 1189, average_packet_size: 64 },
  }),
  'ALT-78411': contextualDetail({
    alertId: 'ALT-78411', flowId: 'FLOW-20260716-00811', timestamp: '2026-07-16T14:12:44+08:00', srcIp: '10.26.11.8', srcPort: 53301,
    dstIp: '8.8.8.8', dstPort: 53, protocol: 'UDP', service: 'DNS', suspected: 'DNS Tunneling', prediction: 'Infiltration', confidence: 0.78,
    known: true, reconstructionError: 0.81, anomalyScore: 0.79, finalScore: 63, lean: 'known_attack', agreement: 'partial', rag: dnsRag, agent: dnsAgent,
    ragQuery: '平均子域长度 47.3 + TXT 比例异常 + 熵值 4.81', relatedRule: { recordId: 'EVO-2026-0715-08', ruleId: 'EVO-2026-0715-08', label: '待验证候选规则' },
    metrics: { flow_duration: 0.084, forward_packet_count: 5, backward_packet_count: 3, forward_bytes: 822, backward_bytes: 402, packets_per_second: 95.2, bytes_per_second: 14571, ack_ratio: 0, destination_port_count_60s: 1, destination_ip_count_60s: 1, flow_count_60s: 48, average_packet_size: 153 },
  }),
  'ALT-78402': contextualDetail({
    alertId: 'ALT-78402', flowId: 'FLOW-20260716-00802', timestamp: '2026-07-16T14:03:29+08:00', srcIp: '10.11.3.44', srcPort: 58432,
    dstIp: '10.14.5.21', dstPort: 3389, protocol: 'TCP', service: 'RDP', suspected: 'Authorized Remote Administration', prediction: 'Benign', confidence: 0.94,
    known: true, reconstructionError: 0.18, anomalyScore: 0.12, finalScore: 39, lean: 'normal', agreement: 'consistent', rag: rdpRag, agent: rdpAgent,
    ragQuery: '非工作时段 RDP + 已批准变更 + 合规终端 + 目标与工单一致', relatedRule: { recordId: null, ruleId: 'EXC-RDP-008', label: '已验证行为例外' },
    metrics: { flow_duration: 1820, forward_packet_count: 8421, backward_packet_count: 7902, forward_bytes: 4258912, backward_bytes: 3892144, packets_per_second: 8.97, bytes_per_second: 4478, syn_ratio: 0.01, ack_ratio: 0.92, rst_ratio: 0, destination_port_count_60s: 1, destination_ip_count_60s: 1, flow_count_60s: 1, average_packet_size: 499 },
  }),
  'ALT-78394': contextualDetail({
    alertId: 'ALT-78394', flowId: 'FLOW-20260716-00794', timestamp: '2026-07-16T13:56:12+08:00', srcIp: '10.31.7.23', srcPort: 59418,
    dstIp: '13.107.42.12', dstPort: 443, protocol: 'TLS', service: 'HTTPS', suspected: 'Normal SaaS Traffic', prediction: 'Benign', confidence: 0.96,
    known: true, reconstructionError: 0.11, anomalyScore: 0.07, finalScore: 18, lean: 'normal', agreement: 'consistent', rag: saasRag, agent: saasAgent,
    ragQuery: '新 SaaS 目标 + Microsoft 网络归属 + 24 台同组终端一致', relatedRule: { recordId: null, ruleId: 'EXC-SAAS-014', label: '已验证基线例外' },
    metrics: { flow_duration: 2.4, forward_packet_count: 32, backward_packet_count: 41, forward_bytes: 12840, backward_bytes: 28420, packets_per_second: 30.4, bytes_per_second: 17192, syn_ratio: 0.01, ack_ratio: 0.9, rst_ratio: 0, destination_port_count_60s: 1, destination_ip_count_60s: 1, flow_count_60s: 4, average_packet_size: 565 },
  }),
  'ALT-78388': contextualDetail({
    alertId: 'ALT-78388', flowId: 'FL-901790', timestamp: '2026-07-16T13:49:37+08:00', srcIp: '198.51.100.64', srcPort: 48112,
    dstIp: '10.8.4.21', dstPort: 80, protocol: 'TCP', service: 'HTTP', suspected: 'DoS', prediction: 'DoS', confidence: 0.97,
    known: true, reconstructionError: 0.91, anomalyScore: 0.95, finalScore: 89, lean: 'dual_confirmed', agreement: 'consistent', rag: dosRag, agent: dosAgent,
    ragQuery: '单一外部源 + 60 秒 18,420 条半开连接 + SYN 0.95 + HTTP 服务容量下降',
    relatedRule: { recordId: null, ruleId: 'SIG-DOS-3302', label: '已部署命中规则' },
    metrics: { flow_duration: 60, forward_packet_count: 36840, backward_packet_count: 420, forward_bytes: 2357760, backward_bytes: 26880, packets_per_second: 621, bytes_per_second: 39744, syn_ratio: 0.95, ack_ratio: 0.03, rst_ratio: 0.01, destination_port_count_60s: 1, destination_ip_count_60s: 1, flow_count_60s: 18420, average_packet_size: 64 },
  }),
  'ALT-78381': contextualDetail({
    alertId: 'ALT-78381', flowId: 'FL-901784', timestamp: '2026-07-16T13:42:18+08:00', srcIp: '203.0.113.77', srcPort: 50918,
    dstIp: '10.9.2.17', dstPort: 443, protocol: 'HTTPS', service: 'HTTPS', suspected: 'Web Attack', prediction: 'Web Attack', confidence: 0.93,
    known: true, reconstructionError: 0.76, anomalyScore: 0.88, finalScore: 85, lean: 'known_attack', agreement: 'consistent', rag: webRag, agent: webAgent,
    ragQuery: '登录接口 + 60 秒 37 次变形 payload + 布尔型 SQL 结构 + WAF 阻断',
    relatedRule: { recordId: null, ruleId: 'RULE-WEB-0074', label: '已验证命中规则' },
    metrics: { flow_duration: 1.84, forward_packet_count: 176, backward_packet_count: 108, forward_bytes: 76420, backward_bytes: 42000, packets_per_second: 154.35, bytes_per_second: 64358.7, syn_ratio: 0.02, ack_ratio: 0.91, rst_ratio: 0.02, destination_port_count_60s: 1, destination_ip_count_60s: 1, flow_count_60s: 37, average_packet_size: 417 },
  }),
  'ALT-78376': contextualDetail({
    alertId: 'ALT-78376', flowId: 'FL-901776', timestamp: '2026-07-16T13:36:44+08:00', srcIp: '10.22.7.31', srcPort: 54421,
    dstIp: '45.141.87.19', dstPort: 443, protocol: 'TLS', service: 'HTTPS', suspected: 'Botnet', prediction: 'Botnet', confidence: 0.95,
    known: true, reconstructionError: 0.84, anomalyScore: 0.93, finalScore: 94, lean: 'dual_confirmed', agreement: 'consistent', rag: botnetRag, agent: botnetAgent,
    ragQuery: '5 分钟周期 + 6.8 KB 加密任务载荷 + 已知 Botnet 基础设施簇 + 内部终端',
    relatedRule: { recordId: null, ruleId: 'RULE-BOTNET-0011', label: '已验证命中规则' },
    metrics: { flow_duration: 1.32, forward_packet_count: 14, backward_packet_count: 12, forward_bytes: 3180, backward_bytes: 3660, packets_per_second: 19.7, bytes_per_second: 5181.8, syn_ratio: 0.04, ack_ratio: 0.88, rst_ratio: 0, destination_port_count_60s: 1, destination_ip_count_60s: 1, flow_count_60s: 1, average_packet_size: 263 },
  }),
}

export function getAlertDetail(id: string) {
  const detail = alertDetails[id]
  if (!detail) throw new Error(`Unknown alert ${id}`)
  return detail
}

export const datasets: DatasetRecord[] = [
  { id: 'DS-CIC-2017', name: 'CICIDS2017', totalSamples: 2830743, normalSamples: 2273097, attackSamples: 557646, featureCount: 78, missingValues: 1358, split: { train: 70, validation: 15, test: 15 }, mainTrainingSet: true, unknownHoldout: true, ruleReplay: true, uses: ['Masked Feature Modeling 预训练', '已知攻击分类微调', 'AutoEncoder 正常流量训练', 'Botnet 类别留出实验', '规则历史回放'], attackDistribution: [{ label: 'DoS/DDoS', count: 380699 }, { label: 'Port Scan', count: 158930 }, { label: 'Brute Force', count: 13835 }, { label: 'Web Attack', count: 2180 }, { label: 'Botnet', count: 1966 }] },
  { id: 'DS-NF-CSE-2018', name: 'NF-CSE-CIC-IDS2018', totalSamples: 8392401, normalSamples: 7373198, attackSamples: 1019203, featureCount: 43, missingValues: 0, split: { train: 70, validation: 15, test: 15 }, mainTrainingSet: false, unknownHoldout: true, ruleReplay: true, uses: ['跨数据集泛化测试', '高流量 DDoS 回放', 'Botnet 未知类别留出', '模型效果对比'], attackDistribution: [{ label: 'DDoS', count: 380096 }, { label: 'DoS', count: 267594 }, { label: 'Brute Force', count: 145859 }, { label: 'Botnet', count: 143097 }, { label: 'Infiltration', count: 82557 }] },
  { id: 'DS-UNSW-2015', name: 'UNSW-NB15', totalSamples: 257673, normalSamples: 93000, attackSamples: 164673, featureCount: 49, missingValues: 0, split: { train: 60, validation: 20, test: 20 }, mainTrainingSet: false, unknownHoldout: true, ruleReplay: false, uses: ['跨数据集泛化测试', 'Unknown Anomaly 留出实验', '模型效果对比'], attackDistribution: [{ label: 'Generic', count: 58871 }, { label: 'Exploits', count: 44525 }, { label: 'Fuzzers', count: 24246 }, { label: 'Reconnaissance', count: 13987 }, { label: 'DoS', count: 16353 }] },
].map((dataset) => ({
  ...dataset,
  version: 'fixed-demo-snapshot',
  state: 'snapshot' as const,
  format: 'snapshot',
  relativePath: '',
  sourceUri: '',
  fileSizeBytes: 0,
  sha256: null,
  labelColumn: null,
  inspectedAt: null,
  inspectionError: '显式演示快照，未连接本地真实数据文件。',
  updatedAt: '2026-07-16T00:00:00+08:00',
}))

export const candidateRule: StructuredRule = {
  rule_id: 'RULE-CAND-0042', rule_name: 'short_time_multi_port_scan', description: '检测同一源地址在短时间内发起的大范围端口探测行为',
  attack_type: 'Port Scan', severity: 'high', attack_stage: 'Reconnaissance', mitre_technique_ids: ['T1046'],
  conditions: [
    { field: 'destination_port_count_60s', operator: '>', value: 50 },
    { field: 'syn_ratio', operator: '>', value: 0.7 },
    { field: 'flow_duration', operator: '<', value: 2 },
  ],
  evidence_ids: portAgent.evidenceIds, generated_by: 'DeepSeek V4 Pro', version: 1, parent_rule_id: 'RULE-DEP-0018',
}

const previousRule: StructuredRule = {
  ...candidateRule, rule_id: 'RULE-DEP-0018', version: 2, parent_rule_id: null,
  conditions: [{ field: 'destination_port_count_60s', operator: '>', value: 90 }, { field: 'syn_ratio', operator: '>', value: 0.75 }],
  generated_by: 'Analyst',
}

export const ruleDetails: Record<string, RuleDetail> = {
  'EVO-2026-0716-14': {
    record: { ...rules[0]!, qualityScore: 92 }, structured: candidateRule,
    validation: {
      qualityScore: 92, syntax: 100, attackHitAbility: 96, lowFalsePositive: 91, coverage: 88, nonRedundancy: 84, evidenceConsistency: 95,
      hitRate: 96.2, falsePositiveRate: 0.31, precision: 95.8, recall: 96.2, f1: 96.0, attackCoverage: 93.4, redundancy: 11.6,
      perturbationRobustness: 89.2, replayAttackFlows: 184260, replayNormalFlows: 468310000,
      schemaChecks: [
        { label: 'JSON Schema', passed: true, note: '结构符合 evonids.rule/v1' },
        { label: '字段合法性', passed: true, note: '3 / 3 字段已在特征注册表中' },
        { label: '运算符合法性', passed: true, note: '全部运算符与字段类型兼容' },
        { label: '阈值范围', passed: true, note: '阈值位于训练分布 P95–P99.5' },
        { label: 'RAG 证据一致性', passed: true, note: `${candidateRule.evidence_ids.length} 条实际采用证据与 Agent、规则 JSON 完全一致` },
      ],
    },
    sourceAlertId: 'ALT-78435', previousVersion: previousRule,
    diffReason: '旧规则的 90 端口阈值无法覆盖低速扫描变体；新增 flow_duration 条件，以控制阈值下调带来的误报。',
    expectedCoverageChange: '对 Port Scan Variant 的回放覆盖率预计从 71.8% 提升至 93.4%。',
    falsePositiveRisk: '服务网格健康检查和内部资产发现任务可能命中，部署时将沿用授权扫描器白名单。',
  },
}
