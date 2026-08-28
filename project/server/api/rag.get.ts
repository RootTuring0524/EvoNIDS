import { ragEvidence } from '../utils/domain-data'
import { fetchBackend, usesMockApi } from '../utils/backend'

export default defineEventHandler(async (event) => {
  if (!usesMockApi(event)) {
    return fetchBackend(event, '/rag', { query: getQuery(event) })
  }
  const vectorCandidates = ragEvidence.filter((item) => item.vectorScore >= 0.7).length
  const keywordSupplementCandidates = ragEvidence.filter((item) => item.vectorScore < 0.7 && item.keywordScore >= 0.5).length
  const filteredCandidates = ragEvidence.filter((item) => !item.allowed).length
  const rerankedCandidates = ragEvidence.filter((item) => item.allowed).length
  const providedToAgent = ragEvidence.filter((item) => item.allowed && item.usedByAgent).length

  return {
    query: '低置信度 Unknown + 60 秒多端口 SYN 探测 + 短连接',
    topK: 10,
    mode: 'fixed_mock_sample' as const,
    retrieval: { vectorCandidates, keywordSupplementCandidates, filteredCandidates, rerankedCandidates, providedToAgent },
    items: ragEvidence,
  }
})
