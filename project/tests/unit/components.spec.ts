import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import MetricCard from '../../app/components/MetricCard.vue'
import RiskScore from '../../app/components/RiskScore.vue'

describe('EvoNIDS base presentation components', () => {
  it('renders a product metric with an explicit semantic tone', () => {
    const wrapper = mount(MetricCard, {
      props: { label: '未知异常', value: '147', delta: '基线偏离 ≥ 0.8', tone: 'info' },
    })

    expect(wrapper.text()).toContain('未知异常')
    expect(wrapper.get('strong').classes()).toContain('tone-info')
  })

  it('exposes a risk score to assistive technology', () => {
    const wrapper = mount(RiskScore, { props: { value: 88, severity: 'high', compact: true } })

    expect(wrapper.get('[aria-label="风险分 88"]').text()).toBe('88')
    expect(wrapper.get('.risk-high').exists()).toBe(true)
  })
})
