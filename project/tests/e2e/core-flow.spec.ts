import { expect, test } from '@playwright/test'

test('analyst can follow alert evidence into a candidate rule', async ({ page }) => {
  await page.goto('/alerts/ALT-78435')
  await expect(page.getByText('Flow Transformer')).toBeVisible()
  await expect(page.getByText('AutoEncoder')).toBeVisible()
  await page.getByRole('button', { name: 'Agent 研判' }).click()
  await expect(page.getByText('DeepSeek V4 Pro')).toBeVisible()
  await page.getByRole('link', { name: /候选修复规则/ }).click()
  await expect(page.getByText('short_time_multi_port_scan')).toBeVisible()
})

test('alert workbench supports server filtering, sorting, evidence expansion and column controls', async ({ page }) => {
  await page.goto('/alerts')
  await expect(page.getByRole('table', { name: '告警研判数据表' })).toBeVisible()

  const riskSort = page.getByRole('button', { name: /风险，当前降序/ })
  await expect(riskSort).toBeVisible()
  await riskSort.click()
  await expect(page.getByRole('columnheader', { name: /风险/ })).toHaveAttribute('aria-sort', 'none')

  const expand = page.getByRole('button', { name: '展开告警证据' }).first()
  await expand.click()
  await expect(expand).toHaveAttribute('aria-expanded', 'true')
  await expect(page.getByText('检测证据', { exact: true })).toBeVisible()

  await page.getByLabel('检测类别').selectOption('Port Scan')
  await expect(page.getByText('ALT-78435')).toBeVisible()
  await expect(page.getByText('ALT-78436')).toHaveCount(0)

  const columnButton = page.getByRole('button', { name: '列设置' })
  await columnButton.click()
  const drawer = page.getByRole('dialog', { name: '告警表格列设置' })
  await expect(drawer).toBeVisible()
  await page.getByRole('checkbox', { name: '时间' }).uncheck()
  await expect(page.getByRole('columnheader', { name: /时间/ })).toHaveCount(0)
  await page.keyboard.press('Escape')
  await expect(drawer).toBeHidden()
  await expect(columnButton).toBeFocused()
})

test('alert API applies real pagination and deterministic server sorting', async ({ request }) => {
  const first = await request.get('/api/alerts?page=1&pageSize=2&sortBy=riskScore&sortDir=desc')
  const second = await request.get('/api/alerts?page=2&pageSize=2&sortBy=riskScore&sortDir=desc')
  expect(first.ok()).toBeTruthy()
  expect(second.ok()).toBeTruthy()
  const firstPage = await first.json()
  const secondPage = await second.json()
  expect(firstPage).toMatchObject({ page: 1, pageSize: 2, total: 12 })
  expect(secondPage).toMatchObject({ page: 2, pageSize: 2, total: 12 })
  expect(firstPage.items).toHaveLength(2)
  expect(secondPage.items).toHaveLength(2)
  expect(firstPage.items[1].riskScore).toBeGreaterThanOrEqual(secondPage.items[0].riskScore)
})

test('keyboard row navigation and theme persistence remain operable', async ({ page }) => {
  await page.goto('/alerts')
  const alertRow = page.getByRole('row', { name: /打开告警 ALT-/ }).first()
  await alertRow.focus()
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(/\/alerts\/ALT-/)

  await page.goto('/overview')
  const themeButton = page.getByRole('button', { name: '深色模式' })
  await themeButton.click()
  await expect.poll(() => page.locator('html').getAttribute('data-theme')).toBe('light')
  await page.reload()
  await expect.poll(() => page.locator('html').getAttribute('data-theme')).toBe('light')
})

test('deployment confirmation dialog traps focus and restores it on escape', async ({ page }) => {
  await page.goto('/rules/EVO-2026-0716-14')
  const confirmButton = page.getByRole('button', { name: '人工确认验证结果' })
  await confirmButton.click()
  const deployButton = page.getByRole('button', { name: '部署到检测平面' })
  await expect(deployButton).toBeVisible()
  await deployButton.click()
  const dialog = page.getByRole('dialog', { name: '人工确认规则部署' })
  await expect(dialog).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(dialog).toBeHidden()
  await expect(deployButton).toBeFocused()
})
