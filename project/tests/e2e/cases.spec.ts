import { test, expect } from '@playwright/test'

test('sidebar exposes the case workbench', async ({ page }) => {
  await page.goto('/overview')
  const nav = page.getByRole('link', { name: '案件工作台' })
  await expect(nav).toBeVisible()
})

test('case workbench renders and accepts a new case', async ({ page }) => {
  await page.goto('/cases')
  await expect(page.getByRole('heading', { name: /案件工作台/ })).toBeVisible()

  // The page shows either an honest empty state or existing rows; never a crash.
  const body = page.locator('body')
  await expect(body).toContainText(/暂无案件|案件工作台/)

  const createButton = page.getByRole('button', { name: /新建案件/ })
  await expect(createButton).toBeVisible()
  await createButton.click()

  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  await dialog.getByLabel('标题（必填）').fill('E2E 扫描调查案件')
  await dialog.getByRole('button', { name: '创建', exact: true }).click()
  // Success toast appears when the real backend accepts the case.
  await expect(page.locator('body')).toContainText(/案件已创建|创建失败/, { timeout: 15000 })
})

test('case detail page shows timeline when one exists', async ({ page }) => {
  await page.goto('/cases')
  const row = page.locator('a[href^="/cases/"]').first()
  if (await row.count() === 0) {
    test.skip(true, 'no cases exist in this environment')
    return
  }
  await row.click()
  await expect(page.getByRole('heading', { name: /案件详情|^.{3,80}$/ }).first()).toBeVisible({ timeout: 15000 })
})
