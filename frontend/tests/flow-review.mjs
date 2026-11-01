// Requires a disposable Commander database and copied MODEL_DIR, with all
// enforcers disabled. Creates flows and reviews; TEST_API_KEY exercises auth.
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { chromium } from 'playwright'

const base = process.env.DASHBOARD_URL || 'http://127.0.0.1:5173'
const key = process.env.TEST_API_KEY || ''
const args = process.env.CHROMIUM_SINGLE_PROCESS === '1' ? ['--no-sandbox', '--single-process', '--no-zygote', '--disable-dev-shm-usage'] : []
const browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.CHROMIUM_EXECUTABLE_PATH } : {}), args })
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } })
const errors = []; const keyedReads = []
page.on('pageerror', error => errors.push(error.message))
page.on('request', request => { if (request.method() === 'GET' && new URL(request.url()).pathname.startsWith('/api/') && request.headers()['x-api-key']) keyedReads.push(request.url()) })
try {
  await page.goto(base, { waitUntil: 'networkidle' })
  await page.getByText('Commander connected').waitFor({ timeout: 15000 })
  const created = await page.evaluate(async (testKey) => {
    const headers = { 'Content-Type': 'application/json', ...(testKey ? { 'X-API-Key': testKey } : {}) }
    const anomaly = { traffic_source:'capture', agent_id:'browser-review-private-host', src_ip:'198.51.100.20', dst_ip:'192.168.1.50', src_port:443, dst_port:55000, protocol:'TCP', flow_duration:3.07, packet_count:3, byte_count:198, iat_mean:1.535, average_packet_size:66, syn_count:3, ack_count:3, syn_ack_ratio:1 }
    const results = []
    for (let i=0; i<25; i++) {
      const response = await fetch('/api/v1/flows/process', { method:'POST', headers, body:JSON.stringify({ ...anomaly, dst_port:55000+i }) })
      results.push(await response.json())
    }
    const normal = await fetch('/api/v1/flows/process', { method:'POST', headers, body:JSON.stringify({ ...anomaly, src_ip:'1.1.1.1', src_port:50000, dst_port:443, flow_duration:12, packet_count:40, byte_count:28000, iat_mean:.3, average_packet_size:700, syn_count:1, ack_count:30, syn_ack_ratio:1/30 }) }).then(r => r.json())
    const synthetic = await fetch('/api/v1/flows/process', { method:'POST', headers, body:JSON.stringify({ ...anomaly, traffic_source:'synthetic' }) }).then(r => r.json())
    return { results, normal, synthetic }
  }, key)
  assert.ok(created.results.every(result => result.detection_source === 'anomaly'), 'Test flows must be anomaly alerts')
  assert.equal(created.normal.classification, 'Normal')
  const targetId = created.results.at(-1).event_id
  await page.getByLabel('Traffic source').selectOption('capture')
  await page.getByRole('button', { name:'Flow review', exact:true }).click(); await page.waitForTimeout(1100)
  const target = page.locator(`[data-review-event-id="${targetId}"]`)
  await target.waitFor({ timeout:10000 })
  assert.ok((await page.locator('.review-overview-head').innerText()).includes('Live capture'))
  assert.equal(await page.locator('.flow-review-row').count(), 20)
  assert.equal(await page.getByRole('button', { name:'Older', exact:true }).isEnabled(), true)

  // A new live record must not replace the row while the analyst is reading.
  const beforeIds = await page.locator('.flow-review-row').evaluateAll(rows => rows.map(row => row.dataset.reviewEventId))
  const addedId = await page.evaluate(async (testKey) => {
    const response = await fetch('/api/v1/flows/process', { method:'POST', headers:{ 'Content-Type':'application/json', ...(testKey ? { 'X-API-Key':testKey } : {}) }, body:JSON.stringify({ traffic_source:'capture', agent_id:'browser-review-new', src_ip:'198.51.100.21', dst_ip:'192.168.1.50', src_port:443, dst_port:56000, protocol:'TCP', flow_duration:3.07, packet_count:3, byte_count:198, iat_mean:1.535, average_packet_size:66, syn_count:3, ack_count:3, syn_ack_ratio:1 }) })
    return (await response.json()).event_id
  }, key)
  await page.waitForTimeout(1300)
  assert.deepEqual(await page.locator('.flow-review-row').evaluateAll(rows => rows.map(row => row.dataset.reviewEventId)), beforeIds, 'Review snapshot must not churn with live traffic')
  await page.getByRole('button', { name:'Refresh list' }).click()
  await page.locator(`[data-review-event-id="${addedId}"]`).waitFor()
  await page.getByRole('button', { name:'Older', exact:true }).click()
  await page.getByText('Page 2 ·', { exact:false }).waitFor()
  assert.ok(await page.locator('.flow-review-row').count() >= 1)
  await page.getByRole('button', { name:'Newer', exact:true }).click()
  await target.waitFor()

  await target.getByRole('button', { name:`Review flow ${targetId}` }).click()
  let dialog = page.getByRole('dialog', { name:`Review flow #${targetId}` })
  await dialog.waitFor()
  assert.equal(await dialog.getByRole('button', { name:'Save review' }).isDisabled(), true, 'No assessment should be preselected')
  await page.keyboard.press('Escape'); await dialog.waitFor({ state:'detached' })
  await target.getByRole('button', { name:`Review flow ${targetId}` }).click(); await dialog.waitFor()
  await dialog.getByRole('radio', { name:/Unsure/ }).check()
  await dialog.getByLabel('Evidence note').fill('Private evidence note')
  await dialog.getByRole('button', { name:'Save review' }).click()
  if (key) {
    const auth = page.getByRole('dialog', { name:'Authentication required' })
    await auth.waitFor(); await auth.getByLabel('API key').fill('wrong-key'); await auth.getByRole('button', { name:'Continue' }).click()
    await auth.getByRole('alert').waitFor(); await auth.getByRole('button', { name:'Cancel' }).click(); await auth.waitFor({ state:'detached' })
    assert.equal(await page.evaluate(async () => (await fetch('/api/v1/reviews?source=capture&detection=all&status=unsure').then(r => r.json())).summary.unsure), 0, 'Cancelled authentication must not save the assessment')
    await dialog.getByRole('button', { name:'Save review' }).click(); await auth.waitFor()
    await auth.getByLabel('API key').fill(key); await auth.getByRole('button', { name:'Continue' }).click()
  }
  await dialog.waitFor({ state:'detached', timeout:10000 }); await target.waitFor({ state:'detached' })
  await page.getByLabel('Review status').selectOption('unsure'); await target.waitFor()
  assert.ok((await target.innerText()).includes('Unsure'))
  await target.getByRole('button', { name:`Edit review for flow ${targetId}` }).click(); await dialog.waitFor()
  assert.equal(await dialog.getByRole('radio', { name:/Unsure/ }).isChecked(), true)
  await dialog.getByRole('radio', { name:/Benign/ }).check()
  await dialog.getByRole('button', { name:'Save review' }).click(); await dialog.waitFor({ state:'detached' })
  await page.getByLabel('Review status').selectOption('benign'); await target.waitFor()

  const downloadPromise = page.waitForEvent('download')
  await page.getByRole('button', { name:'Export features' }).click()
  const download = await downloadPromise; const csv = await readFile(await download.path(), 'utf8')
  assert.ok(csv.includes('analyst_label') && csv.includes('benign') && csv.includes('anomaly_score'))
  for (const privateValue of ['198.51.100.20', '192.168.1.50', 'Private evidence note', 'browser-review-private-host']) assert.ok(!csv.includes(privateValue), `Feature export must omit ${privateValue}`)
  await page.getByText('Feature export downloaded for the selected source and filters.').waitFor()

  await page.reload({ waitUntil:'networkidle' }); await page.getByLabel('Traffic source').selectOption('capture')
  await page.getByRole('button', { name:'Flow review', exact:true }).click(); await page.waitForTimeout(1100)
  await page.getByLabel('Review status').selectOption('benign'); await target.waitFor()
  await target.getByRole('button', { name:`Edit review for flow ${targetId}` }).click(); await dialog.waitFor()
  assert.equal(await dialog.getByRole('radio', { name:/Benign/ }).isChecked(), true)
  assert.equal(await dialog.getByLabel('Evidence note').inputValue(), 'Private evidence note')
  await page.screenshot({ path:'/tmp/mlids-review-desktop.png' })
  for (const width of [1440, 1366, 1024, 700, 390, 360]) {
    await page.setViewportSize({ width, height:900 }); await page.waitForTimeout(150)
    const dims = await page.evaluate(() => {
      const modal = document.querySelector('.flow-review-dialog')
      return { width:innerWidth, page:document.documentElement.scrollWidth, modal:modal.scrollWidth, modalClient:modal.clientWidth }
    })
    assert.ok(dims.page <= dims.width, `No horizontal page overflow at ${width}: ${JSON.stringify(dims)}`)
    assert.ok(dims.modal <= dims.modalClient + 1, `No horizontal dialog overflow at ${width}: ${JSON.stringify(dims)}`)
    if (width === 390) await page.screenshot({ path:'/tmp/mlids-review-mobile.png' })
  }
  await page.setViewportSize({ width:1440, height:900 })
  page.once('dialog', prompt => prompt.accept())
  await dialog.getByRole('button', { name:'Clear review' }).click(); await dialog.waitFor({ state:'detached' })
  await page.getByLabel('Review status').selectOption('unreviewed'); await target.waitFor()
  await page.getByLabel('Review model result').selectOption('normal')
  await page.locator(`[data-review-event-id="${created.normal.event_id}"]`).waitFor()
  const state = await page.evaluate(async () => ({ rules:await fetch('/api/v1/rules').then(r=>r.json()), blocks:await fetch('/api/v1/blocklist').then(r=>r.json()), summary:await fetch('/api/v1/summary?source=capture').then(r=>r.json()), training:await fetch('/api/v1/model/retrain/status').then(r=>r.json()) }))
  assert.equal(state.rules.length, 0); assert.equal(state.blocks.length, 0); assert.equal(state.summary.feedbackExamples, 0); assert.equal(state.training.state, 'idle')
  assert.deepEqual(errors, [], `Browser errors: ${errors.join(', ')}`)
  assert.deepEqual(keyedReads, [], 'Open reads and downloads must not send the API key')
  console.log('Passed flow review, pagination, snapshot, privacy export, persistence, responsive dialog and safety checks' + (key ? ', including protected-action auth' : ''))
} finally { await browser.close() }
