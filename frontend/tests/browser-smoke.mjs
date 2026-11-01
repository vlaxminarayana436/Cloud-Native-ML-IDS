// Requires a running dashboard + Commander with a disposable database and a
// copied baseline MODEL_DIR, with all enforcers disabled. Always sends test flows.
// TEST_MUTATIONS=1 uploads a PCAP and creates/removes a policy entry.
// TEST_LIFECYCLE=1 trains, activates and rolls back the copied model.
// TEST_API_KEY tests on-demand authentication against a key-protected Commander.
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { chromium } from 'playwright'

const base = process.env.DASHBOARD_URL || 'http://127.0.0.1:5173'
const pcap = Buffer.from('1MOyoQIABAAAAAAAAAAAAP//AADkAAAA/4fkakINBQAoAAAAKAAAAEUAACgAAQAAQAao5QgICAjAqAEyw1ABuwAAAAAAAAAAUAIgAPjsAAA=', 'base64')
const args = process.env.CHROMIUM_SINGLE_PROCESS === '1' ? ['--no-sandbox', '--single-process', '--no-zygote', '--disable-dev-shm-usage'] : []
const browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_EXECUTABLE_PATH ? { executablePath: process.env.CHROMIUM_EXECUTABLE_PATH } : {}), args })
// Even an old opt-out and reduced-motion OS setting must not disable navigation.
const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, reducedMotion: 'reduce' })
await page.addInitScript(() => localStorage.setItem('ids-scroll-preference', 'off'))
const errors = []
const keyedReads = []
page.on('pageerror', error => errors.push(error.message))
page.on('request', request => {
  if (request.method() === 'GET' && new URL(request.url()).pathname.startsWith('/api/') && request.headers()['x-api-key']) keyedReads.push(request.url())
})
try {
  await page.goto(base, { waitUntil: 'networkidle' })
  await page.getByText('Commander connected').waitFor({ timeout: 15000 })
  assert.equal(await page.title(), 'Cloud-Native ML-IDS · Security Console')
  assert.equal(await page.locator('h1').innerText(), 'Security overview')
  assert.equal(await page.locator('.sidebar').getByRole('button').count(), 8, 'Only section links should appear in the sidebar')
  assert.equal(await page.locator('.sidebar').getByRole('button', { name: /scroll|api key/i }).count(), 0, 'No motion or API-key controls')
  assert.equal(await page.evaluate(() => localStorage.getItem('ids-scroll-preference')), 'off')
  const visibleText = (await page.locator('body').innerText()).toLowerCase()
  assert.ok(!/\b(example|sample|demo)\b/.test(visibleText), 'The console must not show starter or placeholder content')
  const layout = await page.evaluate(() => {
    const traffic = document.querySelector('.chart-card').getBoundingClientRect()
    const block = document.querySelector('.block-card').getBoundingClientRect()
    return { trafficTop: traffic.top, blockTop: block.top, trafficRight: traffic.right, blockLeft: block.left }
  })
  assert.ok(Math.abs(layout.trafficTop - layout.blockTop) < 2 && layout.blockLeft > layout.trafficRight, 'Traffic and blocklist should share a desktop row')

  if (process.env.TEST_API_KEY) {
    await page.getByRole('button', { name: 'Access policy' }).click(); await page.waitForTimeout(1100)
    await page.getByRole('button', { name: 'Add network' }).click()
    await page.getByLabel('Label', { exact: true }).fill('Browser auth VPN')
    await page.getByLabel('CIDR', { exact: true }).fill('10.88.76.0/24')
    const add = page.locator('.boundary-form').getByRole('button', { name: 'Add', exact: true })
    await add.click()
    const dialog = page.getByRole('dialog', { name: 'Authentication required' })
    await dialog.waitFor()
    assert.equal(await dialog.getByLabel('API key').getAttribute('type'), 'password')
    await dialog.getByLabel('API key').fill('incorrect-test-key')
    await dialog.getByRole('button', { name: 'Continue' }).click()
    await dialog.getByRole('alert').waitFor()
    assert.equal(await page.evaluate(() => sessionStorage.getItem('commander-api-key')), null, 'A rejected key should be cleared')
    assert.equal(await page.getByText('Browser auth VPN', { exact: true }).count(), 0, 'Wrong key must not create a network')
    await dialog.getByRole('button', { name: 'Cancel' }).click()
    await dialog.waitFor({ state: 'detached' })
    assert.equal(await page.getByText('Browser auth VPN', { exact: true }).count(), 0, 'Cancel must not perform the action')
    await add.click()
    await dialog.waitFor()
    await dialog.getByLabel('API key').fill(process.env.TEST_API_KEY)
    await dialog.getByRole('button', { name: 'Continue' }).click()
    await page.getByText('Browser auth VPN', { exact: true }).waitFor()
    assert.equal(await page.evaluate(() => sessionStorage.getItem('commander-api-key')), process.env.TEST_API_KEY)
    assert.equal(await page.evaluate(() => localStorage.getItem('commander-api-key')), null, 'The key must not be stored persistently')
    await page.reload({ waitUntil: 'networkidle' })
    await page.getByText('Browser auth VPN', { exact: true }).waitFor()
    page.once('dialog', confirm => confirm.accept())
    await page.getByRole('button', { name: 'Remove Browser auth VPN' }).click()
    await page.getByText('Browser auth VPN', { exact: true }).waitFor({ state: 'detached' })
    assert.equal(await dialog.count(), 0, 'The session key should be reused for a later action')

    // Multipart uploads must also retry correctly after an authentication prompt.
    await page.evaluate(() => sessionStorage.removeItem('commander-api-key'))
    await page.reload({ waitUntil: 'networkidle' })
    const previousPcap = await page.evaluate(async () => (await fetch('/api/v1/summary?source=pcap').then(r => r.json())).totalEvents)
    await page.getByRole('button', { name: 'PCAP analysis' }).click(); await page.waitForTimeout(1100)
    await page.locator('#pcap-file').setInputFiles({ name: 'auth-test.pcap', mimeType: 'application/octet-stream', buffer: pcap })
    await page.getByRole('button', { name: 'Analyze capture' }).click()
    await dialog.waitFor()
    await dialog.getByLabel('API key').fill(process.env.TEST_API_KEY)
    await dialog.getByRole('button', { name: 'Continue' }).click()
    await page.getByText(/1 flow analyzed/).waitFor({ timeout: 15000 })
    const currentPcap = await page.evaluate(async () => (await fetch('/api/v1/summary?source=pcap').then(r => r.json())).totalEvents)
    assert.equal(currentPcap, previousPcap + 1, 'The authenticated upload must be processed exactly once')
    await page.reload({ waitUntil: 'networkidle' })
    await page.getByRole('button', { name: 'Overview' }).click(); await page.waitForTimeout(1100)
    console.log('Passed protected-action prompt, wrong key, cancellation, session reuse and multipart retry')
  }

  await page.getByRole('button', { name: 'PCAP analysis' }).click()
  await page.waitForTimeout(170)
  const midway = await page.evaluate(() => window.scrollY)
  await page.waitForTimeout(950)
  const finish = await page.evaluate(() => window.scrollY)
  assert.ok(midway > 0 && midway < finish - 30, `Page should visibly animate (${midway} -> ${finish})`)
  assert.equal(await page.getByRole('button', { name: 'PCAP analysis' }).getAttribute('aria-current'), 'page')
  assert.ok(Math.abs(await page.locator('#pcap').evaluate(el => el.getBoundingClientRect().top) - 24) < 12)

  // Add an event while the reader is at PCAP; live rendering must not drive page movement.
  const before = await page.evaluate(() => window.scrollY)
  const response = await page.evaluate(async () => fetch('/api/v1/flows/process', {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...(sessionStorage.getItem('commander-api-key') ? { 'X-API-Key': sessionStorage.getItem('commander-api-key') } : {}) },
    body: JSON.stringify({ traffic_source:'synthetic', agent_id:'browser-test', src_ip:'203.0.113.111', dst_ip:'192.168.1.50', src_port:50000, dst_port:443, protocol:'TCP', flow_duration:1, packet_count:600, byte_count:60000, iat_mean:.001, average_packet_size:100, syn_count:590, ack_count:1, syn_ack_ratio:590 }),
  }).then(r => r.status))
  assert.equal(response, 200)
  const extraStatuses = await page.evaluate(async () => Promise.all([0, 1].map(i => fetch('/api/v1/flows/process', {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...(sessionStorage.getItem('commander-api-key') ? { 'X-API-Key': sessionStorage.getItem('commander-api-key') } : {}) },
    body: JSON.stringify({ traffic_source:'synthetic', agent_id:`browser-score-${i}`, src_ip:`203.0.113.${150+i}`, dst_ip:'192.168.1.50', src_port:51000+i, dst_port:53, protocol:'UDP', flow_duration:.960423958, packet_count:116, byte_count:9549, iat_mean:.00958964, average_packet_size:82.3189655, syn_count:0, ack_count:0, syn_ack_ratio:0 }),
  }).then(r => r.status))))
  assert.ok(extraStatuses.every(status => status === 200))
  await page.waitForTimeout(2300)
  assert.ok(Math.abs((await page.evaluate(() => window.scrollY)) - before) <= 2, 'An incoming alert should not move the page')

  // Percentages must be calculated from the API's recorded data or model artifact.
  const report = await page.evaluate(async () => ({ summary: await fetch('/api/v1/summary?source=all').then(r => r.json()), model: await fetch('/api/v1/model/info').then(r => r.json()) }))
  await page.waitForFunction(expected => Number(document.querySelector('.metrics-grid .metric .metric-number').textContent.replaceAll(',', '')) === expected, report.summary.totalEvents)
  const totalCategories = Object.values(report.summary.attackTypes).reduce((sum, n) => sum + n, 0)
  assert.ok(Object.keys(report.summary.attackTypes).length >= 2, 'Use multiple categories to check nontrivial shares')
  assert.ok(report.summary.modelScores.average < 1, 'Use different scores to check the average')
  for (const [name, n] of Object.entries(report.summary.attackTypes).slice(0, 3)) {
    const item = page.locator('.threat-item').filter({ hasText: name.replaceAll('_', ' ') })
    assert.equal(await item.locator('small').innerText(), `${Math.round(n / totalCategories * 100)}%`, `Alert share for ${name}`)
  }
  const pct = value => value == null ? '—' : `${(value * 100).toFixed(1)}%`
  assert.equal(await page.locator('.confidence-main > strong').innerText(), pct(report.summary.modelScores.average), 'Mean supervised/hybrid score')
  assert.equal(await page.locator('.synthetic-metrics > div').nth(0).locator('strong').innerText(), pct(report.model.metrics.accuracy), 'Held-out model accuracy')
  assert.equal(await page.locator('.synthetic-metrics > div').nth(1).locator('strong').innerText(), pct(report.model.metrics.weighted_f1), 'Held-out model F1')
  if (report.model.metrics.anomaly) {
    assert.equal(await page.locator('.anomaly-metrics span').nth(0).locator('b').innerText(), pct(report.model.metrics.anomaly.normal_false_flag_rate))
    assert.equal(await page.locator('.anomaly-metrics span').nth(1).locator('b').innerText(), pct(report.model.metrics.anomaly.attack_flag_rate))
  }
  const features = Object.entries(report.model.feature_importance).sort((a, b) => b[1] - a[1]).slice(0, 5)
  for (const [index, [name, value]] of features.entries()) {
    const item = page.locator('.feature').nth(index)
    assert.equal(await item.locator('span').first().innerText(), name.replaceAll('_', ' '))
    assert.equal(await item.locator('strong').innerText(), pct(value), `Model feature importance for ${name}`)
  }
  console.log('Passed displayed percentage calculations and event-driven refresh')

  for (const [label, id] of [['Overview','overview'], ['Traffic analysis','traffic'], ['Alert feed','alerts'], ['Flow review','review'], ['PCAP analysis','pcap'], ['Access policy','policy'], ['Adaptive learning','adaptive'], ['Model & health','model']]) {
    const start = await page.evaluate(() => window.scrollY)
    await page.getByRole('button', { name: label, exact: true }).click()
    await page.waitForTimeout(240)
    const during = await page.evaluate(() => window.scrollY)
    await page.waitForTimeout(850)
    assert.equal(await page.getByRole('button', { name: label, exact: true }).getAttribute('aria-current'), 'page', `${label} active`)
    const position = await page.evaluate(target => {
      const el = document.getElementById(target)
      return { actual: window.scrollY, expected: Math.max(0, Math.min(document.documentElement.scrollHeight - innerHeight, el.getBoundingClientRect().top + scrollY - 24)) }
    }, id)
    assert.ok(Math.abs(position.actual - position.expected) < 5, `${label} should land at its section: ${JSON.stringify(position)}`)
    if (Math.abs(position.actual - start) > 30) assert.ok(Math.abs(during - start) > 2 && Math.abs(during - start) < Math.abs(position.actual - start) - 2, `${label} should visibly animate: ${start} → ${during} → ${position.actual}`)
  }
  console.log('Passed all sidebar targets with legacy opt-out and reduced motion')
  await page.reload({ waitUntil:'networkidle' })
  await page.evaluate(() => window.scrollTo(0, 0))
  await page.getByRole('button', { name: 'PCAP analysis', exact: true }).click()
  await page.waitForTimeout(200)
  const reloadMidway = await page.evaluate(() => window.scrollY)
  await page.waitForTimeout(900)
  const reloadFinish = await page.evaluate(() => window.scrollY)
  assert.ok(reloadMidway > 0 && reloadMidway < reloadFinish - 30, 'Navigation must still animate after reload with the old opt-out stored')
  for (const width of [1440, 1366, 1024, 700, 390, 360]) {
    await page.setViewportSize({ width, height: 900 })
    await page.waitForTimeout(200)
    const dimensions = await page.evaluate(() => ({ body: document.body.scrollWidth, document: document.documentElement.scrollWidth, viewport: innerWidth }))
    assert.ok(dimensions.body <= width && dimensions.document <= width, `Horizontal overflow at ${width}: ${JSON.stringify(dimensions)}`)
    await page.getByRole('button', { name: 'Overview' }).click()
    await page.waitForTimeout(1100)
    assert.equal(await page.getByRole('button', { name: 'Overview' }).getAttribute('aria-current'), 'page', `Overview active at ${width}`)
    assert.ok(await page.locator('h1').isVisible())
    await page.getByRole('button', { name: 'Access policy' }).click()
    await page.waitForTimeout(1100)
    assert.equal(await page.getByRole('button', { name: 'Access policy' }).getAttribute('aria-current'), 'page', `Policy active at ${width}`)
    const top = await page.locator('#policy').evaluate(el => el.getBoundingClientRect().top)
    assert.ok(Math.abs(top - (width <= 760 ? 120 : 24)) < 14, `Policy target at ${width}: ${top}`)
    console.log(`Passed ${width}px layout and navigation`)
  }
  // First alerts and block entries must not shift a mobile reader's PCAP section.
  await page.getByRole('button', { name: 'Overview' }).click(); await page.waitForTimeout(1100)
  await page.getByLabel('Traffic source').selectOption('unknown'); await page.waitForTimeout(500)
  await page.getByRole('button', { name: 'PCAP analysis' }).click(); await page.waitForTimeout(1100)
  const mobileBefore = await page.evaluate(() => ({ y: window.scrollY, blockHeight: document.querySelector('.block-card').getBoundingClientRect().height }))
  const mobileStatus = await page.evaluate(async () => fetch('/api/v1/flows/process', { method: 'POST', headers: { 'Content-Type': 'application/json', ...(sessionStorage.getItem('commander-api-key') ? { 'X-API-Key': sessionStorage.getItem('commander-api-key') } : {}) }, body: JSON.stringify({ traffic_source:'unknown', agent_id:'browser-mobile-test', src_ip:'203.0.113.200', dst_ip:'192.168.1.50', src_port:50000, dst_port:443, protocol:'TCP', flow_duration:1, packet_count:600, byte_count:60000, iat_mean:.001, average_packet_size:100, syn_count:590, ack_count:1, syn_ack_ratio:590 }) }).then(r => r.status))
  assert.equal(mobileStatus, 200); await page.waitForTimeout(1600)
  const mobileAfter = await page.evaluate(() => ({ y: window.scrollY, blockHeight: document.querySelector('.block-card').getBoundingClientRect().height }))
  assert.ok(Math.abs(mobileAfter.y - mobileBefore.y) <= 2 && Math.abs(mobileAfter.blockHeight - mobileBefore.blockHeight) < 2, 'Mobile live updates must not shift the page or blocklist')
  await page.setViewportSize({ width: 1440, height: 900 })
  await page.getByRole('button', { name: 'Overview' }).click(); await page.waitForTimeout(1100)
  await page.getByLabel('Traffic source').selectOption('pcap')
  await page.waitForTimeout(500)
  assert.ok((await page.locator('.overview-context').innerText()).includes('offline pcap'))
  await page.getByLabel('Traffic source').selectOption('all')

  if (process.env.TEST_MUTATIONS === '1') {
    await page.getByRole('button', { name: 'PCAP analysis' }).click(); await page.waitForTimeout(1100)
    await page.locator('#pcap-file').setInputFiles({ name: 'browser-test.pcap', mimeType: 'application/octet-stream', buffer: pcap })
    await page.getByRole('button', { name: 'Analyze capture' }).click()
    await page.getByText(/1 flow analyzed/).waitFor({ timeout: 15000 })
    assert.ok((await page.locator('.pcap-result').innerText()).includes('does not create firewall blocks'))
    await page.getByRole('button', { name:'View PCAP alerts' }).click(); await page.waitForTimeout(1100)
    assert.equal(await page.getByLabel('Traffic source').inputValue(), 'pcap')
    assert.equal(await page.getByRole('button', { name:'Alert feed', exact:true }).getAttribute('aria-current'), 'page')
    await page.getByRole('button', { name:'Overview', exact:true }).click(); await page.waitForTimeout(1100)
    await page.getByLabel('Traffic source').selectOption('all'); await page.waitForTimeout(500)
    await page.getByRole('button', { name: 'Access policy' }).click(); await page.waitForTimeout(1100)
    await page.getByRole('button', { name: 'Add network' }).click()
    await page.getByLabel('Label', { exact: true }).fill('Browser test VPN')
    await page.getByLabel('CIDR', { exact: true }).fill('10.88.77.0/24')
    await page.locator('.boundary-form select').selectOption('vpn')
    await page.locator('.boundary-form').getByRole('button', { name: 'Add', exact: true }).click()
    await page.getByText('Browser test VPN').waitFor()
    page.once('dialog', dialog => dialog.accept())
    await page.getByRole('button', { name: 'Remove Browser test VPN' }).click()
    await page.getByText('Browser test VPN').waitFor({ state: 'detached' })

    // Export exactly the filtered rows, escaping spreadsheet formulas in sensor names.
    const posted = await page.evaluate(async () => fetch('/api/v1/flows/process', { method:'POST', headers:{ 'Content-Type':'application/json', ...(sessionStorage.getItem('commander-api-key') ? { 'X-API-Key': sessionStorage.getItem('commander-api-key') } : {}) }, body:JSON.stringify({ traffic_source:'synthetic', agent_id:'=1+1', src_ip:'203.0.113.112', dst_ip:'192.168.1.50', src_port:50002, dst_port:443, protocol:'TCP', flow_duration:1, packet_count:600, byte_count:60000, iat_mean:.001, average_packet_size:100, syn_count:590, ack_count:1, syn_ack_ratio:590 }) }).then(r => r.status))
    assert.equal(posted, 200)
    await page.getByRole('button', { name:'Alert feed', exact:true }).click(); await page.waitForTimeout(1100)
    await page.getByPlaceholder('Search IP, type or sensor').fill('=1+1')
    await page.getByRole('button', { name:'Export CSV' }).waitFor({ state:'visible' })
    const downloadPromise = page.waitForEvent('download')
    await page.getByRole('button', { name:'Export CSV' }).click()
    const download = await downloadPromise
    const csv = await readFile(await download.path(), 'utf8')
    assert.ok(csv.includes('"\'=1+1"'), 'CSV should neutralize spreadsheet formulas')
    assert.ok(!csv.includes('browser-test'), 'CSV should contain only the filtered rows')
    await page.getByPlaceholder('Search IP, type or sensor').clear()

    // Entries beyond the first five must remain accessible and removable.
    const statuses = await page.evaluate(async () => Promise.all(Array.from({ length:7 }, (_, i) => fetch('/api/v1/flows/process', { method:'POST', headers:{ 'Content-Type':'application/json', ...(sessionStorage.getItem('commander-api-key') ? { 'X-API-Key': sessionStorage.getItem('commander-api-key') } : {}) }, body:JSON.stringify({ traffic_source:'synthetic', agent_id:'browser-blocklist', src_ip:`203.0.113.${120+i}`, dst_ip:'192.168.1.50', src_port:50000+i, dst_port:443, protocol:'TCP', flow_duration:1, packet_count:600, byte_count:60000, iat_mean:.001, average_packet_size:100, syn_count:590, ack_count:1, syn_ack_ratio:590 }) }).then(r => r.status))))
    assert.ok(statuses.every(status => status === 200))
    await page.getByRole('button', { name:'Traffic analysis', exact:true }).click(); await page.waitForTimeout(1100)
    await page.waitForFunction(() => document.querySelectorAll('.block-list .block-row').length >= 7)
    const lastAddress = await page.locator('.block-list .block-row').last().locator('.block-details strong').innerText()
    page.once('dialog', dialog => dialog.accept())
    await page.getByRole('button', { name:`Remove ${lastAddress}`, exact:true }).click()
    await page.getByRole('button', { name:`Remove ${lastAddress}`, exact:true }).waitFor({ state:'detached' })
    console.log('Passed PCAP navigation, policy controls, filtered export and complete blocklist access')
  }
  if (process.env.TEST_LIFECYCLE === '1') {
    const result = await page.evaluate(async () => {
      const response = await fetch('/api/v1/flows/process', { method: 'POST', headers: { 'Content-Type': 'application/json', ...(sessionStorage.getItem('commander-api-key') ? { 'X-API-Key': sessionStorage.getItem('commander-api-key') } : {}) }, body: JSON.stringify({ traffic_source:'synthetic', agent_id:'browser-lifecycle', src_ip:'198.51.100.234', dst_ip:'192.168.1.50', src_port:50001, dst_port:443, protocol:'TCP', flow_duration:2, packet_count:800, byte_count:960000, iat_mean:.0025, average_packet_size:1200, syn_count:2, ack_count:700, syn_ack_ratio:2/700 }) })
      return response.json()
    })
    assert.equal(result.detection_source, 'anomaly'); assert.ok(result.pattern_id)
    await page.getByRole('button', { name: 'Adaptive learning' }).click(); await page.waitForTimeout(1100)
    const pattern = page.locator(`[data-pattern-id="${result.pattern_id}"]`)
    await pattern.waitFor({ timeout: 10000 }); await pattern.getByRole('button', { name: /Review & approve/ }).click()
    await pattern.locator('input').fill('Reviewed test anomaly')
    await pattern.getByRole('button', { name: 'Approve', exact: true }).click(); await pattern.waitFor({ state:'detached' })
    const train = page.getByRole('button', { name: 'Train candidate model' })
    await page.waitForFunction(() => { const button = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Train candidate model')); return button && !button.disabled })
    await train.click(); await page.getByText('Candidate ready for review in Model & health.').waitFor({ timeout:30000 })
    await page.getByRole('button', { name: 'Model & health' }).click(); await page.waitForTimeout(1100)
    await page.locator('.candidate-review').waitFor(); assert.ok((await page.locator('.candidate-review').innerText()).includes('Reference F1'))
    page.once('dialog', dialog => dialog.accept()); await page.getByRole('button', { name:'Activate', exact:true }).click()
    await page.getByText(/Active evaluation: synthetic baseline \+ all feedback/).waitFor({ timeout:10000 })
    page.once('dialog', dialog => dialog.accept()); await page.getByRole('button', { name:'Rollback', exact:true }).click()
    await page.getByText(/Active evaluation: synthetic baseline \+ all feedback/).waitFor({ state:'detached', timeout:10000 })
    console.log('Passed analyst review, candidate training, activation and rollback')
  }
  assert.deepEqual(errors, [], `Browser errors: ${errors.join(', ')}`)
  assert.deepEqual(keyedReads, [], 'Open read requests should not send the API key')
  console.log('Browser smoke tests passed')
} finally { await browser.close() }
