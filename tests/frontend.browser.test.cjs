/* Browser-only fixtures: no NAS, upstream node, real password or remote write. */
const { test, before, after, beforeEach, afterEach } = require('node:test')
const assert = require('node:assert/strict')
const http = require('node:http')
const fs = require('node:fs/promises')
const path = require('node:path')
const { setTimeout: pause } = require('node:timers/promises')
const { chromium } = require(process.env.FNOS_PLAYWRIGHT_MODULE || 'playwright')

const root = path.resolve(__dirname, '..')
const pixel = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=', 'base64')
const rfb = `export default class RFB extends EventTarget {
  constructor() { super(); setTimeout(() => this.dispatchEvent(new Event('connect')), 0) }
  disconnect() {} sendCredentials() {}
}`
let server, base, browser, context, page, fixture

function json(response, value, code = 200) {
  response.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
  response.end(JSON.stringify(value))
}

function status(changes = {}) {
  return { app: fixture.app, title: fixture.app === 'v2rayn' ? 'v2rayN' : 'Clash Verge Rev', version: 'fixture',
    gui_running: true, network_active: false, network_owner: null, network_phase: 'stopped',
    network_operation: null, network_cleanup_verified: true, network_needs_recovery: false,
    network_error: null, updating: false, last_update: null, message: '', ...changes }
}

function session() {
  return { authenticated: fixture.authenticated, app: fixture.app,
    title: fixture.app === 'v2rayn' ? 'v2rayN' : 'Clash Verge Rev',
    ...(fixture.authenticated ? { csrf: 'browser-fixture-csrf', vnc_password: 'fixture8' } : {}) }
}

async function body(request) {
  let text = ''
  for await (const chunk of request) text += chunk
  return text ? JSON.parse(text) : null
}

before(async () => {
  server = http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url, 'http://fixture.invalid')
      if (url.pathname === '/novnc/core/rfb.js') {
        response.writeHead(200, { 'Content-Type': 'text/javascript' }); response.end(rfb); return
      }
      if (/^\/assets\/icon-(64|256)\.png$/.test(url.pathname)) {
        const size = url.pathname.includes('256') ? '256' : '64'
        const id = fixture.app === 'v2rayn' ? 'fnv2rayn' : 'fnclash'
        const image = await fs.readFile(path.join(root, 'build', id, 'app', 'ui', 'images', `icon_${size}.png`)).catch(() => pixel)
        response.writeHead(200, { 'Content-Type': 'image/png' }); response.end(image); return
      }
      const files = { '/': 'index.html', '/help': 'help.html', '/assets/app.js': 'app.js', '/assets/app.css': 'app.css' }
      if (files[url.pathname]) {
        const type = url.pathname.endsWith('.js') ? 'text/javascript' : url.pathname.endsWith('.css') ? 'text/css' : 'text/html'
        response.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' })
        response.end(await fs.readFile(path.join(root, 'web', files[url.pathname]))); return
      }
      if (url.pathname === '/api/session') { json(response, session(), fixture.authenticated ? 200 : 401); return }
      if (url.pathname === '/api/login') {
        const value = await body(request)
        fixture.authenticated = value?.password === fixture.password
        json(response, session(), fixture.authenticated ? 200 : 401); return
      }
      if (!fixture.authenticated) { json(response, { error: '请先登录' }, 401); return }
      if (url.pathname === '/api/status') {
        fixture.reads++
        if (fixture.onStatus && await fixture.onStatus(request, response)) return
        if (fixture.failStatus) json(response, { error: '测试：管理服务暂不可用' }, 503)
        else json(response, fixture.status)
        return
      }
      assert.equal(request.headers['x-csrf-token'], 'browser-fixture-csrf')
      const value = await body(request)
      fixture.posts.push({ action: url.pathname, value })
      if (url.pathname === '/api/password') {
        if (fixture.onPassword) { await fixture.onPassword(value, response); return }
        assert.equal(value.current_password, fixture.password)
        assert.equal(value.new_password, value.confirm_password)
        fixture.password = value.new_password
        fixture.authenticated = false
        json(response, { ok: true, reauthenticate: true }); return
      }
      if (url.pathname === '/api/logout') { fixture.authenticated = false; json(response, { ok: true }); return }
      if (['/api/network_on', '/api/network_off'].includes(url.pathname)) {
        if (fixture.onNetwork) { await fixture.onNetwork(url.pathname, response); return }
        const active = url.pathname.endsWith('_on')
        fixture.status = status({ network_active: active, network_owner: active ? fixture.app : null,
          network_phase: active ? 'active' : 'stopped' })
        json(response, fixture.status); return
      }
      if (url.pathname === '/api/import') {
        json(response, { ok: true, message: fixture.app === 'v2rayn'
          ? '已发送至 v2rayN，请在原版窗口确认导入结果' : '配置已导入并应用' }); return
      }
      json(response, { ok: true })
    } catch (_) { if (!response.headersSent) json(response, { error: 'Fixture request failed' }, 500); else response.end() }
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  base = `http://127.0.0.1:${server.address().port}`
  browser = await chromium.launch({ headless: true,
    ...(process.env.FNOS_BROWSER_EXECUTABLE ? { executablePath: process.env.FNOS_BROWSER_EXECUTABLE } : {}) })
})

after(async () => { await browser?.close(); server?.closeAllConnections(); await new Promise((resolve) => server.close(resolve)) })
beforeEach(async (testContext) => {
  fixture = { app: 'v2rayn', authenticated: true, password: 'fixture-current-password', posts: [], reads: 0 }
  fixture.status = status()
  const realMotion = testContext.name.startsWith('a confirmed switch')
  context = await browser.newContext({ viewport: { width: 1440, height: 1000 },
    reducedMotion: realMotion ? 'no-preference' : 'reduce' })
  page = await context.newPage()
  // CSS transitions use the renderer clock; this test uses real time to verify them.
  if (!realMotion) await page.clock.install()
})
afterEach(async () => { await context.close() })

async function open(expected = 'off') {
  await page.goto(base)
  await page.waitForFunction((kind) => document.getElementById('network-toggle').dataset.state === kind, expected)
}

async function confirm(expected) {
  await page.waitForFunction((kind) => document.getElementById('network-toggle').dataset.state === kind, expected)
}

async function cursor() { return page.locator('#network-toggle').evaluate((node) => getComputedStyle(node).cursor) }

async function screenshot(name) {
  if (process.env.FNOS_UI_SCREENSHOTS !== '1') return
  const folder = path.join(root, 'work', 'ui-browser-fixtures')
  await fs.mkdir(folder, { recursive: true })
  await page.screenshot({ path: path.join(folder, name + '.png'), fullPage: true, animations: 'disabled' })
}

test('a confirmed switch is operable in both directions and supports keyboard input', async () => {
  await open()
  assert.equal(await page.locator('#network-toggle').getAttribute('aria-checked'), 'false')
  await page.locator('#network-toggle').click()
  await confirm('on')
  assert.equal(await page.locator('#network-toggle').getAttribute('aria-checked'), 'true')
  assert.equal(await page.locator('#network-toggle').isEnabled(), true)
  assert.equal(await page.locator('#network-toggle').getAttribute('aria-busy'), 'false')
  assert.equal(await cursor(), 'pointer')
  await page.waitForFunction(() => getComputedStyle(document.querySelector('.switch-track')).backgroundColor === 'rgb(40, 88, 216)'
    && new DOMMatrix(getComputedStyle(document.querySelector('.switch-thumb')).transform).m41 === 26)
  assert.equal(await page.locator('.switch-track').evaluate((node) => getComputedStyle(node).backgroundColor), 'rgb(40, 88, 216)')
  assert.equal(await page.locator('.switch-thumb').evaluate((node) => new DOMMatrix(getComputedStyle(node).transform).m41), 26)
  assert.match(await page.locator('#network-chip').innerText(), /已接管/)
  await screenshot('v2rayn-confirmed-switch-fixture')
  await page.locator('#network-toggle').focus()
  await page.keyboard.press('Space')
  await confirm('off')
  await page.waitForFunction(() => getComputedStyle(document.querySelector('.switch-track')).backgroundColor === 'rgb(196, 205, 216)'
    && new DOMMatrix(getComputedStyle(document.querySelector('.switch-thumb')).transform).m41 === 0)
  assert.equal(await page.locator('.switch-track').evaluate((node) => getComputedStyle(node).backgroundColor), 'rgb(196, 205, 216)')
  assert.equal(await page.locator('.switch-thumb').evaluate((node) => new DOMMatrix(getComputedStyle(node).transform).m41), 0)
  assert.deepEqual(fixture.posts.map((p) => p.action), ['/api/network_on', '/api/network_off'])
})

test('pending activation is explicit, blocks duplicates and never flips optimistically', async () => {
  let finish
  fixture.onNetwork = async (_action, response) => {
    fixture.status = status({ network_phase: 'starting', network_operation: 'starting', network_owner: fixture.app })
    await new Promise((resolve) => { finish = resolve })
    fixture.status = status({ network_active: true, network_phase: 'active', network_owner: fixture.app })
    json(response, fixture.status)
  }
  await open()
  await page.locator('#network-toggle').click()
  await confirm('pending')
  assert.equal(await page.locator('#network-toggle').getAttribute('aria-checked'), 'false')
  assert.equal(await page.locator('#network-toggle').getAttribute('aria-busy'), 'true')
  assert.equal(await page.locator('#network-toggle').isDisabled(), true)
  await page.locator('#network-toggle').dispatchEvent('click')
  assert.equal(fixture.posts.length, 1)
  finish()
  await confirm('on')
  assert.equal(await cursor(), 'pointer')
})

test('a delayed poll from before mutation cannot overwrite the confirmed new state', async () => {
  let held, release
  await open()
  const received = new Promise((resolve) => { held = resolve })
  fixture.onStatus = async (_request, response) => {
    fixture.onStatus = null
    const old = { ...fixture.status }
    held()
    await new Promise((resolve) => { release = resolve })
    json(response, old)
    return true
  }
  await page.clock.fastForward(4001)
  await received
  await page.locator('#network-toggle').click()
  await confirm('on')
  release()
  await pause(100)
  assert.equal(await page.locator('#network-toggle').getAttribute('data-state'), 'on')
  assert.equal(await page.locator('#network-toggle').getAttribute('aria-checked'), 'true')
})

test('failed activation returns to the backend-confirmed stopped state', async () => {
  fixture.onNetwork = async (_action, response) => {
    fixture.status = status({ network_phase: 'error', network_error: '测试节点未就绪，已恢复直连' })
    json(response, { error: '测试启用失败，已恢复直连' }, 409)
  }
  await open()
  await page.locator('#network-toggle').click()
  await page.waitForFunction(() => document.getElementById('toast').textContent.includes('测试启用失败'))
  await confirm('off')
  assert.equal(await page.locator('#network-toggle').isEnabled(), true)
  assert.equal(await cursor(), 'pointer')
  assert.match(await page.locator('#network-note').innerText(), /已恢复直连/)
})

test('a timed-out request uses fresh backend state, not an assumed failure', async () => {
  fixture.onNetwork = async () => {
    fixture.status = status({ network_active: true, network_owner: fixture.app, network_phase: 'active' })
    await new Promise(() => {})
  }
  await open()
  await page.locator('#network-toggle').click()
  await page.waitForFunction(() => document.getElementById('network-toggle').getAttribute('aria-busy') === 'true')
  await page.clock.fastForward(91000)
  await confirm('on')
  assert.equal(fixture.posts.length, 1)
  assert.equal(await cursor(), 'pointer')
})

test('unreachable status stays unknown, then read-only reconciliation restores the real state', async () => {
  fixture.onNetwork = async () => {
    fixture.failStatus = true
    fixture.status = status({ network_active: true, network_owner: fixture.app, network_phase: 'active' })
    await new Promise(() => {})
  }
  await open()
  await page.locator('#network-toggle').click()
  await page.clock.fastForward(91000)
  await confirm('unknown')
  assert.equal(await page.locator('#network-toggle').isDisabled(), true)
  assert.equal(await page.locator('#network-state').innerText(), '状态待确认')
  assert.notEqual(await cursor(), 'wait')
  fixture.failStatus = false
  await page.locator('#status-refresh').click()
  await confirm('on')
  assert.equal(fixture.posts.length, 1)
})

test('other-owner and incomplete recovery states cannot be presented as ordinary off', async () => {
  fixture.status = status({ network_owner: 'clash', network_phase: 'active' })
  await open('other')
  assert.equal(await page.locator('#network-toggle').isDisabled(), true)
  assert.match(await page.locator('#network-note').innerText(), /Clash Verge Rev/)
  assert.equal(fixture.posts.length, 0)
  fixture.status = status({ network_owner: fixture.app, network_phase: 'error', network_needs_recovery: true, network_cleanup_verified: false })
  await page.clock.fastForward(4001)
  await confirm('recovery')
  assert.equal(await page.locator('#network-state').innerText(), '待恢复')
  fixture.status = status()
  await page.locator('#status-refresh').click()
  await confirm('off')
})

test('reload reads an already-active backend and native icons are local images', async () => {
  fixture.status = status({ network_active: true, network_owner: fixture.app, network_phase: 'active' })
  await open('on')
  await page.reload()
  await confirm('on')
  assert.equal(await page.locator('.brand .app-mark').evaluate((node) => node.tagName), 'IMG')
  assert.equal(await page.locator('.brand .app-mark').evaluate((node) => node.naturalWidth > 0), true)
  assert.equal(await page.locator('link[rel=icon]').getAttribute('href'), '/assets/icon-64.png')
})

test('a delayed unauthorized poll from the old session cannot log out a new login', async () => {
  let held, release
  await open()
  const received = new Promise((resolve) => { held = resolve })
  fixture.onStatus = async (_request, response) => {
    fixture.onStatus = null
    held()
    await new Promise((resolve) => { release = resolve })
    json(response, { error: '旧会话已失效' }, 401)
    return true
  }
  await page.clock.fastForward(4001)
  await received
  await page.locator('#logout').click()
  await page.waitForFunction(() => !document.getElementById('login').hidden)
  await page.locator('#password').fill(fixture.password)
  await page.locator('#login-submit').click()
  await confirm('off')
  release()
  await pause(100)
  assert.equal(await page.locator('#workspace').isVisible(), true)
  assert.equal(await page.locator('#network-toggle').isEnabled(), true)
})

test('v2rayN accepts generic share links and does not claim confirmed native import', async () => {
  await open()
  await page.locator('#import-form').locator('xpath=..').locator('summary').click()
  assert.equal(await page.locator('#import-format option').count(), 1)
  assert.equal(await page.locator('#import-format').inputValue(), 'share-links')
  assert.match(await page.locator('#import-format').innerText(), /节点分享链接/)
  await page.locator('#import-content').fill('vmess://fixture-example\nvless://fixture-example')
  await page.locator('#import-submit').click()
  await page.waitForFunction(() => document.getElementById('toast').textContent.includes('请在原版窗口确认'))
  assert.equal(fixture.posts.at(-1).value.format, 'share-links')
  await page.locator('#import-content').fill('proxies: []')
  await page.locator('#import-submit').click()
  assert.match(await page.locator('#import-error').innerText(), /第 1 行/)
  assert.equal(fixture.posts.length, 1)
})

test('Clash exposes YAML only and rejects an obvious share URI before sending', async () => {
  fixture.app = 'clash'; fixture.status = status()
  await open()
  await page.locator('#import-form').locator('xpath=..').locator('summary').click()
  assert.equal(await page.locator('#import-format option').count(), 1)
  assert.equal(await page.locator('#import-format').inputValue(), 'clash')
  await page.locator('#import-content').fill('vmess://fixture-example')
  await page.locator('#import-submit').click()
  assert.match(await page.locator('#import-error').innerText(), /YAML/)
  assert.equal(fixture.posts.length, 0)
  await page.locator('#import-content').fill('proxies: []\nrules: [MATCH,DIRECT]')
  await page.locator('#import-submit').click()
  await page.waitForFunction(() => document.getElementById('toast').textContent.includes('导入并应用'))
  assert.equal(fixture.posts.at(-1).value.format, 'clash')
})

test('password validation preserves spaces and successful change clears fields and returns to login', async () => {
  await open()
  await page.locator('#access-settings summary').click()
  await page.locator('#current-password').fill(fixture.password)
  await page.locator('#new-password').fill('too-short')
  await page.locator('#confirm-password').fill('too-short')
  await page.locator('#password-submit').click()
  assert.match(await page.locator('#password-error').innerText(), /12–128/)
  assert.equal(fixture.posts.length, 0)
  const next = '  测试用的新访问密码 2026  '
  await page.locator('#new-password').fill(next)
  await page.locator('#confirm-password').fill(next + 'different')
  await page.locator('#password-submit').click()
  assert.match(await page.locator('#password-error').innerText(), /不一致/)
  await page.locator('#confirm-password').fill(next)
  await page.locator('#password-submit').click()
  await page.waitForFunction(() => !document.getElementById('login').hidden && document.getElementById('login-notice').textContent.includes('已更新'))
  assert.equal(fixture.password, next)
  assert.equal(await page.locator('#current-password').inputValue(), '')
  assert.equal(await page.locator('#new-password').inputValue(), '')
  assert.equal(await page.locator('#confirm-password').inputValue(), '')
  assert.equal((await page.locator('body').innerText()).includes(next), false)
  await page.locator('#password').fill(next)
  await page.locator('#login-submit').click()
  await confirm('off')
})

test('mobile controls and offline mode/password help remain readable without horizontal overflow', async () => {
  await page.setViewportSize({ width: 390, height: 844 })
  await open()
  assert.equal(await page.locator('.brand .app-mark').isVisible(), true)
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
  const size = await page.locator('#network-toggle').boundingBox()
  assert.ok(size.width >= 44 && size.height >= 44)
  await screenshot('mobile-controls-fixture')
  await page.goto(base + '/help')
  assert.match(await page.locator('body').innerText(), /V4 是路由规则版本/)
  assert.match(await page.locator('#access').innerText(), /private\/access.txt/)
  assert.match(await page.locator('#access').innerText(), /reset_portal_password.py/)
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
})
