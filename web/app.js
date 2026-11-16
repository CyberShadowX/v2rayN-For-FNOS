const $ = (id) => document.getElementById(id)
let session = null
let status = {}
let rfb = null
let busy = false
let reconnectTimer = null
let reconnectCount = 0
let pollTimer = null
let toastTimer = null
let previousUpdating = false

function title(value) {
  document.title = value || 'NAS 原生代理'
  document.querySelectorAll('[data-app-title]').forEach((node) => { node.textContent = value || 'NAS 原生代理' })
}

function toast(message, error = false) {
  clearTimeout(toastTimer)
  $('toast').textContent = message
  $('toast').classList.toggle('error', error)
  $('toast').hidden = false
  toastTimer = setTimeout(() => { $('toast').hidden = true }, error ? 9000 : 5000)
}

async function api(path, { method = 'GET', body, allowUnauthorized = false } = {}) {
  const headers = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method === 'POST' && session?.csrf) headers['X-CSRF-Token'] = session.csrf
  const response = await fetch(path, { method, headers, credentials: 'same-origin', cache: 'no-store',
    body: body === undefined ? undefined : JSON.stringify(body) })
  const data = await response.json().catch(() => ({}))
  if (response.status === 401 && !allowUnauthorized) {
    showLogin()
    throw new Error('登录已过期，请重新登录')
  }
  if (!response.ok && !(allowUnauthorized && response.status === 401)) {
    throw new Error(data.error || `操作未完成（${response.status}）`)
  }
  return data
}

function showLogin() {
  session = null
  clearInterval(pollTimer)
  clearTimeout(reconnectTimer)
  rfb?.disconnect()
  rfb = null
  $('workspace').hidden = true
  $('login').hidden = false
  $('password').value = ''
}

async function enterWorkspace() {
  session = await api('/api/session')
  title(session.title)
  $('login').hidden = true
  $('workspace').hidden = false
  $('password').value = ''
  await refreshStatus().catch((error) => toast(error.message, true))
  connectDesktop()
  clearInterval(pollTimer)
  pollTimer = setInterval(() => { refreshStatus().catch(() => {}) }, 4000)
}

function updateButtons() {
  const locked = busy || Boolean(status.updating)
  document.querySelectorAll('[data-mutation]').forEach((button) => { button.disabled = locked })
  if (!locked) {
    $('network-on').disabled = Boolean(status.network_active)
    $('network-off').disabled = !status.network_active
  }
}

function formatTime(value) {
  if (value && typeof value === 'object') {
    const when = value.finished_at ? formatTime(value.finished_at) : ''
    return `${value.success ? '更新成功' : '更新未完成'}${when ? ' · ' + when : ''}`
  }
  if (!value) return '暂无'
  const date = new Date(typeof value === 'number' && value < 1e12 ? value * 1000 : value)
  return Number.isNaN(date.valueOf()) ? String(value).slice(0, 70) : date.toLocaleString('zh-CN', { hour12: false })
}

async function refreshStatus() {
  const next = await api('/api/status')
  status = next
  $('version-chip').textContent = next.version ? `上游 ${next.version}` : '版本待确认'
  $('network-chip').textContent = next.network_active ? '本机 + Docker 已接管' : '网络接管未启用'
  $('network-chip').className = `chip${next.network_active ? ' active' : ''}`
  $('network-state').textContent = next.network_active ? '已接管' : '未接管'
  $('network-state').className = `state-label${next.network_active ? ' active' : ''}`
  $('gui-state').textContent = next.gui_running ? '正在运行' : '未运行'
  $('last-update').textContent = formatTime(next.last_update)
  $('supervisor-message').textContent = next.message || ''
  const otherOwner = next.network_owner && next.network_owner !== session?.app
  $('network-note').textContent = otherOwner
    ? `当前由 ${next.network_owner === 'v2rayn' ? 'v2rayN' : 'Clash Verge Rev'} 接管，请先在该应用中关闭后再切换。`
    : '局域网和远程管理连接按系统保护规则直连。'
  if (next.updating) {
    $('update-state').textContent = '正在更新…'
    $('update-note').textContent = '正在后台更新整套客户端，完成后会恢复图形桌面。'
  } else if (previousUpdating) {
    $('update-state').textContent = '更新流程结束'
    $('update-note').textContent = next.message || '图形桌面正在恢复连接。'
    reconnectCount = 0
    connectDesktop()
  }
  previousUpdating = Boolean(next.updating)
  updateButtons()
}

function desktopState(message, kind = 'waiting') {
  $('desktop-status').textContent = message
  $('desktop-dot').className = `status-dot${kind === 'active' ? ' active' : kind === 'error' ? ' error' : ''}`
}

async function connectDesktop() {
  if (!session) return
  clearTimeout(reconnectTimer)
  const previous = rfb
  rfb = null
  previous?.disconnect()
  $('desktop-placeholder').hidden = false
  desktopState('正在连接图形桌面')
  try {
    const { default: RFB } = await import('/novnc/core/rfb.js')
    if (!session) return
    const url = new URL('/vnc', location.href)
    url.protocol = 'wss:'
    const client = new RFB($('desktop'), url.href, { credentials: { password: session.vnc_password } })
    rfb = client
    client.scaleViewport = true
    client.resizeSession = false
    client.showDotCursor = true
    client.background = '#172231'
    client.addEventListener('connect', () => {
      if (rfb !== client) return
      reconnectCount = 0
      $('desktop-placeholder').hidden = true
      desktopState('图形桌面已连接', 'active')
    })
    client.addEventListener('credentialsrequired', () => {
      client.sendCredentials({ password: session?.vnc_password })
    })
    client.addEventListener('disconnect', () => {
      if (rfb !== client || !session) return
      $('desktop-placeholder').hidden = false
      desktopState(status.updating ? '客户端正在更新，完成后自动重连' : '图形桌面已断开，正在重连', 'waiting')
      if (++reconnectCount <= 15) reconnectTimer = setTimeout(connectDesktop, 3000)
      else desktopState('桌面未就绪，可重新连接或重启客户端', 'error')
    })
    client.addEventListener('securityfailure', () => {
      if (rfb === client) desktopState('桌面认证失败，请重新登录后重试', 'error')
    })
  } catch (error) {
    desktopState('图形桌面暂时不可用，可重新连接或重启客户端', 'error')
    if (++reconnectCount <= 5) reconnectTimer = setTimeout(connectDesktop, 4000)
  }
}

async function runAction(action, body, success) {
  if (busy || status.updating) return
  busy = true
  updateButtons()
  try {
    const result = await api(`/api/${action}`, { method: 'POST', body })
    if (action === 'check_update') {
      const coreOnly = result.network_available && result.current === result.latest
      $('update-state').textContent = coreOnly ? '网络组件可更新' : result.available ? `可更新至 ${result.latest}` : '已是最新稳定版'
      $('update-note').textContent = coreOnly ? '点击一键更新可同步新版网络组件，保留客户端与节点设置。' : result.available ? `当前 ${result.current || status.version}，点击一键更新完成升级。` : '已检查客户端与网络组件的官方稳定版。'
    } else if (action === 'import') {
      $('import-content').value = ''
    }
    toast(result.message || (result.updating ? '更新已开始，完成后桌面会自动重连' : success) || '操作已完成')
    await refreshStatus()
    if (['restart', 'rollback', 'update'].includes(action) && !result.updating) {
      reconnectCount = 0
      setTimeout(connectDesktop, 1500)
    }
  } catch (error) { toast(error.message, true) }
  finally { busy = false; updateButtons() }
}

$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault()
  $('login-submit').disabled = true
  $('login-error').textContent = ''
  try {
    const result = await api('/api/login', { method: 'POST', body: { password: $('password').value }, allowUnauthorized: true })
    if (!result.authenticated) throw new Error(result.error || '访问密码不正确')
    session = result
    await enterWorkspace()
  } catch (error) { $('login-error').textContent = error.message }
  finally { $('login-submit').disabled = false }
})
$('logout').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }) } catch (error) { toast(error.message, true) }
  showLogin()
})
$('reconnect').addEventListener('click', () => { reconnectCount = 0; connectDesktop() })
$('fullscreen').addEventListener('click', () => {
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {})
  else $('desktop').requestFullscreen().catch(() => toast('当前浏览器不支持全屏显示', true))
})
$('check-update').addEventListener('click', () => runAction('check_update', undefined, '已检查上游稳定版'))
$('update').addEventListener('click', () => runAction('update', undefined, '更新流程已完成'))
$('network-on').addEventListener('click', () => runAction('network_on', undefined, '已启用 NAS 网络接管'))
$('network-off').addEventListener('click', () => runAction('network_off', undefined, '已关闭 NAS 网络接管'))
$('restart').addEventListener('click', () => runAction('restart', undefined, '客户端已重启'))
$('rollback').addEventListener('click', () => runAction('rollback', undefined, '已切回保留的上一版本'))
$('import-form').addEventListener('submit', (event) => {
  event.preventDefault()
  const content = $('import-content').value.trim()
  if (!content) return toast('请先填写节点链接或 YAML 配置', true)
  if (new TextEncoder().encode(content).length > 1024 * 1024) return toast('导入内容超过 1 MiB', true)
  runAction('import', { content, format: $('import-format').value }, '节点配置已导入')
})

api('/api/session', { allowUnauthorized: true }).then(async (result) => {
  title(result.title)
  if (result.authenticated) await enterWorkspace()
}).catch(() => { $('login-error').textContent = '无法连接应用，请刷新页面重试' })
