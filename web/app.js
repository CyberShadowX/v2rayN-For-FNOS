const $ = (id) => document.getElementById(id)
const READ_TIMEOUT = 15000
const NETWORK_TIMEOUT = 90000
const ACTION_TIMEOUT = 1200000
let session = null
let identity = null
let status = {}
let statusFresh = false
let statusEpoch = 0
let statusSequence = 0
let appliedSequence = 0
let statusReaders = 0
let busyAction = ''
let rfb = null
let desktopEpoch = 0
let reconnectTimer = null
let reconnectCount = 0
let pollTimer = null
let toastTimer = null
let previousUpdating = false

function setIdentity(value) {
  if (!['v2rayn', 'clash'].includes(value?.app)) return
  identity = { app: value.app, title: value.title || (value.app === 'v2rayn' ? 'v2rayN' : 'Clash Verge Rev') }
  document.title = identity.title
  document.querySelectorAll('[data-app-title]').forEach((node) => { node.textContent = identity.title })
  const v2rayn = identity.app === 'v2rayn'
  const option = document.createElement('option')
  option.value = v2rayn ? 'share-links' : 'clash'
  option.textContent = v2rayn ? '节点分享链接（每行一条）' : 'Clash / Mihomo YAML'
  $('import-format').replaceChildren(option)
  $('import-format-note').textContent = v2rayn
    ? '支持 VMess、VLESS、Trojan、Shadowsocks 等客户端可识别的分享链接；具体以原版客户端为准。'
    : '导入含 proxies 列表的 Clash / Mihomo 配置，可包含内核支持的多种节点协议。'
  $('import-content').placeholder = v2rayn ? '在此粘贴节点分享链接，每行一条' : '在此粘贴 Clash / Mihomo YAML 配置'
  $('import-submit').textContent = v2rayn ? '发送至客户端' : '导入并应用'
}

function toast(message, error = false) {
  clearTimeout(toastTimer)
  $('toast').textContent = message
  $('toast').classList.toggle('error', error)
  $('toast').hidden = false
  toastTimer = setTimeout(() => { $('toast').hidden = true }, error ? 9000 : 5000)
}

async function api(path, { method = 'GET', body, allowUnauthorized = false, timeout = READ_TIMEOUT } = {}) {
  const requestSession = session
  const headers = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method === 'POST' && session?.csrf) headers['X-CSRF-Token'] = session.csrf
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeout)
  let response, data
  try {
    response = await fetch(path, { method, headers, credentials: 'same-origin', cache: 'no-store',
      signal: controller.signal, body: body === undefined ? undefined : JSON.stringify(body) })
    data = await response.json()
  } catch (cause) {
    const error = new Error(controller.signal.aborted
      ? '请求未及时返回，结果需要重新确认'
      : '暂时无法读取应用响应，请重新确认状态')
    error.uncertain = true
    throw error
  } finally { clearTimeout(timer) }
  if (response.status === 401 && !allowUnauthorized) {
    // A late response for an old session must not log out a newly signed-in one.
    if (session === requestSession) showLogin('登录已过期，请重新登录')
    const error = new Error('登录已过期，请重新登录')
    error.authExpired = true
    throw error
  }
  if (!response.ok && !(allowUnauthorized && response.status === 401)) {
    throw new Error(data.error || `操作未完成（${response.status}）`)
  }
  return data
}

function showLogin(notice = '') {
  session = null
  status = {}
  statusFresh = false
  busyAction = ''
  statusEpoch++
  desktopEpoch++
  previousUpdating = false
  clearInterval(pollTimer)
  clearTimeout(reconnectTimer)
  rfb?.disconnect()
  rfb = null
  $('workspace').hidden = true
  $('login').hidden = false
  $('password').value = ''
  $('import-content').value = ''
  $('password-form').reset()
  $('password-error').textContent = ''
  $('login-error').textContent = ''
  $('login-notice').textContent = notice
  updateControls()
}

async function enterWorkspace() {
  session = await api('/api/session')
  setIdentity(session)
  status = {}
  statusFresh = false
  statusEpoch++
  $('login').hidden = true
  $('workspace').hidden = false
  $('password').value = ''
  $('login-notice').textContent = ''
  renderStatus()
  await refreshStatus().catch((error) => { if (!error.authExpired) toast(error.message, true) })
  if (!session) return
  connectDesktop()
  clearInterval(pollTimer)
  pollTimer = setInterval(() => { refreshStatus().catch(() => {}) }, 4000)
}

function networkView() {
  const lastChecked = status.network_active === true
  const otherOwner = status.network_owner && status.network_owner !== session?.app
  const phase = status.network_operation || status.network_phase || (lastChecked ? 'active' : 'stopped')
  const pending = busyAction === 'network_on' ? 'starting' : busyAction === 'network_off' ? 'stopping'
    : ['starting', 'stopping'].includes(phase) ? phase : ''
  if (!statusFresh) return { kind: 'unknown', label: '状态待确认', hint: '重新读取后才能操作', checked: lastChecked,
    note: '当前未能确认网络接管状态；正在查询，尚不能判断操作是否已完成。', blocked: true, pending: Boolean(pending) }
  if (otherOwner) {
    const owner = status.network_owner === 'v2rayn' ? 'v2rayN' : 'Clash Verge Rev'
    return { kind: 'other', label: '其他客户端接管', hint: `当前由 ${owner} 接管`, checked: false,
      note: `请先在 ${owner} 中关闭 NAS 网络，再切换到本应用。`, blocked: true, pending: false }
  }
  if (pending) return { kind: 'pending', label: pending === 'starting' ? '正在启用…' : '正在关闭…',
    hint: '请等待后台确认，期间不能重复切换', checked: lastChecked,
    note: '操作完成后会按后台实际状态更新开关。局域网与远程管理连接保留保护规则。', blocked: true, pending: true }
  if (status.network_needs_recovery || (!lastChecked && status.network_cleanup_verified === false)) {
    return { kind: 'recovery', label: '待恢复', hint: '网络收尾尚未确认', checked: lastChecked,
      note: '请稍后重新确认状态；如持续未恢复，查看恢复与维护及使用说明。', blocked: true, pending: false }
  }
  if (!['active', 'stopped', 'error', 'idle', 'none'].includes(phase) || (phase === 'active' && !lastChecked)) {
    return { kind: 'unknown', label: '状态待确认', hint: '后台状态尚未确定', checked: lastChecked,
      note: '请重新读取实际状态后再操作。', blocked: true, pending: false }
  }
  return { kind: lastChecked ? 'on' : 'off', label: lastChecked ? '已启用' : '未启用',
    hint: lastChecked ? '本应用正在接管 NAS 与 Docker' : '点击右侧开关启用接管', checked: lastChecked,
    note: status.network_error || '局域网和远程管理连接按系统保护规则直连。', blocked: false, pending: false }
}

function updateControls() {
  const locked = Boolean(busyAction || status.updating)
  document.querySelectorAll('[data-mutation]').forEach((button) => { button.disabled = locked || !session })
  const view = networkView()
  $('network-toggle').disabled = locked || view.blocked || !session
  $('network-toggle').setAttribute('aria-disabled', String($('network-toggle').disabled))
  $('status-refresh').disabled = statusReaders > 0 || busyAction === 'password' || !session
  $('logout').disabled = Boolean(busyAction)
  $('password-submit').textContent = busyAction === 'password' ? '正在修改…' : '修改访问密码'
  for (const input of $('password-form').querySelectorAll('input')) input.disabled = busyAction === 'password'
  $('import-format').disabled = busyAction === 'import' || !identity
  $('import-content').disabled = busyAction === 'import'
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

function renderStatus() {
  const view = networkView()
  $('version-chip').textContent = status.version ? `上游 ${status.version}` : '版本待确认'
  $('network-chip').textContent = view.kind === 'on' ? '本机 + Docker 已接管'
    : view.kind === 'off' ? '网络接管未启用' : view.kind === 'other' ? view.hint : view.label
  $('network-chip').className = `chip${view.kind === 'on' ? ' active' : ['unknown', 'pending', 'recovery'].includes(view.kind) ? ' warn' : ''}`
  $('network-state').textContent = view.label
  $('network-state').className = `state-label${view.kind === 'on' ? ' active' : ['unknown', 'pending', 'recovery'].includes(view.kind) ? ' warn' : ''}`
  $('network-control-hint').textContent = view.hint
  $('network-note').textContent = view.note
  const toggle = $('network-toggle')
  toggle.classList.toggle('is-on', view.checked)
  toggle.classList.toggle('is-unknown', ['unknown', 'recovery'].includes(view.kind))
  toggle.setAttribute('aria-checked', String(view.checked))
  toggle.setAttribute('aria-busy', String(view.pending))
  toggle.setAttribute('aria-label', `网络接管，${view.label}`)
  toggle.dataset.state = view.kind
  $('status-refresh').hidden = !['unknown', 'recovery'].includes(view.kind)
  $('gui-state').textContent = statusFresh ? (status.gui_running ? '正在运行' : '未运行') : '待确认'
  $('last-update').textContent = formatTime(status.last_update)
  $('supervisor-message').textContent = statusFresh ? (status.message || '') : '管理状态暂未确认，图形桌面可独立连接。'
  updateControls()
}

async function refreshStatus() {
  if (!session) return
  const epoch = statusEpoch
  const sequence = ++statusSequence
  statusReaders++
  updateControls()
  try {
    const next = await api('/api/status')
    if (!session || epoch !== statusEpoch || sequence < appliedSequence) return
    if (typeof next.network_active !== 'boolean' || (next.app && next.app !== session.app)
        || (next.network_owner != null && !['v2rayn', 'clash'].includes(next.network_owner))) {
      throw new Error('应用返回的网络状态尚不能确认')
    }
    appliedSequence = sequence
    status = next
    statusFresh = true
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
    renderStatus()
    return next
  } catch (error) {
    if (session && epoch === statusEpoch && sequence >= appliedSequence) {
      appliedSequence = sequence
      statusFresh = false
      renderStatus()
    }
    throw error
  } finally { statusReaders--; updateControls() }
}

function desktopState(message, kind = 'waiting') {
  $('desktop-status').textContent = message
  $('desktop-dot').className = `status-dot${kind === 'active' ? ' active' : kind === 'error' ? ' error' : ''}`
}

async function connectDesktop() {
  if (!session) return
  const epoch = ++desktopEpoch
  clearTimeout(reconnectTimer)
  const previous = rfb
  rfb = null
  previous?.disconnect()
  $('desktop-placeholder').hidden = false
  desktopState('正在连接图形桌面')
  try {
    const { default: RFB } = await import('/novnc/core/rfb.js')
    if (!session || epoch !== desktopEpoch) return
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
    client.addEventListener('credentialsrequired', () => { client.sendCredentials({ password: session?.vnc_password }) })
    client.addEventListener('disconnect', () => {
      if (rfb !== client || !session) return
      $('desktop-placeholder').hidden = false
      desktopState(status.updating ? '客户端正在更新，完成后自动重连' : '图形桌面已断开，正在重连')
      if (++reconnectCount <= 15) reconnectTimer = setTimeout(connectDesktop, 3000)
      else desktopState('桌面未就绪，可重新连接或重启客户端', 'error')
    })
    client.addEventListener('securityfailure', () => {
      if (rfb === client) desktopState('桌面认证失败，请重新登录后重试', 'error')
    })
  } catch (error) {
    if (!session || epoch !== desktopEpoch) return
    desktopState('图形桌面暂时不可用，可重新连接或重启客户端', 'error')
    if (++reconnectCount <= 5) reconnectTimer = setTimeout(connectDesktop, 4000)
  }
}

async function runAction(action, body, success) {
  if (!session || busyAction || status.updating) return
  const networkAction = ['network_on', 'network_off'].includes(action)
  if (networkAction && networkView().blocked) return
  const actor = session
  busyAction = action
  statusEpoch++
  renderStatus()
  try {
    const result = await api(`/api/${action}`, { method: 'POST', body,
      timeout: networkAction ? NETWORK_TIMEOUT : action === 'check_update' ? 100000 : ACTION_TIMEOUT })
    if (session !== actor) return
    // Responses from polls issued before completion must not overwrite it.
    statusEpoch++
    if (networkAction) {
      statusFresh = typeof result.network_active === 'boolean'
      if (statusFresh) status = { ...status, ...result }
    }
    if (action === 'check_update') {
      const coreOnly = result.network_available && result.current === result.latest
      $('update-state').textContent = coreOnly ? '网络组件可更新' : result.available ? `可更新至 ${result.latest}` : '已是最新稳定版'
      $('update-note').textContent = coreOnly ? '点击一键更新可同步新版网络组件，保留客户端与节点设置。'
        : result.available ? `当前 ${result.current || status.version}，点击一键更新完成升级。` : '已检查客户端与网络组件的官方稳定版。'
    } else if (action === 'import') { $('import-content').value = '' }
    toast(result.message || (result.updating ? '更新已开始，完成后桌面会自动重连' : success) || '操作已返回')
    await refreshStatus().catch((error) => { if (!error.authExpired) toast('操作已返回，但当前状态暂未确认，请重新读取。', true) })
    if (session && ['restart', 'rollback', 'update'].includes(action) && !result.updating) {
      reconnectCount = 0
      setTimeout(connectDesktop, 1500)
    }
  } catch (error) {
    statusEpoch++
    if (session !== actor) return
    if (networkAction) { statusFresh = false; renderStatus() }
    toast(error.message, true)
    await refreshStatus().catch(() => {})
  } finally {
    if (session === actor || !session) { busyAction = ''; renderStatus() }
  }
}

$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault()
  $('login-submit').disabled = true
  $('login-error').textContent = ''
  $('login-notice').textContent = ''
  try {
    const result = await api('/api/login', { method: 'POST', body: { password: $('password').value }, allowUnauthorized: true })
    if (!result.authenticated) throw new Error(result.error || '访问密码不正确')
    session = result
    await enterWorkspace()
  } catch (error) { $('login-error').textContent = error.message }
  finally { $('login-submit').disabled = false }
})
$('logout').addEventListener('click', async () => {
  if (busyAction) return
  try { await api('/api/logout', { method: 'POST' }) } catch (error) { toast(error.message, true) }
  showLogin()
})
$('reconnect').addEventListener('click', () => { reconnectCount = 0; connectDesktop() })
$('fullscreen').addEventListener('click', () => {
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {})
  else $('desktop').requestFullscreen().catch(() => toast('当前浏览器不支持全屏显示', true))
})
$('status-refresh').addEventListener('click', () => { refreshStatus().catch((error) => toast(error.message, true)) })
$('check-update').addEventListener('click', () => runAction('check_update', undefined, '已检查上游稳定版'))
$('update').addEventListener('click', () => runAction('update', undefined, '更新流程已完成'))
$('network-toggle').addEventListener('click', () => {
  const view = networkView()
  if (view.blocked) return
  runAction(view.checked ? 'network_off' : 'network_on', undefined, view.checked ? '已关闭 NAS 网络接管' : '已启用 NAS 网络接管')
})
$('restart').addEventListener('click', () => runAction('restart', undefined, '客户端已重启'))
$('rollback').addEventListener('click', () => runAction('rollback', undefined, '已切回保留的上一版本'))
$('import-form').addEventListener('submit', (event) => {
  event.preventDefault()
  $('import-error').textContent = ''
  const content = $('import-content').value.trim()
  let message = ''
  if (!content) message = '请先填写节点分享链接或 YAML 配置'
  else if (new TextEncoder().encode(content).length > 1024 * 1024) message = '导入内容超过 1 MiB'
  else if (identity?.app === 'v2rayn') {
    const badLine = content.split(/\r?\n/).findIndex((line) => line.trim() && !/^[a-z][a-z\d+.-]*:\/\//i.test(line.trim()))
    if (badLine >= 0) message = `第 ${badLine + 1} 行不是节点分享链接，请每行填写一条完整链接`
  } else if (/^[a-z][a-z\d+.-]*:\/\//i.test(content)) message = '此处需要 Clash / Mihomo YAML 配置，不能直接填写节点分享链接'
  if (message) { $('import-error').textContent = message; return }
  runAction('import', { content, format: identity?.app === 'v2rayn' ? 'share-links' : 'clash' },
    identity?.app === 'v2rayn' ? '已发送至 v2rayN，请在原版窗口确认导入结果' : '配置已导入并应用')
})
$('password-form').addEventListener('submit', async (event) => {
  event.preventDefault()
  if (!session || busyAction || status.updating) return
  $('password-error').textContent = ''
  const current = $('current-password').value
  const next = $('new-password').value
  const confirmation = $('confirm-password').value
  let error = ''
  if (!current) error = '请填写当前访问密码'
  else if (Array.from(next).length < 12 || Array.from(next).length > 128 || new TextEncoder().encode(next).length > 512) error = '新密码需要 12–128 个字符，且不超过 512 UTF-8 字节'
  else if (/[\u0000-\u001f\u007f-\u009f]/u.test(next)) error = '新密码不能包含控制字符'
  else if (next !== confirmation) error = '两次新密码不一致'
  else if (next === current) error = '新密码不能与当前密码相同'
  if (error) { $('password-error').textContent = error; return }
  const actor = session
  busyAction = 'password'
  statusEpoch++
  updateControls()
  try {
    const result = await api('/api/password', { method: 'POST', body: { current_password: current, new_password: next, confirm_password: confirmation }, timeout: 30000 })
    if (session && session !== actor) return
    if (!result.ok || !result.reauthenticate) throw new Error('密码修改结果未确认，请重新登录确认')
    showLogin('访问密码已更新，请使用新密码登录。')
  } catch (cause) {
    if (session && session !== actor) return
    $('current-password').value = ''
    if (cause.uncertain) {
      try { await api('/api/logout', { method: 'POST', timeout: 3000, allowUnauthorized: true }) } catch (_) {}
      showLogin('修改请求未返回，请先用新密码尝试登录；如未生效，再使用原密码或由 NAS 管理员恢复。')
    } else if (session) { $('password-error').textContent = cause.message }
  } finally {
    if (session === actor || !session) { busyAction = ''; updateControls() }
  }
})

api('/api/session', { allowUnauthorized: true }).then(async (result) => {
  setIdentity(result)
  if (result.authenticated) await enterWorkspace()
  else updateControls()
}).catch(() => { $('login-error').textContent = '无法连接应用，请刷新页面重试' })
