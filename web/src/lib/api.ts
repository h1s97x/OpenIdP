// API client 封装：统一处理会话、CSRF 刷新与响应解包。
import type {
  AdminAuditSettingsPayload,
  AdminCaptchaPayload,
  AdminSmsPayload,
  AdminCreateUserPayload,
  AdminDataCleanupPayload,
  AdminLocationPayload,
  AdminMailPayload,
  AdminMailTestPayload,
  AdminOAuthClientPayload,
  AdminOAuthProviderPayload,
  AdminProxyPayload,
  AdminOAuthScopePayload,
  AdminSecurityPolicyPayload,
  AdminSitePatchPayload,
  AdminStoragePayload,
  AdminUpdateUserPayload,
  CaptchaPayload,
  NotificationPrefsPayload,
  PasswordResetPayload,
  ProfilePatchPayload,
  SetupPayload,
  SettingsBackupGroup,
  SignupPayload,
  WebAuthnCredential,
} from './api-types'
const API = '/api/v1'
const CSRF_HEADER = 'X-OpenIdP-CSRF'
const REQUEST_ID_HEADER = 'X-Request-ID'

// 免 CSRF 的端点
const CSRF_FREE = new Set([
  `${API}/setup/status`,
  `${API}/setup`,
  `${API}/session/login`,
  `${API}/session/email-code/request`,
  `${API}/session/email-code/verify`,
  `${API}/session/passkey/begin`,
  `${API}/session/passkey/finish`,
  `${API}/session/mfa/verify`,
  `${API}/signup/email-code/request`,
  `${API}/password-reset/request`,
  `${API}/password-reset/confirm`,
  `${API}/signup`,
  `${API}/me/email/verify`,
  `${API}/site`,
])

export class ApiError extends Error {
  status: number
  code: string
  requestId?: string
  fields?: Record<string, string>
  constructor(message: string, opts: { status: number; code: string; requestId?: string; fields?: Record<string, string> }) {
    super(message)
    this.name = 'ApiError'
    this.status = opts.status
    this.code = opts.code
    this.requestId = opts.requestId
    this.fields = opts.fields
  }
}

let csrfToken: string | null = null
const sessionListeners = new Set<() => void>()

export function setCsrf(t: string) { csrfToken = t }
export function getCsrf() { return csrfToken }

// refreshCsrfToken re-fetches a fresh CSRF token from the session endpoint.
// Called when the server rejects a request with csrf.invalid (e.g. the server
// restarted and the in-memory token store was cleared).
let refreshing: Promise<string | null> | null = null
export async function refreshCsrfToken(): Promise<string | null> {
  if (refreshing) return refreshing
  refreshing = (async () => {
    try {
      const res: { data?: { csrfToken?: string } } = await fetch(`${API}/session`, { credentials: 'include' }).then((r) => r.json())
      const tok = res?.data?.csrfToken
      if (tok) setCsrf(tok)
      return tok ?? null
    } catch {
      return null
    } finally {
      refreshing = null
    }
  })()
  return refreshing
}

export function onUnauthorized(fn: () => void) {
  sessionListeners.add(fn)
  return () => sessionListeners.delete(fn)
}

function notifyUnauthorized() {
  csrfToken = null
  sessionListeners.forEach((fn) => fn())
}

type ApiOptions = Omit<RequestInit, 'body'> & { body?: unknown; _retried?: boolean }

// parseJsonSafe 读取 JSON 响应体；不是 JSON（网关错误页等）时返回 null。
async function parseJsonSafe(res: Response): Promise<any> {
  return res.json().catch(() => null)
}

// errorFromResponse 把失败响应转成 ApiError，字段与语义同 request()，
// 供不走 JSON 解包路径的接口（如备份 ZIP）复用。
function errorFromResponse(res: Response, data: any): ApiError {
  const requestId = res.headers.get(REQUEST_ID_HEADER) ?? undefined
  const message = data?.message ?? data?.error_description ?? data?.error ?? 'Request failed'
  const code = data?.code ?? data?.error ?? (res.status === 401 ? 'session.unauthenticated' : 'request.failed')
  if (res.status === 401 && code === 'session.unauthenticated') {
    notifyUnauthorized()
  }
  return new ApiError(message, { status: res.status, code, requestId, fields: data?.fields })
}

// sendBackupZip 以 application/zip 上传备份归档并解包 JSON 响应。
// 备份的上传类端点（解析 / 恢复）共用这一条链路：显式 Content-Type（浏览器对 .zip
// 可能报 x-zip-compressed，写死才与后端中间件的大小上限判定一致）、CSRF 头，
// 以及令牌失效后的刷新重试（服务重启会清空内存令牌）。
async function sendBackupZip<T>(path: string, archive: Blob): Promise<T> {
  const send = () => {
    const headers = new Headers({ 'Content-Type': 'application/zip', Accept: 'application/json' })
    if (csrfToken) headers.set(CSRF_HEADER, csrfToken)
    return fetch(path, { method: 'POST', credentials: 'include', headers, body: archive })
  }
  let res = await send()
  let data = await parseJsonSafe(res)
  if (!res.ok && (data?.code === 'csrf.invalid' || data?.code === 'csrf.missing')) {
    if (await refreshCsrfToken()) {
      res = await send()
      data = await parseJsonSafe(res)
    }
  }
  if (!res.ok) {
    throw errorFromResponse(res, data)
  }
  return (data && 'data' in data ? data.data : data) as T
}

async function request<T = unknown>(path: string, options: ApiOptions = {}): Promise<T> {
  const method = (options.method ?? 'GET').toUpperCase()
  const headers = new Headers(options.headers)
  headers.set('Accept', 'application/json')

  const needsCsrf = !['GET', 'HEAD', 'OPTIONS'].includes(method) && !CSRF_FREE.has(path)
  if (needsCsrf) {
    if (!csrfToken) {
      throw new ApiError('CSRF token is missing', { status: 0, code: 'csrf.missing' })
    }
    headers.set(CSRF_HEADER, csrfToken)
  }

  let body: BodyInit | undefined = options.body as BodyInit
  if (body && typeof body === 'object' && !(body instanceof FormData) && !(body instanceof URLSearchParams) && !(body instanceof Blob) && !(body instanceof ArrayBuffer)) {
    body = JSON.stringify(body)
    headers.set('Content-Type', 'application/json')
  }

  let res: Response
  try {
    // credentials: 'include' 而非 'same-origin'：
    // 前后端分离（跨源）部署时，'same-origin' 会让浏览器在跨源请求上完全不发送
    // 会话 Cookie，表现为「接口能调通但永远是未登录」。同源场景下 include 行为一致。
    res = await fetch(path, { ...options, method, headers, body, credentials: 'include' })
  } catch {
    throw new ApiError('Network unavailable', { status: 0, code: 'network.unavailable' })
  }

  const requestId = res.headers.get(REQUEST_ID_HEADER) ?? undefined
  // 边界处唯一保留的 any：响应体形状由后端 envelope 决定，
  // 解包后经 request<T> 的断言交给调用方类型。
  // 解析失败时：响应本身是错误状态则抛出，否则视为空体（204 等）。
  const data: any = await res.json().catch(() => {
    if (!res.ok) {
      throw new ApiError('Malformed JSON response', { status: res.status, code: 'response.invalid_json', requestId })
    }
    return null
  })

  if (!res.ok) {
    const errMsg = data?.message ?? data?.error_description ?? data?.error ?? 'Request failed'
    const code = data?.code ?? data?.error ?? (res.status === 401 ? 'session.unauthenticated' : 'request.failed')
    if (res.status === 401 && code === 'session.unauthenticated') {
      notifyUnauthorized()
    }
    // CSRF token 失效（服务重启后内存 token 丢失、或 token 过期）：自动刷新后重试一次
    if ((code === 'csrf.invalid' || code === 'csrf.missing') && !options._retried) {
      const fresh = await refreshCsrfToken()
      if (fresh) {
        return request<T>(path, { ...options, _retried: true, headers: new Headers({ ...Object.fromEntries(headers.entries()), [CSRF_HEADER]: fresh }) })
      }
    }
    throw new ApiError(errMsg, { status: res.status, code, requestId, fields: data?.fields })
  }

  return (data && 'data' in data ? data.data : data) as T
}

export const api = {
  // ---- 首次部署初始化（未初始化时公开可用）----
  setupStatus: <T = unknown>() => request<T>(`${API}/setup/status`),
  setup: <T = unknown>(body: SetupPayload) => request<T>(`${API}/setup`, { method: 'POST', body }),

  // captcha 为统一负载 { turnstile?: string, captcha?: GeeTestProof }，嵌套在 captcha 字段提交。
  login: <T = unknown>(login: string, password: string, returnUrl?: string, captcha?: CaptchaPayload) =>
    request<T>(`${API}/session/login`, { method: 'POST', body: { login, password, ...(returnUrl ? { returnUrl } : {}), ...(captcha ? { captcha } : {}) } }),
  getSession: <T = unknown>() => request<T>(`${API}/session`),
  logout: <T = unknown>() => request<T>(`${API}/session`, { method: 'DELETE' }),
  loginPolicy: <T = unknown>(returnUrl?: string) => request<T>(`${API}/login-policy${returnUrl ? `?returnUrl=${encodeURIComponent(returnUrl)}` : ''}`),
  loginProviders: <T = unknown>(returnUrl?: string) => request<T>(`${API}/login/providers${returnUrl ? `?returnUrl=${encodeURIComponent(returnUrl)}` : ''}`),
  capabilities: <T = unknown>() => request<T>(`${API}/capabilities`),
  // 公开站点信息（品牌 + 页脚备案），未登录页面也可读取
  siteInfo: <T = unknown>() => request<T>(`${API}/site`),

  // OAuth 授权确认（consent）页
  consentInfo: <T = unknown>(consentRequest: string) => request<T>(`${API}/oauth/consent?request=${encodeURIComponent(consentRequest)}`),
  consentAction: (consentRequest: string, action: 'allow' | 'deny') =>
    request(`${API}/oauth/consent`, { method: 'POST', body: { request: consentRequest, action } }),

  // email code (登录/注册/找回密码)
  emailCodeRequest: (email: string, captcha?: CaptchaPayload) =>
    request(`${API}/session/email-code/request`, { method: 'POST', body: { email, ...(captcha ? { captcha } : {}) } }),
  emailCodeVerify: <T = unknown>(email: string, code: string, captcha?: CaptchaPayload) =>
    request<T>(`${API}/session/email-code/verify`, { method: 'POST', body: { email, code, ...(captcha ? { captcha } : {}) } }),
  signupEmailCodeRequest: (email: string, captcha?: CaptchaPayload) =>
    request(`${API}/signup/email-code/request`, { method: 'POST', body: { email, ...(captcha ? { captcha } : {}) } }),
  signup: <T = unknown>(body: SignupPayload) => request<T>(`${API}/signup`, { method: 'POST', body }),
  passwordResetRequest: (email: string, captcha?: CaptchaPayload) =>
    request(`${API}/password-reset/request`, { method: 'POST', body: { email, ...(captcha ? { captcha } : {}) } }),
  passwordResetConfirm: <T = unknown>(body: PasswordResetPayload) => request<T>(`${API}/password-reset/confirm`, { method: 'POST', body }),

  // passkey (登录)
  passkeyBegin: <T = unknown>(login?: string) => request<T>(`${API}/session/passkey/begin`, { method: 'POST', body: { ...(login ? { login } : {}) } }),
  passkeyFinish: <T = unknown>(ceremonyId: string, credential: WebAuthnCredential) =>
    request<T>(`${API}/session/passkey/finish`, { method: 'POST', body: { ceremonyId, credential } }),
  // 第三方登录
  providerAuthorize: (provider: string, returnUrl?: string) => {
    const p = new URLSearchParams()
    if (returnUrl) p.set('returnUrl', returnUrl)
    const q = p.toString()
    window.location.assign(`/api/login/provider/${encodeURIComponent(provider)}/authorize${q ? `?${q}` : ''}`)
  },
  // 绑定第三方：整页跳转到后端发起授权（避免 fetch 处理 302 到外部域导致“无响应”）
  providerBind: (provider: string) => {
    window.location.assign(`/api/v1/login/provider/${encodeURIComponent(provider)}/bind`)
  },

  // dashboard & events
  dashboard: <T = unknown>(window: string) => request<T>(`${API}/me/dashboard?window=${encodeURIComponent(window)}`),
  // events 支持按分类过滤（category=login|profile|session|grant），
  // 由服务端统计总数，避免前端取一页再本地 filter 导致计数失真。
  events: <T = unknown>(type?: string, page = 1, pageSize = 20, category?: string) => {
    const p = new URLSearchParams({ page: String(page), pageSize: String(pageSize) })
    if (type) p.set('type', type)
    if (category) p.set('category', category)
    return request<T>(`${API}/me/events?${p.toString()}`)
  },
  // 各分类的事件总数（用于页签与右侧摘要的计数）
  eventCounts: <T = unknown>() => request<T>(`${API}/me/events/counts`),

  // profile
  profile: <T = unknown>() => request<T>(`${API}/me/profile`),
  patchProfile: <T = unknown>(body: ProfilePatchPayload) => request<T>(`${API}/me/profile`, { method: 'PATCH', body }),
  changePassword: (oldPassword: string, newPassword: string) =>
    request(`${API}/me/password`, { method: 'POST', body: { oldPassword, newPassword } }),
  uploadAvatar: (file: File) => {
    const fd = new FormData()
    fd.set('file', file)
    return request(`${API}/me/avatar`, { method: 'POST', body: fd })
  },
  sendEmailVerify: <T = unknown>() => request<T>(`${API}/me/email/verify/send`, { method: 'POST', body: {} }),
  // 提交邮箱验证令牌（由 /verify-email 页面调用）。免 CSRF：用户可能从未登录状态
  // 打开邮件链接，需要拿到 401 以便页面引导登录后再跳回。
  verifyEmail: <T = unknown>(token: string) =>
    request<T>(`${API}/me/email/verify`, { method: 'POST', body: { token } }),
  // 变更登录邮箱：需先通过 /me/step-up 取得 stepUpToken
  // 携带 emailCode（新邮箱验证码）时，校验通过后直接标记邮箱已验证。
  changeEmail: (body: { email: string; stepUpToken: string; emailCode?: string }) =>
    request(`${API}/me/email`, { method: 'POST', body }),
  // 向待绑定的「新邮箱」发送验证码（添加/更换邮箱一步式验证）
  sendNewEmailCode: (body: { email: string; stepUpToken: string }) =>
    request(`${API}/me/email/code`, { method: 'POST', body }),
  // 手机号验证：发送验证码 / 校验并标记已验证 / 保存未验证手机号
  sendPhoneCode: (phone: string) => request(`${API}/me/phone/send-code`, { method: 'POST', body: { phone } }),
  verifyPhone: <T = unknown>(phone: string, code: string) =>
    request<T>(`${API}/me/phone/verify`, { method: 'POST', body: { phone, code } }),
  patchPhone: <T = unknown>(phone: string) => request<T>(`${API}/me/phone`, { method: 'PATCH', body: { phone } }),
  export: <T = unknown>() => request<T>(`${API}/me/export`),
  // 账号注销：申请 / 查询 / 撤回 / 二次验证邮箱验证码
  accountDeletion: <T = unknown>() => request<T>(`${API}/me/account-deletion`),
  requestAccountDeletion: (body: { password?: string; code: string; reason?: string; method?: string }) =>
    request(`${API}/me/account-deletion`, { method: 'POST', body }),
  cancelAccountDeletion: <T = unknown>() => request<T>(`${API}/me/account-deletion`, { method: 'DELETE' }),
  sendDeletionEmailCode: <T = unknown>() => request<T>(`${API}/me/account-deletion/email-code`, { method: 'POST', body: {} }),
  // 敏感操作二次验证（step-up）：校验通过后返回短效 stepUpToken
  sendStepUpEmailCode: <T = unknown>() => request<T>(`${API}/me/step-up/email-code`, { method: 'POST', body: {} }),
  // method 指定二次验证方式（'mfa' | 'email'），为空则由服务端自动选择。
  // 用户在界面上切换了方式就必须带上，否则后端仍按 MFA 优先隐式校验。
  stepUp: <T = unknown>(password: string, code: string, method?: string) =>
    request<T>(`${API}/me/step-up`, { method: 'POST', body: { password, code, method } }),
  // 重新验证身份：改密码/解绑等敏感操作的通用前置，返回短效 reauthToken
  reauthenticate: (password: string, mfaCode: string, method?: string) =>
    request(`${API}/me/reauthenticate`, { method: 'POST', body: { password, mfaCode, method } }),

  // sessions & devices
  sessions: <T = unknown>() => request<T>(`${API}/me/sessions`),
  deleteSession: <T = unknown>(id: string) => request<T>(`${API}/me/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  deleteOtherSessions: <T = unknown>() => request<T>(`${API}/me/sessions?scope=others`, { method: 'DELETE' }),
  devices: <T = unknown>() => request<T>(`${API}/me/devices`),
  trustedDevices: <T = unknown>() => request<T>(`${API}/me/trusted-devices`),
  addTrustedDevice: <T = unknown>(name: string) => request<T>(`${API}/me/trusted-devices`, { method: 'POST', body: { name } }),
  deleteTrustedDevice: <T = unknown>(id: string) => request<T>(`${API}/me/trusted-devices/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  // grants & identities
  grants: <T = unknown>() => request<T>(`${API}/me/grants`),
  revokeGrant: <T = unknown>(id: string) => request<T>(`${API}/me/grants/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  identities: <T = unknown>() => request<T>(`${API}/me/identities`),
  // 解绑第三方属敏感操作，服务端要求携带 reauthToken（由 /me/reauthenticate 签发）
  deleteIdentity: <T = unknown>(id: string, reauthToken?: string) =>
    request<T>(`${API}/me/identities/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      ...(reauthToken ? { headers: { 'X-OpenIdP-Reauth': reauthToken } } : {}),
    }),

  // mfa & passkeys
  mfa: <T = unknown>() => request<T>(`${API}/me/mfa`),
  mfaBegin: <T = unknown>() => request<T>(`${API}/me/mfa/begin`),
  mfaConfirm: <T = unknown>(code: string) => request<T>(`${API}/me/mfa/confirm`, { method: 'POST', body: { code } }),
  mfaDisable: <T = unknown>(code: string) => request<T>(`${API}/me/mfa/disable`, { method: 'POST', body: { code } }),
  mfaRecoveryCodes: <T = unknown>(code: string) => request<T>(`${API}/me/mfa/recovery-codes`, { method: 'POST', body: { code } }),
  sessionMFAVerify: <T = unknown>(challengeId: string, code: string) =>
    request<T>(`${API}/session/mfa/verify`, { method: 'POST', body: { challengeId, code } }),
  passkeys: <T = unknown>() => request<T>(`${API}/me/passkeys`),
  passkeysBegin: <T = unknown>() => request<T>(`${API}/me/passkeys/begin`, { method: 'POST' }),
  passkeysFinish: (ceremonyId: string, name: string, credential: WebAuthnCredential) =>
    request(`${API}/me/passkeys/finish`, { method: 'POST', body: { ceremonyId, name, credential } }),
  // 删除通行密钥属敏感操作，服务端要求携带 reauthToken
  deletePasskey: <T = unknown>(id: string, reauthToken?: string) =>
    request<T>(`${API}/me/passkeys/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      ...(reauthToken ? { headers: { 'X-OpenIdP-Reauth': reauthToken } } : {}),
    }),

  // notification preferences
  notificationPrefs: <T = unknown>() => request<T>(`${API}/me/notification-preferences`),
  patchNotificationPrefs: <T = unknown>(body: NotificationPrefsPayload) => request<T>(`${API}/me/notification-preferences`, { method: 'PATCH', body }),

  // notification center
  // 独立未读计数：轮询时无需拉取全量列表。
  unreadNotificationCount: <T = unknown>() => request<T>(`${API}/me/notifications/unread-count`),
  notifications: <T = unknown>(page = 1, pageSize = 50) =>
    request<T>(`${API}/me/notifications?page=${page}&pageSize=${pageSize}`),
  markNotificationRead: <T = unknown>(id: number) => request<T>(`${API}/me/notifications/${id}`, { method: 'PATCH', body: { read: true } }),
  markAllNotificationsRead: <T = unknown>() => request<T>(`${API}/me/notifications/read-all`, { method: 'POST', body: {} }),
  // 清空当前用户的全部站内通知（不可恢复）
  clearNotifications: <T = unknown>() => request<T>(`${API}/me/notifications`, { method: 'DELETE' }),

  // ---- 设备授权流（RFC 8628）----

  // ---- admin console ----
  adminDashboard: <T = unknown>() => request<T>(`${API}/admin/dashboard`),
  adminUsers: <T = unknown>(q?: string, page = 1, pageSize = 20) => request<T>(`${API}/admin/users?q=${encodeURIComponent(q ?? '')}&page=${page}&pageSize=${pageSize}`),
  adminCreateUser: <T = unknown>(body: AdminCreateUserPayload) => request<T>(`${API}/admin/users`, { method: 'POST', body }),
  adminUpdateUser: <T = unknown>(id: number, body: AdminUpdateUserPayload) => request<T>(`${API}/admin/users/${id}`, { method: 'PATCH', body }),
  adminDeleteUser: <T = unknown>(id: number) => request<T>(`${API}/admin/users/${id}`, { method: 'DELETE' }),
  adminSite: <T = unknown>() => request<T>(`${API}/admin/site`),
  adminUpdateSite: <T = unknown>(body: AdminSitePatchPayload) => request<T>(`${API}/admin/site`, { method: 'PATCH', body }),
  adminSecurityPolicy: <T = unknown>() => request<T>(`${API}/admin/security-policy`),
  adminUpdateSecurityPolicy: <T = unknown>(body: AdminSecurityPolicyPayload) => request<T>(`${API}/admin/security-policy`, { method: 'PATCH', body }),
  adminOAuthClients: <T = unknown>() => request<T>(`${API}/admin/oauth-clients`),
  adminCreateOAuthClient: <T = unknown>(body: AdminOAuthClientPayload) => request<T>(`${API}/admin/oauth-clients`, { method: 'POST', body }),
  adminUpdateOAuthClient: <T = unknown>(id: string, body: AdminOAuthClientPayload) => request<T>(`${API}/admin/oauth-clients/${encodeURIComponent(id)}`, { method: 'PATCH', body }),
  adminRotateOAuthClientSecret: <T = unknown>(id: string) => request<T>(`${API}/admin/oauth-clients/${encodeURIComponent(id)}/secret`, { method: 'POST' }),
  adminDeleteOAuthClient: <T = unknown>(id: string) => request<T>(`${API}/admin/oauth-clients/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  adminOAuthProviders: <T = unknown>() => request<T>(`${API}/admin/oauth-providers`),
  adminProxy: <T = unknown>() => request<T>(`${API}/admin/proxy`),
  adminUpdateProxy: <T = unknown>(body: AdminProxyPayload) => request<T>(`${API}/admin/proxy`, { method: 'PATCH', body }),
  adminTestProxy: <T = unknown>(body: { target?: string } = {}) => request<T>(`${API}/admin/proxy/test`, { method: 'POST', body }),
  adminCreateOAuthProvider: <T = unknown>(body: AdminOAuthProviderPayload) => request<T>(`${API}/admin/oauth-providers`, { method: 'POST', body }),
  adminUpdateOAuthProvider: <T = unknown>(id: string, body: AdminOAuthProviderPayload) => request<T>(`${API}/admin/oauth-providers/${encodeURIComponent(id)}`, { method: 'PATCH', body }),
  /** 测试该提供商的出站链路（含「使用代理」配置），返回各端点可达性与耗时。 */
  adminTestOAuthProvider: <T = unknown>(id: string) =>
    request<T>(`${API}/admin/oauth-providers/${encodeURIComponent(id)}/test`, { method: 'POST', body: {} }),
  adminDeleteOAuthProvider: <T = unknown>(id: string) => request<T>(`${API}/admin/oauth-providers/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  adminOAuthGrants: <T = unknown>() => request<T>(`${API}/admin/oauth-grants`),
  // 管理员撤销授权走独立管理端点。
  adminRevokeGrant: <T = unknown>(id: string) => request<T>(`${API}/admin/oauth-grants/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  // 注销账号申请审核
  adminDeletionRequests: <T = unknown>() => request<T>(`${API}/admin/account-deletion-requests`),
  adminApproveDeletionRequest: (id: string, note?: string) =>
    request(`${API}/admin/account-deletion-requests/${encodeURIComponent(id)}/approve`, { method: 'POST', body: { note } }),
  adminRejectDeletionRequest: (id: string, note?: string) =>
    request(`${API}/admin/account-deletion-requests/${encodeURIComponent(id)}/reject`, { method: 'POST', body: { note } }),
  adminMail: <T = unknown>() => request<T>(`${API}/admin/mail`),
  adminUpdateMail: <T = unknown>(body: AdminMailPayload) => request<T>(`${API}/admin/mail`, { method: 'PATCH', body }),
  adminMailTest: <T = unknown>(to: string) => request<T>(`${API}/admin/mail/test`, { method: 'POST', body: { to } }),
  adminCaptcha: <T = unknown>() => request<T>(`${API}/admin/captcha`),
  adminUpdateCaptcha: <T = unknown>(body: AdminCaptchaPayload) => request<T>(`${API}/admin/captcha`, { method: 'PATCH', body }),
  adminCaptchaTest: <T = unknown>(body: AdminMailTestPayload) => request<T>(`${API}/admin/captcha/test`, { method: 'POST', body }),
  adminSms: <T = unknown>() => request<T>(`${API}/admin/sms`),
  adminUpdateSms: <T = unknown>(body: AdminSmsPayload) => request<T>(`${API}/admin/sms`, { method: 'PATCH', body }),
  adminSmsTest: <T = unknown>(body: AdminSmsPayload) => request<T>(`${API}/admin/sms/test`, { method: 'POST', body }),

  // ---- 存储管理（配置 + 文件记录 + 孤儿回收）----
  adminStorage: <T = unknown>() => request<T>(`${API}/admin/storage`),
  adminUpdateStorage: <T = unknown>(body: AdminStoragePayload) => request<T>(`${API}/admin/storage`, { method: 'PUT', body }),
  adminStorageTestAndSave: (body: AdminStoragePayload) =>
    request(`${API}/admin/storage/test-and-save`, { method: 'POST', body }),
  adminStorageStats: <T = unknown>() => request<T>(`${API}/admin/storage/stats`),
  adminFiles: <T = unknown>(purpose?: string, page = 1, pageSize = 20) => {
    const p = new URLSearchParams({ page: String(page), pageSize: String(pageSize) })
    if (purpose) p.set('purpose', purpose)
    return request<T>(`${API}/admin/files?${p.toString()}`)
  },
  adminDeleteFile: (publicId: string) =>
    request(`${API}/admin/files/${encodeURIComponent(publicId)}`, { method: 'DELETE' }),
  adminOrphanFiles: <T = unknown>() => request<T>(`${API}/admin/files/orphans`),
  adminCleanupOrphans: <T = unknown>() => request<T>(`${API}/admin/files/orphans/cleanup`, { method: 'POST', body: {} }),

  // ---- IP 归属地配置 ----
  adminLocation: <T = unknown>() => request<T>(`${API}/admin/location`),
  adminUpdateLocation: <T = unknown>(body: AdminLocationPayload) => request<T>(`${API}/admin/location`, { method: 'PUT', body }),
  adminTestLocation: (sampleIp?: string) =>
    request(`${API}/admin/location/test`, { method: 'POST', body: { sampleIp } }),

  // ---- 审计日志（分页增强）与保留策略 ----
  // 审计日志唯一入口：支持 q / type / endpoint / outcome / userId / user 过滤。
  // user 为用户名/邮箱/昵称模糊搜索（筛选框用），userId 为精确 ID。
  adminAuditEvents: <T = unknown>(params: { q?: string; type?: string; endpoint?: string; outcome?: string; userId?: string; user?: string; page?: number; pageSize?: number } = {}) => {
    const p = new URLSearchParams()
    if (params.q) p.set('q', params.q)
    if (params.type) p.set('type', params.type)
    if (params.endpoint) p.set('endpoint', params.endpoint)
    if (params.outcome) p.set('outcome', params.outcome)
    if (params.userId) p.set('userId', params.userId)
    if (params.user) p.set('user', params.user)
    p.set('page', String(params.page ?? 1))
    p.set('pageSize', String(params.pageSize ?? 20))
    return request<T>(`${API}/admin/audit-events?${p.toString()}`)
  },
  // 审计统计摘要：总量 / 成功 / 失败 + 最近 N 天按天序列（统计卡与迷你趋势线用）。
  adminAuditStats: <T = unknown>(days = 7) => request<T>(`${API}/admin/audit-stats?days=${days}`),
  adminAuditSettings: <T = unknown>() => request<T>(`${API}/admin/audit-settings`),
  adminUpdateAuditSettings: <T = unknown>(body: AdminAuditSettingsPayload) => request<T>(`${API}/admin/audit-settings`, { method: 'PUT', body }),

  // ---- 分类数据清理 ----
  adminDataCleanup: <T = unknown>() => request<T>(`${API}/admin/data-cleanup`),
  adminUpdateDataCleanup: <T = unknown>(body: AdminDataCleanupPayload) => request<T>(`${API}/admin/data-cleanup`, { method: 'PUT', body }),
  adminRunDataCleanup: <T = unknown>() => request<T>(`${API}/admin/data-cleanup/run`, { method: 'POST', body: {} }),
  /** 清理前的占用概览：缓存规模 / 存储用量 / 各类超期记录数（判定条件与 run 一致）。 */
  adminDataCleanupUsage: <T = unknown>() => request<T>(`${API}/admin/data-cleanup/usage`),

  // ---- 数据备份（导出 / 恢复，ZIP 二进制）----
  // 备份是 ZIP：导出返回二进制流、恢复上传 ZIP，都不走 request() 的 JSON 解包，
  // 因此在这里单独实现（仍然带会话 Cookie，恢复还要带 CSRF 头）。
  adminBackupExportZip: async (groups: SettingsBackupGroup[]): Promise<Blob> => {
    const params = new URLSearchParams()
    if (groups.length > 0) params.set('groups', groups.join(','))
    const qs = params.toString()
    const res = await fetch(`${API}/admin/backup/export${qs ? `?${qs}` : ''}`, { credentials: 'include' })
    if (!res.ok) {
      throw errorFromResponse(res, await parseJsonSafe(res))
    }
    return res.blob()
  },
  /** 上传备份 ZIP 解析其内容（恢复前先确认文件里到底有什么）。 */
  adminBackupInspectZip: <T = unknown>(archive: Blob) =>
    sendBackupZip<T>(`${API}/admin/backup/inspect`, archive),
  adminBackupRestoreZip: <T = unknown>(groups: SettingsBackupGroup[], archive: Blob) => {
    const params = new URLSearchParams()
    if (groups.length > 0) params.set('groups', groups.join(','))
    const qs = params.toString()
    return sendBackupZip<T>(`${API}/admin/backup/restore${qs ? `?${qs}` : ''}`, archive)
  },

  // ---- 系统状态 / OAuth 权限项 / 定点通知 ----
  adminSystemStatus: <T = unknown>() => request<T>(`${API}/admin/system-status`),
  adminOAuthScopes: <T = unknown>() => request<T>(`${API}/admin/oauth-scopes`),
  // OIDC 发现文档是公开端点，不经过 request()：无需会话、也拿不到 { data } 包裹，
  // 且 CSRF 头对它没有意义。管理后台「应用管理」据此展示本站接入地址，
  // 直接读取发现文档可避免前端硬编码的路径与后端路由漂移。
  oauthDiscovery: () =>
    fetch('/.well-known/openid-configuration', { credentials: 'same-origin' })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error('discovery unavailable')))),
  adminUpdateOAuthScope: <T = unknown>(body: AdminOAuthScopePayload) => request<T>(`${API}/admin/oauth-scopes`, { method: 'PUT', body }),
  adminSetOAuthScope: (id: string, enabled: boolean) =>
    request(`${API}/admin/oauth-scopes/${encodeURIComponent(id)}/${enabled ? 'enable' : 'disable'}`, { method: 'POST', body: {} }),
  adminNotifications: (page = 1, pageSize = 20) =>
    request(`${API}/admin/notifications?page=${page}&pageSize=${pageSize}`),
  adminNotificationPresets: <T = unknown>() => request<T>(`${API}/admin/notification-presets`),
  adminBroadcastNotification: (body: { title: string; summary?: string; userIds?: number[]; preset?: string; allUsers?: boolean }) =>
    request(`${API}/admin/notifications`, { method: 'POST', body }),

}
