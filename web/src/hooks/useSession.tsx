import * as React from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, setCsrf, onUnauthorized } from '../lib/api'
import type { CaptchaPayload, SignupPayload } from '../lib/api-types'
import { setSiteTimezone } from '../lib/timezone'
import { applySiteFavicon } from './useSiteBrand'

export interface SiteInfo {
  name: string
  displayName: string
  logo: string
  logoDark: string
  favicon: string
  languages: string[]
  // 系统时区（IANA 名，默认 Asia/Shanghai）与当前 UTC 偏移分钟数。
  // 前端按它渲染所有时间，与后端日志、统计日界保持同一口径。
  timezone?: string
  timezoneLabel?: string
  utcOffsetMinutes?: number
  avatarUploadEnabled?: boolean
  // 页脚三件套：自定义文本 / ICP 备案号 / 公安联网备案号（后台「品牌信息」配置）
  footerText?: string
  icpBeian?: string
  publicSecurityBeian?: string
}

export interface SessionUser {
  id: number
  subject: string
  username: string
  displayName: string
  avatarUrl: string
  email: string
  emailVerified: boolean
  passwordSet: boolean
  isAdmin: boolean
}

export interface SessionData {
  csrfToken: string
  site: SiteInfo
  user: SessionUser
  ipAddress?: string
  ipRegion?: string
}

// passkeyBegin 返回的 ceremony 描述。
interface PasskeyBegin {
  ceremonyId: string
  options: Parameters<Awaited<ReturnType<typeof import('../lib/webauthn')['assertPasskey']>>>[0]
}

// SecondFactorOptions 是账号当前可用的二次验证方式（由 /api/v1/capabilities 下发）。
//
// required=false 表示账号既未启用 MFA 也没有可用邮箱，此时后端只校验密码，
// 前端不应再渲染验证码输入框——否则用户填无可填，等于被锁死在敏感操作之外。
export interface SecondFactorOptions {
  required: boolean
  mfaEnabled: boolean
  emailAvailable: boolean
  methods: Array<'mfa' | 'email'>
}

// Capabilities 是登录策略下发的能力开关集合。
//
// personal / admin 用枚举联合而非 Record<string, boolean>：宽松类型会让
// 「后端新增/下线能力位、前端漏消费」这类漂移在编译期完全静默——
// 拼错 key 取到 undefined，与「能力确实为 false」无法区分。
// 收紧后，新增能力位必须同步改这里，下线能力位则会在引用处直接报错。
export type PersonalCapability =
  | 'profileEdit' | 'avatarUpload' | 'passwordChange' | 'emailChange'
  | 'sessionManagement' | 'grantManagement' | 'identityManagement'
  | 'securityEvents' | 'accountDeletion' | 'phoneVerify'
  // phoneAdd：管理员允许用户自助添加手机号（策略开关，关闭后不展示手机号入口）。
  | 'phoneAdd'
  // notificationEmail：邮件类自动通知可用（依赖 SMTP 配置）。
  | 'notificationEmail'

export type AdminCapability =
  | 'dashboard' | 'auditEvents' | 'notifications' | 'users'
  | 'oauthClients' | 'oauthGrants' | 'oauthProviders'
  | 'mail' | 'location' | 'site' | 'storage' | 'securityPolicy'
  | 'oauthScopes' | 'dataCleanup' | 'systemStatus'

export interface Capabilities {
  personal: Partial<Record<PersonalCapability, boolean>>
  login: { password: boolean; providers: string[] }
  admin: Partial<Record<AdminCapability, boolean>>
  secondFactor?: SecondFactorOptions
}

const SessionContext = React.createContext<{
  session?: SessionData
  isLoading: boolean
  capabilities?: Capabilities
  login: (login: string, password: string, captcha?: CaptchaPayload) => Promise<void>
  loginWithPasskey: (login: string, captcha?: CaptchaPayload) => Promise<void>
  signup: (body: SignupPayload) => Promise<void>
  logout: () => Promise<void>
  verifyMFA: (challengeId: string, code: string) => Promise<void>
  applySession: (res: SessionData) => void
}>({
  isLoading: true,
  login: async () => {},
  loginWithPasskey: async () => {},
  signup: async () => {},
  logout: async () => {},
  verifyMFA: async () => {},
  applySession: () => {},
})

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const qc = useQueryClient()
  const { data: session, isLoading } = useQuery({
    queryKey: ['session'],
    queryFn: () => api.getSession<SessionData>(),
    retry: false,
  })

  const { data: capabilities } = useQuery({
    queryKey: ['capabilities'],
    queryFn: () => api.capabilities<Capabilities>(),
    enabled: !!session,
    retry: false,
  })

  React.useEffect(() => {
    if (session?.csrfToken) setCsrf(session.csrfToken)
  }, [session])

  // 站点时区随会话下发：登录用户按系统时区渲染所有时间。
  React.useEffect(() => {
    if (session?.site) setSiteTimezone(session.site)
  }, [session])

  // 浏览器标签页标题跟随站点显示名（默认“OpenIdP”）；未登录时保持 index.html 的默认标题。
  React.useEffect(() => {
    const name = session?.site?.displayName
    if (name) document.title = name
  }, [session])

  // 站点图标同样跟随会话下发的品牌配置：后台「品牌信息」里改了 favicon，
  // 已登录页面也应立即生效，而不只是未登录页面（后者由 useSiteBrand 处理）。
  React.useEffect(() => {
    if (session?.site) applySiteFavicon(session.site)
  }, [session])

  React.useEffect(() => {
    const unsub = onUnauthorized(() => {
      qc.setQueryData(['session'], undefined)
    })
    return () => { unsub() }
  }, [qc])

  const applySession = (res: SessionData) => {
    setCsrf(res.csrfToken)
    qc.setQueryData(['session'], res)
  }

  const login = async (login: string, password: string, captcha?: CaptchaPayload) => {
    const res = await api.login<SessionData>(login, password, undefined, captcha)
    applySession(res)
  }

  const loginWithPasskey = async (login: string, captcha?: CaptchaPayload) => {
    const begin = await api.passkeyBegin<PasskeyBegin>(login)
    const { assertPasskey } = await import('../lib/webauthn')
    const credential = await assertPasskey(begin.options)
    const res = await api.passkeyFinish<SessionData>(begin.ceremonyId, credential)
    applySession(res)
  }

  const signup = async (body: SignupPayload) => {
    const res = await api.signup<SessionData>(body)
    applySession(res)
  }

  const logout = async () => {
    try { await api.logout() } catch { /* ignore */ }
    qc.setQueryData(['session'], undefined)
    window.location.href = '/sign-in'
  }

  const verifyMFA = async (challengeId: string, code: string) => {
    const res = await api.sessionMFAVerify<SessionData>(challengeId, code)
    applySession(res)
  }

  return (
    <SessionContext.Provider value={{ session, isLoading, capabilities, login, loginWithPasskey, signup, logout, verifyMFA, applySession }}>
      {children}
    </SessionContext.Provider>
  )
}

export function useSession() {
  return React.useContext(SessionContext)
}
