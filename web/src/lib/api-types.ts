// API 请求负载与响应的公共类型定义。
// 目标：把 `: any` 收敛到边界一层（见 api.ts 的 request<T>），
// 调用方与 api 方法的参数尽量使用这里的 interface。

/** 验证码统一负载：Turnstile token 或 GeeTest v4 校验结果。 */
export interface CaptchaPayload {
  turnstile?: string
  captcha?: import('./captcha').GeeTestProof
}

/** WebAuthn / 通行密钥 ceremony 凭证（浏览器 Crypto API 产物）。 */
export type WebAuthnCredential = Record<string, unknown>

/**
 * 数据备份的分组标识。
 * 与后端 handler 的 group* 常量是同一个契约（改动需两侧同步）：
 * 备份是「系统设置 + 若干可选业务数据分组」，业务数据必须显式勾选才会导出。
 * 文件记录（files）不在备份范围内：文件本体在存储后端，元数据单独搬运会悬空。
 */
export type SettingsBackupGroup = 'settings' | 'users' | 'sessions' | 'events' | 'oauth'

/** 备份文件里存在的单个分组；settings 没有表清单（它是单个文件）。 */
export interface SettingsBackupInspectGroup {
  name: string
  tables?: string[]
}

/** 上传解析结果：这份备份文件里实际包含什么。 */
export interface SettingsBackupInspectResult {
  format?: string
  version?: number
  exportedAt?: string
  exportedBy?: string
  secretsPlaintext?: boolean
  groups?: SettingsBackupInspectGroup[]
}

/** 单张表在恢复中的行数统计。skipped 是「属于当前账号而被跳过」的行数。 */
export interface SettingsBackupTableResult {
  table: string
  inserted?: number
  updated?: number
  skipped?: number
}

/** 一个分组的恢复回执。settings 分组用 sections，数据分组用 tables。 */
export interface SettingsBackupGroupResult {
  name: string
  sections?: string[]
  tables?: SettingsBackupTableResult[]
}

/** 恢复备份的回执。 */
export interface SettingsBackupRestoreResult {
  groups?: SettingsBackupGroupResult[]
  /** 请求恢复但备份文件里不存在的分组 / 表名。 */
  missing?: string[]
  currentUser?: { id?: number; username?: string }
}

// ---- 请求负载 ----

export interface SetupPayload {
  username: string
  password: string
  email?: string
  [key: string]: unknown
}

export interface SignupPayload {
  username: string
  password: string
  email: string
  [key: string]: unknown
}

export interface PasswordResetPayload {
  email: string
  code: string
  newPassword: string
  [key: string]: unknown
}

export interface ProfilePatchPayload {
  displayName?: string
  [key: string]: unknown
}

export interface NotificationPrefsPayload {
  newDeviceInApp?: boolean
  newDeviceEmail?: boolean
  privacyEmailReminder?: boolean
  [key: string]: unknown
}

export interface AdminCreateUserPayload {
  username: string
  email?: string
  password?: string
  isAdmin?: boolean
  [key: string]: unknown
}

export interface AdminUpdateUserPayload {
  isAdmin?: boolean
  displayName?: string
  email?: string
  passwordSet?: string
  [key: string]: unknown
}

export interface AdminSitePatchPayload {
  [key: string]: unknown
}

export interface AdminSecurityPolicyPayload {
  [key: string]: unknown
}

export interface AdminOAuthClientPayload {
  name?: string
  redirectUris?: string[]
  description?: string
  logoUrl?: string
  homepageUrl?: string
  [key: string]: unknown
}

export interface AdminOAuthProviderPayload {
  type?: string
  clientId?: string
  clientSecret?: string
  scopes?: string[]
  custom?: boolean
  authorizeUrl?: string
  tokenUrl?: string
  userInfoUrl?: string
  // openIdUrl：换取唯一 openid 的额外端点（仅部分平台需要，如 QQ）。
  openIdUrl?: string
  docsUrl?: string
  useProxy?: boolean
  [key: string]: unknown
}

export interface AdminProxyPayload {
  protocol?: string
  host?: string
  port?: number
  username?: string
  password?: string
  clearPassword?: boolean
  enabled?: boolean
}

export interface AdminMailPayload {
  [key: string]: unknown
}

export interface AdminMailTestPayload {
  [key: string]: unknown
}

export interface AdminCaptchaPayload {
  [key: string]: unknown
}

export interface AdminSmsPayload {
  [key: string]: unknown
}

export interface AdminStoragePayload {
  [key: string]: unknown
}

export interface AdminLocationPayload {
  [key: string]: unknown
}

export interface AdminAuditSettingsPayload {
  [key: string]: unknown
}

export interface AdminDataCleanupPayload {
  [key: string]: unknown
}

export interface AdminOAuthScopePayload {
  [key: string]: unknown
}
