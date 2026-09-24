// 系统设置分区清单：唯一事实来源。
//
// 背景：分区清单此前在 AppShell（侧栏高亮白名单）与 AdminSettingsPage（分区渲染
// 列表）各维护一份，靠人工同步。新增分区时只改一处就会漂移 —— 表现为「侧栏没有
// 入口，只能手敲 URL，且高亮落到 brand」，或「侧栏能点进去但内容区空白」。
//
// 因此把「分区标识 + 文案 key + 图标 + 子页签」抽到本文件，共同 import：
//   - AppShell           → 生成侧栏「系统设置」的子项与高亮
//   - AdminSettingsPage  → 按 ?section= / ?tab= 渲染分区内容
//
// 语义相近的分区合并为一个分区 + 页签（页签文案复用原分区标题 key）：
//   security   登录安全   = 安全策略 / 通行密钥 / 人机验证
//   messaging  消息服务   = 邮件 / 短信 / 发送通知
//   audit      数据与运维 = 审计与状态 / 归属地 / 存储管理 / 数据清理
// 旧地址（?section=location / storage / passkey / captcha / cleanup / mail / sms /
// notifications）通过 SECTION_ALIASES 归一化到新位置，已存在的书签与外部链接不会失效。
import {
  Store, ShieldCheck, Globe, AppWindow, MessagesSquare,
  FileClock, Network,
} from 'lucide-react'

// ---- 子页签 ----

// 登录安全：三者都在回答「登录要多严格」；通行密钥与人机验证各自只有少量配置，
// 单独占一个侧栏项性价比最低，合并后改密码策略时也能顺手看到它们的状态。
export const SECURITY_TABS = [
  { key: 'policy', labelKey: 'admin.settings.tab.security' },
  { key: 'passkey', labelKey: 'admin.settings.tab.passkey' },
  { key: 'captcha', labelKey: 'admin.settings.tab.captcha' },
] as const

// 消息服务：三者同属「给用户投递消息的渠道」，配置结构同源
// （选服务商 → 填凭据 → 测试 → 保存），「配置渠道」与「使用渠道」同屏。
export const MESSAGING_TABS = [
  { key: 'mail', labelKey: 'admin.settings.tab.mail' },
  { key: 'sms', labelKey: 'admin.settings.tab.sms' },
  { key: 'broadcast', labelKey: 'admin.settings.tab.notifications' },
] as const

// 数据与运维：日志保留、存储用量与清理策略互为约束（清理早了审计断档、保留太久占
// 空间，而存储用量决定了「能回收多少」）；归属地是这些数据的来源配置（IP 库路径 /
// 请求头 / 可信代理）。同属「存量数据与运行配置」，放在一个分区里换页签即可。
// 顺序：先看状态与来源，再看存了什么，然后是破坏性的清理，最后是备份与恢复
// （备份能救回清理/误改造成的损失，放在清理之后，二者形成「破坏—兜底」的闭环）。
export const OPS_TABS = [
  { key: 'audit', labelKey: 'admin.settings.tab.audit' },
  { key: 'location', labelKey: 'admin.settings.tab.location' },
  { key: 'storage', labelKey: 'admin.settings.tab.storage' },
  { key: 'cleanup', labelKey: 'admin.settings.tab.cleanup' },
  { key: 'backup', labelKey: 'admin.settings.tab.backup' },
] as const

export type SectionTab = { readonly key: string; readonly labelKey: string }

// ---- 分区清单 ----

export const SETTINGS_SECTIONS = [
  { key: 'brand', labelKey: 'admin.settings.tab.brand', icon: Store },
  { key: 'security', labelKey: 'admin.settings.tab.securityGroup', icon: ShieldCheck, tabs: SECURITY_TABS },
  { key: 'providers', labelKey: 'admin.settings.tab.providers', icon: Globe },
  { key: 'apps', labelKey: 'admin.settings.tab.apps', icon: AppWindow },
  { key: 'messaging', labelKey: 'admin.settings.tab.messaging', icon: MessagesSquare, tabs: MESSAGING_TABS },
  { key: 'proxy', labelKey: 'admin.settings.tab.proxy', icon: Network },
  { key: 'audit', labelKey: 'admin.settings.tab.opsGroup', icon: FileClock, tabs: OPS_TABS },
] as const

export type SettingsSection = (typeof SETTINGS_SECTIONS)[number]['key']

export const SETTINGS_SECTION_KEYS: readonly string[] = SETTINGS_SECTIONS.map((s) => s.key)

// 分区 → 页签列表（无页签的分区返回空数组）。
// SETTINGS_SECTIONS 用了 as const，元素形状不齐（只有合并分区带 tabs），
// 故在这里统一取一次并收敛为 Record，避免调用方各自做类型断言。
const TAB_MAP: Record<string, readonly SectionTab[]> = {}
for (const s of SETTINGS_SECTIONS) {
  const tabs = (s as { tabs?: readonly SectionTab[] }).tabs
  if (tabs) TAB_MAP[s.key] = tabs
}

export function settingsTabs(section: SettingsSection): readonly SectionTab[] {
  return TAB_MAP[section] ?? []
}

export function isSectionTab(section: SettingsSection, tab: string | null | undefined): boolean {
  return !!tab && settingsTabs(section).some((tb) => tb.key === tab)
}

export function defaultTab(section: SettingsSection): string {
  return settingsTabs(section)[0]?.key ?? ''
}

// ---- 地址解析 ----

// 旧分区地址 → 新位置。分区合并不能破坏已存在的书签、文档与外部链接。
const SECTION_ALIASES: Record<string, { section: SettingsSection; tab: string }> = {
  mail: { section: 'messaging', tab: 'mail' },
  sms: { section: 'messaging', tab: 'sms' },
  notifications: { section: 'messaging', tab: 'broadcast' },
  passkey: { section: 'security', tab: 'passkey' },
  captcha: { section: 'security', tab: 'captcha' },
  location: { section: 'audit', tab: 'location' },
  storage: { section: 'audit', tab: 'storage' },
  cleanup: { section: 'audit', tab: 'cleanup' },
}

export interface SettingsLocation {
  section: SettingsSection
  /** 当前页签；无页签的分区为空字符串 */
  tab: string
}

// resolveSettingsLocation 把地址栏参数归一化为「分区 + 页签」：
//   ?section=passkey              → security / passkey（旧地址别名）
//   ?section=security&tab=captcha → security / captcha
//   ?section=未知 / 缺省           → brand（默认分区）
export function resolveSettingsLocation(
  sectionParam?: string | null,
  tabParam?: string | null,
): SettingsLocation {
  const raw = (sectionParam ?? '').trim()
  const alias = SECTION_ALIASES[raw]
  if (alias) return alias
  const section = (SETTINGS_SECTION_KEYS.includes(raw) ? raw : 'brand') as SettingsSection
  return {
    section,
    tab: isSectionTab(section, tabParam) ? (tabParam as string) : defaultTab(section),
  }
}

// parseSettingsSection 保留原签名，供只关心分区、不关心页签的调用方使用。
export function parseSettingsSection(v: string | null | undefined): SettingsSection {
  return resolveSettingsLocation(v, null).section
}

// 分区子项的跳转地址：brand 为默认分区，不带参数，保持 URL 干净；
// 带页签的分区始终把页签写进地址，便于分享与浏览器回退。
export function settingsSectionPath(key: SettingsSection, tab?: string): string {
  if (key === 'brand') return '/admin/settings'
  if (settingsTabs(key).length === 0) return `/admin/settings?section=${key}`
  return `/admin/settings?section=${key}&tab=${isSectionTab(key, tab) ? tab : defaultTab(key)}`
}
