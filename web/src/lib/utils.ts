import { utcToZonedParts } from './timezone'
import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// 语言感知的日期格式化。UI 通过 useI18n().t('date.format', …) 生成文案。
//
// 所有时间一律按系统时区（后端下发，默认 UTC+8）换算后再取日历字段，
// 不再直接读浏览器本地时区，避免与后端日志/统计的时区口径不一致。
function zonedParts(iso: string) {
  const ms = new Date(iso).getTime()
  return utcToZonedParts(ms)
}

// 语言感知版本：供 i18n 页面使用。lang 为 i18n 语言代码（zh-CN/zh-TW/ja/en）。
export function formatDateTimeI18n(iso: string, lang: string): string {
  const d = zonedParts(iso)
  if (!d) return '—'
  const pad = (n: number) => String(n).padStart(2, '0')
  if (lang === 'en') {
    return `${d.year}/${d.month}/${d.day} ${pad(d.hours)}:${pad(d.minutes)}`
  }
  return `${d.year}年${d.month}月${d.day}日 ${pad(d.hours)}:${pad(d.minutes)}`
}

export function formatDayI18n(iso: string, lang: string): string {
  const d = zonedParts(iso)
  if (!d) return '—'
  if (lang === 'en') {
    return `${d.month}/${d.day}`
  }
  return `${d.month}月${d.day}日`
}

// 区县后缀：县 / 旗 均为明确的县级行政区名称后缀（「区」存在歧义，如「内蒙古自治区」，不纳入）。
const COUNTY_SUFFIXES = ['县', '旗']

// formatIpRegion 归一化 IP 归属地展示串：国家 · 省/州 · 城市 · 运营商。
//
// 历史记录里存的是旧格式（含区县与冗余的国家代码，例如
// 「中国 · 甘肃省 · 兰州市 · 榆中县 · 联通 · CN」），服务端重新解析只会影响新数据，
// 因此展示侧再裁剪一次，保证新旧数据呈现一致。
export function formatIpRegion(region?: string | null): string {
  const raw = (region ?? '').trim()
  if (!raw) return ''
  const segs = raw.split('·').map((s) => s.trim()).filter(Boolean)
  if (segs.length <= 1) return raw
  // 去掉冗余的 CN（国家名已用「中国」给出）
  if (segs[segs.length - 1].toUpperCase() === 'CN') segs.pop()
  // 去掉区县
  const out = segs.filter((s, i) => i === 0 || !COUNTY_SUFFIXES.some((sfx) => s.endsWith(sfx)))
  return out.length ? out.join(' · ') : raw
}

// methodLabelKey 把事件元数据里的登录方式映射为 i18n key。
//
// 此前这里（classForMethod）直接返回中英文字面量：日文与繁体用户看到的是中文，
// 而且 events.method* 这 5 条已经翻译好的文案全部成了死 key。改为只返回 key，
// 由调用方走 t()，四种语言自然一致。
export function methodLabelKey(method?: string): string {
  const map: Record<string, string> = {
    password: 'events.methodPassword',
    emailCode: 'events.methodEmailCode',
    passkey: 'events.methodPasskey',
    thirdParty: 'events.methodThirdParty',
  }
  return map[method ?? ''] ?? 'events.methodOther'
}

// safeExternalUrl 校验外部链接地址，只放行 http / https。
//
// 应用（OAuth client）的 Logo / 主页地址由管理员填写，前端会渲染进
// <img src> / <a href>。若原样透传，javascript:alert(document.cookie) 这类取值
// 会让所有访问 /apps 的用户在点击时于本站域内执行脚本（存储型 XSS）。
// 后端入库前已做白名单，这里再兜一层：历史数据与直接改库的场景仍可能带毒。
export function safeExternalUrl(raw?: string | null): string {
  const v = (raw ?? '').trim()
  if (!v) return ''
  try {
    const u = new URL(v)
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return ''
    if (!u.host) return ''
    return v
  } catch {
    return ''
  }
}

// secretPlaceholder 统一密钥/密码类输入框的占位提示：
//   - 未配置：完全留空，不出现任何「已配置」字样；
//   - 已配置：提示「留空不修改」，并说明提交空值即保留原值。
//
// 仅用于系统配置里的凭据字段（SMTP 密码、人机验证密钥、对象存储密钥、
// 代理密码、OAuth 提供商 Client Secret 等）。登录、注册、找回密码、
// 修改密码、二次验证码等用户侧输入框不适用本规则。
//
// configured 必须取自后端 payload（或列表项）里的 hasXxx / xxxSet 标记：
// 手工构造的表单对象通常不含该标记，传进来恒为 falsy，提示就永远不出现
// ——「保存成功却看不到留空提示」看起来和没保存一样。
export function secretPlaceholder(configured: boolean, text: string): string {
  return configured ? text : ''
}

// formatDayKey 按系统时区把时间点格式化为 YYYY-MM-DD（用于导出文件名等）。
export function formatDayKey(ms: number): string {
  const d = utcToZonedParts(ms)
  if (!d) return ''
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.year}-${pad(d.month)}-${pad(d.day)}`
}
