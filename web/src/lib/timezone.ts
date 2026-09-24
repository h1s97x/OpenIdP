// 系统时区：前端所有时间展示都以后端下发的系统时区为准。
//
// 后端通过 /api/v1/site 下发 timezone（IANA 名，默认 Asia/Shanghai）与
// utcOffsetMinutes（当前时刻偏移）。这里在首屏前读取并缓存，
// 之后 formatDateTime（lib/utils）统一按该时区渲染，
// 避免「服务端按 UTC+8 统计、浏览器按本地时区展示」造成的时间错位。

export interface SiteTimezone {
  /** IANA 时区名，如 Asia/Shanghai */
  name: string
  /** 当前时刻相对 UTC 的偏移分钟数 */
  offsetMinutes: number
  /** 可读标签，如 UTC+08:00 */
  label: string
}

const DEFAULT_TIMEZONE: SiteTimezone = {
  name: 'Asia/Shanghai',
  offsetMinutes: 8 * 60,
  label: 'UTC+08:00',
}

const TZ_CACHE_KEY = '__openidp_system_timezone__'

function normalize(raw: unknown): SiteTimezone {
  const v = raw as { timezone?: unknown; utcOffsetMinutes?: unknown; timezoneLabel?: unknown } | null
  const name = typeof v?.timezone === 'string' && v.timezone.trim() ? v.timezone.trim() : DEFAULT_TIMEZONE.name
  const offset = typeof v?.utcOffsetMinutes === 'number' && Number.isFinite(v.utcOffsetMinutes)
    ? v.utcOffsetMinutes
    : offsetFromName(name) ?? DEFAULT_TIMEZONE.offsetMinutes
  const label = typeof v?.timezoneLabel === 'string' && v.timezoneLabel.trim()
    ? v.timezoneLabel.trim()
    : labelFromOffset(offset)
  return { name, offsetMinutes: offset, label }
}

// offsetFromName 用浏览器内置时区库推导偏移；无法识别时返回 null。
function offsetFromName(name: string): number | null {
  try {
    const dtf = new Intl.DateTimeFormat('en-US', { timeZone: name, timeZoneName: 'longOffset' })
    const tzName = dtf.formatToParts(new Date()).find((p) => p.type === 'timeZoneName')?.value ?? ''
    const m = tzName.match(/GMT([+-])(\d{2}):(\d{2})/)
    if (!m) return tzName === 'GMT' ? 0 : null
    const sign = m[1] === '-' ? -1 : 1
    return sign * (Number(m[2]) * 60 + Number(m[3]))
  } catch {
    return null
  }
}

function labelFromOffset(offsetMinutes: number): string {
  const sign = offsetMinutes < 0 ? '-' : '+'
  const abs = Math.abs(offsetMinutes)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`
}

// setSiteTimezone 在拿到站点配置后写入缓存（应用启动时可调用）。
export function setSiteTimezone(raw: unknown): SiteTimezone {
  const tz = normalize(raw)
  ;(globalThis as Record<string, unknown>)[TZ_CACHE_KEY] = tz
  return tz
}

// getSiteTimezone 读取系统时区；未拿到站点配置时返回默认 UTC+8。
export function getSiteTimezone(): SiteTimezone {
  const cached = (globalThis as Record<string, unknown>)[TZ_CACHE_KEY] as SiteTimezone | undefined
  return cached ?? DEFAULT_TIMEZONE
}

// fetchSiteTimezone 在内嵌首帧渲染前同步读取站点时区。
// 与 i18n 的站点默认语言同理：时间展示口径必须首帧就确定，否则会出现
// 「先按本地时区渲染、再跳到系统时区」的可见跳变。失败时静默回落。
export function fetchSiteTimezone(): SiteTimezone {
  const cached = (globalThis as Record<string, unknown>)[TZ_CACHE_KEY] as SiteTimezone | undefined
  if (cached) return cached
  try {
    const xhr = new XMLHttpRequest()
    xhr.open('GET', '/api/v1/site', false)
    xhr.timeout = 3000
    xhr.send()
    if (xhr.status >= 200 && xhr.status < 300) {
      const data = JSON.parse(xhr.responseText)
      return setSiteTimezone(data?.data)
    }
  } catch { /* ignore */ }
  return getSiteTimezone()
}

// utcToZonedParts 把 UTC 毫秒数换算为系统时区下的日历字段。
//
// 实现方式：先按目标时区格式化取出年月日时分，再按同一套日历字段
// 在本地时区重建 Date，读出的字段即为系统时区下的墙钟时间。
// 不依赖浏览器本地时区与旧式 getUTCxxx 的混算。
export function utcToZonedParts(ms: number): { year: number; month: number; day: number; hours: number; minutes: number; seconds: number } | null {
  if (!Number.isFinite(ms)) return null
  const tz = getSiteTimezone()
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz.name,
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
    }).formatToParts(new Date(ms))
    const pick = (type: string) => Number(parts.find((p) => p.type === type)?.value ?? '')
    const year = pick('year')
    const month = pick('month')
    const day = pick('day')
    const hours = pick('hour') % 24
    const minutes = pick('minute')
    const seconds = pick('second')
    if (![year, month, day, hours, minutes, seconds].every((n) => Number.isFinite(n))) return null
    return { year, month, day, hours, minutes, seconds }
  } catch {
    // 目标时区不被浏览器支持时退回偏移换算（保证仍按 UTC+8 展示）。
    const shifted = new Date(ms + tz.offsetMinutes * 60_000)
    return {
      year: shifted.getUTCFullYear(),
      month: shifted.getUTCMonth() + 1,
      day: shifted.getUTCDate(),
      hours: shifted.getUTCHours(),
      minutes: shifted.getUTCMinutes(),
      seconds: shifted.getUTCSeconds(),
    }
  }
}
