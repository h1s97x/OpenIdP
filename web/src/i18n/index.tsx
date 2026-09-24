// 全局 i18n：基于 i18next 的多语言支持（简体中文 / 繁體中文 / 日本語 / English）。
// 保持 useI18n()/t()/LangToggle 的 API 不变。
//
// 语言优先级：
//  1. 本浏览器保存过的选择（localStorage，key: openidp.lang）——用户显式切换过就记住；
//  2. 站点默认语言（由 /api/v1/site 下发，管理后台「品牌信息」可配，未配置为简体中文）；
//  3. 简体中文兜底。
//
// 注意：不再跟随浏览器 navigator.language —— 未登录时必须落到站点默认语言，
// 而不是该访客系统语言；只有用户在本浏览器主动切换过才覆盖默认值。
//
// 说明：t() 直接读取当前 lang 对应的语言字典（同步），而不是依赖 i18next 内部的
// 异步 changeLanguage()。因为 setLang 触发 React 重渲染的时机早于 useEffect 里
// 的 i18n.changeLanguage()，若 t() 走 i18n.t()，重渲染瞬间 i18next 仍停留在旧语言，
// 导致“选择的语言与显示语言不对应”。改为按 React 的 lang 状态读字典后彻底消除该竞态。
//
// 字典就绪前必须让 t() 返回稳定的占位值：
// t() 是 useCallback 且依赖 [lang, ready]，在 lang 变化而目标字典尚未加载完成时，
// 它会返回一棵“值不同、但组件类型序列相同”的新元素树。React 对函数组件做 bailout
// 判断时，看到同一元素类型的子元素会沿 alternate 复用子 fiber 并 skip 其子树更新，
// 于是「旧文案节点被原样复用」——现象就是：首次切换语言点完没反应，
// 再切一次（此时目标语言包已在上一轮加载完）才生效。
//
// 字典按需加载：四个语言字典不再静态 import（此前无论用户用哪种语言都要下载全部
// 约 312KB 的 i18n chunk），改为 init 时只加载当前语言 + 回退语言（zh-CN），
// 其余语言在用户切换时才动态 import。
import * as React from 'react'
import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'
import { Languages } from 'lucide-react'
import { Select, SelectItem } from '../components/ui/select'
export type Lang = 'zh-CN' | 'zh-TW' | 'ja' | 'en'

// 字典的按需加载器：返回值是「扁平 key → 文案」的普通对象。
// 用动态 import 让打包器为每个语言产出独立 chunk。
const LOADERS: Record<Lang, () => Promise<Record<string, string>>> = {
  'zh-CN': () => import('./zh-CN').then((m) => m.default as unknown as Record<string, string>),
  'zh-TW': () => import('./zh-TW').then((m) => m.default as unknown as Record<string, string>),
  ja: () => import('./ja').then((m) => m.default as unknown as Record<string, string>),
  en: () => import('./en').then((m) => m.default as unknown as Record<string, string>),
}

// 已加载的语言字典（扁平 key → 文案），t() 直接按当前 lang 读取，保证切换即时生效。
// 只有真正被访问过的语言才会出现在这里，未加载的语言按下文回退。
const RESOURCES: Partial<Record<Lang, Record<string, string>>> = {}

// LANG_KEY 是本浏览器的语言记忆，仅存 localStorage。
const LANG_KEY = 'openidp.lang'

// writeLangCache 写入本浏览器的语言记忆。
function writeLangCache(lang: Lang) {
  try { localStorage.setItem(LANG_KEY, lang) } catch { /* ignore */ }
}

function isLang(v: string): boolean {
  return v === 'zh-CN' || v === 'zh-TW' || v === 'ja' || v === 'en'
}

// 语言代码 → 本地语言名（用于语言切换下拉）
export const LANG_OPTIONS: { value: Lang; label: string }[] = [
  { value: 'zh-CN', label: '简体中文' },
  { value: 'zh-TW', label: '繁體中文' },
  { value: 'ja', label: '日本語' },
  { value: 'en', label: 'English' },
]

// 初始化 i18next。资源不在此处静态注入（改为 loadLanguage 按需注册），
// 仅保留语言检测、回退与插值配置。
// 语言检测交由本文件的 detectInitialLang 处理（本浏览器记忆 / 站点默认语言），
// 不再挂 LanguageDetector：它默认会读取 navigator.language，
// 会让未登录访客的语言跑偏到「访客系统语言」而不是站点默认语言。
i18n
  .use(initReactI18next)
  .init({
    resources: {},
    fallbackLng: 'zh-CN',
    supportedLngs: ['zh-CN', 'zh-TW', 'ja', 'en'],
    nonExplicitSupportedLngs: true,
    load: 'currentOnly',
    interpolation: { escapeValue: false },
  })

// 语言加载的进行中/已完成状态：同一语言只加载一次。
const pending = new Map<Lang, Promise<void>>()

// loadLanguage 按需加载并注册某个语言字典。重复调用复用同一个 Promise。
export function loadLanguage(lang: Lang): Promise<void> {
  const cached = pending.get(lang)
  if (cached) return cached
  const p = LOADERS[lang]()
    .then((dict) => {
      RESOURCES[lang] = dict
      // 同步注册到 i18next：LangToggle 之外还有少量 i18n.t() 调用点（如日期格式）。
      i18n.addResourceBundle(lang, 'translation', dict, true, true)
    })
    .catch((err) => {
      // 加载失败时退化为「返回 key 本身」，不阻断渲染。
      console.error(`[i18n] 语言包加载失败: ${lang}`, err)
    })
  pending.set(lang, p)
  return p
}

// detectInitialLang 读取本浏览器记住的语言；没记住过则返回 null，
// 由调用方在拿到站点配置后回落到站点默认语言。
function detectSavedLang(): Lang | null {
  try {
    const saved = localStorage.getItem(LANG_KEY)
    if (saved && isLang(saved)) return saved as Lang
  } catch { /* ignore */ }
  return null
}

// DEFAULT_LANG 是兜底语言：站点默认语言尚未下发时的取值。
const DEFAULT_LANG: Lang = 'zh-CN'
const SITE_DEFAULT_KEY = '__openidp_site_default_lang__'

// fetchSiteDefaultLang 在首屏前读取站点默认语言。
// 用同步 XHR 是刻意的：语言必须在内嵌首帧渲染前确定，否则会出现
// 「先按默认语言渲染 → 拿到配置再切换」的整页闪烁。请求很小且带 3s 超时，
// 失败时静默回落到简体中文。
function fetchSiteDefaultLang(): Lang | null {
  try {
    const cached = (window as any)[SITE_DEFAULT_KEY]
    if (cached) return cached as Lang
    const xhr = new XMLHttpRequest()
    xhr.open('GET', '/api/v1/site', false)
    xhr.timeout = 3000
    xhr.send()
    if (xhr.status >= 200 && xhr.status < 300) {
      const data = JSON.parse(xhr.responseText)
      const v = data?.data?.defaultLanguage
      const lang = typeof v === 'string' && isLang(v) ? (v as Lang) : null
      if (lang) (window as any)[SITE_DEFAULT_KEY] = lang
      return lang
    }
  } catch { /* ignore */ }
  return null
}

// detectInitialLang：本浏览器记忆优先，其次站点默认语言，最后简体中文。
function detectInitialLang(): Lang {
  return detectSavedLang() ?? fetchSiteDefaultLang() ?? DEFAULT_LANG
}

export interface I18nContextValue {
  lang: Lang
  setLang: (l: Lang) => void
  t: (key: string, vars?: Record<string, string | number>) => string
}

const I18nContext = React.createContext<I18nContextValue>({
  lang: 'zh-CN',
  setLang: () => {},
  t: (k) => k,
})

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = React.useState<Lang>(detectInitialLang)
  // ready 表示当前语言的字典已就绪。未就绪时 t() 返回空串，
  // 加载完成后置 true 触发一次重渲染，页面文案随即补齐。
  const [ready, setReady] = React.useState(false)

  // 语言字典加载：首次挂载加载当前语言 + 回退语言（zh-CN），
  // 后续切换语言时只加载目标语言，已加载过的语言不会重复下载。
  React.useEffect(() => {
    let alive = true
    // 切换语言时先把 ready 复位：配合 t() 的「未就绪返回空串」，
    // 保证字典到位前后渲染结果是确定的，不会出现半截旧文案。
    if (!RESOURCES[lang]) setReady(false)
    const need: Lang[] = lang === 'zh-CN' ? ['zh-CN'] : ['zh-CN', lang]
    Promise.all(need.map(loadLanguage)).then(() => {
      if (alive) setReady(true)
    })
    return () => { alive = false }
  }, [lang])

  // 初始化时同步 i18next 语言
  React.useEffect(() => {
    if (i18n.language !== lang) {
      i18n.changeLanguage(lang)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  React.useEffect(() => {
    document.documentElement.lang = lang
    i18n.changeLanguage(lang)
  }, [lang])

  // setLang 是用户显式切换语言的唯一入口：只有这时才写入本浏览器记忆。
  //
  // 不在初始化时落缓存是刻意的：站点默认语言可能被管理员随时调整，
  // 若首次访问就把「当时的默认值」当成用户选择存下来，
  // 之后无论后台怎么改，该浏览器都会一直停留在旧语言。
  const setLang = React.useCallback((l: Lang) => {
    writeLangCache(l)
    setLangState(l)
    // 立即发起目标语言包加载：它通常早于本次重渲染的提交阶段完成，
    // 用户视觉上是一次即生效，无需任何二次点击。
    void loadLanguage(l)
  }, [])

  const t = React.useCallback(
    (key: string, vars?: Record<string, string | number>): string => {
      // 目标语言的字典尚未加载完成时，一律返回「与上一次渲染完全相同」的空串。
      //
      // 不能在这里回退到 zh-CN 文案：t() 是 useCallback([lang, ready])，lang 一变就会
      // 生成一棵新的元素树；而 React 在 beginWork 前的 bailoutOnAlreadyFinishedWork 会
      // 把「元素类型与上一次相同」的子元素视为可复用 —— 直接沿 alternate 复用子 fiber
      // 并跳过整棵子树的更新。于是语言包加载完成后的那次重渲染，会被这类“文案值变了、
      // 但组件类型序列没变”的层挡住，旧文案原样留在页面上。
      // 表现为：第一次点切换语言“没有反应”，必须先切到别的语言（顺带把目标语言包加载完）
      // 再切回来才显示正确。
      //
      // 统一返回 '' 后，语言包就绪前后的元素树在结构上一致，是否重渲染完全由 lang
      // 决定，不再掺杂“字典有没有加载好”这一偶然因素。
      if (!ready || !RESOURCES[lang]) return ''
      let raw = RESOURCES[lang][key] ?? key
      if (vars) {
        for (const [k, v] of Object.entries(vars)) {
          raw = raw.replace(`{${k}}`, String(v))
        }
      }
      return raw
    },
    [lang, ready] // eslint-disable-line react-hooks/exhaustive-deps
  )

  const value = React.useMemo<I18nContextValue>(
    () => ({
      lang,
      setLang,
      t,
    }),
    [lang, setLang, t]
  )

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n() {
  return React.useContext(I18nContext)
}

// 便捷组件：语言切换下拉（登录页 / TopBar 复用）
export function LangToggle({ className }: { className?: string }) {
  const { lang, setLang } = useI18n()
  return (
    <Select
      value={lang}
      onValueChange={(v) => setLang(v as Lang)}
      className={className}
      size="sm"
      ariaLabel="语言"
      icon={<Languages className="size-4" />}
    >
      {LANG_OPTIONS.map((o) => (
        <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
      ))}
    </Select>
  )
}
