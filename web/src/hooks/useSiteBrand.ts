// 站点品牌资源（Logo / Favicon）。
//
// 后端 /api/v1/site 与 /api/v1/session 都会下发后台「品牌信息」配置的 logo 与
// favicon，但此前前端把 /images/logo.svg 硬编码在登录页、侧栏、找回密码页，
// favicon 更是从未写进 <link rel="icon">——后台填了等于白填。
// 这里统一取用：取不到（未配置 / 未加载）时回落到内置资源。
//
// 数据来自 react-query 的 ['site-info']（与站点页脚共用同一份缓存，不会多打请求）。

import * as React from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { SiteInfo } from './useSession'

// 内置默认资源：站点未配置时使用，保证任何部署形态下都有稳定的品牌展示。
export const DEFAULT_LOGO = '/images/logo.svg'
export const DEFAULT_FAVICON = '/images/logo.svg'

// sanitizeBrandURL 只接受站内绝对路径与 http/https 绝对地址。
// 后台数据可能被直接改库写入奇怪取值，前端渲染前再兜一层，
// 避免把奇怪协议塞进 <img src> / <link href>。
// 拒绝协议相对地址（//host）：它看起来像站内路径，实际指向外部站点。
export function sanitizeBrandURL(raw?: string | null): string {
  const v = (raw ?? '').trim()
  if (!v) return ''
  if (v.startsWith('//')) return ''
  if (v.startsWith('/')) return v
  if (/^https?:\/\//i.test(v)) return v
  return ''
}

// applySiteFavicon 按站点配置应用图标（含未配置时的内置回落）。
// 供已登录会话（useSession）与公开站点信息（useSiteBrand）共用同一份实现，
// 避免两处各写一遍、行为漂移。
export function applySiteFavicon(site?: { favicon?: string } | null) {
  applyFavicon(sanitizeBrandURL(site?.favicon) || DEFAULT_FAVICON)
}

// applyFavicon 把站点图标写入 <link rel="icon">。
// 复用已有的 link 标签（index.html 内置一个），没有则创建一个。
export function applyFavicon(href: string) {
  if (typeof document === 'undefined') return
  let link = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
  if (!link) {
    link = document.createElement('link')
    link.rel = 'icon'
    document.head.appendChild(link)
  }
  link.type = href.endsWith('.svg') ? 'image/svg+xml' : 'image/x-icon'
  link.href = href
}

// useSiteBrand 返回当前生效的品牌资源，并把 favicon 应用到文档。
export function useSiteBrand() {
  const { data } = useQuery({
    queryKey: ['site-info'],
    queryFn: () => api.siteInfo<SiteInfo>(),
    staleTime: 5 * 60 * 1000,
    retry: false,
  })

  const logo = sanitizeBrandURL(data?.logo) || DEFAULT_LOGO
  const favicon = sanitizeBrandURL(data?.favicon) || DEFAULT_FAVICON

  React.useEffect(() => {
    if (data) applyFavicon(favicon)
  }, [data, favicon])

  return { logo, favicon, site: data }
}
