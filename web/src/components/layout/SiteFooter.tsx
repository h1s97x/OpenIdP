import * as React from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../../lib/api'
import type { SiteInfo } from '../../hooks/useSession'
import { cn } from '../../lib/utils'
import { setSiteTimezone } from '../../lib/timezone'

// 备案查询入口
const ICP_URL = 'https://beian.miit.gov.cn/'
const PSB_URL = 'https://www.beian.gov.cn/portal/registerSystemInfo'

// 公安备案号形如「京公网安备11010802000000号」，末位为「号」，
// 查询参数 recordcode 只取其中的数字串。
function recordCode(beian: string): string {
  const m = beian.match(/\d{6,}/)
  return m ? m[0] : ''
}

function trim(v?: string): string {
  return (v ?? '').trim()
}

// 站点页脚：展示后台「系统设置 → 品牌信息」配置的页脚文本与备案号。
// 未配置任何内容时返回 null，避免登录页/控制台出现空壳区域。
export function SiteFooter({
  site,
  className,
}: {
  site?: Partial<SiteInfo> | null
  className?: string
}) {
  const footerText = trim(site?.footerText)
  const icp = trim(site?.icpBeian)
  const psb = trim(site?.publicSecurityBeian)
  // 未自定义页脚文本时，回落到「© 年份 站点名」的通用版权行。
  const copyright = footerText || (site?.displayName ? `© ${new Date().getFullYear()} ${site.displayName}` : '')

  if (!copyright && !icp && !psb) return null

  return (
    <footer className={cn('flex flex-col items-center gap-1.5 text-center text-xs text-muted-foreground', className)}>
      {copyright && <div className="leading-5">{copyright}</div>}
      {(icp || psb) && (
        <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1">
          {icp && (
            <a
              href={ICP_URL}
              target="_blank"
              rel="noreferrer noopener"
              className="transition-colors hover:text-foreground hover:underline"
            >
              {icp}
            </a>
          )}
          {psb && (
            <a
              href={recordCode(psb) ? `${PSB_URL}?recordcode=${recordCode(psb)}` : PSB_URL}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-1 transition-colors hover:text-foreground hover:underline"
            >
              {/* 公安联网备案标识（内联 SVG，避免额外图标资源请求） */}
              <svg viewBox="0 0 24 24" aria-hidden className="size-3.5 shrink-0 fill-current">
                <path d="M12 2 3 5.5v6.2c0 5.3 3.7 9.3 9 10.3 5.3-1 9-5 9-10.3V5.5L12 2Zm0 2.2 6.8 2.6v4.9c0 4-2.6 7.1-6.8 8.1-4.2-1-6.8-4.1-6.8-8.1V6.8L12 4.2Zm-1 3.3v2.3H8.7v1.9H11v2.3h1.9v-2.3h2.4v-1.9h-2.4V7.5H11Z" />
              </svg>
              {psb}
            </a>
          )}
        </div>
      )}
    </footer>
  )
}

// 未登录页面（登录 / 注册 / 找回密码 / 授权确认）专用：自行拉取公开站点信息。
// 控制台（AppShell）已持有 session.site，直接传 site 渲染即可，无需重复请求。
export function PublicSiteFooter({ className }: { className?: string }) {
  const { data: site } = useQuery({
    queryKey: ['site-info'],
    queryFn: () => api.siteInfo<SiteInfo>(),
    staleTime: 5 * 60 * 1000,
    retry: false,
  })
  // 公开站点信息同样携带系统时区：未登录页面也要按系统时区展示时间。
  React.useEffect(() => {
    if (site) setSiteTimezone(site)
  }, [site])
  return <SiteFooter site={site} className={className} />
}
