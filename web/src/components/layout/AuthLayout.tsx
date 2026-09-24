import * as React from 'react'
import { KeyRound, MonitorSmartphone, Fingerprint, ShieldCheck, Sun, Moon, Check } from 'lucide-react'
import { useI18n, LangToggle } from '../../i18n'
import { useTheme } from '../../hooks/useTheme'
import { DropdownMenu, DropdownMenuTrigger, DropdownMenuContent, DropdownMenuItem } from '../ui/dropdown-menu'
import { PublicSiteFooter } from './SiteFooter'
import { useSiteBrand } from '../../hooks/useSiteBrand'

// 主题切换（登录/注册/找回密码页复用）
export function ThemeToggle() {
  const { theme, setTheme, resolvedTheme } = useTheme()
  const { t } = useI18n()
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        className="inline-flex size-9 items-center justify-center gap-2 rounded-full text-sm font-medium transition-all hover:bg-accent hover:text-accent-foreground"
        aria-label={t('theme.toggle')}
      >
        {/* 浅色模式显示太阳，深色模式显示月亮（system 按实际生效外观解析） */}
        {resolvedTheme === 'dark' ? <Moon className="size-[1.2rem]" /> : <Sun className="size-[1.2rem]" />}
        <span className="sr-only">{t('theme.toggle')}</span>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={() => setTheme('light')}>
          {t('appearance.themeLight')} {theme === 'light' && <Check className="ms-auto" />}
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setTheme('dark')}>
          {t('appearance.themeDark')} {theme === 'dark' && <Check className="ms-auto" />}
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => setTheme('system')}>
          {t('appearance.themeSystem')} {theme === 'system' && <Check className="ms-auto" />}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

// 语言 + 主题切换（桌面端右上角 / 移动端卡片头部）
export function AuthToggles({ className }: { className?: string }) {
  return (
    <div className={className}>
      <LangToggle />
      <ThemeToggle />
    </div>
  )
}

// 移动端卡片头部：品牌 + 语言/主题切换（登录/注册页）
export function AuthCardMobileHeader() {
  const { t } = useI18n()
  const { logo } = useSiteBrand()
  return (
    <div className="flex w-full items-center justify-between gap-3 lg:hidden">
      <div className="flex min-w-0 items-center gap-3">
        <div className="size-10 shrink-0 overflow-hidden rounded-md">
          <img alt="" className="size-full object-contain" src={logo} />
        </div>
        <div className="min-w-0">
          <p className="truncate text-base font-semibold">{t('brand.name')}</p>
        </div>
      </div>
      <AuthToggles className="flex shrink-0 items-center gap-1" />
    </div>
  )
}

// 未登录通用布局：左品牌分栏 + 右表单卡片（登录/注册/找回密码页共用）
export function AuthLayout({ children }: { children: React.ReactNode }) {
  const { t } = useI18n()
  const { logo } = useSiteBrand()
  return (
    <div className="grid min-h-svh bg-muted/20 lg:grid-cols-[minmax(320px,0.95fr)_minmax(420px,1.05fr)]">
      {/* Left: brand split */}
      <aside className="hidden border-r bg-background p-10 lg:flex lg:flex-col">
        <div className="flex items-center gap-3">
          <div className="size-10 shrink-0 overflow-hidden rounded-md">
            <img alt="" className="size-full object-contain" src={logo} />
          </div>
          <div className="min-w-0">
            <p className="truncate font-semibold uppercase">{t('brand.name')}</p>
          </div>
        </div>

        <div className="mt-16 max-w-sm">
          <p className="text-xs font-medium uppercase tracking-[0.18em] text-muted-foreground">{t('brand.slogan1')}</p>
          <h1 className="mt-4 max-w-xs text-3xl font-semibold leading-tight">{t('brand.slogan2')}</h1>
          <p className="mt-3 max-w-sm text-sm leading-6 text-muted-foreground">{t('brand.subtitle')}</p>
          <div className="mt-8 flex flex-col gap-4 border-l pl-4">
            {[
              { icon: KeyRound, title: t('login.feat1.title'), desc: t('login.feat1.desc') },
              { icon: MonitorSmartphone, title: t('login.feat2.title'), desc: t('login.feat2.desc') },
              { icon: Fingerprint, title: t('login.feat3.title'), desc: t('login.feat3.desc') },
            ].map(({ icon: Icon, title, desc }) => (
              <div className="flex gap-3" key={title}>
                <div className="grid size-9 shrink-0 place-items-center rounded-md bg-muted text-muted-foreground">
                  <Icon className="size-4" />
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-medium">{title}</p>
                  <p className="mt-1 text-xs leading-5 text-muted-foreground">{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="mt-auto flex max-w-sm flex-col gap-5">
          <ShieldCheck className="size-8 stroke-1 text-muted-foreground" />
          <div className="flex flex-col gap-2">
            <p className="text-2xl font-semibold tracking-tight">{t('brand.footerTitle')}</p>
            <p className="text-sm leading-6 text-muted-foreground">{t('brand.footerDesc')}</p>
          </div>
          <p className="text-xs text-muted-foreground">{t('brand.footer')}</p>
        </div>
      </aside>

      {/* Right: form */}
      {/* min-w-0 必须有：grid 子项默认 min-width:auto，会被内容撑到 min-content 宽度
          （实测 364px），窄屏下整页横向溢出、卡片右侧被切掉。 */}
      <main className="relative flex min-h-svh min-w-0 flex-col px-4 py-6 sm:px-8 sm:py-10 max-sm:p-0">
        {/* 右上角：语言 + 主题下拉（仅桌面端） */}
        <AuthToggles className="absolute right-8 top-8 hidden items-center gap-1 lg:flex" />
        {/* 表单在剩余空间内垂直居中，页脚固定在底部（备案信息需始终可见） */}
        <div className="flex w-full flex-1 items-center justify-center">
          <div className="w-full max-w-md max-sm:max-w-none max-sm:self-stretch">{children}</div>
        </div>
        <PublicSiteFooter className="pt-8 max-sm:px-4 max-sm:pb-6" />
      </main>
    </div>
  )
}
