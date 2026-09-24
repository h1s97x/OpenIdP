import * as React from 'react'
import { NavLink, Outlet, useLocation, useNavigate, useSearchParams } from 'react-router-dom'
import {
  LayoutDashboard, AppWindow, Shield, User, Settings2,
  Palette, MonitorSmartphone, History, ChevronsLeft, ChevronsRight,
  PanelLeft, Users, FileClock, X, ChevronDown,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { cn } from '../../lib/utils'
import { SETTINGS_SECTIONS, settingsSectionPath, resolveSettingsLocation } from '../../lib/settings-sections'
import type { SettingsSection } from '../../lib/settings-sections'
import { useSession } from '../../hooks/useSession'
import { useAppearance } from '../../hooks/useAppearance'
import { useIsMobile } from '../../hooks/useMediaQuery'
import { useI18n } from '../../i18n'
import { NotificationCenter } from './NotificationCenter'
import { SiteFooter } from './SiteFooter'
import { AppearanceDrawer } from '../appearance/AppearanceDrawer'
import { UserMenu } from './UserMenu'
import { useSiteBrand } from '../../hooks/useSiteBrand'


// 系统设置下拉的展开状态持久化到 localStorage。此前只在进入 /admin/settings 时
// 置 true 且从不复位，一旦访问过就永久展开，把个人区的条目挤出视野；
// 现在由「系统设置」条目本身切换，并记住用户的选择。
const SETTINGS_OPEN_KEY = 'openidp.sidebar.settings'

// NavItem 是侧栏的一条条目。
//   collapsible —— 该条目不是导航链接，而是展开/收起子项的开关（仅系统设置）
type NavItem = {
  to: string
  label: string
  icon: LucideIcon
  collapsible?: boolean
}

// 侧栏分组。
//   admin —— 管理员分组：仅用于在用户级与管理级之间渲染一条分隔线。
//            除此之外与用户分组样式完全一致，不叠加徽章、色条或主色。
type NavGroup = {
  key: string
  label: string
  admin?: boolean
  items: NavItem[]
}

// 侧栏字号（固定 normal 档）：菜单项 / 分组标题 / 图标 / 行高 / 侧栏宽度。
// 整体取偏紧凑的一档：侧栏只是导航，过宽会挤压正文、过大的字号在二级子项
// （系统设置分区）上会快速撑满高度。
const SIDEBAR_SCALE = {
  normal: { item: 'text-[13px]', group: 'text-[11px]', icon: 'size-[15px]', subIcon: 'size-3', row: 'py-1.5', width: 'w-52' },
} as const

// GroupHeader 渲染分组标题（静态）。
// 管理员分组与用户分组样式完全一致——区分只靠两者之间那条横线。
function GroupHeader({ label, size }: { label: string; size: string }) {
  return (
    <div className={cn('mb-1 px-2 font-medium text-muted-foreground', size)}>
      {label}
    </div>
  )
}

// NavRow 渲染一条普通导航条目。
function NavRow({
  to, label, icon: Icon, row, item, iconSize, collapsed, onNavigate,
}: {
  to: string
  label: string
  icon: LucideIcon
  row: string
  item: string
  iconSize: string
  collapsed: boolean
  onNavigate?: () => void
}) {
  return (
    <NavLink
      to={to}
      end
      title={collapsed ? label : undefined}
      onClick={onNavigate}
      className={({ isActive }) =>
        cn(
          'flex items-center gap-2 rounded-md transition-colors',
          row, item,
          collapsed ? 'justify-center px-0' : 'px-2',
          'hover:bg-muted hover:text-sidebar-foreground',
          isActive ? 'bg-sidebar-accent text-sidebar-accent-foreground font-medium' : 'text-muted-foreground'
        )
      }
    >
      <Icon className={cn('shrink-0', iconSize)} />
      {!collapsed && <span className="whitespace-nowrap">{label}</span>}
    </NavLink>
  )
}

export function AppShell() {
  const { t } = useI18n()
  const [collapsed, setCollapsed] = React.useState(false)
  const [appearanceOpen, setAppearanceOpen] = React.useState(false)
  const [mobileOpen, setMobileOpen] = React.useState(false)
  const isMobile = useIsMobile()
  const location = useLocation()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const [loading, setLoading] = React.useState(false)
  const prevPath = React.useRef(location.pathname)
  const [settingsOpen, setSettingsOpen] = React.useState(() => {
    try { return localStorage.getItem(SETTINGS_OPEN_KEY) === '1' } catch { return false }
  })

  // 高亮只在系统设置页内生效：离开设置页后子项必须全部熄灭，
  // 否则切到个人总览等页面时「品牌信息」还会一直亮着。
  // 归一化走 resolveSettingsLocation：旧地址（?section=mail / sms / notifications）
  // 也要高亮到合并后的「消息服务」，否则从旧书签进来会没有选中项。
  const activeSection: SettingsSection | null = React.useMemo(() => {
    if (!location.pathname.startsWith('/admin/settings')) return null
    return resolveSettingsLocation(searchParams.get('section'), searchParams.get('tab')).section
  }, [searchParams, location.pathname])

  const onAdminSettings = location.pathname.startsWith('/admin/settings')

  // 进入系统设置时自动展开；用户手动收起后不在此处强制拉回
  // （该 effect 只在 pathname 变化时执行，不会与折叠操作打架）。
  React.useEffect(() => {
    if (onAdminSettings) setSettingsOpen(true)
  }, [onAdminSettings])

  React.useEffect(() => {
    try { localStorage.setItem(SETTINGS_OPEN_KEY, settingsOpen ? '1' : '0') } catch { /* ignore */ }
  }, [settingsOpen])

  // 路由切换时仅在顶部展示窄进度条，仅刷新右侧 <Outlet/>，侧边栏保持不动
  React.useEffect(() => {
    if (prevPath.current !== location.pathname) {
      setLoading(true)
      prevPath.current = location.pathname
    }
    const timer = setTimeout(() => setLoading(false), 250)
    return () => clearTimeout(timer)
  }, [location.pathname])
  const { sidebar: sidebarStyle, layout } = useAppearance()
  const { session, capabilities } = useSession()
  // 后台「品牌信息」里配置的 Logo 优先，未配置时回落到内置资源。
  const { logo: brandLogo } = useSiteBrand()
  const sb = SIDEBAR_SCALE['normal']

  const isAdmin = session?.user.isAdmin && !!capabilities

  const isIconLayout = layout === 'icon'
  // 移动端一律按 offcanvas（抽屉）处理；桌面端才遵循用户布局偏好
  const isOffcanvas = isMobile ? true : layout === 'offcanvas'
  const sideCollapsed = isOffcanvas ? !mobileOpen : collapsed

  React.useEffect(() => {
    if (layout === 'icon') setCollapsed(true)
    if (layout === 'default' || layout === 'offcanvas') setCollapsed(false)
  }, [layout])

  // 刷新页面后侧栏是全新挂载的，滚动位置默认停在顶部。当前处于系统设置时，
  // 把选中的分区子项滚动到可视区内，否则刷新后看不到自己选中的是哪一项。
  const activeSubRef = React.useRef<HTMLButtonElement | null>(null)
  // 子项面板：常驻 DOM 并在展开时把实测高度写入 --collapsible-panel-height，
  // 供 CSS keyframe 做 0 ↔ 实测高度 的过渡（不用 max-height 猜值，
  // 否则菜单多出一项就会被截断）。
  // 用 state + ref callback 持有面板节点：面板在管理员分组内，随 session 异步就绪才挂载，
  // 若只用 useRef + effect，首帧 ref 为空时 effect 早退且依赖项不再变化 → 永不重试，
  // 高度变量会一直停在 CSS 兜底值 0（展开入场动画的 to 取值失效）。
  const [subPanelEl, setSubPanelEl] = React.useState<HTMLDivElement | null>(null)
  React.useEffect(() => {
    if (!settingsOpen || sideCollapsed) return
    activeSubRef.current?.scrollIntoView({ block: 'nearest' })
  }, [settingsOpen, sideCollapsed, activeSection])

  // 「系统设置」下拉展开的子项
  const settingsSubItems = React.useMemo(() => SETTINGS_SECTIONS.map((item) => ({
    to: settingsSectionPath(item.key),
    section: item.key,
    label: t(item.labelKey),
    icon: item.icon,
  })), [t])

  // 子项面板高度：展开时把实测高度写入 --collapsible-panel-height 供 CSS 过渡使用。
  // 收起态**不写入**：一是留上次展开的实测值给收回动画 from 取值，二是首屏即收起时
  // 面板此刻可能尚未挂载（管理员分组随 session 异步就绪），若在此写死内容高度，
  // 收起态入场动画会从内容高度收到 0，出现可见闪现（CSS 侧有 0 兜底，见 index.css）。
  React.useLayoutEffect(() => {
    if (!subPanelEl || !settingsOpen) return
    subPanelEl.style.setProperty('--collapsible-panel-height', `${subPanelEl.scrollHeight}px`)
  }, [subPanelEl, settingsOpen, sideCollapsed, settingsSubItems, sb.item])

  // inert 必须走渲染期落属性，不能放 effect：
  // 首屏即收起时面板节点可能尚未就绪（管理员分组随 session 异步就绪），
  // effect 早退后依赖项不再变化 → 永不重试，面板会停在「aria-hidden=true 却仍可 Tab 聚焦」
  // 的 a11y 违规状态（axe: aria-hidden-focus）。
  // React 18 类型定义尚无 inert，故用 spread 透传原生布尔属性（存在即为 inert）。
  const subPanelInert = settingsOpen ? {} : ({ inert: '' } as Record<string, string>)

  // 侧栏结构：个人区按「账号属性 / 发生了什么」分两类；
  // 管理员区为「管理控制台」与「服务配置」两组，与用户区之间仅以一条横线分隔。
  const groups = React.useMemo<NavGroup[]>(() => {
    const personal: NavGroup[] = [
      {
        key: 'overview',
        // 个人总览是首页锚点，独立成组且不显示组名
        label: '',
        items: [{ to: '/', label: t('nav.overview'), icon: LayoutDashboard }],
      },
      {
        key: 'account',
        label: t('nav.account'),
        items: [
          { to: '/settings', label: t('nav.profile'), icon: User },
          { to: '/settings/account', label: t('nav.security'), icon: Shield },
          // 通知设置在「个人资料」页的偏好小节内，侧栏不再单列入口
        ],
      },
      {
        key: 'activity',
        label: t('nav.activity'),
        items: [
          { to: '/sessions', label: t('nav.sessions'), icon: MonitorSmartphone },
          { to: '/events', label: t('nav.events'), icon: History },
          { to: '/apps', label: t('nav.apps'), icon: AppWindow },
        ],
      },
    ]
    if (!isAdmin) return personal
    return [
      ...personal,
      {
        key: 'admin',
        label: t('nav.adminConsole'),
        admin: true,
        items: [
          { to: '/admin', label: t('nav.adminDashboard'), icon: LayoutDashboard },
          { to: '/admin/users', label: t('nav.adminUsers'), icon: Users },
          { to: '/admin/audit', label: t('nav.adminAudit'), icon: FileClock },
        ],
      },
      {
        key: 'service',
        label: t('nav.service'),
        admin: true,
        items: [
          { to: '/admin/settings', label: t('nav.adminSettings'), icon: Settings2, collapsible: true },
        ],
      },
    ]
  }, [t, isAdmin])

  // 「系统设置」条目是展开/收起子项的开关，不是导航链接。
  // 点击只做展开/收起，无论身处哪个页面都不跳转——
  // 用户可能只是在其他页面顺手展开看看，被强行带走会打断当前操作。
  const toggleSettings = () => {
    setSettingsOpen(!settingsOpen)
    // 折叠态点击：先展开侧栏，否则子项无处可显示。
    if (sideCollapsed) setCollapsed(false)
  }

  const sidebarWidth = isOffcanvas
    ? (mobileOpen ? sb.width : 'w-0')
    : (sideCollapsed ? 'w-[52px]' : sb.width)

  // 三种侧栏形态必须在“容器形态”上拉开差距。此前 inset 与 floating 仅相差
  // shadow-sm / shadow-lg，肉眼几乎不可辨，等于该选项失效。
  //   inset    —— 侧栏与内容区同为内嵌卡片（双卡片），外层以 bg-sidebar 衬托
  //   floating —— 侧栏悬浮于内容之上：更大外边距、更大圆角、更重阴影，内容区铺满
  //   standard —— 贴边全高，仅右侧分隔线
  // offcanvas 收起时侧栏宽度为 0，此时必须连外边距/边框/阴影一并移除：
  // 仅设 w-0 是不够的 —— margin 仍会占位、border 仍是可见的 1px 竖线，
  // 表现为“左侧未完整隐藏”。
  const sidebarFullyHidden = isOffcanvas && !mobileOpen

  const sidebarVariantClass = sidebarFullyHidden
    ? ''
    : sidebarStyle === 'inset'
      ? 'm-2 h-[calc(100vh-1rem)] rounded-xl border border-sidebar-border shadow-sm'
      : sidebarStyle === 'floating'
        ? 'm-3 h-[calc(100vh-1.5rem)] rounded-2xl border border-sidebar-border shadow-xl'
        : 'border-r'

  // inset 语义下内容区也应是内嵌卡片，这是它与 floating 的本质区别。
  const mainColumnClass =
    sidebarStyle === 'inset' ? 'm-2 rounded-xl border border-border bg-background shadow-sm' : ''

  return (
    <div className={cn(
      'flex h-screen overflow-hidden text-foreground',
      sidebarStyle === 'inset' ? 'bg-sidebar' : 'bg-background'
    )}>
      {/* 侧栏遮罩（offcanvas 布局展开时） */}
      {isOffcanvas && mobileOpen && (
        <div className="fixed inset-0 z-30 bg-black/40" onClick={() => setMobileOpen(false)} />
      )}

      {/* Sidebar */}
      <aside
        data-state={sideCollapsed ? 'collapsed' : 'expanded'}
        data-variant={sidebarStyle}
        data-collapsible={isOffcanvas ? 'offcanvas' : isIconLayout ? 'icon' : 'none'}
        className={cn(
          'relative z-40 flex shrink-0 flex-col bg-sidebar text-sidebar-foreground transition-[width,margin] duration-200',
          sidebarWidth,
          sidebarVariantClass,
          isOffcanvas && !mobileOpen && 'overflow-hidden'
        )}
      >
        {/* 侧栏头部：品牌区（logo + 名称 + 徽章 + 折叠按钮） */}
        <div className="flex items-center gap-2 border-b px-3 py-3">
          {!sideCollapsed && (
            <a href="/" className="flex min-w-0 flex-1 items-center gap-2 overflow-hidden">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center overflow-hidden rounded-md">
                <img src={brandLogo} alt="" className="h-full w-full object-contain" />
              </span>
              <span className={cn('truncate font-semibold', sb.item)}>{session?.site.displayName ?? t('brand.name')}</span>
            </a>
          )}
          {isOffcanvas ? (
            <button
              onClick={() => setMobileOpen(false)}
              aria-label={t('common.close')}
              className={cn(
                'flex items-center justify-center rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
                sideCollapsed ? 'mx-auto' : 'ms-auto'
              )}
            >
              <X className="size-4" />
            </button>
          ) : (
            <button
              onClick={() => setCollapsed(!collapsed)}
              aria-label="Toggle Sidebar"
              className={cn(
                'flex items-center justify-center rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
                sideCollapsed ? 'mx-auto' : 'ms-auto'
              )}
            >
              {sideCollapsed ? <ChevronsRight className="size-4" /> : <ChevronsLeft className="size-4" />}
            </button>
          )}
        </div>

        <nav className="no-scrollbar flex-1 overflow-y-auto p-3">
          {groups.map((group, gi) => {
            // 用户级与管理级之间只保留一条横线：不叠加徽章、色条或主色，
            // 让侧栏回到纯粹的导航形态。
            const showAdminDivider = group.admin && !groups[gi - 1]?.admin
            return (
              <React.Fragment key={group.key}>
                {showAdminDivider && (
                  <div className={cn('border-t border-sidebar-border', sideCollapsed ? 'my-2' : 'my-5')} />
                )}
                <div className="mb-4">
                  {!sideCollapsed && group.label && (
                    <GroupHeader label={group.label} size={sb.group} />
                  )}
                  <div className="space-y-0.5">
                    {group.items.map((item) =>
                      item.collapsible ? (
                        <div key={item.to}>
                          <button
                            type="button"
                            title={sideCollapsed ? item.label : undefined}
                            onClick={() => {
                              toggleSettings()
                              if (isOffcanvas) setMobileOpen(false)
                            }}
                            aria-expanded={settingsOpen}
                            className={cn(
                              'flex w-full items-center gap-2 rounded-md transition-colors',
                              sb.row, sb.item,
                              sideCollapsed ? 'justify-center px-0' : 'px-2',
                              'hover:bg-sidebar-accent hover:text-sidebar-accent-foreground text-muted-foreground'
                            )}
                          >
                            <item.icon className={cn('shrink-0', sb.icon)} />
                            {!sideCollapsed && <span className="flex-1 whitespace-nowrap text-start">{item.label}</span>}
                            {!sideCollapsed && (
                              <ChevronDown className={cn('transition-transform', sb.subIcon, settingsOpen && 'rotate-180')} />
                            )}
                          </button>
                          {!sideCollapsed && (
                            <div
                              ref={setSubPanelEl}
                              {...subPanelInert}
                              data-open={settingsOpen ? '' : undefined}
                              aria-hidden={!settingsOpen}
                              className="openidp-collapsible-content mt-1 space-y-0.5 ps-3"
                            >
                              {settingsSubItems.map((sub) => {
                                const active = activeSection === sub.section
                                return (
                                  <button
                                    key={sub.section}
                                    // 仅对当前选中项绑定 ref：刷新后靠它把选中分区滚回可视区
                                    ref={active ? activeSubRef : null}
                                    type="button"
                                    onClick={() => {
                                      navigate(sub.to)
                                      if (isOffcanvas) setMobileOpen(false)
                                    }}
                                    aria-current={active ? 'page' : undefined}
                                    className={cn(
                                      'flex w-full items-center gap-2 rounded-md px-2 transition-colors',
                                      sb.row, sb.item,
                                      'hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
                                      active ? 'bg-sidebar-accent font-medium text-sidebar-accent-foreground' : 'text-muted-foreground'
                                    )}
                                  >
                                    {/* 分区图标：14 个子项时「小白点 + 文字」很难扫读，
                                        图标能让人按位置记忆快速定位 */}
                                    <sub.icon
                                      aria-hidden
                                      className={cn(
                                        'shrink-0 transition-colors',
                                        sb.subIcon,
                                        active ? 'text-sidebar-accent-foreground' : 'text-muted-foreground'
                                      )}
                                    />
                                    <span className="whitespace-nowrap">{sub.label}</span>
                                  </button>
                                )
                              })}
                            </div>
                          )}
                        </div>
                      ) : (
                        <NavRow
                          key={item.to}
                          to={item.to}
                          label={item.label}
                          icon={item.icon}
                          row={sb.row}
                          item={sb.item}
                          iconSize={sb.icon}
                          collapsed={sideCollapsed}
                          onNavigate={() => isOffcanvas && setMobileOpen(false)}
                        />
                      )
                    )}
                  </div>
                </div>
              </React.Fragment>
            )
          })}
        </nav>

        {/* user area（头像 + 昵称 + 邮箱）
            折叠态侧栏仅 52px：外层 px-3(24) + 内层 px-2(16) 只剩 12px，
            而头像为 32px 且 shrink-0，会撑破容器。故折叠时收窄外层 padding、
            去掉内层 padding 并居中。 */}
        <div className={cn('border-t pb-4 pt-2', sideCollapsed ? 'px-2' : 'px-3')}>
          <div
            className={cn(
              'flex items-center gap-2 rounded-md py-1.5',
              sideCollapsed ? 'justify-center px-0' : 'px-2'
            )}
          >
            <div className="flex h-8 w-8 shrink-0 items-center justify-center overflow-hidden rounded-full bg-primary text-sm font-semibold text-primary-foreground">
              <img src={session?.user.avatarUrl || '/images/avatar.svg'} alt="" className="h-full w-full object-cover" />
            </div>
            {!sideCollapsed && (
              <div className={cn('grid min-w-0 flex-1 text-start leading-tight', sb.item)}>
                <div className="truncate font-semibold">{session?.user.displayName}</div>
                <div className={cn('truncate text-muted-foreground', sb.group)}>{session?.user.email}</div>
              </div>
            )}
          </div>
        </div>
      </aside>

      {/* Main column */}
      <div className={cn('relative flex flex-1 flex-col overflow-hidden', mainColumnClass)}>
        {/* 路由切换顶部窄进度条（仅右侧正文刷新，侧边栏不动） */}
        <div className={cn('pointer-events-none absolute inset-x-0 top-0 z-[60] h-0.5 transition-opacity duration-200', loading ? 'opacity-100' : 'opacity-0')}>
          <div className="h-full w-full origin-left animate-progress bg-primary" />
        </div>
        {/* TopBar（sticky h-18 + 滚动渐变 + 分隔线 + 外观/通知/用户） */}
        <header className="sticky top-0 z-50 h-18 shrink-0 w-full border-b border-border/35 bg-background/20 shadow-none backdrop-blur-sm">
          <div className="relative flex h-full items-center gap-3 px-4 sm:gap-4 sm:px-6">
          <button
            onClick={() => {
              if (isOffcanvas) setMobileOpen(!mobileOpen)
              else setCollapsed(!collapsed)
            }}
            aria-label="Toggle Sidebar"
            className="flex size-7 shrink-0 items-center justify-center rounded-md border bg-background text-foreground shadow-xs hover:bg-accent hover:text-accent-foreground dark:border-input dark:bg-input/30 dark:hover:bg-input/50"
          >
            <PanelLeft className="size-4" />
          </button>
          <div aria-hidden className="h-6 w-px shrink-0 bg-border" />
          <div className="ml-auto flex items-center gap-1">
            {/* 外观设置（含主题/语言等） */}
            <button
              onClick={() => setAppearanceOpen(true)}
              aria-label={t('topbar.appearance')}
              className="flex size-9 items-center justify-center rounded-full text-foreground hover:bg-accent hover:text-accent-foreground"
            >
              <Palette className="size-[1.15rem]" />
            </button>

            {/* 通知中心 */}
            <NotificationCenter />

            {/* 用户菜单 */}
            <UserMenu />
            </div>
          </div>
        </header>

        {/* 内容区自身可滚动。用 flex-col + 内容层 min-h-full 让页脚在空间富余时
            贴到底部，而不是紧跟在内容后面悬在半空。 */}
        <main data-layout="auto" className="flex min-h-0 grow flex-col overflow-y-auto px-4 py-7 sm:px-6 sm:py-8 lg:px-8">
          <div className="mx-auto flex w-full max-w-7xl flex-1 flex-col">
            {/* pb-8 是内容与页脚之间的间距；页脚自身用 mt-auto 贴底，
                两者分开写，避免 mt-8 与 mt-auto 相互覆盖。 */}
            <div className="flex-1 pb-8">
              <Outlet />
            </div>
            <SiteFooter site={session?.site} className="mt-auto pt-6" />
          </div>
        </main>
      </div>

      <AppearanceDrawer open={appearanceOpen} onClose={() => setAppearanceOpen(false)} />
    </div>
  )
}
