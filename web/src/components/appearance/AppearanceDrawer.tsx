// 外观设置抽屉。
//
// 结构沿用右侧 Sheet + 标题/说明 + 可滚动设置区 + 底部整宽重置：
//   设置区按 主题 → 侧栏样式 → 布局 → 界面字体 → 显示语言 的顺序排列，
//   前三组是「示意图 + 文字」的单选卡，后两组是下拉选择。
//
// 外观轴刻意只保留三条（主题 / 侧栏样式 / 布局），不引入「颜色预设 / 圆角 /
// 密度 / 内容宽度」这类需要多套令牌并存的轴：OpenIdP 的设计令牌只有一套品牌色
// 与一套间距、圆角，若为每条轴再叠一层覆盖样式，长期维护成本远超收益。
// 同样不提供「方向（LTR/RTL）」轴——样式层未做 RTL 适配，给出开关反而误导。
import * as React from 'react'
import { Palette, X } from 'lucide-react'
import {
  IconLayoutCompact, IconLayoutDefault, IconLayoutFull,
  IconSidebarFloating, IconSidebarInset, IconSidebarSidebar,
  IconThemeDark, IconThemeLight, IconThemeSystem,
} from './icons'
import { APPEARANCE_RADIO_GRID, OptionTile, PreviewFrame, SectionTitle } from './primitives'
import { useTheme } from '../../hooks/useTheme'
import { useAppearance, FONT_VALUES, fontCss } from '../../hooks/useAppearance'
import type { FontKey, LayoutStyle, SidebarStyle } from '../../hooks/useAppearance'
import { useI18n, LANG_OPTIONS } from '../../i18n'
import type { Lang } from '../../i18n'
import { Select, SelectItem } from '../ui/select'
import { cn } from '../../lib/utils'

// 单选组：role=radiogroup + 键盘左右键切换（原生 input 缺失，需手动补齐 a11y）。
function OptionGroup({ label, value, onChange, options, gridClass }: {
  label: string
  value: string
  onChange: (v: string) => void
  options: Option[]
  gridClass?: string
}) {
  return (
    <div
      role="radiogroup"
      aria-label={label}
      className={cn(APPEARANCE_RADIO_GRID, gridClass)}
      onKeyDown={(e) => {
        if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return
        e.preventDefault()
        const i = options.findIndex((o) => o.value === value)
        const next = e.key === 'ArrowRight' ? (i + 1) % options.length : (i - 1 + options.length) % options.length
        onChange(options[next].value)
      }}
    >
      {options.map((o) => o.node)}
    </div>
  )
}

interface Option { value: string; node: React.ReactNode }

// useTheme 的 Theme 类型未导出，这里就地声明等价字面量联合，避免改动公共 hook 的导出面。
type ThemeMode = 'light' | 'dark' | 'system'

export function AppearanceDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t, lang, setLang } = useI18n()
  const { defaultTheme, theme, setTheme, resetTheme } = useTheme()
  const {
    sidebar, setSidebar, layout, setLayout, font, applyFont, reset: resetAppearance,
    defaultSidebar, defaultLayout, defaultFont,
  } = useAppearance()

  const themeOptions: Option[] = [
    { value: 'system', node: <OptionTile key="system" value="system" label={t('appearance.themeSystem')} active={theme === 'system'} onSelect={(v) => setTheme(v as ThemeMode)}><PreviewFrame><IconThemeSystem /></PreviewFrame></OptionTile> },
    { value: 'light', node: <OptionTile key="light" value="light" label={t('appearance.themeLight')} active={theme === 'light'} onSelect={(v) => setTheme(v as ThemeMode)}><PreviewFrame className="[&_svg]:text-primary"><IconThemeLight /></PreviewFrame></OptionTile> },
    { value: 'dark', node: <OptionTile key="dark" value="dark" label={t('appearance.themeDark')} active={theme === 'dark'} onSelect={(v) => setTheme(v as ThemeMode)}><PreviewFrame className="[&_svg]:text-primary"><IconThemeDark /></PreviewFrame></OptionTile> },
  ]

  const sidebarOptions: Option[] = [
    { value: 'inset', node: <OptionTile key="inset" value="inset" label={t('appearance.sidebarInset')} active={sidebar === 'inset'} onSelect={(v) => setSidebar(v as SidebarStyle)}><PreviewFrame><IconSidebarInset /></PreviewFrame></OptionTile> },
    { value: 'floating', node: <OptionTile key="floating" value="floating" label={t('appearance.sidebarFloating')} active={sidebar === 'floating'} onSelect={(v) => setSidebar(v as SidebarStyle)}><PreviewFrame><IconSidebarFloating /></PreviewFrame></OptionTile> },
    { value: 'standard', node: <OptionTile key="standard" value="standard" label={t('appearance.sidebarStandard')} active={sidebar === 'standard'} onSelect={(v) => setSidebar(v as SidebarStyle)}><PreviewFrame><IconSidebarSidebar /></PreviewFrame></OptionTile> },
  ]

  const layoutOptions: Option[] = [
    { value: 'default', node: <OptionTile key="default" value="default" label={t('appearance.layoutDefault')} active={layout === 'default'} onSelect={(v) => setLayout(v as LayoutStyle)}><PreviewFrame><IconLayoutDefault /></PreviewFrame></OptionTile> },
    { value: 'icon', node: <OptionTile key="icon" value="icon" label={t('appearance.layoutIcon')} active={layout === 'icon'} onSelect={(v) => setLayout(v as LayoutStyle)}><PreviewFrame><IconLayoutCompact /></PreviewFrame></OptionTile> },
    { value: 'offcanvas', node: <OptionTile key="offcanvas" value="offcanvas" label={t('appearance.layoutOffcanvas')} active={layout === 'offcanvas'} onSelect={(v) => setLayout(v as LayoutStyle)}><PreviewFrame><IconLayoutFull /></PreviewFrame></OptionTile> },
  ]

  // 抽屉每次打开都把当前字体落到 --app-font，避免上一轮遗留的内联值。
  React.useEffect(() => {
    if (!open) return
    document.documentElement.style.setProperty('--app-font', fontCss(font))
  }, [open, font])

  const handleReset = () => {
    onClose()
    resetTheme()
    resetAppearance()
  }

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 bg-black/40" onClick={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label={t('appearance.title')}
        data-slot="sheet-content"
        className="fixed inset-y-0 right-0 z-50 flex h-full w-full flex-col border-l bg-background text-foreground shadow-lg sm:max-w-md"
        onClick={(e) => e.stopPropagation()}
      >
        {/* 头部：标题 + 说明 */}
        <div className="flex shrink-0 items-start justify-between gap-4 border-b p-4">
          <div>
            <h2 className="flex items-center gap-2 font-semibold">
              <Palette className="size-4" aria-hidden />
              {t('appearance.title')}
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">{t('appearance.sheetDesc')}</p>
          </div>
          <button
            onClick={onClose}
            aria-label={t('common.close')}
            className="flex size-8 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            <X className="size-4" />
          </button>
        </div>

        {/* 设置区 */}
        <div className="flex min-h-0 flex-1 flex-col gap-6 overflow-y-auto p-4">
          {/* 主题 */}
          <section>
            <SectionTitle
              title={t('appearance.theme')}
              showReset={theme !== defaultTheme}
              onReset={() => setTheme(defaultTheme)}
            />
            <OptionGroup label={t('appearance.theme')} value={theme} onChange={(v) => setTheme(v as ThemeMode)} options={themeOptions} />
          </section>

          {/* 侧栏样式 */}
          <section>
            <SectionTitle
              title={t('appearance.sidebar')}
              showReset={sidebar !== defaultSidebar}
              onReset={() => setSidebar(defaultSidebar)}
            />
            <OptionGroup label={t('appearance.sidebar')} value={sidebar} onChange={(v) => setSidebar(v as SidebarStyle)} options={sidebarOptions} />
          </section>

          {/* 布局 */}
          <section>
            <SectionTitle
              title={t('appearance.layout')}
              showReset={layout !== defaultLayout}
              onReset={() => setLayout(defaultLayout)}
            />
            <OptionGroup label={t('appearance.layout')} value={layout} onChange={(v) => setLayout(v as LayoutStyle)} options={layoutOptions} />
          </section>

          {/* 界面字体 */}
          <section>
            <SectionTitle
              title={t('appearance.font')}
              showReset={font !== defaultFont}
              onReset={() => applyFont(defaultFont)}
            />
            <Select
              value={font}
              onValueChange={(v) => applyFont(v as FontKey)}
              className="w-full max-w-md"
              ariaLabel={t('appearance.font')}
            >
              {FONT_VALUES.map((f) => (
                <SelectItem key={f} value={f}>{t(`appearance.font_${f}`)}</SelectItem>
              ))}
            </Select>
          </section>

          {/* 显示语言 */}
          <section>
            <SectionTitle title={t('appearance.language')} />
            <Select
              value={lang}
              onValueChange={(v) => setLang(v as Lang)}
              className="w-full max-w-md"
              ariaLabel={t('appearance.language')}
            >
              {LANG_OPTIONS.map((o) => (
                <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
              ))}
            </Select>
          </section>
        </div>

        {/* 底部：整宽重置 */}
        <div className="shrink-0 border-t p-4">
          <button
            onClick={handleReset}
            className="w-full rounded-md bg-destructive px-4 py-2 text-sm font-medium text-destructive-foreground transition-colors hover:bg-destructive/90"
          >
            {t('appearance.reset')}
          </button>
        </div>
      </div>
    </div>
  )
}
