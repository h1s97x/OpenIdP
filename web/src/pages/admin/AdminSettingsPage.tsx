import * as React from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/card'
import { Button } from '../../components/ui/button'
import { Input, Label } from '../../components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../../components/ui/table'
import { Select, SelectItem } from '../../components/ui/select'
import { api, ApiError } from '../../lib/api'
import type { SettingsBackupGroup, SettingsBackupInspectResult, SettingsBackupRestoreResult } from '../../lib/api-types'
import { useI18n } from '../../i18n'
import { useToast } from '../../components/ui/toast'
import { useConfirm } from '../../components/ui/confirm'
import { Badge } from '../../components/ui/badge'
import { Switch } from '../../components/ui/switch'
import { Tabs, TabsList, TabsTrigger } from '../../components/ui/tabs'
import { Dialog } from '../../components/ui/dialog'
import { cn, formatDateTimeI18n, secretPlaceholder } from '../../lib/utils'
import {
  Store, Globe, ShieldCheck, Mail, Bot, Save, Copy,
  CloudCog, Plus, Trash2, Loader2, PlugZap, Check, X, MapPin, AppWindow, Network, RotateCcw,
  FileClock, Activity, BellRing, Send, KeyRound, Smartphone, HardDrive,
  Download, Upload, FileJson,
} from 'lucide-react'
// 「应用管理」已并入系统设置：独立页面移除后，这里复用其分区组件。
import { AppsSection } from './AdminAppsPage'
import {
  SECURITY_TABS, MESSAGING_TABS, OPS_TABS, resolveSettingsLocation, settingsSectionPath,
  type SectionTab,
} from '../../lib/settings-sections'

/* ------------------------------------------------------------------ */
/*  系统设置：整合站点/提供商/安全/消息/存储/运维等配置分区              */
/* ------------------------------------------------------------------ */

// 分区清单、子页签与地址别名来自 lib/settings-sections.ts（唯一事实来源）：
// 侧栏「系统设置」的子项由该常量生成，本页只按 ?section= / ?tab= 渲染对应分区。

// SectionTabs 是带页签分区的切换条。未选中的内容用 hidden 容器而非 TabsContent：
// 后者会卸载子树，切页签就把未保存的表单状态丢了。
function SectionTabs({ tabs, value, onChange }: {
  tabs: readonly SectionTab[]
  value: string
  onChange: (v: string) => void
}) {
  const { t } = useI18n()
  return (
    <Tabs value={value} onValueChange={onChange}>
      <TabsList className="w-full sm:max-w-md">
        {tabs.map((tb) => (
          <TabsTrigger key={tb.key} value={tb.key}>{t(tb.labelKey)}</TabsTrigger>
        ))}
      </TabsList>
    </Tabs>
  )
}


interface ProviderRow { id?: string; [k: string]: unknown }

// 内置提供商随列表下发的「内置默认端点」，用于展示默认值、判断字段是否被改过，
// 以及提供「恢复默认」。端点本身以数据库取值为准（初始化时写入）。
interface ProviderDefaultEndpoints {
  authorizeUrl?: string
  tokenUrl?: string
  userInfoUrl?: string
  openIdUrl?: string
  scopes?: string[]
  docsUrl?: string
}

// 连通性测试返回（POST /admin/oauth-providers/{id}/test）。
// reachable 的口径是「拿到了 HTTP 响应」，4xx/5xx 也算可达（端点不接受裸 GET 而已）。
interface ProviderProbe {
  key: string
  url: string
  reachable?: boolean
  statusCode?: number
  elapsedMs?: number
  error?: string
}
interface ProviderTest {
  providerType?: string
  useProxy?: boolean
  /** 非空表示本次测试确实走了代理（显示出来，省得再确认「到底走没走」） */
  proxyAddr?: string
  results?: ProviderProbe[]
}
interface DeletionReq { id?: string; [k: string]: unknown }
interface StorageStats { totalFiles?: number; totalBytes?: number; orphanBytes?: number; backend?: string; [k: string]: unknown }
interface FileRow { publicId?: string; [k: string]: unknown }

export function AdminSettingsPage() {
  const { t } = useI18n()
  const [params, setParams] = useSearchParams()

  // 分区与页签全部由地址栏驱动：刷新、前进后退、分享链接都能还原到同一屏。
  // 旧地址（?section=mail / passkey / cleanup …）由 resolveSettingsLocation 归一化。
  // 分区切换由侧栏「系统设置」的子项完成（navigate + ?section=），本页只渲染内容。
  const { section: active, tab } = React.useMemo(
    () => resolveSettingsLocation(params.get('section'), params.get('tab')),
    [params],
  )

  // 页签切换写回 ?section=&tab=，与侧栏子项跳转保持同一套深链语义。
  const setTab = React.useCallback((next: string) => {
    const p = new URLSearchParams()
    p.set('section', active)
    p.set('tab', next)
    setParams(p, { replace: true })
  }, [active, setParams])

  return (
    <div className="space-y-6">
      {/* 页头 */}
      <div>
        <h1 className="text-2xl font-semibold">{t('admin.settings.title')}</h1>
      </div>

      {/* 分区内容：全部保持挂载以保留未保存的表单状态 */}
      <div className={active === 'brand' ? '' : 'hidden'}>
        <BrandSection />
      </div>
      {/* 登录安全：安全策略 / 通行密钥 / 人机验证 */}
      <div className={active === 'security' ? '' : 'hidden'}>
        <SectionTabs tabs={SECURITY_TABS} value={tab} onChange={setTab} />
        <div className={tab === 'policy' ? 'pt-2' : 'hidden'}>
          <SecuritySection />
        </div>
        <div className={tab === 'passkey' ? 'pt-2' : 'hidden'}>
          <PasskeySection />
        </div>
        <div className={tab === 'captcha' ? 'pt-2' : 'hidden'}>
          <CaptchaSection />
        </div>
      </div>
      <div className={active === 'providers' ? '' : 'hidden'}>
        <ProvidersSection />
      </div>
      <div className={active === 'apps' ? '' : 'hidden'}>
        <AppsSection />
      </div>
      {/* 消息服务：邮件 / 短信 / 发送通知 */}
      <div className={active === 'messaging' ? '' : 'hidden'}>
        <SectionTabs tabs={MESSAGING_TABS} value={tab} onChange={setTab} />
        <div className={tab === 'mail' ? 'pt-2' : 'hidden'}>
          <MailSection />
        </div>
        <div className={tab === 'sms' ? 'pt-2' : 'hidden'}>
          <SmsSection />
        </div>
        <div className={tab === 'broadcast' ? 'pt-2' : 'hidden'}>
          <BroadcastSection />
        </div>
      </div>
      <div className={active === 'proxy' ? '' : 'hidden'}>
        <ProxySection />
      </div>
      {/* 数据与运维：审计与状态 / 归属地 / 存储管理 / 数据清理 */}
      <div className={active === 'audit' ? '' : 'hidden'}>
        <SectionTabs tabs={OPS_TABS} value={tab} onChange={setTab} />
        <div className={tab === 'audit' ? 'pt-2' : 'hidden'}>
          <AuditSection />
        </div>
        <div className={tab === 'location' ? 'pt-2' : 'hidden'}>
          <LocationSection />
        </div>
        <div className={tab === 'storage' ? 'pt-2' : 'hidden'}>
          <StorageSection />
        </div>
        <div className={tab === 'cleanup' ? 'pt-2' : 'hidden'}>
          <CleanupSection />
        </div>
        <div className={tab === 'backup' ? 'pt-2' : 'hidden'}>
          <BackupSection />
        </div>
      </div>
    </div>
  )
}

/* ------------------------------- 通用开关行 ------------------------------ */
// EndpointField 是端点输入项。
function EndpointField({ label, value, placeholder, onChange }: {
  label: string
  value: string
  placeholder?: string
  onChange: (v: string) => void
}) {
  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      <Input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder} />
    </div>
  )
}

// 复用 ui/switch 的 Switch 原语，只负责左侧文案与右侧开关的排版。
// 此前这里把开关按钮的样式（尺寸、圆角、thumb 位移、role/aria-checked）又抄了一遍，
// 与 Switch 组件各改各的，迟早会出现两处外观不一致。
function SwitchRow({ label, desc, checked, onChange, disabled, divider = true }: {
  label: string; desc?: string; checked?: boolean; onChange: () => void
  disabled?: boolean; divider?: boolean
}) {
  return (
    <div className={cn('flex items-center justify-between py-3', divider && 'border-b last:border-0')}>
      <div className="pr-4">
        <div className="text-sm font-medium">{label}</div>
        {desc && <div className="mt-0.5 text-xs text-muted-foreground">{desc}</div>}
      </div>
      <Switch checked={!!checked} onCheckedChange={() => onChange()} disabled={disabled} />
    </div>
  )
}

/* ------------------------------- 1. 品牌信息 ------------------------------ */

// 品牌信息分区提交的字段白名单。
//
// /admin/site 同时承载品牌字段、通行密钥字段（passkeyEnabled / passkeyRPID /
// passkeyOrigins 等）与上传策略（avatarUploadEnabled）。此前把 GET 返回的完整快照
// 整包 PATCH 回去，于是：
//   - 在「通行密钥」改了 RPID 未保存 → 切到「品牌信息」点保存 → 整包快照把改动回滚；
//   - 在「品牌信息」改了页脚未保存 → 切到「通行密钥」点保存 → 品牌改动被静默丢弃。
// 改为只提交本分区真正拥有的字段，各分区互不干扰。
// avatarUploadEnabled 已随「用户上传」移到「数据与运维 → 存储管理」，必须一并移出白名单：
// 留在白名单里，在品牌信息点保存就会按旧快照把那边的开关写回去。
const BRAND_FIELDS = [
  'displayName', 'logoUrl', 'faviconUrl', 'siteUrl',
  'footerText', 'icpBeian', 'publicSecurityBeian',
  'defaultLanguage',
] as const

// 站点默认语言选项：未登录页面使用该语言，用户在本浏览器切换过则以其选择为准。
const SITE_LANGUAGE_OPTIONS = [
  { value: 'zh-CN', label: '简体中文' },
  { value: 'zh-TW', label: '繁體中文' },
  { value: 'ja', label: '日本語' },
  { value: 'en', label: 'English' },
]

function BrandSection() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { success: toastSuccess, error: toastError } = useToast()
  const { data: site } = useQuery({ queryKey: ['admin', 'site'], queryFn: () => api.adminSite<Record<string, unknown>>() })
  const [form, setForm] = React.useState<any>(null)
  // 未保存改动保护：invalidate 带回新 site 时不要覆盖正在编辑的内容。
  const dirtyRef = React.useRef(false)
  const syncedRef = React.useRef(false)

  React.useEffect(() => {
    if (!site) return
    if (!syncedRef.current || !dirtyRef.current) {
      // 只保留一个站点名称配置项：忽略内部 slug（siteName），表单仅含显示名。
      const { siteName: _dropSite, ...rest } = site
      setForm(rest)
      syncedRef.current = true
    }
  }, [site])

  const save = useMutation({
    // 按白名单取字段提交，避免把不属于本分区的通行密钥配置一起写回。
    mutationFn: () => {
      const body: Record<string, unknown> = {}
      for (const k of BRAND_FIELDS) body[k] = form?.[k]
      return api.adminUpdateSite(body)
    },
    onSuccess: async () => {
      dirtyRef.current = false
      await qc.invalidateQueries({ queryKey: ['admin', 'site'] })
      qc.invalidateQueries({ queryKey: ['session'] })
      toastSuccess(t('admin.site.saved'))
    },
    onError: (e) => toastError(t('admin.site.saveFail'), e instanceof ApiError ? e.message : ''),
  })

  const set = (k: string, v: any) => {
    dirtyRef.current = true
    setForm((f: any) => ({ ...f, [k]: v }))
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Store className="size-4" /> {t('admin.site.brand')}</CardTitle>
        </CardHeader>
        <CardContent className="max-w-3xl">
          {form && (
            <div className="space-y-5">
              <div className="grid gap-4">
                <div className="space-y-1.5">
                  <Label>{t('admin.site.displayName')}</Label>
                  <Input value={form.displayName ?? ''} onChange={(e) => set('displayName', e.target.value)} placeholder="OpenIdP" />
                </div>
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label>{t('admin.site.logoUrl')}</Label>
                  <Input value={form.logoUrl ?? ''} onChange={(e) => set('logoUrl', e.target.value)} placeholder="https://example.com/logo.svg" />
                </div>
                <div className="space-y-1.5">
                  <Label>{t('admin.site.faviconUrl')}</Label>
                  <Input value={form.faviconUrl ?? ''} onChange={(e) => set('faviconUrl', e.target.value)} placeholder="https://example.com/favicon.ico" />
                </div>
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.site.siteUrl')}</Label>
                <Input value={form.siteUrl ?? ''} onChange={(e) => set('siteUrl', e.target.value)} placeholder="https://auth.example.com" />
              </div>
              <div className="max-w-xs space-y-1.5">
                <Label>{t('admin.site.defaultLanguage')}</Label>
                <Select
                  value={form.defaultLanguage || 'zh-CN'}
                  onValueChange={(v) => set('defaultLanguage', v)}
                  className="w-full"
                  ariaLabel={t('admin.site.defaultLanguage')}
                >
                  {SITE_LANGUAGE_OPTIONS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
                  ))}
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.site.footerText')}</Label>
                <Input value={form.footerText ?? ''} onChange={(e) => set('footerText', e.target.value)} placeholder="© 2026 OpenIdP" />
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label>{t('admin.site.icpBeian')}</Label>
                  <Input value={form.icpBeian ?? ''} onChange={(e) => set('icpBeian', e.target.value)} placeholder="京ICP备00000000号" />
                </div>
                <div className="space-y-1.5">
                  <Label>{t('admin.site.publicSecurityBeian')}</Label>
                  <Input value={form.publicSecurityBeian ?? ''} onChange={(e) => set('publicSecurityBeian', e.target.value)} placeholder="京公网安备00000000000000号" />
                </div>
              </div>
              <div className="flex justify-end">
                <Button onClick={() => save.mutate()} disabled={save.isPending}><Save className="size-4" /> {t('admin.site.save')}</Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

/* ------------------------------- 2. 登录提供商 ------------------------------ */
function ProvidersSection() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { confirm } = useConfirm()
  const { data: providers } = useQuery({ queryKey: ['admin', 'oauth-providers'], queryFn: () => api.adminOAuthProviders<ProviderRow[]>() })
  const [editId, setEditId] = React.useState<string | null>(null)
  const [form, setForm] = React.useState<any>({})
  const [adding, setAdding] = React.useState(false)
  const [newForm, setNewForm] = React.useState<any>({})
  const [createError, setCreateError] = React.useState('')
  // 连通性测试结果：按**已保存**的配置测（含代理），所以保存/换提供商后要清掉，
  // 否则会拿旧配置的结果误导管理员。
  const [testResult, setTestResult] = React.useState<ProviderTest | null>(null)

  const testConn = useMutation({
    mutationFn: () => api.adminTestOAuthProvider<ProviderTest>(editId!),
    onSuccess: (res) => setTestResult(res),
    onError: (e) => {
      setTestResult(null)
      toast({ type: 'error', title: t('admin.providers.testFail'), description: e instanceof ApiError ? e.message : '' })
    },
  })

  const save = useMutation({
    mutationFn: () => api.adminUpdateOAuthProvider(editId!, form),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'oauth-providers'] })
      qc.invalidateQueries({ queryKey: ['login-policy'] })
      qc.invalidateQueries({ queryKey: ['capabilities'] })
      setEditId(null)
      setTestResult(null)
      toast({ type: 'success', title: t('common.saved') })
    },
    onError: (e) => {
      // 保存时检查代理配置：开启「使用代理」但系统代理未配置时右下角弹窗提示
      if (e instanceof ApiError && e.code === 'proxy.not_configured') {
        toast({ type: 'error', title: t('admin.providers.proxyMissingTitle'), description: t('admin.providers.proxyMissingDesc') })
      } else {
        toast({ type: 'error', title: t('common.saveFailed'), description: e instanceof ApiError ? e.message : '' })
      }
    },
  })

  const create = useMutation({
    mutationFn: () => api.adminCreateOAuthProvider(newForm),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'oauth-providers'] })
      qc.invalidateQueries({ queryKey: ['login-policy'] })
      qc.invalidateQueries({ queryKey: ['capabilities'] })
      setAdding(false)
      setNewForm({})
      setCreateError('')
      toast({ type: 'success', title: t('admin.providers.created') })
    },
    onError: (e) => setCreateError(e instanceof ApiError ? e.message : t('admin.providers.createFail')),
  })

  const del = useMutation({
    mutationFn: (id: string) => api.adminDeleteOAuthProvider(id),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['admin', 'oauth-providers'] })
      qc.invalidateQueries({ queryKey: ['login-policy'] })
      // 删除成功后关闭编辑面板：面板编辑的是已不存在的提供商
      setEditId(null)
      qc.invalidateQueries({ queryKey: ['capabilities'] })
      toast({ type: 'success', title: t('common.saved') })
    },
    onError: (e) => toast({ type: 'error', title: e instanceof ApiError ? e.message : t('admin.providers.deleteFail') }),
  })

  const handleSave = () => {
    save.mutate()
  }

  const copy = async (v: string) => {
    try {
      await navigator.clipboard.writeText(v)
      toast({ type: 'success', title: t('common.saved') })
    } catch { /* ignore */ }
  }

  const items: any[] = providers ?? []
  const editing = items.find((p) => p.id === editId)
  // 内置默认端点（仅内置提供商下发）。用「生效值 ?? 内置默认」渲染，
  // 使界面展示的口径与后端解析口径一致：留空即用内置默认。
  const defaults: ProviderDefaultEndpoints =
    ((editing?.defaultEndpoints as ProviderDefaultEndpoints | undefined) ?? {})
  // 一键把端点表单恢复到内置默认值（清空 scopes 也会回落默认）。
  const resetEndpoints = () => setForm((f: any) => ({
    ...f,
    authorizeUrl: defaults.authorizeUrl ?? '',
    tokenUrl: defaults.tokenUrl ?? '',
    userInfoUrl: defaults.userInfoUrl ?? '',
    openIdUrl: defaults.openIdUrl ?? '',
    scopes: defaults.scopes ?? [],
    docsUrl: defaults.docsUrl ?? '',
  }))

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Globe className="size-4" /> {t('admin.providers.listTitle')}</CardTitle>
          <CardDescription className="flex items-center justify-between gap-2">
            <span>{t('admin.providers.count', { count: items.length })}</span>
            <Button variant="outline" size="sm" onClick={() => setAdding(true)}>
              <Plus className="size-3.5" /> {t('admin.providers.add')}
            </Button>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('admin.providers.provider')}</TableHead>
                <TableHead>{t('admin.providers.type')}</TableHead>
                <TableHead>{t('admin.providers.clientId')}</TableHead>
                <TableHead>{t('admin.providers.status')}</TableHead>
                <TableHead className="text-right">{t('common.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((p: any) => (
                <TableRow key={p.id}>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      {p.logoUrl
                        ? <img src={p.logoUrl} alt="" className="h-7 w-7 rounded" />
                        : <span className="flex h-7 w-7 items-center justify-center rounded bg-muted"><Globe className="size-4 text-muted-foreground" /></span>}
                      <span className="text-sm font-medium">{p.displayName}</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {p.providerType}
                  </TableCell>
                  <TableCell className="text-xs">{p.clientId || '—'}</TableCell>
                  <TableCell>
                    {p.enabled ? (
                      <span className="inline-flex rounded-full bg-success/10 px-2 py-0.5 text-xs text-success">{t('common.enabled')}</span>
                    ) : (
                      <span className="inline-flex rounded-full bg-muted px-2 py-0.5 text-xs text-muted-foreground">{t('common.disabled')}</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex justify-end">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => { setEditId(p.id); setTestResult(null); setForm({ enabled: p.enabled, clientId: p.clientId, displayName: p.displayName, logoUrl: p.logoUrl, authorizeUrl: p.authorizeUrl, tokenUrl: p.tokenUrl, userInfoUrl: p.userInfoUrl, openIdUrl: p.openIdUrl, scopes: p.scopes ?? [], docsUrl: p.docsUrl, useProxy: !!p.useProxy }) }}
                      >
                        <KeyRound className="size-3.5" /> {t('admin.providers.configure')}
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {items.length === 0 && (
                <TableRow><TableCell colSpan={5} className="py-10 text-center text-sm text-muted-foreground">{t('common.none')}</TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {editId && editing && (
        <Card>
          <CardHeader>
            <CardTitle>{t('admin.providers.configTitle')}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* 1. 回调地址 */}
            <div className="rounded-md border bg-muted/20 p-3">
              <div className="text-xs font-medium text-muted-foreground">{t('admin.providers.callbackUrl')}</div>
              <div className="mt-1 flex items-center gap-2">
                <code className="min-w-0 flex-1 break-all font-mono text-xs">{editing.callbackUrl}</code>
                <Button size="sm" variant="ghost" onClick={() => copy(editing.callbackUrl ?? '')}>
                  <Copy className="size-3.5" />
                </Button>
              </div>
            </div>

            {/* 2. 凭据 */}
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>{t('admin.providers.displayName')}</Label>
                <Input value={form.displayName ?? ''} onChange={(e) => setForm({ ...form, displayName: e.target.value })} />
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.providers.logoUrl')}</Label>
                <Input value={form.logoUrl ?? ''} onChange={(e) => setForm({ ...form, logoUrl: e.target.value })} placeholder="https://provider.com/logo.svg" />
              </div>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>{t('admin.providers.clientId')}</Label>
                <Input value={form.clientId ?? ''} onChange={(e) => setForm({ ...form, clientId: e.target.value })} />
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.providers.clientSecret')}</Label>
                {/* 密钥不回显：已配置时仅以占位提示「留空不修改」，提交空值即保留原值。
                    「是否已配置」取自列表项（editing）而不是表单：编辑面板的表单是按字段
                    手工构造的，不带 secretSet —— 之前读 form.secretSet 恒为 undefined，
                    于是已配置的密钥重开面板后也看不到提示，像是没保存成功。 */}
                <Input
                  type="password"
                  value={form.clientSecret ?? ''}
                  placeholder={secretPlaceholder(!!editing.secretSet, t('common.secretPlaceholder'))}
                  onChange={(e) => setForm({ ...form, clientSecret: e.target.value })}
                />
              </div>
            </div>

            {/* 端点配置：内置与自定义提供商共用同一份表单。
                内置提供商的端点由初始化写入数据库，这里可直接查看与修改
                （例如走自建反代或企业内网网关）。 */}
            <div className="space-y-4 rounded-lg border bg-muted/10 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="text-sm font-medium">{t('admin.providers.endpointsTitle')}</div>
                </div>
                {editing.builtin && (
                  <Button variant="outline" size="sm" onClick={resetEndpoints}>
                    <RotateCcw className="size-3.5" /> {t('admin.providers.endpointsReset')}
                  </Button>
                )}
              </div>

              <EndpointField
                label={t('admin.providers.authorizeUrl')}
                value={form.authorizeUrl ?? ''}
                placeholder="https://provider.com/oauth/authorize"
                onChange={(v) => setForm({ ...form, authorizeUrl: v })}
              />
              <EndpointField
                label={t('admin.providers.tokenUrl')}
                value={form.tokenUrl ?? ''}
                placeholder="https://provider.com/oauth/token"
                onChange={(v) => setForm({ ...form, tokenUrl: v })}
              />
              <EndpointField
                label={t('admin.providers.userInfoUrl')}
                value={form.userInfoUrl ?? ''}
                placeholder="https://provider.com/api/user"
                onChange={(v) => setForm({ ...form, userInfoUrl: v })}
              />
              {/* openid 端点只有部分平台需要（如 QQ 的 /oauth2.0/me）：
                  没有取值时不必占位，避免让人以为漏填了。 */}
              {!!form.openIdUrl && (
                <EndpointField
                  label={t('admin.providers.openIdUrl')}
                  value={form.openIdUrl ?? ''}
                  placeholder="https://provider.com/oauth2.0/me"
                  onChange={(v) => setForm({ ...form, openIdUrl: v })}
                />
              )}
              <div className="space-y-1.5">
                <Label>{t('admin.providers.scopes')}</Label>
                <Input
                  value={(form.scopes ?? []).join(' ')}
                  onChange={(e) => setForm({ ...form, scopes: e.target.value.split(/\s+/).filter(Boolean) })}
                  placeholder={t('admin.providers.scopesPlaceholder')}
                />
              </div>
              {/* 文档地址仅自定义提供商需要；内置提供商的文档地址由系统维护，不提供编辑。 */}
              {editing.custom && (
                <EndpointField
                  label={t('admin.providers.docsUrl')}
                  value={form.docsUrl ?? ''}
                  placeholder="https://docs.example.com"
                  onChange={(v) => setForm({ ...form, docsUrl: v })}
                />
              )}
            </div>

            {/* 连通性测试结果：按已保存的配置（含代理）实测，用来区分
                「网络层不通」与「上游返回错误」——登录失败时最需要判断的一件事。 */}
            {testResult && (
              <div className="space-y-2 rounded-lg border bg-muted/20 p-4">
                <div className="divide-y overflow-hidden rounded-lg border bg-background">
                  {(testResult.results ?? []).map((r) => (
                    <div key={r.key} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
                      <span className="flex items-center gap-2 font-medium">
                        <span className={cn('size-2 shrink-0 rounded-full', r.reachable ? 'bg-emerald-500' : 'bg-destructive')} />
                        {t(`admin.providers.testEndpoint.${r.key}`)}
                      </span>
                      <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground" title={r.url}>{r.url}</span>
                      <span className={cn('font-mono text-xs', r.reachable ? 'text-emerald-600' : 'text-destructive')}>
                        {r.reachable
                          ? `${r.statusCode} · ${r.elapsedMs}ms`
                          : (r.error || t('admin.providers.testUnreachable'))}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* 启用 / 代理开关：放在保存按钮上方，先定开关再保存，动线更顺。 */}
            <div className="rounded-lg border bg-muted/20 px-4">
              <SwitchRow
                label={t('admin.providers.enable')}
                checked={!!form.enabled}
                onChange={() => setForm({ ...form, enabled: !form.enabled })}
              />
              <SwitchRow
                label={t('admin.providers.useProxy')}
                checked={!!form.useProxy}
                onChange={() => setForm({ ...form, useProxy: !form.useProxy })}
                divider={false}
              />
            </div>

            <div className="flex flex-wrap gap-2 pt-1">
              <Button onClick={handleSave} disabled={save.isPending}><Save className="size-4" /> {t('common.save')}</Button>
              <Button variant="outline" onClick={() => testConn.mutate()} disabled={testConn.isPending}>
                {testConn.isPending ? <Loader2 className="size-4 animate-spin" /> : <PlugZap className="size-4" />} {t('admin.providers.test')}
              </Button>
              <Button variant="outline" onClick={() => setEditId(null)}>{t('common.cancel')}</Button>
              {editing.custom && (
                // 取消删除时不能关闭编辑面板：此前 setEditId(null) 写在 if 之外，
                // 点「取消」会把刚填的 clientId/secret/端点全部丢弃。
                <Button
                  variant="destructive"
                  className="ms-auto"
                  disabled={del.isPending}
                  onClick={() => {
                    confirm({
                      title: t('admin.providers.deleteConfirm', { name: editing.displayName }),
                      confirmText: t('common.delete'),
                      variant: 'destructive',
                      onConfirm: async () => { await del.mutateAsync(editing.id) },
                    })
                  }}
                >
                  <Trash2 className="size-4" /> {t('admin.providers.delete')}
                </Button>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* 添加自定义提供商表单 */}
      {adding && (
        <Card>
          <CardHeader>
            <CardTitle>{t('admin.providers.addTitle')}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>{t('admin.providers.providerType')}</Label>
                <Input value={newForm.providerType ?? ''} onChange={(e) => setNewForm({ ...newForm, providerType: e.target.value })} placeholder={t('admin.providers.providerTypePlaceholder')} />
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.providers.displayName')}</Label>
                <Input value={newForm.displayName ?? ''} onChange={(e) => setNewForm({ ...newForm, displayName: e.target.value })} />
              </div>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>{t('admin.providers.clientId')}</Label>
                <Input value={newForm.clientId ?? ''} onChange={(e) => setNewForm({ ...newForm, clientId: e.target.value })} />
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.providers.clientSecret')}</Label>
                <Input type="password" value={newForm.clientSecret ?? ''} onChange={(e) => setNewForm({ ...newForm, clientSecret: e.target.value })} />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label>{t('admin.providers.logoUrl')}</Label>
              <Input value={newForm.logoUrl ?? ''} onChange={(e) => setNewForm({ ...newForm, logoUrl: e.target.value })} placeholder="https://provider.com/logo.svg" />
            </div>
            <div className="space-y-1.5">
              <Label>{t('admin.providers.authorizeUrl')}</Label>
              <Input value={newForm.authorizeUrl ?? ''} onChange={(e) => setNewForm({ ...newForm, authorizeUrl: e.target.value })} placeholder="https://provider.com/oauth/authorize" />
            </div>
            <div className="space-y-1.5">
              <Label>{t('admin.providers.tokenUrl')}</Label>
              <Input value={newForm.tokenUrl ?? ''} onChange={(e) => setNewForm({ ...newForm, tokenUrl: e.target.value })} placeholder="https://provider.com/oauth/token" />
            </div>
            <div className="space-y-1.5">
              <Label>{t('admin.providers.userInfoUrl')}</Label>
              <Input value={newForm.userInfoUrl ?? ''} onChange={(e) => setNewForm({ ...newForm, userInfoUrl: e.target.value })} placeholder="https://provider.com/api/user" />
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>{t('admin.providers.scopes')}</Label>
                <Input value={(newForm.scopes ?? []).join(' ')} onChange={(e) => setNewForm({ ...newForm, scopes: e.target.value.split(/\s+/).filter(Boolean) })} placeholder={t('admin.providers.scopesPlaceholder')} />
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.providers.docsUrl')}</Label>
                <Input value={newForm.docsUrl ?? ''} onChange={(e) => setNewForm({ ...newForm, docsUrl: e.target.value })} placeholder="https://docs.example.com" />
              </div>
            </div>
            {createError && <div className="text-sm text-destructive">{createError}</div>}
            {/* 启用 / 代理开关：与编辑面板一致，放在创建按钮上方。 */}
            <div className="rounded-lg border bg-muted/20 px-4">
              <SwitchRow
                label={t('admin.providers.enable')}
                checked={!!newForm.enabled}
                onChange={() => setNewForm({ ...newForm, enabled: !newForm.enabled })}
              />
              {/* 与编辑面板保持一致：出站请求（令牌 / 用户信息）可走「系统设置 → 代理设置」
                  的代理。系统代理未配置时保存会被后端拒绝（proxy.not_configured），
                  错误信息直接显示在本表单下方。 */}
              <SwitchRow
                label={t('admin.providers.useProxy')}
                checked={!!newForm.useProxy}
                onChange={() => setNewForm({ ...newForm, useProxy: !newForm.useProxy })}
                divider={false}
              />
            </div>
            <div className="flex gap-2 pt-1">
              <Button onClick={() => create.mutate()} disabled={create.isPending}><Save className="size-4" /> {t('common.create')}</Button>
              <Button variant="outline" onClick={() => { setAdding(false); setNewForm({}); setCreateError('') }}>{t('common.cancel')}</Button>
            </div>
          </CardContent>
        </Card>
      )}

    </div>
  )
}

/* ------------------------------- 3. 安全策略 ------------------------------ */
function SecuritySection() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { success: toastSuccess, error: toastError } = useToast()
  const { data: policy, isError, refetch } = useQuery({ queryKey: ['admin', 'security-policy'], queryFn: () => api.adminSecurityPolicy<Record<string, unknown>>() })
  const [form, setForm] = React.useState<any>(null)
  const dirtyRef = React.useRef(false)
  const syncedRef = React.useRef(false)

  React.useEffect(() => {
    if (!policy) return
    if (!syncedRef.current || !dirtyRef.current) {
      setForm(policy)
      syncedRef.current = true
    }
  }, [policy])

  const save = useMutation({
    mutationFn: () => api.adminUpdateSecurityPolicy(form),
    onSuccess: async () => {
      dirtyRef.current = false
      await qc.invalidateQueries({ queryKey: ['admin', 'security-policy'] })
      toastSuccess(t('common.saved'))
    },
    // 此前缺 onError：保存失败时界面毫无变化，管理员会以为已生效。
    onError: (e) => toastError(t('common.saveFail'), e instanceof ApiError ? e.message : ''),
  })

  const set = (k: string, v: any) => {
    dirtyRef.current = true
    setForm((f: any) => ({ ...f, [k]: v }))
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      {/* 左列：密码策略与手机号各占一张卡片（格式与其他卡片一致）。
          两张卡合计高度与右侧「会话策略」对齐 —— 密码策略内容少，用 flex-1 吸收
          行内多余的高度，这样左列底部不会空出一块，右列也不再单独很长。 */}
      <div className="flex flex-col gap-6">
        <Card className="flex-1">
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><ShieldCheck className="size-4" /> {t('admin.security.passwordPolicy')}</CardTitle>
          </CardHeader>
          <CardContent>
            {form && (
              <>
                <div className="mb-4 max-w-xs space-y-1.5">
                  <Label>{t('admin.security.minLength')}</Label>
                  <Input
                    type="number"
                    min={6}
                    max={64}
                    value={form.minPasswordLength ?? 12}
                    // 清空输入框会得到空串，Number('') 是 0；
                    // 后端会把 0 夹取到最小值再落库，UI 与库值就会不一致。
                    // 这里空值回落到默认 12，并钳制到 [6,64]。
                    onChange={(e) => {
                      const raw = e.target.value
                      if (raw === '') { set('minPasswordLength', 12); return }
                      const n = Number(raw)
                      if (!Number.isFinite(n)) return
                      set('minPasswordLength', Math.min(64, Math.max(6, Math.trunc(n))))
                    }}
                  />
                </div>
                <SwitchRow label={t('admin.security.requireUpper')} checked={!!form.requireUppercase} onChange={() => set('requireUppercase', !form.requireUppercase)} />
                <SwitchRow label={t('admin.security.requireLower')} checked={!!form.requireLowercase} onChange={() => set('requireLowercase', !form.requireLowercase)} />
                <SwitchRow label={t('admin.security.requireNumber')} checked={!!form.requireNumber} onChange={() => set('requireNumber', !form.requireNumber)} />
                <SwitchRow label={t('admin.security.requireSymbol')} checked={!!form.requireSymbol} onChange={() => set('requireSymbol', !form.requireSymbol)} />
              </>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2"><Smartphone className="size-4" /> {t('admin.security.phoneTitle')}</CardTitle>
          </CardHeader>
          <CardContent>
            {form && (
              <SwitchRow
                label={t('admin.security.phoneAdd')}
                checked={!!form.phoneAddEnabled}
                onChange={() => set('phoneAddEnabled', !form.phoneAddEnabled)}
                divider={false}
              />
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t('admin.security.sessionPolicy')}</CardTitle>
        </CardHeader>
        <CardContent>
          {form && (
            <>
              <div className="mb-4 max-w-xs space-y-1.5">
                <Label>{t('admin.security.sessionTtl')}</Label>
                <Input
                  type="number"
                  min={1}
                  max={90}
                  value={form.sessionTTLDays ?? 14}
                  onChange={(e) => {
                    const raw = e.target.value
                    if (raw === '') { set('sessionTTLDays', 14); return }
                    const n = Number(raw)
                    if (!Number.isFinite(n)) return
                    set('sessionTTLDays', Math.min(90, Math.max(1, Math.trunc(n))))
                  }}
                />
              </div>
              {/* 「允许密码登录」开关已隐藏：系统默认开启且不在管理后台暴露。 */}
              <SwitchRow label={t('admin.security.allowSignup')} checked={!!form.signupEnabled} onChange={() => set('signupEnabled', !form.signupEnabled)} />
              <SwitchRow label={t('admin.security.verifyEmail')} checked={!!form.signupEmailVerification} onChange={() => set('signupEmailVerification', !form.signupEmailVerification)} />
              <SwitchRow label={t('admin.security.disableAliasEmail')} checked={!!form.disableAliasEmail} onChange={() => set('disableAliasEmail', !form.disableAliasEmail)} />
              <SwitchRow
                label={t('admin.security.emailDomainWhitelistEnabled')}
                checked={!!form.emailDomainWhitelistEnabled}
                onChange={() => set('emailDomainWhitelistEnabled', !form.emailDomainWhitelistEnabled)}
              />
              <SwitchRow label={t('admin.security.allowAccountDeletion')} checked={!!form.accountDeletionEnabled} onChange={() => set('accountDeletionEnabled', !form.accountDeletionEnabled)} />
              <div className="pt-3 space-y-1.5">
                <Label>{t('admin.security.accountDeletionCooldown')}</Label>
                <Input
                  type="number"
                  min={0}
                  max={720}
                  value={form.accountDeletionCooldownHours ?? 0}
                  onChange={(e) => {
                    const raw = e.target.value
                    if (raw === '') { set('accountDeletionCooldownHours', 0); return }
                    const n = Number(raw)
                    if (!Number.isFinite(n)) return
                    set('accountDeletionCooldownHours', Math.min(720, Math.max(0, Math.trunc(n))))
                  }}
                />
              </div>
              <div className="pt-3">
                <Label>{t('admin.security.emailDomainWhitelist')}</Label>
                <textarea
                  rows={5}
                  className="mt-1.5 flex w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-xs transition-[color,box-shadow] outline-none selection:bg-primary selection:text-primary-foreground placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] disabled:cursor-not-allowed disabled:opacity-50"
                  placeholder={t('admin.security.emailDomainWhitelistPlaceholder')}
                  value={(form.emailDomainWhitelist ?? '').split(',').filter(Boolean).join('\n')}
                  onChange={(e) => set('emailDomainWhitelist', e.target.value.split('\n').map((s: string) => s.trim()).filter(Boolean).join(','))}
                />
                <p className="mt-1 text-xs text-muted-foreground">{t('admin.security.emailDomainWhitelistDesc')}</p>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <div className="lg:col-span-2 flex justify-end">
        <Button onClick={() => save.mutate()} disabled={save.isPending}><Save className="size-4" /> {t('admin.security.save')}</Button>
      </div>

      {/* 注销账号申请审核：冷静期结束后才允许通过 */}
      <div className="lg:col-span-2">
        <DeletionRequestsCard />
      </div>
    </div>
  )
}

/* -------------------- 注销账号申请审核 -------------------- */
function DeletionRequestsCard() {
  const { t, lang } = useI18n()
  const qc = useQueryClient()
  const { success: toastSuccess, error: toastError } = useToast()
  const { confirm } = useConfirm()
  const { data: reqs } = useQuery({
    queryKey: ['admin', 'deletion-requests'],
    queryFn: () => api.adminDeletionRequests<DeletionReq[]>(),
  })
  const items: any[] = reqs ?? []
  // 通过/驳回期间锁定的行：此前这两个 async 函数在 await 期间按钮仍可点击，
  // 重复提交会写入重复审计事件。
  const [pendingReq, setPendingReq] = React.useState<string | null>(null)

  const approve = async (id: string, name: string) => {
    const ok = await confirm({
      title: t('admin.deletion.approveTitle'),
      description: t('admin.deletion.approveDesc', { name }),
      confirmText: t('admin.deletion.approve'),
      variant: 'destructive',
    })
    if (!ok) return
    setPendingReq(id)
    try {
      await api.adminApproveDeletionRequest(id)
      await qc.invalidateQueries({ queryKey: ['admin', 'deletion-requests'] })
      qc.invalidateQueries({ queryKey: ['admin', 'dashboard'] })
      qc.invalidateQueries({ queryKey: ['admin', 'users'] })
      toastSuccess(t('admin.deletion.approved'))
    } catch (e: any) {
      toastError(t('admin.deletion.approveFailed'), e?.message ?? '')
    } finally {
      setPendingReq(null)
    }
  }

  // 驳回同样是不可撤销的破坏性操作（此前连二次确认都没有）。
  const reject = async (id: string) => {
    const ok = await confirm({
      title: t('admin.deletion.rejectTitle'),
      description: t('admin.deletion.rejectDesc'),
      confirmText: t('admin.deletion.reject'),
      variant: 'destructive',
    })
    if (!ok) return
    setPendingReq(id)
    try {
      await api.adminRejectDeletionRequest(id)
      await qc.invalidateQueries({ queryKey: ['admin', 'deletion-requests'] })
      toastSuccess(t('admin.deletion.rejected'))
    } catch (e: any) {
      toastError(t('admin.deletion.rejectFailed'), e?.message ?? '')
    } finally {
      setPendingReq(null)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><Trash2 className="size-4" /> {t('admin.deletion.title')}</CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('admin.deletion.user')}</TableHead>
              <TableHead>{t('admin.deletion.reason')}</TableHead>
              <TableHead>{t('admin.deletion.requestedAt')}</TableHead>
              <TableHead>{t('admin.deletion.scheduledAt')}</TableHead>
              <TableHead>{t('common.status')}</TableHead>
              <TableHead className="text-right">{t('common.actions')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((r: any) => {
              const cooling = r.remainingSeconds > 0
              return (
                <TableRow key={r.id}>
                  <TableCell>
                    <div className="text-sm font-medium">{r.username || `#${r.userId}`}</div>
                    <div className="text-xs text-muted-foreground">{r.email}</div>
                  </TableCell>
                  <TableCell className="max-w-48 truncate text-xs text-muted-foreground" title={r.reason}>{r.reason || '—'}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatDateTimeI18n(r.createdAt, lang)}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatDateTimeI18n(r.scheduledAt, lang)}</TableCell>
                  <TableCell>
                    <Badge variant={r.status === 'pending' ? 'secondary' : 'outline'}>
                      {t(`security.deleteAccountStatus.${r.status}`)}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex justify-end gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-destructive hover:text-destructive"
                        disabled={r.status !== 'pending' || cooling || pendingReq === r.id}
                        title={cooling ? t('admin.deletion.cooling') : undefined}
                        onClick={() => approve(r.id, r.username || `#${r.userId}`)}
                      >
                        <Check className="size-4" /> {t('admin.deletion.approve')}
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={r.status !== 'pending' || pendingReq === r.id}
                        onClick={() => reject(r.id)}
                      >
                        <X className="size-4" /> {t('admin.deletion.reject')}
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              )
            })}
            {items.length === 0 && (
              <TableRow><TableCell colSpan={6} className="py-10 text-center text-sm text-muted-foreground">{t('admin.deletion.empty')}</TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

/* ------------------------------- 4. 邮件服务 ------------------------------ */
function MailSection() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { data: mail } = useQuery({ queryKey: ['admin', 'mail'], queryFn: () => api.adminMail<Record<string, unknown>>() })
  const [form, setForm] = React.useState<any>(null)
  const [to, setTo] = React.useState('')

  React.useEffect(() => {
    if (mail) setForm(mail)
  }, [mail])

  const save = useMutation({
    mutationFn: () => api.adminUpdateMail({
      enabled: !!form?.enabled,
      host: form?.host ?? '',
      port: Number(form?.port) || 465,
      user: form?.user ?? '',
      password: form?.password ?? '',
      fromEmail: form?.fromEmail ?? '',
      fromName: form?.fromName ?? '',
      useTLS: !!form?.useTLS,
      skipVerify: !!form?.skipVerify,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'mail'] })
      toast({ type: 'success', title: t('admin.mail.saved') })
    },
    onError: (e) => toast({ type: 'error', title: t('admin.mail.saveFail'), description: e instanceof ApiError ? e.message : '' }),
  })

  const sendTest = useMutation({
    mutationFn: () => api.adminMailTest(to.trim()),
    onSuccess: () => toast({ type: 'success', title: t('admin.mail.testSent'), description: to }),
    onError: (e) => toast({ type: 'error', title: t('admin.mail.testFailed'), description: e instanceof ApiError ? e.message : '' }),
  })

  const setField = (key: string, v: any) => setForm((f: any) => ({ ...f, [key]: v }))

  return (
    <div className="grid gap-6">
      {/* SMTP 配置 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Mail className="size-4" /> {t('admin.mail.smtp')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          {/* 邮件服务启用开关 */}
          <div className="rounded-lg border bg-muted/20 px-4">
            <SwitchRow
              label={t('admin.mail.enable')}
              checked={!!form?.enabled}
              onChange={() => setField('enabled', !form?.enabled)}
              divider={false}
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label>{t('admin.mail.host')}</Label>
              <Input value={form?.host ?? ''} onChange={(e) => setField('host', e.target.value)} placeholder="smtp.example.com" />
            </div>
            <div className="space-y-1.5">
              <Label>{t('admin.mail.port')}</Label>
              <Input value={form?.port ?? ''} onChange={(e) => setField('port', e.target.value)} placeholder="465" inputMode="numeric" />
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label>{t('admin.mail.user')}</Label>
              <Input value={form?.user ?? ''} onChange={(e) => setField('user', e.target.value)} placeholder="user@example.com" autoComplete="off" />
            </div>
            <div className="space-y-1.5">
              <Label>{t('admin.mail.password')}</Label>
              <Input
                type="password"
                value={form?.password ?? ''}
                onChange={(e) => setField('password', e.target.value)}
                placeholder={secretPlaceholder(!!form?.hasPassword, t('common.secretPlaceholder'))}
                autoComplete="new-password"
              />
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label>{t('admin.mail.fromAddress')}</Label>
              <Input value={form?.fromEmail ?? ''} onChange={(e) => setField('fromEmail', e.target.value)} placeholder="noreply@example.com" />
            </div>
            <div className="space-y-1.5">
              <Label>{t('admin.mail.fromName')}</Label>
              <Input value={form?.fromName ?? ''} onChange={(e) => setField('fromName', e.target.value)} placeholder="OpenIdP" />
            </div>
          </div>

          <div className="rounded-lg border bg-muted/20 px-4">
            <SwitchRow label={t('admin.mail.useTLS')} checked={!!form?.useTLS} onChange={() => setField('useTLS', !form?.useTLS)} />
            <SwitchRow label={t('admin.mail.skipVerify')} checked={!!form?.skipVerify} onChange={() => setField('skipVerify', !form?.skipVerify)} divider={false} />
          </div>

          <div className="space-y-1.5 border-t pt-4">
            <Label>{t('admin.mail.testTo')}</Label>
            <div className="flex gap-2">
              <Input value={to} onChange={(e) => setTo(e.target.value)} placeholder={t('admin.mail.testPlaceholder')} />
              <Button variant="outline" onClick={() => sendTest.mutate()} disabled={!to.trim() || sendTest.isPending}>
                <Send className="size-4" /> {t('admin.mail.sendTest')}
              </Button>
            </div>
          </div>

          <div className="flex items-center gap-3 pt-2">
            <Button onClick={() => save.mutate()} disabled={save.isPending}><Save className="size-4" /> {t('admin.mail.save')}</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

/* ------------------------------- 5. 人机验证 ------------------------------ */
function CaptchaSection() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { success: toastSuccess, error: toastError } = useToast()
  const { data } = useQuery({ queryKey: ['admin', 'captcha'], queryFn: () => api.adminCaptcha<Record<string, unknown>>() })
  const [form, setForm] = React.useState<any>(null)
  const [testing, setTesting] = React.useState(false)
  const [testResult, setTestResult] = React.useState<{ ok: boolean; msg: string } | null>(null)
  const dirtyRef = React.useRef(false)
  const syncedRef = React.useRef(false)

  React.useEffect(() => {
    if (!data) return
    if (!syncedRef.current || !dirtyRef.current) {
      setForm(data)
      syncedRef.current = true
    }
  }, [data])

  const save = useMutation({
    mutationFn: () => api.adminUpdateCaptcha({
      provider: form.provider ?? 'none',
      geetestCaptchaId: form.geetestCaptchaId ?? '',
      geetestCaptchaKey: form.geetestCaptchaKey ?? '',
      // 验证模式强制内置为 bind，隐藏“验证模式 / API 域名”填写
      geetestApiDomain: '',
      geetestBindMode: 'bind',
      turnstileSiteKey: form.turnstileSiteKey ?? '',
      turnstileSecretKey: form.turnstileSecretKey ?? '',
      // 自定义 siteverify 端点：留空使用内置默认域名。
      // 此前该字段后台能读能写却从不参与保存，填了不会生效。
      turnstileVerifyUrl: form.turnstileVerifyUrl ?? '',
      requiredForLogin: !!form.requiredForLogin,
      requiredForSignup: !!form.requiredForSignup,
      requiredForPasswordReset: !!form.requiredForPasswordReset,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'captcha'] })
      toastSuccess(t('common.saved'))
    },
    // 此前缺 onError：保存失败时界面毫无变化，管理员会以为配置已生效。
    onError: (e) => toastError(t('common.saveFail'), e instanceof ApiError ? e.message : ''),
  })

  // 测试连接：用当前表单中的值直接请求验证服务，不保存
  const test = useMutation({
    mutationFn: () => api.adminCaptchaTest({
      provider: form.provider ?? 'none',
      geetestCaptchaId: form.geetestCaptchaId ?? '',
      geetestCaptchaKey: form.geetestCaptchaKey ?? '',
      geetestApiDomain: form.geetestApiDomain ?? '',
      turnstileSiteKey: form.turnstileSiteKey ?? '',
      turnstileSecretKey: form.turnstileSecretKey ?? '',
    }),
    onSuccess: async () => {
      setTestResult({ ok: true, msg: t('admin.captcha.testOk') })
    },
    onError: (e) => {
      setTestResult({ ok: false, msg: e instanceof ApiError ? e.message : t('admin.captcha.testFailed') })
    },
    onSettled: () => setTesting(false),
  })

  const toggle = (key: string) => setForm((f: any) => ({ ...f, [key]: !f?.[key] }))
  // 用 || 而非 ??：新建的人机验证配置 provider 是空字符串（后端初始化即留空表示
  // 未启用），空串不是 nullish，?? 兜不住，会导致下拉框既没选中项也没占位文案。
  const provider = form?.provider || 'none'

  return (
    <div className="grid gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><CloudCog className="size-4" /> {t('admin.captcha.provider')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {form && (
            <>
              <div className="space-y-1.5">
                <Label>{t('admin.captcha.activeProvider')}</Label>
                <Select value={provider} onValueChange={(v) => setForm({ ...form, provider: v })} ariaLabel={t('admin.captcha.activeProvider')} className="w-full">
                  <SelectItem value="none">{t('admin.captcha.none')}</SelectItem>
                  <SelectItem value="turnstile">Cloudflare Turnstile</SelectItem>
                  <SelectItem value="geetest">极验 GeeTest v4</SelectItem>
                </Select>
              </div>

              {/* 按所选提供商动态展示填写框（极验强制 bind 内嵌，隐藏模式/API域名/默认域名/提示） */}
              {provider === 'turnstile' && (
                <div className="space-y-4">
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label>{t('admin.captcha.turnstileSiteKey')}</Label>
                      <Input value={form.turnstileSiteKey ?? ''} onChange={(e) => setForm({ ...form, turnstileSiteKey: e.target.value })} placeholder="0x4AAAAAA..." />
                    </div>
                    <div className="space-y-1.5">
                      <Label>{t('admin.captcha.turnstileSecretKey')}</Label>
                      <Input
                        type="password"
                        value={form.turnstileSecretKey ?? ''}
                        onChange={(e) => setForm({ ...form, turnstileSecretKey: e.target.value })}
                        placeholder={secretPlaceholder(!!form.hasTurnstileKey, t('common.secretPlaceholder'))}
                      />
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.captcha.turnstileVerifyUrl')}</Label>
                    <Input
                      value={form.turnstileVerifyUrl ?? ''}
                      onChange={(e) => setForm({ ...form, turnstileVerifyUrl: e.target.value })}
                      placeholder={form.turnstileVerifyUrlDefault ?? 'https://challenges.cloudflare.com/turnstile/v0/siteverify'}
                    />
                    <p className="text-xs text-muted-foreground">{t('admin.captcha.turnstileVerifyUrlDesc')}</p>
                  </div>
                </div>
              )}

              {provider === 'geetest' && (
                <div className="space-y-4">
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label>{t('admin.captcha.geetestId')}</Label>
                      <Input value={form.geetestCaptchaId ?? ''} onChange={(e) => setForm({ ...form, geetestCaptchaId: e.target.value })} placeholder="captcha_id" />
                    </div>
                    <div className="space-y-1.5">
                      <Label>{t('admin.captcha.geetestKey')}</Label>
                      <Input
                        type="password"
                        value={form.geetestCaptchaKey ?? ''}
                        onChange={(e) => setForm({ ...form, geetestCaptchaKey: e.target.value })}
                        placeholder={secretPlaceholder(!!form.hasGeetestKey, t('common.secretPlaceholder'))}
                      />
                    </div>
                  </div>
                </div>
              )}

              <div className="rounded-lg border bg-muted/20 px-4">
                <SwitchRow label={t('admin.captcha.requiredForLogin')} checked={form.requiredForLogin} onChange={() => toggle('requiredForLogin')} />
                <SwitchRow label={t('admin.captcha.requiredForSignup')} checked={form.requiredForSignup} onChange={() => toggle('requiredForSignup')} />
                <SwitchRow label={t('admin.captcha.requiredForPasswordReset')} checked={form.requiredForPasswordReset} onChange={() => toggle('requiredForPasswordReset')} divider={false} />
              </div>

              <div className="flex items-center gap-3 pt-2">
                <Button onClick={() => { setTesting(true); setTestResult(null); test.mutate() }} disabled={test.isPending || testing} variant="outline">
                  {test.isPending || testing ? <Loader2 className="size-4 animate-spin" /> : <PlugZap className="size-4" />} {t('admin.captcha.test')}
                </Button>
                <Button onClick={() => save.mutate()} disabled={save.isPending}><Save className="size-4" /> {t('common.save')}</Button>
              </div>
              {testResult && (
                <div className={cn('mt-1 rounded-md border px-3 py-2 text-sm', testResult.ok ? 'border-success/30 bg-success/5 text-success' : 'border-destructive/30 bg-destructive/5 text-destructive')}>
                  {testResult.msg}
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

/* ------------------------------- 5b. 短信验证码 ----------------------------- */
// 短信验证码服务配置：与人机验证同一套交互（下拉切换服务商 → 按服务商动态渲染
// 字段 → 测试连接 → 保存）。短信仅用于手机号归属验证。
function SmsSection() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { success: toastSuccess, error: toastError } = useToast()
  const { data } = useQuery({ queryKey: ['admin', 'sms'], queryFn: () => api.adminSms<Record<string, unknown>>() })
  const [form, setForm] = React.useState<any>(null)
  const [testing, setTesting] = React.useState(false)
  const [testResult, setTestResult] = React.useState<{ ok: boolean; msg: string } | null>(null)
  const dirtyRef = React.useRef(false)
  const syncedRef = React.useRef(false)

  React.useEffect(() => {
    if (!data) return
    if (!syncedRef.current || !dirtyRef.current) {
      setForm({ ...data, enabled: !!data.enabled, codeTtl: data.codeTtl ?? 5, cooldown: data.cooldown ?? 60 })
      syncedRef.current = true
    }
  }, [data])

  const payload = () => ({
    enabled: !!form.enabled,
    provider: form.provider || 'none',
    siteName: form.siteName ?? '',
    codeTtl: Number(form.codeTtl) || 5,
    cooldown: Number(form.cooldown) || 60,
    aliyunAccessKeyId: form.aliyunAccessKeyId ?? '',
    aliyunAccessKeySecret: form.aliyunAccessKeySecret ?? '',
    aliyunSignName: form.aliyunSignName ?? '',
    aliyunTemplateCode: form.aliyunTemplateCode ?? '',
    aliyunEndpoint: form.aliyunEndpoint ?? '',
    tencentSecretId: form.tencentSecretId ?? '',
    tencentSecretKey: form.tencentSecretKey ?? '',
    tencentSdkAppId: form.tencentSdkAppId ?? '',
    tencentSignName: form.tencentSignName ?? '',
    tencentTemplateId: form.tencentTemplateId ?? '',
    tencentRegion: form.tencentRegion ?? '',
    volcAccessKeyId: form.volcAccessKeyId ?? '',
    volcAccessKeySecret: form.volcAccessKeySecret ?? '',
    volcSmsAccount: form.volcSmsAccount ?? '',
    volcSign: form.volcSign ?? '',
    volcTemplateId: form.volcTemplateId ?? '',
    volcRegion: form.volcRegion ?? '',
    huaweiAppKey: form.huaweiAppKey ?? '',
    huaweiAppSecret: form.huaweiAppSecret ?? '',
    huaweiSender: form.huaweiSender ?? '',
    huaweiTemplateId: form.huaweiTemplateId ?? '',
    huaweiEndpoint: form.huaweiEndpoint ?? '',
    qimoAccountSid: form.qimoAccountSid ?? '',
    qimoAuthToken: form.qimoAuthToken ?? '',
    qimoAppId: form.qimoAppId ?? '',
    qimoTemplateId: form.qimoTemplateId ?? '',
    submailAppId: form.submailAppId ?? '',
    submailAppKey: form.submailAppKey ?? '',
    submailSign: form.submailSign ?? '',
    submailTemplateId: form.submailTemplateId ?? '',
    customUrl: form.customUrl ?? '',
    customMethod: form.customMethod ?? '',
    customHeaders: form.customHeaders ?? '',
    customBody: form.customBody ?? '',
    customSecret: form.customSecret ?? '',
  })

  const save = useMutation({
    mutationFn: () => api.adminUpdateSms(payload()),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'sms'] })
      qc.invalidateQueries({ queryKey: ['session'] })
      toastSuccess(t('common.saved'))
    },
    onError: (e) => toastError(t('common.saveFail'), e instanceof ApiError ? e.message : ''),
  })

  const test = useMutation({
    mutationFn: () => api.adminSmsTest(payload()),
    onSuccess: () => setTestResult({ ok: true, msg: t('admin.sms.testOk') }),
    onError: (e) => setTestResult({ ok: false, msg: e instanceof ApiError ? e.message : t('admin.sms.testFailed') }),
    onSettled: () => setTesting(false),
  })

  const toggle = (key: string) => setForm((f: any) => ({ ...f, [key]: !f?.[key] }))
  const provider = form?.provider || 'none'
  const set = (k: string, v: any) => { dirtyRef.current = true; setForm((f: any) => ({ ...f, [k]: v })) }

  return (
    <div className="grid gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Smartphone className="size-4" /> {t('admin.sms.provider')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {form && (
            <>
              <div className="rounded-lg border bg-muted/20 px-4">
                <SwitchRow label={t('admin.sms.enabled')} checked={form.enabled} onChange={() => toggle('enabled')} divider={false} />
              </div>

              <div className="space-y-1.5">
                <Label>{t('admin.sms.activeProvider')}</Label>
                <Select value={provider} onValueChange={(v) => set('provider', v)} ariaLabel={t('admin.sms.activeProvider')} className="w-full">
                  <SelectItem value="none">{t('admin.sms.none')}</SelectItem>
                  <SelectItem value="aliyun">Aliyun PNVS</SelectItem>
                  <SelectItem value="tencent">Tencent Cloud SMS</SelectItem>
                  <SelectItem value="volcengine">Volcengine SMS</SelectItem>
                  <SelectItem value="huawei">Huawei Cloud SMS</SelectItem>
                  <SelectItem value="qimo">Qimo SMS</SelectItem>
                  <SelectItem value="submail">SUBMAIL</SelectItem>
                  <SelectItem value="custom">{t('admin.sms.custom')}</SelectItem>
                </Select>
              </div>

              {/* 通用：签名 / 应用名 + 有效期 / 冷却 */}
              <div className="grid gap-4 sm:grid-cols-3">
                <div className="space-y-1.5">
                  <Label>{t('admin.sms.siteName')}</Label>
                  <Input value={form.siteName ?? ''} onChange={(e) => set('siteName', e.target.value)} placeholder={t('admin.sms.siteNamePlaceholder')} />
                </div>
                <div className="space-y-1.5">
                  <Label>{t('admin.sms.codeTtl')}</Label>
                  <Input type="number" value={form.codeTtl ?? 5} onChange={(e) => set('codeTtl', e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label>{t('admin.sms.cooldown')}</Label>
                  <Input type="number" value={form.cooldown ?? 60} onChange={(e) => set('cooldown', e.target.value)} />
                </div>
              </div>

              {provider === 'aliyun' && (
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.aliyunAccessKeyId')}</Label>
                    <Input value={form.aliyunAccessKeyId ?? ''} onChange={(e) => set('aliyunAccessKeyId', e.target.value)} placeholder="LTAI..." />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.aliyunAccessKeySecret')}</Label>
                    <Input type="password" value={form.aliyunAccessKeySecret ?? ''} onChange={(e) => set('aliyunAccessKeySecret', e.target.value)} placeholder={secretPlaceholder(!!form.hasAliyunSecret, t('common.secretPlaceholder'))} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.aliyunSignName')}</Label>
                    <Input value={form.aliyunSignName ?? ''} onChange={(e) => set('aliyunSignName', e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.aliyunTemplateCode')}</Label>
                    <Input value={form.aliyunTemplateCode ?? ''} onChange={(e) => set('aliyunTemplateCode', e.target.value)} placeholder="SMS_..." />
                  </div>
                  <div className="space-y-1.5 sm:col-span-2">
                    <Label>{t('admin.sms.endpoint')}</Label>
                    <Input value={form.aliyunEndpoint ?? ''} onChange={(e) => set('aliyunEndpoint', e.target.value)} placeholder={String(form.aliyunEndpointDefault ?? '')} />
                  </div>
                </div>
              )}

              {provider === 'tencent' && (
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.tencentSecretId')}</Label>
                    <Input value={form.tencentSecretId ?? ''} onChange={(e) => set('tencentSecretId', e.target.value)} placeholder="AKID..." />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.tencentSecretKey')}</Label>
                    <Input type="password" value={form.tencentSecretKey ?? ''} onChange={(e) => set('tencentSecretKey', e.target.value)} placeholder={secretPlaceholder(!!form.hasTencentSecret, t('common.secretPlaceholder'))} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.tencentSdkAppId')}</Label>
                    <Input value={form.tencentSdkAppId ?? ''} onChange={(e) => set('tencentSdkAppId', e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.signName')}</Label>
                    <Input value={form.tencentSignName ?? ''} onChange={(e) => set('tencentSignName', e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.templateId')}</Label>
                    <Input value={form.tencentTemplateId ?? ''} onChange={(e) => set('tencentTemplateId', e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.region')}</Label>
                    <Input value={form.tencentRegion ?? ''} onChange={(e) => set('tencentRegion', e.target.value)} placeholder="ap-guangzhou" />
                  </div>
                </div>
              )}

              {provider === 'volcengine' && (
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.accessKeyId')}</Label>
                    <Input value={form.volcAccessKeyId ?? ''} onChange={(e) => set('volcAccessKeyId', e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.accessKeySecret')}</Label>
                    <Input type="password" value={form.volcAccessKeySecret ?? ''} onChange={(e) => set('volcAccessKeySecret', e.target.value)} placeholder={secretPlaceholder(!!form.hasVolcSecret, t('common.secretPlaceholder'))} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.smsAccount')}</Label>
                    <Input value={form.volcSmsAccount ?? ''} onChange={(e) => set('volcSmsAccount', e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.signName')}</Label>
                    <Input value={form.volcSign ?? ''} onChange={(e) => set('volcSign', e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.templateId')}</Label>
                    <Input value={form.volcTemplateId ?? ''} onChange={(e) => set('volcTemplateId', e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.region')}</Label>
                    <Input value={form.volcRegion ?? ''} onChange={(e) => set('volcRegion', e.target.value)} placeholder="cn-north-1" />
                  </div>
                </div>
              )}

              {provider === 'huawei' && (
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.appKey')}</Label>
                    <Input value={form.huaweiAppKey ?? ''} onChange={(e) => set('huaweiAppKey', e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.appSecret')}</Label>
                    <Input type="password" value={form.huaweiAppSecret ?? ''} onChange={(e) => set('huaweiAppSecret', e.target.value)} placeholder={secretPlaceholder(!!form.hasHuaweiSecret, t('common.secretPlaceholder'))} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.sender')}</Label>
                    <Input value={form.huaweiSender ?? ''} onChange={(e) => set('huaweiSender', e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.templateId')}</Label>
                    <Input value={form.huaweiTemplateId ?? ''} onChange={(e) => set('huaweiTemplateId', e.target.value)} />
                  </div>
                  <div className="space-y-1.5 sm:col-span-2">
                    <Label>{t('admin.sms.endpoint')}</Label>
                    <Input value={form.huaweiEndpoint ?? ''} onChange={(e) => set('huaweiEndpoint', e.target.value)} placeholder={String(form.huaweiEndpointDefault ?? '')} />
                  </div>
                </div>
              )}

              {provider === 'qimo' && (
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.accountSid')}</Label>
                    <Input value={form.qimoAccountSid ?? ''} onChange={(e) => set('qimoAccountSid', e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.authToken')}</Label>
                    <Input type="password" value={form.qimoAuthToken ?? ''} onChange={(e) => set('qimoAuthToken', e.target.value)} placeholder={secretPlaceholder(!!form.hasQimoToken, t('common.secretPlaceholder'))} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.appId')}</Label>
                    <Input value={form.qimoAppId ?? ''} onChange={(e) => set('qimoAppId', e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.templateId')}</Label>
                    <Input value={form.qimoTemplateId ?? ''} onChange={(e) => set('qimoTemplateId', e.target.value)} />
                  </div>
                </div>
              )}

              {provider === 'submail' && (
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.appId')}</Label>
                    <Input value={form.submailAppId ?? ''} onChange={(e) => set('submailAppId', e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.appKey')}</Label>
                    <Input type="password" value={form.submailAppKey ?? ''} onChange={(e) => set('submailAppKey', e.target.value)} placeholder={secretPlaceholder(!!form.hasSubmailKey, t('common.secretPlaceholder'))} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.signName')}</Label>
                    <Input value={form.submailSign ?? ''} onChange={(e) => set('submailSign', e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.templateId')}</Label>
                    <Input value={form.submailTemplateId ?? ''} onChange={(e) => set('submailTemplateId', e.target.value)} />
                  </div>
                </div>
              )}

              {provider === 'custom' && (
                <div className="grid gap-4 sm:grid-cols-2">
                  <div className="space-y-1.5 sm:col-span-2">
                    <Label>{t('admin.sms.customUrl')}</Label>
                    <Input value={form.customUrl ?? ''} onChange={(e) => set('customUrl', e.target.value)} placeholder="https://sms.example.com/send?phone={phone}&code={code}" />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.customMethod')}</Label>
                    <Select value={form.customMethod || 'POST'} onValueChange={(v) => set('customMethod', v)} ariaLabel={t('admin.sms.customMethod')} className="w-full">
                      <SelectItem value="POST">POST</SelectItem>
                      <SelectItem value="GET">GET</SelectItem>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label>{t('admin.sms.customSecret')}</Label>
                    <Input type="password" value={form.customSecret ?? ''} onChange={(e) => set('customSecret', e.target.value)} placeholder={secretPlaceholder(!!form.hasCustomSecret, t('common.secretPlaceholder'))} />
                  </div>
                  <div className="space-y-1.5 sm:col-span-2">
                    <Label>{t('admin.sms.customHeaders')}</Label>
                    <Input value={form.customHeaders ?? ''} onChange={(e) => set('customHeaders', e.target.value)} placeholder={'X-Api-Key: xxx'} />
                  </div>
                  <div className="space-y-1.5 sm:col-span-2">
                    <Label>{t('admin.sms.customBody')}</Label>
                    <Input value={form.customBody ?? ''} onChange={(e) => set('customBody', e.target.value)} placeholder={'{"mobile":"{phone}","code":"{code}"}'} />
                  </div>
                </div>
              )}

              <div className="flex items-center gap-3 pt-2">
                <Button onClick={() => { setTesting(true); setTestResult(null); test.mutate() }} disabled={test.isPending || testing || provider === 'none'} variant="outline">
                  {test.isPending || testing ? <Loader2 className="size-4 animate-spin" /> : <PlugZap className="size-4" />} {t('admin.sms.test')}
                </Button>
                <Button onClick={() => save.mutate()} disabled={save.isPending}><Save className="size-4" /> {t('common.save')}</Button>
              </div>
              {testResult && (
                <div className={cn('mt-1 rounded-md border px-3 py-2 text-sm', testResult.ok ? 'border-success/30 bg-success/5 text-success' : 'border-destructive/30 bg-destructive/5 text-destructive')}>
                  {testResult.msg}
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

/* ------------------------------- 6. 通行密钥 ------------------------------ */
function PasskeySection() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { success: toastSuccess, error: toastError } = useToast()
  const { data: site } = useQuery({ queryKey: ['admin', 'site'], queryFn: () => api.adminSite<Record<string, unknown>>() })
  const [form, setForm] = React.useState<any>(null)

  React.useEffect(() => {
    if (site) setForm(site)
  }, [site])

  const save = useMutation({
    onError: (e) => toastError(t('admin.site.saveFail'), e instanceof ApiError ? e.message : ''),
    mutationFn: () => api.adminUpdateSite({
      displayName: form?.displayName,
      siteUrl: form?.siteUrl ?? '',
      passkeyEnabled: !!form?.passkeyEnabled,
      passkeyDisplayName: form?.passkeyDisplayName ?? '',
      passkeyRPID: form?.passkeyRPID ?? '',
      passkeyAllowInsecure: !!form?.passkeyAllowInsecure,
      passkeyOrigins: form?.passkeyOrigins ?? [],
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'site'] })
      qc.invalidateQueries({ queryKey: ['session'] })
      toastSuccess(t('common.saved'))
    },
  })

  const set = (k: string, v: any) => setForm((f: any) => ({ ...f, [k]: v }))

  // 未填写依赖方 ID 时禁止开启通行密钥
  const submit = () => {
    if (form?.passkeyEnabled && !String(form?.passkeyRPID ?? '').trim()) {
      toastError(t('admin.passkey.rpIDRequired'))
      return
    }
    save.mutate()
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><KeyRound className="size-4" /> {t('admin.passkey.title')}</CardTitle>
        </CardHeader>
        <CardContent className="max-w-3xl">
          {form && (
            <div className="space-y-5">
              <div className="max-w-xl rounded-lg border bg-muted/20 px-4">
                <SwitchRow
                  label={t('admin.passkey.enable')}
                  checked={!!form.passkeyEnabled}
                  onChange={() => set('passkeyEnabled', !form.passkeyEnabled)}
                  divider={false}
                />
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.passkey.displayName')}</Label>
                <Input value={form.passkeyDisplayName ?? ''} onChange={(e) => set('passkeyDisplayName', e.target.value)} placeholder={t('admin.passkey.displayNamePlaceholder')} />
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.passkey.rpID')}</Label>
                <Input value={form.passkeyRPID ?? ''} onChange={(e) => set('passkeyRPID', e.target.value)} placeholder="auth.example.com" />
              </div>
              <div className="max-w-xl rounded-lg border bg-muted/20 px-4">
                <SwitchRow
                  label={t('admin.passkey.allowInsecure')}
                  desc={t('admin.passkey.allowInsecureDesc')}
                  checked={!!form.passkeyAllowInsecure}
                  onChange={() => set('passkeyAllowInsecure', !form.passkeyAllowInsecure)}
                  divider={false}
                />
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.passkey.origins')}</Label>
                <textarea
                  rows={5}
                  className="mt-1.5 flex w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm shadow-xs transition-[color,box-shadow] outline-none selection:bg-primary selection:text-primary-foreground placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] disabled:cursor-not-allowed disabled:opacity-50"
                  placeholder="https://auth.example.com"
                  value={(form.passkeyOrigins ?? []).join('\n')}
                  onChange={(e) => set('passkeyOrigins', e.target.value.split(/[\n,]/).map((s: string) => s.trim()).filter(Boolean))}
                />
                <p className="text-xs text-muted-foreground">{t('admin.passkey.originsDesc')}</p>
              </div>
              <div className="flex justify-end">
                <Button onClick={submit} disabled={save.isPending}><Save className="size-4" /> {t('common.save')}</Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  代理设置：仅作为配置项，供开启「使用代理」的登录提供商使用           */
/* ------------------------------------------------------------------ */

function ProxySection() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { data: proxy } = useQuery({ queryKey: ['admin', 'proxy'], queryFn: () => api.adminProxy<Record<string, unknown>>() })
  const [form, setForm] = React.useState<any>(null)
  const [password, setPassword] = React.useState('')
  const [testing, setTesting] = React.useState(false)
  const [testResult, setTestResult] = React.useState<string>('')

  React.useEffect(() => {
    if (proxy) setForm(proxy)
  }, [proxy])

  const setField = (k: string, v: unknown) => setForm((f: any) => ({ ...f, [k]: v }))

  const save = useMutation({
    mutationFn: () => {
      const body: any = {
        protocol: form.protocol ?? 'http',
        host: form.host ?? '',
        port: Number(form.port) || 0,
        username: form.username ?? '',
        enabled: !!form.enabled,
      }
      if (password) body.password = password
      return api.adminUpdateProxy(body)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'proxy'] })
      qc.invalidateQueries({ queryKey: ['admin', 'oauth-providers'] })
      setPassword('')
      setTestResult('')
      toast({ type: 'success', title: t('common.saved') })
    },
    onError: (e) => toast({ type: 'error', title: t('common.saveFailed'), description: e instanceof ApiError ? e.message : '' }),
  })

  const test = useMutation({
    mutationFn: () => api.adminTestProxy<{ success?: boolean; statusCode?: number; elapsedMilli?: number; error?: string }>({}),
    onSuccess: (res) => {
      if (res?.success) {
        setTestResult(t('admin.proxy.testOk', { code: res.statusCode ?? 0, time: res.elapsedMilli ?? 0 }))
      } else {
        setTestResult(res?.error || t('admin.proxy.testFail'))
      }
    },
    onError: (e) => setTestResult(e instanceof ApiError ? e.message : t('admin.proxy.testFail')),
  })

  const runTest = async () => {
    setTesting(true)
    setTestResult('')
    try {
      // 先保存当前填写内容再测试，保证测试用的是最新配置
      await api.adminUpdateProxy({
        protocol: (form.protocol as string) ?? 'http',
        host: (form.host as string) ?? '',
        port: Number(form.port) || 0,
        username: (form.username as string) ?? '',
        enabled: !!form.enabled,
        ...(password ? { password } : {}),
      })
      await qc.invalidateQueries({ queryKey: ['admin', 'proxy'] })
      test.mutate()
    } catch (e) {
      setTestResult(e instanceof ApiError ? e.message : t('admin.proxy.testFail'))
    } finally {
      setTesting(false)
    }
  }

  if (!form) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><Network className="size-4" /> {t('admin.proxy.title')}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <SwitchRow label={t('admin.proxy.enable')} checked={!!form.enabled} onChange={() => setField('enabled', !form.enabled)} />
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label>{t('admin.proxy.protocol')}</Label>
            {/* 与验证码 / 存储等同类型的下拉框选择代理协议 */}
            <Select value={form.protocol ?? 'http'} onValueChange={(v) => setField('protocol', v)} ariaLabel={t('admin.proxy.protocol')} className="w-full">
              <SelectItem value="http">HTTP</SelectItem>
              <SelectItem value="https">HTTPS</SelectItem>
              <SelectItem value="socks5">SOCKS5</SelectItem>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label>{t('admin.proxy.port')}</Label>
            <Input type="number" min={0} max={65535} value={form.port ?? ''} onChange={(e) => setField('port', e.target.value)} placeholder="7890" />
          </div>
          <div className="space-y-1.5">
            <Label>{t('admin.proxy.host')}</Label>
            <Input value={form.host ?? ''} onChange={(e) => setField('host', e.target.value)} placeholder="127.0.0.1" />
          </div>
          <div className="space-y-1.5">
            <Label>{t('admin.proxy.username')}</Label>
            <Input value={form.username ?? ''} onChange={(e) => setField('username', e.target.value)} placeholder={t('admin.proxy.optional')} />
          </div>
          <div className="space-y-1.5">
            <Label>{t('admin.proxy.password')}</Label>
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={secretPlaceholder(!!form.hasPassword, t('common.secretPlaceholder'))}
              autoComplete="new-password"
            />
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Button variant="outline" onClick={runTest} disabled={testing}>
            {testing ? <Loader2 className="size-4 animate-spin" /> : <PlugZap className="size-4" />} {t('admin.proxy.test')}
          </Button>
          <Button onClick={() => save.mutate()} disabled={save.isPending}><Save className="size-4" /> {t('common.save')}</Button>
          {testResult && <span className="text-xs text-muted-foreground">{testResult}</span>}
        </div>
      </CardContent>
    </Card>
  )
}

/* ------------------------------------------------------------------ */
/*  存储管理：后端配置 + 文件记录 + 孤儿文件回收                        */
/* ------------------------------------------------------------------ */

function formatBytes(n: number): string {
  if (!n || n < 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1)
  const v = n / Math.pow(1024, i)
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`
}

function StorageSection() {
  const { t, lang } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { confirm } = useConfirm()
  const [purpose, setPurpose] = React.useState('')

  const { data: cfg, isLoading } = useQuery({ queryKey: ['admin', 'storage'], queryFn: () => api.adminStorage<Record<string, unknown>>() })
  const { data: stats } = useQuery({ queryKey: ['admin', 'storage', 'stats'], queryFn: () => api.adminStorageStats<StorageStats>() })
  const { data: files } = useQuery({
    queryKey: ['admin', 'files', purpose],
    queryFn: () => api.adminFiles<{ items: FileRow[] }>(purpose || undefined, 1, 20),
  })
  const { data: orphans } = useQuery({ queryKey: ['admin', 'files', 'orphans'], queryFn: () => api.adminOrphanFiles<{ items: FileRow[]; pending?: number }>() })

  const [form, setForm] = React.useState<any>({})
  const [dirty, setDirty] = React.useState(false)
  React.useEffect(() => {
    if (cfg && !dirty) setForm(cfg)
  }, [cfg, dirty])
  const set = (k: string, v: any) => { setForm((p: any) => ({ ...p, [k]: v })); setDirty(true) }

  const save = useMutation({
    mutationFn: (mode: 'test' | 'plain') =>
      mode === 'test' ? api.adminStorageTestAndSave(form) : api.adminUpdateStorage(form),
    onSuccess: (_d, mode) => {
      toast({ type: 'success', title: mode === 'test' ? t('admin.storage.saved') : t('admin.storage.savedPlain') })
      setDirty(false)
      qc.invalidateQueries({ queryKey: ['admin', 'storage'] })
      qc.invalidateQueries({ queryKey: ['admin', 'storage', 'stats'] })
    },
    // 失败同样必须清 dirty：dirty 一直为 true 会让 `if (cfg && !dirty)`
    // 永不成立，该分区此后切走再回来、他人改动配置都不会再刷新到表单。
    onError: (e: any) => {
      setDirty(false)
      toast({ type: 'error', title: t('common.saveFail'), description: e?.message ?? '' })
    },
  })

  const del = useMutation({
    mutationFn: (publicId: string) => api.adminDeleteFile(publicId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'files'] })
      qc.invalidateQueries({ queryKey: ['admin', 'storage', 'stats'] })
    },
    onError: (e: any) => toast({ type: 'error', title: e?.message ?? t('common.failed') }),
  })

  const cleanup = useMutation({
    mutationFn: () => api.adminCleanupOrphans(),
    onSuccess: (res: any) => {
      toast({
        type: 'success',
        title: `${t('admin.storage.cleanupDone')}：${res?.deleted ?? 0}${res?.failed ? ` / ${t('admin.storage.failed')} ${res.failed}` : ''}`,
      })
      qc.invalidateQueries({ queryKey: ['admin', 'files'] })
      qc.invalidateQueries({ queryKey: ['admin', 'storage', 'stats'] })
    },
    onError: (e: any) => toast({ type: 'error', title: e?.message ?? t('common.failed') }),
  })

  // 头像上传开关：控制「允许用户往存储里写什么」，与存储后端同属存储管理。
  // 单开关直接落库（不走表单保存）：它写的是 /admin/site，混进上面的存储配置表单
  // 会让一次保存变成两个接口的联合操作，任一侧失败就出现半保存状态。
  const { data: site } = useQuery({ queryKey: ['admin', 'site'], queryFn: () => api.adminSite<Record<string, unknown>>() })
  const avatarUpload = useMutation({
    mutationFn: (v: boolean) => api.adminUpdateSite({ avatarUploadEnabled: v }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'site'] })
      // 用户端头像入口读的是 session.site.avatarUploadEnabled，必须一起失效。
      qc.invalidateQueries({ queryKey: ['session'] })
      toast({ type: 'success', title: t('admin.site.saved') })
    },
    onError: (e) => toast({
      type: 'error',
      title: t('admin.site.saveFail'),
      description: e instanceof ApiError ? e.message : '',
    }),
  })

  if (isLoading) {
    return <div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" /> {t('common.loading')}</div>
  }

  const items: any[] = files?.items ?? []
  const orphanItems: any[] = orphans?.items ?? []

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.storage.title')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="max-w-xl rounded-lg border bg-muted/20 px-4">
            <SwitchRow
              label={t('admin.storage.isEnabled')}
              desc={t('admin.storage.isEnabledDesc')}
              checked={!!form.isEnabled}
              onChange={() => set('isEnabled', !form.isEnabled)}
            />
            <SwitchRow
              label={t('admin.storage.backend')}
              desc={t('admin.storage.backendDesc')}
              checked={form.backend === 's3'}
              onChange={() => set('backend', form.backend === 's3' ? 'local' : 's3')}
              divider={false}
            />
          </div>

          {form.backend === 's3' ? (
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-1.5">
                <Label>{t('admin.storage.s3Endpoint')}</Label>
                <Input value={form.s3Endpoint ?? ''} onChange={(e) => set('s3Endpoint', e.target.value)} placeholder="https://s3.amazonaws.com" />
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.storage.s3Bucket')}</Label>
                <Input value={form.s3Bucket ?? ''} onChange={(e) => set('s3Bucket', e.target.value)} placeholder="openidp-files" />
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.storage.s3Region')}</Label>
                <Input value={form.s3Region ?? ''} onChange={(e) => set('s3Region', e.target.value)} placeholder="us-east-1" />
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.storage.s3Prefix')}</Label>
                <Input value={form.s3Prefix ?? ''} onChange={(e) => set('s3Prefix', e.target.value)} placeholder="openidp/" />
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.storage.s3PublicBaseUrl')}</Label>
                <Input value={form.s3PublicBaseUrl ?? ''} onChange={(e) => set('s3PublicBaseUrl', e.target.value)} placeholder="https://cdn.example.com" />
              </div>
              <div className="space-y-1.5">
                <Label>{t('admin.storage.s3AccessKey')}</Label>
                <Input value={form.s3AccessKey ?? ''} onChange={(e) => set('s3AccessKey', e.target.value)} placeholder="AKIAIOSFODNN7EXAMPLE" />
              </div>
              <div className="space-y-1.5 md:col-span-2">
                <Label>{t('admin.storage.s3SecretKey')}</Label>
                <Input
                  type="password"
                  value={form.s3SecretKey ?? ''}
                  onChange={(e) => set('s3SecretKey', e.target.value)}
                  placeholder={secretPlaceholder(!!form.hasSecretKey, t('common.secretPlaceholder'))}
                />
                <p className="text-xs text-muted-foreground">{t('admin.storage.s3SecretKeyDesc')}</p>
              </div>
            </div>
          ) : (
            <div className="space-y-1.5">
              <Label>{t('admin.storage.localPath')}</Label>
              <Input value={form.localPath ?? ''} onChange={(e) => set('localPath', e.target.value)} placeholder="./data" />
              <p className="text-xs text-muted-foreground">{t('admin.storage.localPathDesc')}</p>
            </div>
          )}

          <div className="flex flex-wrap justify-end gap-2">
            {/* 默认走 test-and-save：先探测连通性再落库，避免误配被持久化。
                仅保存用于离线部署 / 临时排障：不做连通性校验，直接落库。 */}
            <Button variant="outline" onClick={() => save.mutate('plain')} disabled={save.isPending}>
              {t('admin.storage.savePlain')}
            </Button>
            <Button onClick={() => save.mutate('test')} disabled={save.isPending}>
              {save.isPending ? <Loader2 className="size-4 animate-spin" /> : <Save className="size-4" />} {t('admin.storage.saveAndTest')}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('admin.storage.stats')}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-lg border p-3">
              <div className="text-xs text-muted-foreground">{t('admin.storage.totalFiles')}</div>
              <div className="text-xl font-semibold">{stats?.totalFiles ?? 0}</div>
            </div>
            <div className="rounded-lg border p-3">
              <div className="text-xs text-muted-foreground">{t('admin.storage.totalBytes')}</div>
              <div className="text-xl font-semibold">{formatBytes(stats?.totalBytes ?? 0)}</div>
            </div>
            <div className="rounded-lg border p-3">
              <div className="text-xs text-muted-foreground">{t('admin.storage.orphanBytes')}</div>
              <div className="text-xl font-semibold">{formatBytes(stats?.orphanBytes ?? 0)}</div>
            </div>
            <div className="rounded-lg border p-3">
              <div className="text-xs text-muted-foreground">{t('admin.storage.backend')}</div>
              <div className="text-xl font-semibold">{stats?.backend ?? '-'}</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* 用户上传策略：单独一张卡，因为它落的是 /admin/site，而不是存储配置 ——
          混进上面那张表单会让「保存」变成两个接口的联合操作。
          放在用量统计之后：先看清用了多少，再看允许谁往里写。 */}
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.storage.uploadPolicy')}</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="max-w-xl rounded-lg border bg-muted/20 px-4">
            <SwitchRow
              label={t('admin.site.avatarUpload')}
              desc={t('admin.site.avatarUploadDesc')}
              checked={!!site?.avatarUploadEnabled}
              disabled={avatarUpload.isPending}
              onChange={() => avatarUpload.mutate(!site?.avatarUploadEnabled)}
              divider={false}
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('admin.storage.orphans')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex justify-end">
            <Button
              variant="outline"
              disabled={cleanup.isPending || orphanItems.length === 0}
              onClick={async () => {
                const ok = await confirm({
                  title: t('admin.storage.cleanupConfirm'),
                  description: `${t('admin.storage.cleanupConfirmDesc')}：${orphanItems.length}`,
                })
                if (ok) cleanup.mutate()
              }}
            >
              {cleanup.isPending ? <Loader2 className="size-4 animate-spin" /> : <Trash2 className="size-4" />} {t('admin.storage.cleanup')}
            </Button>
          </div>
          {orphanItems.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('admin.storage.noOrphans')}</p>
          ) : (
            <div className="overflow-x-auto rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('admin.storage.file')}</TableHead>
                    <TableHead>{t('admin.storage.size')}</TableHead>
                    <TableHead>{t('admin.storage.detachedAt')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {orphanItems.map((f: any) => (
                    <TableRow key={f.publicId}>
                      <TableCell className="font-mono text-xs">{f.publicId}</TableCell>
                      <TableCell>{formatBytes(f.byteSize)}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatDateTimeI18n(f.detachedAt, lang)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('admin.storage.files')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Select value={purpose} onValueChange={setPurpose} className="w-40" ariaLabel={t('admin.storage.purpose')}>
            <SelectItem value="">{t('admin.storage.allPurposes')}</SelectItem>
            <SelectItem value="avatar">{t('admin.storage.purposeAvatar')}</SelectItem>
            <SelectItem value="attachment">{t('admin.storage.purposeAttachment')}</SelectItem>
          </Select>
          {items.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t('admin.storage.noFiles')}</p>
          ) : (
            <div className="overflow-x-auto rounded-lg border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('admin.storage.file')}</TableHead>
                    <TableHead>{t('admin.storage.purpose')}</TableHead>
                    <TableHead>{t('admin.storage.type')}</TableHead>
                    <TableHead>{t('admin.storage.size')}</TableHead>
                    <TableHead>{t('admin.storage.createdAt')}</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {items.map((f: any) => (
                    <TableRow key={f.publicId}>
                      <TableCell className="max-w-48 truncate font-mono text-xs">
                        <a href={f.url} target="_blank" rel="noreferrer" className="hover:underline">{f.publicId}</a>
                      </TableCell>
                      <TableCell><Badge variant="secondary">{f.purpose}</Badge></TableCell>
                      <TableCell className="text-xs text-muted-foreground">{f.mimeType}</TableCell>
                      <TableCell>{formatBytes(f.byteSize)}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{formatDateTimeI18n(f.createdAt, lang)}</TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="sm"
                          // 行级 loading：只禁用正在删除的那一行
                          disabled={del.isPending && del.variables === f.publicId}
                          onClick={async () => {
                            const ok = await confirm({
                              title: t('admin.storage.deleteConfirm'),
                              confirmText: t('common.delete'),
                              variant: 'destructive',
                            })
                            if (ok) del.mutate(f.publicId)
                          }}
                        >
                          <Trash2 className="size-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/*  IP 归属地配置                                                      */
/* ------------------------------------------------------------------ */

function LocationSection() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()

  const { data: cfg, isLoading } = useQuery({ queryKey: ['admin', 'location'], queryFn: () => api.adminLocation<Record<string, unknown>>() })
  const [form, setForm] = React.useState<any>({})
  const [dirty, setDirty] = React.useState(false)
  const [sample, setSample] = React.useState('')
  React.useEffect(() => { if (cfg && !dirty) setForm(cfg) }, [cfg, dirty])
  const set = (k: string, v: any) => { setForm((p: any) => ({ ...p, [k]: v })); setDirty(true) }

  const save = useMutation({
    mutationFn: () => api.adminUpdateLocation(form),
    onSuccess: () => {
      toast({ type: 'success', title: t('common.saved') })
      setDirty(false)
      qc.invalidateQueries({ queryKey: ['admin', 'location'] })
    },
    // 同上：失败也要复位 dirty，否则该分区永久失去与服务端同步的能力。
    onError: (e: any) => {
      setDirty(false)
      toast({ type: 'error', title: t('common.saveFail'), description: e?.message ?? '' })
    },
  })

  const test = useMutation({
    mutationFn: () => api.adminTestLocation(sample || undefined),
    onSuccess: (res: any) => {
      toast({
        type: res?.resolved ? 'success' : 'error',
        title: res?.resolved ? `${res.sampleIp} → ${res.sampleRegion}` : t('admin.location.testFailed'),
      })
    },
    onError: (e: any) => toast({ type: 'error', title: e?.message ?? t('common.failed') }),
  })

  if (isLoading) {
    return <div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" /> {t('common.loading')}</div>
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>{t('admin.location.title')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="max-w-xl rounded-lg border bg-muted/20 px-4">
            <SwitchRow
              label={t('admin.location.enabled')}
              checked={!!form.enabled}
              onChange={() => set('enabled', !form.enabled)}
              divider={false}
            />
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-1.5">
              <Label>{t('admin.location.dbPath')}</Label>
              <Input value={form.dbPath ?? ''} onChange={(e) => set('dbPath', e.target.value)} placeholder="GeoCN.mmdb" />
            </div>
            <div className="space-y-1.5">
              <Label>{t('admin.location.v6DbPath')}</Label>
              <Input value={form.v6DbPath ?? ''} onChange={(e) => set('v6DbPath', e.target.value)} placeholder="GeoCN-IPv6.mmdb" />
            </div>
            <div className="space-y-1.5">
              <Label>{t('admin.location.realIpHeader')}</Label>
              <Input value={form.realIpHeader ?? ''} onChange={(e) => set('realIpHeader', e.target.value)} placeholder="EO-Client-IP" />
            </div>
            <div className="space-y-1.5">
              <Label>{t('admin.location.trustedProxies')}</Label>
              <Input value={form.trustedProxies ?? ''} onChange={(e) => set('trustedProxies', e.target.value)} placeholder="127.0.0.1/8, 10.0.0.0/8" />
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={() => test.mutate()} disabled={test.isPending}>
              {test.isPending ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />} {t('admin.location.test')}
            </Button>
            <Button onClick={() => save.mutate()} disabled={save.isPending}>
              <Save className="size-4" /> {t('common.save')}
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
/* ------------------------- 审计日志与保留策略 ------------------------- */
// 分区入口：侧栏「系统设置 → 审计日志」。
// 详情列表仍在 /admin/audit（分区授权为 dashboard），此处只承载保留策略与
// 系统健康面板 —— 两者此前有后端、有 api.ts 封装，却没有任何前端入口。
function AuditSection() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { data: audit } = useQuery({ queryKey: ['admin', 'audit-settings'], queryFn: api.adminAuditSettings })
  const [form, setForm] = React.useState<any>(null)

  React.useEffect(() => { if (audit) setForm(audit) }, [audit])
  const set = (k: string, v: any) => setForm((f: any) => ({ ...f, [k]: v }))

  const save = useMutation({
    mutationFn: () => api.adminUpdateAuditSettings({
      retentionDays: Number(form?.retentionDays) || 0,
      archiveEnabled: !!form?.archiveEnabled,
      loginEventsOnly: !!form?.loginEventsOnly,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'audit-settings'] })
      toast({ type: 'success', title: t('common.saved') })
    },
    onError: (e) => toast({ type: 'error', title: e instanceof ApiError ? e.message : t('common.failed') }),
  })

  return (
    <div className="grid gap-6">
      <SystemStatusCard />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><FileClock className="size-4" /> {t('admin.auditSettings.title')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          {form && (
            <>
              <div className="max-w-xs space-y-1.5">
                <Label>{t('admin.auditSettings.retentionDays')}</Label>
                <Input
                  type="number"
                  min={0}
                  value={form.retentionDays ?? 0}
                  onChange={(e) => set('retentionDays', Number(e.target.value))}
                />
                <p className="text-xs text-muted-foreground">{t('admin.auditSettings.retentionDaysDesc')}</p>
              </div>
              <div className="max-w-xl rounded-lg border bg-muted/20 px-4">
                <SwitchRow
                  label={t('admin.auditSettings.archive')}
                  desc={t('admin.auditSettings.archiveDesc')}
                  checked={!!form.archiveEnabled}
                  onChange={() => set('archiveEnabled', !form.archiveEnabled)}
                />
                <SwitchRow
                  label={t('admin.auditSettings.loginOnly')}
                  desc={t('admin.auditSettings.loginOnlyDesc')}
                  checked={!!form.loginEventsOnly}
                  onChange={() => set('loginEventsOnly', !form.loginEventsOnly)}
                  divider={false}
                />
              </div>
              <div className="flex justify-end">
                <Button onClick={() => save.mutate()} disabled={save.isPending}><Save className="size-4" /> {t('common.save')}</Button>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

/* ---------------------------- 运行状态面板 ---------------------------- */
// 三块资源（CPU / 内存 / 存储）用环形进度图展示占用率，
// 按区间配色：<60% 正常（绿）、60%~85% 注意（橙）、>85% 危险（红）。
// 每 30 秒自动刷新一次。
function ResourceRing({ label, percent, detail }: { label: string; percent: number; detail?: string }) {
  const value = Math.max(0, Math.min(100, percent || 0))
  const radius = 44
  const circumference = 2 * Math.PI * radius
  const dash = (value / 100) * circumference
  // 阈值配色：与 newapi 风格一致的三段式
  const tone = value >= 85 ? 'danger' : value >= 60 ? 'warning' : 'normal'
  const stroke = tone === 'danger' ? 'var(--destructive)' : tone === 'warning' ? '#f59e0b' : '#10b981'
  const textClass = tone === 'danger' ? 'text-destructive' : tone === 'warning' ? 'text-amber-500' : 'text-emerald-500'

  return (
    <div className="flex flex-col items-center gap-2 rounded-lg border p-4">
      <div className="relative size-28">
        <svg viewBox="0 0 100 100" className="size-full -rotate-90">
          <circle cx="50" cy="50" r={radius} fill="none" strokeWidth="8" className="stroke-muted" />
          <circle
            cx="50" cy="50" r={radius} fill="none" strokeWidth="8" strokeLinecap="round"
            stroke={stroke}
            strokeDasharray={`${dash} ${circumference - dash}`}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={cn('text-xl font-semibold tabular-nums', textClass)}>{value.toFixed(1)}%</span>
        </div>
      </div>
      <div className="text-sm font-medium">{label}</div>
      {detail && <div className="text-xs text-muted-foreground">{detail}</div>}
    </div>
  )
}

function SystemStatusCard() {
  const { t, lang } = useI18n()
  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['admin', 'system-status'],
    queryFn: api.adminSystemStatus,
    refetchInterval: 30_000,
  })
  const db = (data as any)?.database ?? {}
  const cache = (data as any)?.cache ?? {}
  const ver = (data as any)?.version ?? {}
  const cpu = (data as any)?.cpu ?? {}
  const memory = (data as any)?.memory ?? {}
  const disk = (data as any)?.disk ?? {}
  const uptime = Number((data as any)?.uptime ?? 0)
  const startedAt = (data as any)?.startedAt

  const uptimeText = uptime > 86400
    ? `${Math.floor(uptime / 86400)}d ${Math.floor((uptime % 86400) / 3600)}h`
    : uptime > 3600
      ? `${Math.floor(uptime / 3600)}h ${Math.floor((uptime % 3600) / 60)}m`
      : `${Math.floor(uptime / 60)}m`

  const rows: { label: string; value: string; ok?: boolean }[] = [
    { label: t('admin.systemStatus.status'), value: (data as any)?.status ?? '—', ok: (data as any)?.status === 'ok' },
    { label: t('admin.systemStatus.version'), value: String(ver.version ?? '—') },
    { label: t('admin.systemStatus.startedAt'), value: startedAt ? formatDateTimeI18n(String(startedAt), lang) : '—' },
    { label: t('admin.systemStatus.uptime'), value: uptimeText },
    { label: t('admin.systemStatus.database'), value: `${db.kind ?? '—'}`, ok: db.ok !== false },
    { label: t('admin.systemStatus.cache'), value: String(cache.kind ?? '—') },
  ]

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2"><Activity className="size-4" /> {t('admin.systemStatus.title')}</CardTitle>
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()} disabled={isFetching}>
            {isFetching ? <Loader2 className="size-4 animate-spin" /> : <Activity className="size-4" />} {t('admin.systemStatus.refresh')}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" /> {t('common.loading')}
          </div>
        ) : (
          <div className="space-y-6">
            <div className="grid gap-4 sm:grid-cols-3">
              <ResourceRing
                label={t('admin.systemStatus.cpu')}
                percent={Number(cpu.percent ?? 0)}
                detail={cpu.available === false ? t('admin.systemStatus.unavailable') : undefined}
              />
              <ResourceRing
                label={t('admin.systemStatus.memory')}
                percent={Number(memory.percent ?? 0)}
                detail={memory.total ? `${formatBytes(memory.used)} / ${formatBytes(memory.total)}` : t('admin.systemStatus.unavailable')}
              />
              <ResourceRing
                label={t('admin.systemStatus.storage')}
                percent={Number(disk.percent ?? 0)}
                detail={disk.total ? `${formatBytes(disk.used)} / ${formatBytes(disk.total)}` : t('admin.systemStatus.unavailable')}
              />
            </div>
            <div className="grid gap-x-8 gap-y-3 sm:grid-cols-2">
              {rows.map((r) => (
                <div key={r.label} className="flex items-center justify-between border-b pb-2 last:border-0">
                  <span className="text-sm text-muted-foreground">{r.label}</span>
                  <span className="flex items-center gap-2 text-sm font-medium">
                    {r.ok !== undefined && (
                      <span className={cn('size-2 rounded-full', r.ok ? 'bg-emerald-500' : 'bg-destructive')} />
                    )}
                    <span className="font-mono text-xs">{r.value}</span>
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

/* ---------------------------- 数据清理策略 ---------------------------- */

// 占用概览的响应形状（GET /admin/data-cleanup/usage）。
interface CleanupUsage {
  cache?: { kind?: string; entries?: number; bytes?: number }
  storage?: StorageStats
  records?: Record<string, { total?: number; stale?: number }>
  retention?: Record<string, number>
}

function CleanupSection() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { confirm } = useConfirm()
  const { data: cfg } = useQuery({ queryKey: ['admin', 'data-cleanup'], queryFn: api.adminDataCleanup })
  // 占用概览：与「立即清理」读同一份保留策略，因此「待清理」列的数字
  // 与点下按钮后实际删除的行数对得上（同一天内）。
  const { data: usage } = useQuery({
    queryKey: ['admin', 'data-cleanup', 'usage'],
    queryFn: () => api.adminDataCleanupUsage<CleanupUsage>(),
  })
  const [form, setForm] = React.useState<any>(null)
  const [result, setResult] = React.useState<Record<string, number> | null>(null)

  React.useEffect(() => { if (cfg) setForm(cfg) }, [cfg])
  const set = (k: string, v: any) => setForm((f: any) => ({ ...f, [k]: v }))

  const save = useMutation({
    mutationFn: () => api.adminUpdateDataCleanup({
      sessionRetentionDays: Number(form?.sessionRetentionDays) || 0,
      tokenRetentionDays: Number(form?.tokenRetentionDays) || 0,
      notificationRetentionDays: Number(form?.notificationRetentionDays) || 0,
      deletionRequestRetentionDays: Number(form?.deletionRequestRetentionDays) || 0,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['admin', 'data-cleanup'] })
      toast({ type: 'success', title: t('common.saved') })
    },
    onError: (e) => toast({ type: 'error', title: e instanceof ApiError ? e.message : t('common.failed') }),
  })

  const run = useMutation({
    mutationFn: () => api.adminRunDataCleanup(),
    onSuccess: (res: any) => {
      setResult(res?.deleted ?? {})
      toast({ type: 'success', title: t('admin.cleanup.runDone') })
    },
    onError: (e) => toast({ type: 'error', title: e instanceof ApiError ? e.message : t('common.failed') }),
  })

  // record 对应 /data-cleanup/usage 返回的 records 键名，用于取「总记录 / 待清理」。
  const days: { key: string; labelKey: string; record: string }[] = [
    { key: 'sessionRetentionDays', labelKey: 'admin.cleanup.sessions', record: 'sessions' },
    { key: 'tokenRetentionDays', labelKey: 'admin.cleanup.tokens', record: 'tokens' },
    { key: 'notificationRetentionDays', labelKey: 'admin.cleanup.notifications', record: 'notifications' },
    { key: 'deletionRequestRetentionDays', labelKey: 'admin.cleanup.deletionRequests', record: 'accountDeletionRequests' },
  ]

  // 超期记录合计：概览里「超期记录」tile 用它，等于本轮清理将删除的行数上限。
  const staleTotal = days.reduce((sum, d) => sum + (usage?.records?.[d.record]?.stale ?? 0), 0)
  const cacheBytes = usage?.cache?.bytes ?? 0

  const doRun = async () => {
    const ok = await confirm({
      title: t('admin.cleanup.runConfirm'),
      description: t('admin.cleanup.runConfirmDesc'),
      confirmText: t('admin.cleanup.run'),
      variant: 'destructive',
    })
    if (ok) run.mutate()
  }

  return (
    <div className="grid gap-6">
      {/* 当前占用：先看清「有多大、这一轮能清掉多少」，再决定是改保留天数还是直接清理。
          缓存与存储的字节数取自后端真实统计，不是估算值。 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><HardDrive className="size-4" /> {t('admin.cleanup.usageTitle')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="rounded-lg border p-3">
              <div className="text-xs text-muted-foreground">{t('admin.cleanup.usageCache')}</div>
              <div className="text-xl font-semibold">{usage?.cache?.kind ?? '—'}</div>
              <div className="mt-1 text-xs text-muted-foreground">
                {t('admin.cleanup.cacheKeys', { count: usage?.cache?.entries ?? 0 })}
                {/* 内存后端能给近似字节数；Redis 无法按 DB 归因内存占用，故只报键数 */}
                {cacheBytes > 0 && ` · ${t('admin.cleanup.cacheBytes', { size: formatBytes(cacheBytes) })}`}
              </div>
            </div>
            <div className="rounded-lg border p-3">
              <div className="text-xs text-muted-foreground">{t('admin.cleanup.usageOrphans')}</div>
              <div className="text-xl font-semibold">{formatBytes(usage?.storage?.orphanBytes ?? 0)}</div>
              <div className="mt-1 text-xs">
                <Link
                  to={settingsSectionPath('audit', 'storage')}
                  className="text-primary underline-offset-4 hover:underline"
                >
                  {t('admin.cleanup.gotoStorage')}
                </Link>
              </div>
            </div>
            <div className="rounded-lg border p-3">
              <div className="text-xs text-muted-foreground">{t('admin.cleanup.usageStale')}</div>
              <div className="text-xl font-semibold tabular-nums">{staleTotal}</div>
            </div>
          </div>

          {/* 分类明细：总数 → 待清理（按当前保留天数实时计算） */}
          <div className="overflow-hidden rounded-lg border">
            <div className="flex items-center justify-between bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
              <span>{t('admin.cleanup.colCategory')}</span>
              <span className="flex items-center gap-6">
                <span>{t('admin.cleanup.colTotal')}</span>
                <span className="w-14 text-right">{t('admin.cleanup.colStale')}</span>
              </span>
            </div>
            {days.map((d) => {
              const rec = usage?.records?.[d.record]
              const stale = rec?.stale ?? 0
              return (
                <div key={d.key} className="flex items-center justify-between border-t px-3 py-2 text-sm">
                  <span>{t(d.labelKey)}</span>
                  <span className="flex items-center gap-6">
                    <span className="tabular-nums text-muted-foreground">{rec?.total ?? 0}</span>
                    {/* 有待清理项时用琥珀色提示，与「立即清理」的动作呼应 */}
                    <span className={cn('w-14 text-right tabular-nums', stale > 0 && 'font-medium text-amber-600')}>
                      {stale}
                    </span>
                  </span>
                </div>
              )
            })}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Trash2 className="size-4" /> {t('admin.cleanup.title')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          {form && (
            <>
              <div className="grid gap-4 sm:grid-cols-2">
                {days.map((d) => (
                  <div key={d.key} className="space-y-1.5">
                    <Label>{t(d.labelKey)}</Label>
                    <Input
                      type="number"
                      min={0}
                      value={form[d.key] ?? 0}
                      onChange={(e) => set(d.key, Number(e.target.value))}
                    />
                  </div>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">{t('admin.cleanup.zeroHint')}</p>
              <div className="flex flex-wrap justify-end gap-2">
                <Button variant="outline" onClick={doRun} disabled={run.isPending}>
                  {run.isPending ? <Loader2 className="size-4 animate-spin" /> : <Trash2 className="size-4" />} {t('admin.cleanup.run')}
                </Button>
                <Button onClick={() => save.mutate()} disabled={save.isPending}><Save className="size-4" /> {t('common.save')}</Button>
              </div>
            </>
          )}

          {result && (
            <div className="rounded-lg border bg-muted/20 p-4">
              <div className="mb-2 text-sm font-medium">{t('admin.cleanup.resultTitle')}</div>
              <div className="grid gap-2 sm:grid-cols-2">
                {days.map((d) => (
                  <div key={d.key} className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{t(d.labelKey)}</span>
                    <span className="font-mono">{result[d.key.replace('RetentionDays', '').replace(/^./, (c) => c.toLowerCase())] ?? 0}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

/* ------------------------------ 数据备份 ------------------------------ */
// 备份是一个 ZIP：settings.json 装系统设置，data/<表名>.json 装业务数据。
//
// 分组可选：系统设置默认勾选；用户 / 会话 / 事件等业务数据必须显式勾选 ——
// 它们体积大且敏感（含密码哈希、通行密钥、IP 与 UA），不该被默认带走。
// 交互上导出只放一个按钮，选择内容在弹窗里完成；恢复则是「先上传解析、
// 再按文件里实际存在的内容勾选」，界面不展示文件里没有的选项。
//
// 恢复边界：无论勾了哪些分组，属于当前登录账号的行都会被跳过（后端按用户归属列过滤），
// 所以执行恢复的人不会被自己的旧备份覆盖密码、通行密钥或会话。这条边界写在界面上，
// 让「为什么我的账号没被换掉」不需要翻文档。
const BACKUP_GROUPS: { key: SettingsBackupGroup; labelKey: string; descKey: string }[] = [
  { key: 'settings', labelKey: 'admin.backup.group.settings', descKey: 'admin.backup.group.settingsDesc' },
  { key: 'users', labelKey: 'admin.backup.group.users', descKey: 'admin.backup.group.usersDesc' },
  { key: 'sessions', labelKey: 'admin.backup.group.sessions', descKey: 'admin.backup.group.sessionsDesc' },
  { key: 'events', labelKey: 'admin.backup.group.events', descKey: 'admin.backup.group.eventsDesc' },
  { key: 'oauth', labelKey: 'admin.backup.group.oauth', descKey: 'admin.backup.group.oauthDesc' },
]

// BACKUP_TABLE_LABELS 是恢复回执里表名的文案表；
// 未收录的表名直接显示原名，不静默丢弃（后端加了新表而前端没跟上时至少看得见）。
const BACKUP_TABLE_LABELS: Record<string, string> = {
  users: 'admin.backup.table.users',
  identities: 'admin.backup.table.identities',
  passkeys: 'admin.backup.table.passkeys',
  mfas: 'admin.backup.table.mfas',
  trusted_devices: 'admin.backup.table.trustedDevices',
  devices: 'admin.backup.table.devices',
  notification_preferences: 'admin.backup.table.notificationPreferences',
  account_deletion_requests: 'admin.backup.table.accountDeletionRequests',
  sessions: 'admin.backup.table.sessions',
  tokens: 'admin.backup.table.tokens',
  authorization_codes: 'admin.backup.table.authorizationCodes',
  device_authorizations: 'admin.backup.table.deviceAuthorizations',
  mfa_challenges: 'admin.backup.table.mfaChallenges',
  verification_codes: 'admin.backup.table.verificationCodes',
  events: 'admin.backup.table.events',
  notifications: 'admin.backup.table.notifications',
  grants: 'admin.backup.table.grants',
}

// backupLabel 把后端回执里的分组名 / 表名翻成文案；两者都可能出现在 missing 列表里，
// 因此先按分组名匹配，再按表名匹配，都没有就原样返回。
function backupLabel(t: (key: string) => string, name: string): string {
  if (BACKUP_GROUPS.some((g) => g.key === name)) return t(`admin.backup.group.${name}`)
  const key = BACKUP_TABLE_LABELS[name]
  return key ? t(key) : name
}

// backupFileName 生成下载文件名：与后端导出响应头同款命名（含秒级时间戳），
// 多次备份并存时按文件名即可排序，不必依赖文件系统时间。
function backupFileName(): string {
  const d = new Date()
  const p = (n: number) => String(n).padStart(2, '0')
  return `openidp-backup-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}.zip`
}

// GroupPicker 是分组勾选列表：导出与恢复共用同一套选项与样式。
function GroupPicker({ value, onChange, only, tables }: {
  value: SettingsBackupGroup[]
  onChange: (next: SettingsBackupGroup[]) => void
  /** 只展示这些分组。恢复时必须传：界面只允许勾选文件里真实存在的内容 */
  only?: SettingsBackupGroup[]
  /** 分组 → 文件里实际包含的表名（恢复时贴出来，让「文件里有什么」一目了然） */
  tables?: Record<string, string[]>
}) {
  const { t } = useI18n()
  const options = only ? BACKUP_GROUPS.filter((g) => only.includes(g.key)) : BACKUP_GROUPS
  return (
    <div className="divide-y rounded-lg border">
      {options.map((g) => (
        <div key={g.key} className="flex items-start justify-between gap-4 px-3 py-2.5">
          <div className="min-w-0 space-y-0.5">
            <div className="text-sm font-medium">{t(g.labelKey)}</div>
            <div className="text-xs text-muted-foreground">{t(g.descKey)}</div>
            {(tables?.[g.key]?.length ?? 0) > 0 && (
              <div className="text-xs text-muted-foreground/80">
                {t('admin.backup.groupTables', {
                  items: (tables?.[g.key] ?? []).map((n) => backupLabel(t, n)).join(' / '),
                })}
              </div>
            )}
          </div>
          <Switch
            checked={value.includes(g.key)}
            onCheckedChange={(on) => onChange(on ? [...value, g.key] : value.filter((k) => k !== g.key))}
          />
        </div>
      ))}
    </div>
  )
}

function BackupSection() {
  const { t, lang } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { confirm } = useConfirm()
  const fileRef = React.useRef<HTMLInputElement | null>(null)

  // 导出：页面上只留一个按钮，分组选择放在弹窗里（否则一整排开关长期占位）。
  const [exportOpen, setExportOpen] = React.useState(false)
  const [exportGroups, setExportGroups] = React.useState<SettingsBackupGroup[]>(['settings'])

  // 恢复：选中文件先上传解析，解析成功后才展示「文件里实际包含」的可选项。
  const [archive, setArchive] = React.useState<File | null>(null)
  const [contents, setContents] = React.useState<SettingsBackupInspectResult | null>(null)
  const [restoreGroups, setRestoreGroups] = React.useState<SettingsBackupGroup[]>(['settings'])
  const [result, setResult] = React.useState<SettingsBackupRestoreResult | null>(null)

  const exportBackup = useMutation({
    mutationFn: () => api.adminBackupExportZip(exportGroups),
    onSuccess: (blob) => {
      // 后端直接返回 ZIP 流，前端只负责落盘：用 Blob + a.click() 触发下载，
      // 这样整条链路仍然带会话 Cookie（而不是让浏览器直连端点）。
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = backupFileName()
      a.click()
      URL.revokeObjectURL(url)
      setExportOpen(false)
      toast({ type: 'success', title: t('admin.backup.exported') })
    },
    onError: (e) => toast({ type: 'error', title: e instanceof ApiError ? e.message : t('common.failed') }),
  })

  // 上传即解析：ZIP 的格式、版本与内容清单都由后端判定，前端不自己解压
  // （浏览器端解 ZIP 要么引入依赖、要么手写解析，都会多出一套可能与后端漂移的规则）。
  const inspect = useMutation({
    mutationFn: (file: File) => api.adminBackupInspectZip<SettingsBackupInspectResult>(file),
    onSuccess: (res) => {
      setContents(res ?? null)
      // 默认只勾系统设置：业务数据要显式再确认一次，避免「选个文件就全量写回」。
      setRestoreGroups(['settings'])
    },
    onError: (e) => {
      setContents(null)
      setArchive(null)
      if (fileRef.current) fileRef.current.value = ''
      toast({ type: 'error', title: e instanceof ApiError ? e.message : t('admin.backup.inspectFailed') })
    },
  })

  const restore = useMutation({
    mutationFn: (file: File) => api.adminBackupRestoreZip<SettingsBackupRestoreResult>(restoreGroups, file),
    onSuccess: (res) => {
      setResult(res ?? null)
      setArchive(null)
      setContents(null)
      if (fileRef.current) fileRef.current.value = ''
      // 恢复会改写几乎所有配置分区，整体失效 admin 下的查询，
      // 否则切到别的页签还会看到恢复前的旧值。
      qc.invalidateQueries({ queryKey: ['admin'] })
      toast({ type: 'success', title: t('admin.backup.restored') })
    },
    onError: (e) => toast({ type: 'error', title: e instanceof ApiError ? e.message : t('common.failed') }),
  })

  const pickFile = (file: File | undefined) => {
    setResult(null)
    setContents(null)
    setRestoreGroups(['settings'])
    setArchive(file ?? null)
    if (!file) {
      if (fileRef.current) fileRef.current.value = ''
      return
    }
    inspect.mutate(file)
  }

  const doRestore = async () => {
    if (!archive) return
    const ok = await confirm({
      title: t('admin.backup.restoreConfirm'),
      description: t('admin.backup.restoreConfirmDesc', { name: archive.name }),
      confirmText: t('admin.backup.restore'),
      variant: 'destructive',
    })
    if (ok) restore.mutate(archive)
  }

  // 文件里实际存在的分组与表：勾选项严格来自它，不展示文件里没有的内容。
  const contained = contents?.groups ?? []
  const containedKeys = contained.map((g) => g.name) as SettingsBackupGroup[]
  const containedTables: Record<string, string[]> = {}
  for (const g of contained) {
    if (g.tables && g.tables.length > 0) containedTables[g.name] = g.tables
  }

  return (
    <div className="grid gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Download className="size-4" /> {t('admin.backup.exportTitle')}</CardTitle>
          <CardDescription>{t('admin.backup.exportDesc')}</CardDescription>
        </CardHeader>
        <CardContent className="flex justify-end">
          <Button onClick={() => setExportOpen(true)}>
            <Download className="size-4" /> {t('admin.backup.export')}
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Upload className="size-4" /> {t('admin.backup.restoreTitle')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* 文件选择用隐藏 input + 按钮触发：浏览器默认的文件控件在各语言下样式不一致 */}
          <input
            ref={fileRef}
            type="file"
            accept="application/zip,.zip"
            className="hidden"
            onChange={(e) => pickFile(e.target.files?.[0])}
          />
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" onClick={() => fileRef.current?.click()} disabled={inspect.isPending}>
              {inspect.isPending ? <Loader2 className="size-4 animate-spin" /> : <FileJson className="size-4" />} {t('admin.backup.chooseFile')}
            </Button>
            {archive && (
              <span className="text-sm text-muted-foreground">
                {inspect.isPending
                  ? t('admin.backup.inspecting')
                  : t('admin.backup.selected', { name: archive.name })}
              </span>
            )}
          </div>

          {/* 解析成功后才出现可选项：勾选框严格来自文件里实际包含的内容 */}
          {contents && (
            <div className="space-y-3 rounded-lg border bg-muted/20 p-4">
              <GroupPicker
                value={restoreGroups}
                onChange={setRestoreGroups}
                only={containedKeys}
                tables={containedTables}
              />
              <div className="flex justify-end">
                <Button
                  variant="destructive"
                  onClick={doRestore}
                  disabled={restore.isPending || restoreGroups.length === 0}
                >
                  {restore.isPending ? <Loader2 className="size-4 animate-spin" /> : <Upload className="size-4" />} {t('admin.backup.restore')}
                </Button>
              </div>
            </div>
          )}

          {result && (
            <div className="space-y-3 rounded-lg border bg-muted/20 p-4">
              <div className="text-sm font-medium">{t('admin.backup.resultTitle')}</div>
              {(result.groups ?? []).map((g) => (
                <div key={g.name} className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <Badge variant="secondary">{backupLabel(t, g.name)}</Badge>
                    {g.sections && g.sections.length > 0 && (
                      <span className="text-muted-foreground">{t('admin.backup.resultSections', { count: g.sections.length })}</span>
                    )}
                  </div>
                  {(g.tables ?? []).length > 0 && (
                    <div className="overflow-hidden rounded-md border">
                      {(g.tables ?? []).map((tb) => (
                        <div key={tb.table} className="flex items-center justify-between gap-4 border-t px-3 py-1.5 text-xs first:border-t-0">
                          <span>{backupLabel(t, tb.table)}</span>
                          <span className="tabular-nums text-muted-foreground">
                            {t('admin.backup.tableCounts', {
                              inserted: tb.inserted ?? 0,
                              updated: tb.updated ?? 0,
                              skipped: tb.skipped ?? 0,
                            })}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
              {(result.missing ?? []).length > 0 && (
                <p className="text-xs text-amber-600">
                  {t('admin.backup.resultMissing', {
                    items: (result.missing ?? []).map((m) => backupLabel(t, m)).join(' / '),
                  })}
                </p>
              )}
              {result.currentUser?.username && (
                <p className="text-xs text-muted-foreground">
                  {t('admin.backup.resultUser', { name: result.currentUser.username })}
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* 导出弹窗：页面上只留一个按钮，选择内容与确认导出都在这里完成 */}
      <Dialog
        open={exportOpen}
        onClose={() => setExportOpen(false)}
        title={t('admin.backup.chooseTitle')}
        description={t('admin.backup.chooseDesc')}
        busy={exportBackup.isPending}
        footer={
          <>
            <Button variant="outline" className="h-10 px-5" onClick={() => setExportOpen(false)} disabled={exportBackup.isPending}>
              {t('common.cancel')}
            </Button>
            <Button
              className="h-10 px-5"
              onClick={() => exportBackup.mutate()}
              disabled={exportBackup.isPending || exportGroups.length === 0}
            >
              {exportBackup.isPending && <Loader2 className="size-4 animate-spin" />}
              {t('admin.backup.export')}
            </Button>
          </>
        }
      >
        <GroupPicker value={exportGroups} onChange={setExportGroups} />
      </Dialog>
    </div>
  )
}

/* ------------------------------ 定点通知 ------------------------------ */
// 目标三选一：全量 / 预设 / 手工勾选。
// 预设由后端解析并实时回传命中人数；预设之外还能按关键词搜索用户多选，
// 解决「关掉全部用户开关后无从选择目标」的问题。
function BroadcastSection() {
  const { t, lang } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { data } = useQuery({ queryKey: ['admin', 'notifications'], queryFn: () => api.adminNotifications(1, 20) })
  const { data: presetData } = useQuery({ queryKey: ['admin', 'notification-presets'], queryFn: api.adminNotificationPresets })
  const [title, setTitle] = React.useState('')
  const [summary, setSummary] = React.useState('')
  const [allUsers, setAllUsers] = React.useState(true)
  const [preset, setPreset] = React.useState('')
  const [userQuery, setUserQuery] = React.useState('')
  const [selected, setSelected] = React.useState<{ id: number; label: string }[]>([])

  const presets: any[] = (presetData as any)?.items ?? []

  // 手工勾选用户的搜索：防抖 300ms，避免每敲一个字符就打一次接口。
  const [debouncedQuery, setDebouncedQuery] = React.useState('')
  React.useEffect(() => {
    const tm = setTimeout(() => setDebouncedQuery(userQuery.trim()), 300)
    return () => clearTimeout(tm)
  }, [userQuery])

  const { data: userData } = useQuery({
    queryKey: ['admin', 'notify-users', debouncedQuery],
    queryFn: () => api.adminUsers<any>(debouncedQuery, 1, 20),
    enabled: !allUsers && !preset && debouncedQuery.length > 0,
  })
  const users: any[] = (userData as any)?.items ?? []

  const toggleUser = (u: any) => {
    const label = u.displayName || u.username || u.email || String(u.id)
    setSelected((prev) => prev.some((x) => x.id === u.id)
      ? prev.filter((x) => x.id !== u.id)
      : [...prev, { id: u.id, label }])
  }

  const mode: 'all' | 'preset' | 'manual' = allUsers ? 'all' : (preset ? 'preset' : 'manual')

  const send = useMutation({
    mutationFn: () => api.adminBroadcastNotification({
      title: title.trim(),
      summary: summary.trim(),
      allUsers: mode === 'all',
      preset: mode === 'preset' ? preset : undefined,
      userIds: mode === 'manual' ? selected.map((x) => x.id) : undefined,
    }),
    onSuccess: (res: any) => {
      qc.invalidateQueries({ queryKey: ['admin', 'notifications'] })
      toast({ type: 'success', title: t('admin.broadcast.sent', { count: res?.delivered ?? 0 }) })
      setTitle('')
      setSummary('')
      setSelected([])
      setUserQuery('')
    },
    onError: (e) => toast({ type: 'error', title: e instanceof ApiError ? e.message : t('admin.broadcast.failed') }),
  })

  // 手工模式下必须先选人：后端也会拒绝空目标，这里提前给出提示。
  const targetMissing = mode === 'manual' && selected.length === 0
  const canSend = !!title.trim() && !targetMissing && !send.isPending

  const items: any[] = (data as any)?.items ?? []
  const total = (data as any)?.total ?? 0

  return (
    <div className="grid gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><BellRing className="size-4" /> {t('admin.broadcast.title')}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="max-w-2xl space-y-4">
            <div className="space-y-1.5">
              <Label>{t('admin.broadcast.notifTitle')}</Label>
              <Input value={title} maxLength={100} onChange={(e) => setTitle(e.target.value)} placeholder={t('admin.broadcast.titlePlaceholder')} />
            </div>
            <div className="space-y-1.5">
              <Label>{t('admin.broadcast.summary')}</Label>
              <textarea
                value={summary}
                onChange={(e) => setSummary(e.target.value)}
                rows={3}
                className="w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
                placeholder={t('admin.broadcast.summaryPlaceholder')}
              />
            </div>

            {/* 发送目标 */}
            <div className="space-y-3 rounded-lg border bg-muted/20 p-4">
              <div className="rounded-md border bg-background px-3">
                <SwitchRow
                  label={t('admin.broadcast.allUsers')}
                  desc={t('admin.broadcast.allUsersDesc')}
                  checked={allUsers}
                  onChange={() => { setAllUsers(!allUsers); setPreset('') }}
                  divider={false}
                />
              </div>

              {!allUsers && (
                <>
                  <div className="space-y-1.5">
                    <Label>{t('admin.broadcast.preset')}</Label>
                    <Select
                      value={preset || '__none__'}
                      onValueChange={(v) => setPreset(v === '__none__' ? '' : v)}
                      className="w-full max-w-sm"
                      ariaLabel={t('admin.broadcast.preset')}
                    >
                      <SelectItem value="__none__">{t('admin.broadcast.presetNone')}</SelectItem>
                      {presets.map((p: any) => (
                        <SelectItem key={p.key} value={p.key}>{`${p.label}（${p.count}）`}</SelectItem>
                      ))}
                    </Select>
                  </div>

                  {!preset && (
                    <div className="space-y-2">
                      <Label>{t('admin.broadcast.pickUsers')}</Label>
                      <Input
                        value={userQuery}
                        onChange={(e) => setUserQuery(e.target.value)}
                        placeholder={t('admin.broadcast.searchPlaceholder')}
                      />
                      {debouncedQuery.length > 0 && (
                        <div className="max-h-56 overflow-auto rounded-md border bg-background">
                          {users.length === 0 ? (
                            <div className="px-3 py-6 text-center text-xs text-muted-foreground">{t('admin.broadcast.searchEmpty')}</div>
                          ) : users.map((u: any) => {
                            const checked = selected.some((x) => x.id === u.id)
                            return (
                              <button
                                key={u.id}
                                type="button"
                                onClick={() => toggleUser(u)}
                                className={cn(
                                  'flex w-full items-center justify-between px-3 py-2 text-left text-sm hover:bg-muted/50',
                                  checked && 'bg-muted/40'
                                )}
                              >
                                <span className="truncate">
                                  <span className="font-medium">{u.displayName || u.username}</span>
                                  <span className="ml-2 text-xs text-muted-foreground">{u.email || u.username}</span>
                                </span>
                                {checked && <Check className="size-4 shrink-0 text-primary" />}
                              </button>
                            )
                          })}
                        </div>
                      )}
                      {selected.length > 0 && (
                        <div className="flex flex-wrap items-center gap-2">
                          {selected.map((s) => (
                            <span key={s.id} className="inline-flex items-center gap-1 rounded-full border bg-background px-2.5 py-1 text-xs">
                              {s.label}
                              <button
                                type="button"
                                onClick={() => setSelected((prev) => prev.filter((x) => x.id !== s.id))}
                                className="text-muted-foreground hover:text-foreground"
                                aria-label={t('common.delete')}
                              >
                                <X className="size-3" />
                              </button>
                            </span>
                          ))}
                          <Button variant="ghost" size="sm" onClick={() => setSelected([])}>{t('admin.broadcast.clearSelected')}</Button>
                        </div>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>

            <div className="flex items-center justify-end gap-3">
              <Button onClick={() => send.mutate()} disabled={!canSend}>
                {send.isPending ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />} {t('admin.broadcast.send')}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('admin.broadcast.history')}</CardTitle>
          <CardDescription>{t('admin.broadcast.total', { count: total })}</CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('admin.broadcast.notifTitle')}</TableHead>
                <TableHead>{t('admin.broadcast.summary')}</TableHead>
                <TableHead>{t('admin.broadcast.read')}</TableHead>
                <TableHead>{t('admin.broadcast.time')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((n: any) => (
                <TableRow key={n.id}>
                  <TableCell className="text-sm font-medium">{n.title}</TableCell>
                  <TableCell className="max-w-80 truncate text-xs text-muted-foreground" title={n.summary}>{n.summary || '—'}</TableCell>
                  <TableCell>
                    <Badge variant={n.read ? 'default' : 'secondary'}>
                      {n.read ? t('admin.broadcast.readYes') : t('admin.broadcast.readNo')}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatDateTimeI18n(n.createdAt, lang)}</TableCell>
                </TableRow>
              ))}
              {items.length === 0 && (
                <TableRow><TableCell colSpan={4} className="py-10 text-center text-sm text-muted-foreground">{t('admin.broadcast.empty')}</TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
