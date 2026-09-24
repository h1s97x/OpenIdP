import * as React from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../../components/ui/card'
import { Button } from '../../components/ui/button'
import { Input, Label } from '../../components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../../components/ui/table'
import { api, ApiError } from '../../lib/api'
import { useI18n } from '../../i18n'
import { useToast } from '../../components/ui/toast'
import { useConfirm } from '../../components/ui/confirm'
import { cn, formatDateTimeI18n } from '../../lib/utils'
import { Badge } from '../../components/ui/badge'
import { AppWindow, Trash2, Plus, Pencil, RefreshCw, Copy, Check, PlugZap, AlertTriangle, KeyRound } from 'lucide-react'

interface OAuthClientItem {
  id: string
  name: string
  description?: string
  logoUrl?: string
  homepageUrl?: string
  redirectUris?: string[]
  scopes?: string[]
  createdAt: string
}

// 权限项定义，来自 GET /admin/oauth-scopes。
interface ScopeDef {
  name: string
  displayName?: string
  description?: string
  // 关闭后新的授权请求会剔除该权限，但已存在的授权仍需如实展示。
  enabled?: boolean
  // 基础权限（如 openid）：必选且不允许取消勾选。
  required?: boolean
}

const EMPTY_FORM = { name: '', description: '', logoUrl: '', homepageUrl: '', redirectUris: '', scopes: [] as string[] }

// 权限项在表格中的固定展示顺序：id → 资料 → 邮箱 → 手机号 → 地址 → 离线访问。
// 未收录的自定义权限排在最后，按字母序保持稳定。
const SCOPE_ORDER = ['openid', 'profile', 'email', 'phone', 'address', 'offline_access']

// sortScopes 按 SCOPE_ORDER 重排权限项，避免后端按 name ASC 返回的字母序
// 与运营期望的固定顺序不一致（address 缺失时自动忽略，不参与排序）。
function sortScopes(list: ScopeDef[]): ScopeDef[] {
  const rank = new Map(SCOPE_ORDER.map((s, i) => [s, i]))
  return [...list].sort((a, b) => {
    const ra = rank.get(a.name)
    const rb = rank.get(b.name)
    if (ra !== undefined && rb !== undefined) return ra - rb
    if (ra !== undefined) return -1
    if (rb !== undefined) return 1
    return a.name.localeCompare(b.name)
  })
}

/* --------------------------- 可复制的键值行 --------------------------- */
// 端点地址与 Client ID / Client Secret 共用同一套排版，避免两行高度、内边距、
// 字号不一致（此前 ID 用 text-xs、Secret 用 text-sm，看起来像两种控件）。
function CopyRow({ label, value }: { label: string; value: string }) {
  const { t } = useI18n()
  const { toast } = useToast()
  const [copied, setCopied] = React.useState(false)
  const valueRef = React.useRef<HTMLElement>(null)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
      return
    } catch {
      /* 非安全上下文（http / 无权限）下剪贴板不可用，退化为选中文本 */
    }
    const node = valueRef.current
    if (!node) return
    const range = document.createRange()
    range.selectNodeContents(node)
    const sel = window.getSelection()
    sel?.removeAllRanges()
    sel?.addRange(range)
    toast({ type: 'info', title: t('admin.apps.selected') })
  }

  return (
    <div className="flex items-center gap-2">
      <span className="w-28 shrink-0 text-xs text-muted-foreground">{label}</span>
      <code ref={valueRef} className="min-w-0 flex-1 break-all rounded-md bg-muted px-3 py-2 font-mono text-sm leading-relaxed">
        {value}
      </code>
      <Button size="sm" variant="outline" onClick={copy} aria-label={t('admin.apps.copy')} title={t('admin.apps.copy')}>
        {copied ? <Check className="size-4 text-success" /> : <Copy className="size-4" />}
      </Button>
    </div>
  )
}

/* ------------------------------ 接入地址 ------------------------------ */
// 第三方应用接入本站点时需要用到这些地址。此前管理后台没有展示它们，接入方
// 只能去翻文档；这里直接读 OIDC 发现文档，避免前端硬编码路径与后端路由漂移。
function OauthEndpointsCard() {
  const { t } = useI18n()
  const { data } = useQuery({
    queryKey: ['oauth-discovery'],
    queryFn: api.oauthDiscovery,
    staleTime: Infinity,
    retry: false,
  })

  const origin = typeof window === 'undefined' ? '' : window.location.origin
  const d = (data ?? {}) as Record<string, string>
  const endpoints = [
    { label: t('admin.apps.authorizeUrl'), value: d.authorization_endpoint ?? `${origin}/login/oauth/authorize` },
    { label: t('admin.apps.tokenUrl'), value: d.token_endpoint ?? `${origin}/api/login/oauth/access_token` },
    { label: t('admin.apps.userInfoUrl'), value: d.userinfo_endpoint ?? `${origin}/api/userinfo` },
    { label: t('admin.apps.discoveryUrl'), value: d.issuer ? `${d.issuer}/.well-known/openid-configuration` : `${origin}/.well-known/openid-configuration` },
  ]

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><PlugZap className="size-4" /> {t('admin.apps.endpointsTitle')}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {endpoints.map((e) => <CopyRow key={e.label} label={e.label} value={e.value} />)}
      </CardContent>
    </Card>
  )
}

/* ---------------------------- 权限范围复选框 ---------------------------- */
function ScopeCheckboxes({ options, value, onChange }: {
  options: ScopeDef[]
  value: string[]
  onChange: (v: string[]) => void
}) {
  const { t } = useI18n()

  // 已停用的权限不再对新授权开放，但应用若在停用前就已带上该权限，仍需如实展示。
  //
  // 排序放在这里而不是交给调用方：本组件是两列网格，数组顺序即「从左到右、
  // 从上到下」，按 SCOPE_ORDER 排一次即可与上方「OAuth 权限项」表格的顺序一致。
  const items = sortScopes(options.filter((s) => s.enabled !== false || value.includes(s.name)))

  if (items.length === 0) {
    return <p className="text-xs text-muted-foreground">{t('admin.apps.scopesEmpty')}</p>
  }

  const toggle = (name: string) =>
    onChange(value.includes(name) ? value.filter((s) => s !== name) : [...value, name])

  return (
    <div className="grid gap-2 sm:grid-cols-2">
      {items.map((s) => {
        const required = !!s.required
        const checked = required || value.includes(s.name)
        // 语言包提供的是面向用户的中文名；未收录时回落到后台配置的 displayName。
        const nameKey = `admin.scopes.${s.name}`
        const descKey = `${nameKey}.desc`
        const name = t(nameKey) === nameKey ? (s.displayName || s.name) : t(nameKey)
        const desc = t(descKey) === descKey ? (s.description || '') : t(descKey)
        return (
          <label
            key={s.name}
            className={cn(
              'flex items-start gap-2.5 rounded-md border px-3 py-2 transition-colors',
              required || s.enabled === false ? 'cursor-default opacity-70' : 'cursor-pointer hover:bg-accent'
            )}
          >
            <input
              type="checkbox"
              checked={checked}
              disabled={required || s.enabled === false}
              onChange={() => toggle(s.name)}
              className="mt-0.5 size-4 shrink-0 accent-primary"
            />
            <span className="min-w-0">
              <span className="flex flex-wrap items-center gap-1.5 text-sm font-medium">
                {name}
                {required && (
                  <span className="rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-normal text-primary">{t('admin.apps.scopeRequired')}</span>
                )}
                {s.enabled === false && (
                  <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] font-normal text-muted-foreground">{t('admin.apps.scopeDisabled')}</span>
                )}
              </span>
              {desc && <span className="mt-0.5 block text-xs text-muted-foreground">{desc}</span>}
            </span>
          </label>
        )
      })}
    </div>
  )
}

/* ---------------------------- 权限项管理 ---------------------------- */
// 权限项此前只在应用表单里以只读复选框出现：管理员能看到有哪些权限，
// 却不能改名称/说明，也不能启停。后端 PUT /admin/oauth-scopes 与
// enable/disable 两个端点一直存在但没有入口，这里补上。
function ScopeManagerCard() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  const { data } = useQuery({ queryKey: ['admin', 'oauth-scopes'], queryFn: () => api.adminOAuthScopes<{ items?: ScopeDef[] }>() })
  const [editingName, setEditingName] = React.useState<string | null>(null)
  const [form, setForm] = React.useState({ displayName: '', description: '' })

  const items: ScopeDef[] = sortScopes((data as any)?.items ?? [])

  const invalidate = () => qc.invalidateQueries({ queryKey: ['admin', 'oauth-scopes'] })

  const save = useMutation({
    mutationFn: () => api.adminUpdateOAuthScope({ name: editingName!, displayName: form.displayName, description: form.description }),
    onSuccess: () => {
      invalidate()
      setEditingName(null)
      toast({ type: 'success', title: t('common.saved') })
    },
    onError: (e) => toast({ type: 'error', title: e instanceof ApiError ? e.message : t('common.failed') }),
  })

  // 端点路径参数虽名为 {id}，后端按 name 查询权限项。
  const toggle = useMutation({
    mutationFn: (v: { name: string; enabled: boolean }) => api.adminSetOAuthScope(v.name, v.enabled),
    onSuccess: () => {
      invalidate()
      toast({ type: 'success', title: t('common.saved') })
    },
    onError: (e) => toast({ type: 'error', title: e instanceof ApiError ? e.message : t('common.failed') }),
  })

  const startEdit = (s: ScopeDef) => {
    setEditingName(s.name)
    setForm({ displayName: s.displayName ?? '', description: s.description ?? '' })
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><KeyRound className="size-4" /> {t('admin.scopeManager.title')}</CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t('admin.scopeManager.scope')}</TableHead>
              <TableHead>{t('admin.scopeManager.displayName')}</TableHead>
              <TableHead>{t('admin.scopeManager.description')}</TableHead>
              <TableHead>{t('common.status')}</TableHead>
              <TableHead className="text-right">{t('common.actions')}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((s) => (
              <TableRow key={s.name}>
                <TableCell><code className="text-xs">{s.name}</code></TableCell>
                <TableCell className="text-sm">{s.displayName || '—'}</TableCell>
                <TableCell className="max-w-72 truncate text-xs text-muted-foreground" title={s.description}>{s.description || '—'}</TableCell>
                <TableCell>
                  <Badge variant={s.enabled === false ? 'outline' : 'default'}>
                    {s.enabled === false ? t('admin.scopeManager.disabled') : t('admin.scopeManager.enabled')}
                  </Badge>
                </TableCell>
                <TableCell>
                  <div className="flex justify-end gap-1">
                    <Button variant="ghost" size="icon" className="size-8" title={t('admin.apps.edit')} aria-label={t('admin.apps.edit')} onClick={() => startEdit(s)}>
                      <Pencil className="size-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={!!s.required || toggle.isPending}
                      title={s.required ? t('admin.scopeManager.requiredHint') : undefined}
                      onClick={() => toggle.mutate({ name: s.name, enabled: s.enabled === false })}
                    >
                      {s.enabled === false ? t('admin.scopeManager.enable') : t('admin.scopeManager.disable')}
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
            {items.length === 0 && (
              <TableRow><TableCell colSpan={5} className="py-10 text-center text-sm text-muted-foreground">{t('admin.apps.scopesEmpty')}</TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>

      {editingName && (
        <CardContent className="border-t pt-6">
          <div className="max-w-2xl space-y-4">
            <div className="text-sm font-medium">{t('admin.scopeManager.editTitle', { name: editingName })}</div>
            <div className="space-y-1.5">
              <Label>{t('admin.scopeManager.displayName')}</Label>
              <Input value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} />
            </div>
            <div className="space-y-1.5">
              <Label>{t('admin.scopeManager.description')}</Label>
              <Input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </div>
            <div className="flex justify-end gap-2">
              <Button onClick={() => save.mutate()} disabled={save.isPending}>{t('common.save')}</Button>
              <Button variant="outline" onClick={() => setEditingName(null)}>{t('common.cancel')}</Button>
            </div>
          </div>
        </CardContent>
      )}
    </Card>
  )
}

/* ------------------------------ 应用管理 ------------------------------ */
// 作为「系统设置 → 应用管理」分区渲染，因此不自带页面级标题。
interface ScopeRow { id?: string; [k: string]: unknown }

export function AppsSection() {
  const { t, lang } = useI18n()
  const qc = useQueryClient()
  const { toast } = useToast()
  // 用自建确认弹窗而非 window.confirm：后者阻塞主线程、样式与全站不一致、
  // 按钮文案无法走 i18n，且在部分内嵌环境会被禁用而直接返回 false。
  const { confirm: confirmDialog } = useConfirm()
  const { data: clients, isError, refetch } = useQuery({ queryKey: ['admin', 'oauth-clients'], queryFn: () => api.adminOAuthClients<OAuthClientItem[]>() })
  const { data: scopeData } = useQuery({ queryKey: ['admin', 'oauth-scopes'], queryFn: () => api.adminOAuthScopes<ScopeRow[]>() })
  const [creating, setCreating] = React.useState(false)
  const [editing, setEditing] = React.useState<OAuthClientItem | null>(null)
  const [form, setForm] = React.useState({ ...EMPTY_FORM })
  // 新密钥不再以顶部卡片呈现，而是绑定到具体应用，在该应用行下方就地展示，
  // 与「查看 Client ID / 复制密钥」的操作路径保持一致。
  const [reveal, setReveal] = React.useState<{ id: string; secret: string } | null>(null)

  const scopeDefs: ScopeDef[] = (scopeData as any)?.items ?? []
  // 基础权限（openid）始终随应用提交，避免用户漏勾导致授权流程不可用。
  const requiredScopes = scopeDefs.filter((s) => s.required).map((s) => s.name)

  const invalidate = () => qc.invalidateQueries({ queryKey: ['admin', 'oauth-clients'] })

  const buildBody = () => ({
    name: form.name.trim(),
    description: form.description.trim(),
    logoUrl: form.logoUrl.trim(),
    homepageUrl: form.homepageUrl.trim(),
    redirectUris: form.redirectUris.split('\n').map((s) => s.trim()).filter(Boolean),
    scopes: Array.from(new Set([...requiredScopes, ...form.scopes])),
  })

  const closeForm = () => {
    setCreating(false)
    setEditing(null)
    setForm({ ...EMPTY_FORM })
  }

  const create = useMutation({
    mutationFn: () => api.adminCreateOAuthClient(buildBody()),
    onSuccess: (d: any) => {
      invalidate()
      closeForm()
      const id = d?.client?.id ?? d?.id
      if (id && d?.clientSecret) setReveal({ id, secret: d.clientSecret })
    },
    onError: (e) => toast({ type: 'error', title: t('admin.apps.createFailed'), description: e instanceof ApiError ? e.message : '' }),
  })

  const update = useMutation({
    mutationFn: () => api.adminUpdateOAuthClient(editing!.id, buildBody()),
    onSuccess: () => {
      invalidate()
      closeForm()
      toast({ type: 'success', title: t('admin.apps.updateSuccess') })
    },
    onError: (e) => toast({ type: 'error', title: t('admin.apps.updateFailed'), description: e instanceof ApiError ? e.message : '' }),
  })

  const rotate = useMutation({
    mutationFn: (c: OAuthClientItem) => api.adminRotateOAuthClientSecret(c.id),
    onSuccess: (d: any) => {
      invalidate()
      const id = d?.client?.id ?? d?.id
      const secret = d?.clientSecret ?? ''
      if (id && secret) {
        setReveal({ id, secret })
        toast({ type: 'success', title: t('admin.apps.rotateSuccess') })
      }
    },
    onError: (e) => toast({ type: 'error', title: t('admin.apps.rotateFailed'), description: e instanceof ApiError ? e.message : '' }),
  })

  const del = useMutation({
    mutationFn: (id: string) => api.adminDeleteOAuthClient(id),
    onSuccess: async (_d, id) => {
      await invalidate()
      setReveal((prev) => (prev?.id === id ? null : prev))
      toast({ type: 'success', title: t('admin.apps.deleteSuccess') })
    },
    onError: (e) => toast({ type: 'error', title: t('admin.apps.deleteFailed'), description: e instanceof ApiError ? e.message : '' }),
  })

  const items: OAuthClientItem[] = clients ?? []

  // 展示新密钥时滚动到对应应用行，避免列表较长时密钥出现在视口之外。
  // 依赖必须是 items：invalidate 触发的 refetch 是异步的，
  // 只依赖 reveal 会在新行渲染前就 getElementById，结果恒为 null 而静默不滚动。
  React.useEffect(() => {
    if (!reveal) return
    document.getElementById(`app-row-${reveal.id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }, [reveal, items])

  const startEdit = (c: OAuthClientItem) => {
    setCreating(false)
    setEditing(c)
    setForm({
      name: c.name ?? '',
      description: c.description ?? '',
      logoUrl: c.logoUrl ?? '',
      homepageUrl: c.homepageUrl ?? '',
      redirectUris: (c.redirectUris ?? []).join('\n'),
      scopes: c.scopes ?? [],
    })
  }

  // 创建/编辑共用的表单字段，避免两处表单字段与校验逻辑漂移。
  const formFields = (
    <div className="max-w-2xl space-y-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label>{t('admin.apps.name')}</Label>
          <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder={t('admin.apps.namePlaceholder')} />
        </div>
        <div className="space-y-1.5">
          <Label>{t('admin.apps.description')}</Label>
          <Input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder={t('admin.apps.descriptionPlaceholder')} />
        </div>
      </div>
      <div className="space-y-1.5">
        <Label>{t('admin.apps.logoUrl')}</Label>
        <Input value={form.logoUrl} onChange={(e) => setForm({ ...form, logoUrl: e.target.value })} placeholder="https://…" />
      </div>
      <div className="space-y-1.5">
        <Label>{t('admin.apps.homepageUrl')}</Label>
        <Input value={form.homepageUrl} onChange={(e) => setForm({ ...form, homepageUrl: e.target.value })} placeholder="https://…" />
      </div>
      <div className="space-y-1.5">
        <Label>{t('admin.apps.redirectUris')}</Label>
        <textarea
          value={form.redirectUris}
          onChange={(e) => setForm({ ...form, redirectUris: e.target.value })}
          className="min-h-20 w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50"
          placeholder="https://app.example.com/callback"
        />
      </div>
      <div className="space-y-1.5">
        <Label>{t('admin.apps.scopes')}</Label>
        <p className="text-xs text-muted-foreground">{t('admin.apps.scopesHint')}</p>
        <ScopeCheckboxes
          options={scopeDefs}
          value={form.scopes}
          onChange={(scopes) => setForm({ ...form, scopes })}
        />
      </div>
      <div className="flex justify-end gap-2">
        <Button
          onClick={() => (editing ? update.mutate() : create.mutate())}
          // 必须等 scopes 定义加载完：它在飞行中时 requiredScopes 是空数组，
          // 提交会创建出缺少 openid 的客户端，授权/令牌流程不可用且看不出原因。
          disabled={!form.name.trim() || create.isPending || update.isPending || !scopeData}
        >
          {editing ? t('common.save') : t('common.create')}
        </Button>
        <Button variant="outline" onClick={closeForm}>{t('common.cancel')}</Button>
      </div>
    </div>
  )

  return (
    <div className="space-y-6">
      <OauthEndpointsCard />

      <ScopeManagerCard />

      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <CardTitle>{t('admin.apps.listTitle')}</CardTitle>
              <CardDescription>{t('admin.apps.count', { count: items.length })}</CardDescription>
            </div>
            <Button size="sm" onClick={() => { closeForm(); setCreating(true) }}><Plus className="size-4" /> {t('admin.apps.register')}</Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {(creating || editing) && (
            <div className="rounded-lg border bg-muted/10 p-4">
              <div className="mb-4">
                <div className="text-sm font-medium">{editing ? t('admin.apps.editTitle') : t('admin.apps.registerTitle')}</div>
                <p className="mt-0.5 text-xs text-muted-foreground">{editing ? t('admin.apps.editDesc') : t('admin.apps.registerDesc')}</p>
              </div>
              {formFields}
            </div>
          )}

          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t('admin.apps.app')}</TableHead>
                <TableHead>{t('admin.apps.clientId')}</TableHead>
                <TableHead>{t('admin.apps.redirect')}</TableHead>
                <TableHead>{t('admin.apps.registeredAt')}</TableHead>
                <TableHead className="text-right">{t('common.actions')}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((c) => (
                <React.Fragment key={c.id}>
                  <TableRow id={`app-row-${c.id}`} className={reveal?.id === c.id ? 'bg-primary/5' : undefined}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        {c.logoUrl
                          ? <img src={c.logoUrl} alt="" className="h-7 w-7 rounded" />
                          : <span className="flex h-7 w-7 items-center justify-center rounded bg-muted"><AppWindow className="size-4 text-muted-foreground" /></span>}
                        <span className="text-sm font-medium">{c.name}</span>
                      </div>
                    </TableCell>
                    <TableCell><code className="text-xs">{c.id}</code></TableCell>
                    <TableCell className="max-w-[14rem] truncate text-xs text-muted-foreground">{(c.redirectUris ?? []).join(', ')}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{formatDateTimeI18n(c.createdAt, lang)}</TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-1">
                        <Button variant="ghost" size="icon" className="size-8" title={t('admin.apps.edit')} aria-label={t('admin.apps.edit')} onClick={() => startEdit(c)}>
                          <Pencil className="size-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8"
                          title={t('admin.apps.rotate')}
                          aria-label={t('admin.apps.rotate')}
                          disabled={rotate.isPending || del.isPending}
                          onClick={() => {
                            void confirmDialog({
                              title: t('admin.apps.rotateConfirm', { name: c.name }),
                              confirmText: t('admin.apps.rotate'),
                              // 轮换会让旧密钥立即失效，属破坏性操作
                              onConfirm: async () => { await rotate.mutateAsync(c) },
                            })
                          }}
                        >
                          <RefreshCw className="size-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8 text-destructive hover:text-destructive"
                          title={t('common.delete')}
                          aria-label={t('common.delete')}
                          disabled={rotate.isPending || del.isPending}
                          onClick={() => {
                            void confirmDialog({
                              title: t('admin.apps.deleteConfirm', { name: c.name }),
                              confirmText: t('common.delete'),
                              variant: 'destructive',
                              onConfirm: async () => { await del.mutateAsync(c.id) },
                            })
                          }}
                        >
                          <Trash2 className="size-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>

                  {/* 新凭据就地展示在同一应用行下方：先看到 Client ID，再复制紧邻其后的密钥。
                      两行复用 CopyRow，样式与行高完全一致。 */}
                  {reveal?.id === c.id && (
                    <TableRow className="hover:bg-transparent">
                      <TableCell colSpan={5} className="whitespace-normal bg-primary/5 p-0">
                        <div className="m-2 overflow-hidden rounded-lg border border-primary/40 bg-background">
                          <div className="border-b px-4 py-3">
                            <div className="text-sm font-medium">{t('admin.apps.credentialsTitle')}</div>
                            <p className="mt-0.5 text-xs text-muted-foreground">{t('admin.apps.credentialsDesc')}</p>
                          </div>
                          <div className="space-y-3 px-4 py-3">
                            <CopyRow label={t('admin.apps.clientId')} value={c.id} />
                            <CopyRow label={t('admin.apps.secretLabel')} value={reveal.secret} />
                          </div>
                          {/* 密钥可随时刷新，因此不强制复制：未保存也允许直接关闭。 */}
                          <div className="flex flex-wrap items-center justify-between gap-3 border-t px-4 py-3">
                            <span className="text-xs text-muted-foreground">{t('admin.apps.secretCloseHint')}</span>
                            <Button size="sm" onClick={() => setReveal(null)}>{t('common.close')}</Button>
                          </div>
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </React.Fragment>
              ))}
              {isError && (
                <TableRow><TableCell colSpan={5} className="py-10 text-center">
                  <div className="flex flex-col items-center gap-3 text-sm text-muted-foreground">
                    <span className="inline-flex items-center gap-2 text-destructive">
                      <AlertTriangle className="size-4" /> {t('common.loadFailed')}
                    </span>
                    <Button variant="outline" size="sm" onClick={() => refetch()}>
                      <RefreshCw className="size-4" /> {t('common.retry')}
                    </Button>
                  </div>
                </TableCell></TableRow>
              )}
              {!isError && items.length === 0 && (
                <TableRow><TableCell colSpan={5} className="py-10 text-center text-sm text-muted-foreground">{t('admin.apps.empty')}</TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
