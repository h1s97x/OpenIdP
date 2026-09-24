import * as React from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle, CardDescription, CardFooter } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Input, Label } from '../components/ui/input'
import { Badge } from '../components/ui/badge'
import { Field } from '../components/ui/field'
import { InputOTP } from '../components/ui/input-otp'
import { api, ApiError } from '../lib/api'
import { useI18n } from '../i18n'
import { useToast } from '../components/ui/toast'
import { useConfirm } from '../components/ui/confirm'
import { useSession } from '../hooks/useSession'
import { useReauth } from '../hooks/useReauth'
import { useSecondFactor } from '../hooks/useSecondFactor'
import { SecondFactorField } from '../components/ui/second-factor-field'
import { usePasswordPolicy } from '../hooks/usePasswordPolicy'
import { formatDateTimeI18n, formatDayKey, cn } from '../lib/utils'
import {
  KeyRound, Smartphone, ShieldCheck, ShieldAlert, Copy, Check, Trash2, RefreshCw,
  Link2, Unlink, Fingerprint, X, MailCheck, Mail, Download, Loader2, Clock,
} from 'lucide-react'

export function SecurityPage() {
  const { t, lang } = useI18n()
  const qc = useQueryClient()
  const { success: toastSuccess, error: toastError } = useToast()
  const { confirm } = useConfirm()
  const { capabilities, session } = useSession()
  const accountDeletionEnabled = capabilities?.personal?.accountDeletion !== false
  // 管理员账号不提供自助注销：安全中心对其隐藏整个注销模块。
  const isAdmin = !!session?.user?.isAdmin

  // 能力位（能否改邮箱、能否添加手机号）取决于 SMTP / 短信配置与管理员策略开关，
  // 这些随时可能在后台被改动。react-query 会复用缓存，导致「刚配好 SMTP 再回到
  // 安全中心」仍提示未配置、必须整页刷新才恢复。进入本页时主动失效一次，
  // 让能力位与服务端配置对齐。
  React.useEffect(() => {
    qc.invalidateQueries({ queryKey: ['capabilities'] })
  }, [qc])
  // 删除通行密钥属敏感操作，服务端要求携带 reauthToken
  const { requestReauth: requestPasskeyReauth, dialog: reauthDialog } = useReauth()

  // 密码策略：提示词与下方规则清单都按服务端实际策略生成，不写死「8 位」，
  // 也不再宣称并不存在的大写/小写/数字要求。
  const passwordReqs = usePasswordPolicy()

  // ---- 修改密码 ----
  const [oldPassword, setOldPassword] = React.useState('')
  const [newPassword, setNewPassword] = React.useState('')
  const [confirmPw, setConfirmPw] = React.useState('')

  const changePw = useMutation({
    mutationFn: () => api.changePassword(oldPassword, newPassword),
    onSuccess: () => {
      setOldPassword(''); setNewPassword(''); setConfirmPw('')
      toastSuccess(t('security.passwordChanged'))
    },
    onError: (e) => toastError(t('security.passwordChangeFailed'), e instanceof ApiError ? e.message : ''),
  })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (newPassword !== confirmPw) {
      toastError(t('security.passwordMismatch'))
      return
    }
    changePw.mutate()
  }

  // ---- 通行密钥 ----
  // 后端未启用通行密钥时返回 { enabled: false, passkeys: [] }，
  // 据此隐藏注册入口并给出说明，而不是让用户点了一次才看到报错。
  const { data: passkeyData } = useQuery({ queryKey: ['passkeys'], queryFn: () => api.passkeys<PasskeysData>() })
  const passkeyEnabled = passkeyData?.enabled !== false
  const passkeyList: any[] = passkeyData?.passkeys ?? []

  // 通行密钥与 MFA 各操作的进行中标识：此前这些按钮都没有 loading，
  // WebAuthn 与二维码注册都要走秒级流程，期间可重复点击。
  const [passkeyBusy, setPasskeyBusy] = React.useState(false)
  const [enrollBusy, setEnrollBusy] = React.useState(false)
  const [pendingPasskeyId, setPendingPasskeyId] = React.useState<string | null>(null)

  // 添加通行密钥分两步：先在浏览器/认证器完成创建（此时才能推断保存到哪里），
  // 再用推断出的名称预填命名弹窗，用户确认或改名后才写入后端。
  //
  // 之所以「先创建后命名」：通行密钥保存在哪个密码管理器，只有在 credential
  // 返回后（authenticatorAttachment / transports）才可得知；若在弹窗前就要求
  // 命名，就只能用「通行密钥 1」这类没有信息量的默认名。
  const [nameOpen, setNameOpen] = React.useState(false)
  const [passkeyName, setPasskeyName] = React.useState('')
  // 已创建但尚未提交的凭证与仪式 ID
  const pendingCred = React.useRef<any>(null)
  const [pendingCeremony, setPendingCeremony] = React.useState<string | null>(null)

  // closeNameDialog 放弃本次创建：仪式未被消费，过期后自动清理，无副作用。
  const closeNameDialog = () => {
    setNameOpen(false)
    setPendingCeremony(null)
    pendingCred.current = null
  }

  // uniquePasskeyName 保证默认名不与已有条目重复。
  // 同一台设备上添加的多个通行密钥，推断出的管理器名是相同的
  // （例如两个都保存在 Windows Hello），不去重就又回到「全是同名」的老问题。
  const uniquePasskeyName = (base: string) => {
    const used = new Set(passkeyList.map((p: any) => p.name))
    if (!used.has(base)) return base
    let i = 2
    while (used.has(`${base} ${i}`)) i++
    return `${base} ${i}`
  }

  const openAddPasskey = async () => {
    if (passkeyBusy) return
    setPasskeyBusy(true)
    try {
      const begin = await api.passkeysBegin<PasskeyBegin>()
      const { createPasskey } = await import('../lib/webauthn')
      const { credential, suggestedName } = await createPasskey(begin.options, t)
      pendingCred.current = credential
      setPendingCeremony(begin.ceremonyId)
      setPasskeyName(uniquePasskeyName(suggestedName || defaultPasskeyName(passkeyList.length)))
      setNameOpen(true)
    } catch (err) {
      // 用户取消（退出密码管理器）或认证器报错都算本次添加失败：
      // 统一右下角提示，不再静默吞掉取消场景。
      const errName = err instanceof Error ? err.name : ''
      if (errName === 'NotAllowedError' || errName === 'AbortError') {
        toastError(t('security.passkeyCancelled'))
      } else {
        toastError(t('security.passkeyAddFailed'), err instanceof Error ? err.message : '')
      }
    } finally {
      setPasskeyBusy(false)
    }
  }

  const confirmAddPasskey = async () => {
    const ceremonyId = pendingCeremony
    const credential = pendingCred.current
    if (!ceremonyId || !credential) return
    const name = passkeyName.trim() || t('security.passkeyDefaultName')
    setNameOpen(false)
    setPasskeyBusy(true)
    try {
      await api.passkeysFinish(ceremonyId, name, credential)
      await qc.invalidateQueries({ queryKey: ['passkeys'] })
      toastSuccess(t('security.passkeyAdded'))
    } catch (err) {
      toastError(t('security.passkeyAddFailed'), err instanceof Error ? err.message : '')
    } finally {
      setPasskeyBusy(false)
      setPendingCeremony(null)
      pendingCred.current = null
    }
  }

  const deletePasskey = async (id: string, name: string) => {
    await confirm({
      title: t('security.passkeyDeleteConfirm'),
      // 明确点出要删除的是哪一个：原先把名称拼在句末的括号里
      // （「…无法再使用此通行密钥登录。（其他设备）」），读起来像补充说明而非名称。
      description: t('security.passkeyDeleteDescNamed', { name: name || t('security.passkeyDefaultName') }),
      confirmText: t('common.delete'),
      // 传 onConfirm：弹窗会等到请求完成才关闭，期间锁定按钮，
      // 避免「弹窗关了、请求还在飞」造成重复提交。
      onConfirm: async () => {
        // 删除通行密钥属敏感操作：先完成身份重验证
        requestPasskeyReauth(async (token) => {
          setPendingPasskeyId(id)
          try {
            await api.deletePasskey(id, token)
            await qc.invalidateQueries({ queryKey: ['passkeys'] })
            toastSuccess(t('security.passkeyDeleted'))
          } catch (err) {
            toastError(t('security.passkeyDeleteFailed'), err instanceof ApiError ? err.message : '')
            throw err
          } finally {
            setPendingPasskeyId(null)
          }
        })
      },
    })
  }

  // ---- 双因素认证 (MFA) ----
  const { data: mfaData } = useQuery({ queryKey: ['mfa'], queryFn: () => api.mfa<MfaData>() })
  const mfaEnabled = !!mfaData?.enabled
  const [enroll, setEnroll] = React.useState<any>(null)
  const [totpCode, setTotpCode] = React.useState('')
  const [recoveryCodes, setRecoveryCodes] = React.useState<string[] | null>(null)
  const [copied, setCopied] = React.useState(false)
  // 弹窗状态：enroll → 绑定弹窗；prompt → 输入 TOTP 验证码弹窗
  const [enrollOpen, setEnrollOpen] = React.useState(false)
  const [promptOpen, setPromptOpen] = React.useState(false)
  const [promptAction, setPromptAction] = React.useState<'disable' | 'regenerate'>('disable')
  const [promptCode, setPromptCode] = React.useState('')
  const [promptBusy, setPromptBusy] = React.useState(false)
  const [promptError, setPromptError] = React.useState('')

  const startEnroll = async () => {
    if (enrollBusy) return
    setEnrollBusy(true)
    try {
      const begin = await api.mfaBegin()
      setEnroll(begin)
      setTotpCode('')
      setEnrollOpen(true)
    } catch (err) {
      toastError(t('security.mfaEnrollFailed'), err instanceof ApiError ? err.message : '')
    } finally {
      setEnrollBusy(false)
    }
  }

  const confirmEnroll = async () => {
    // 请求期间锁定，避免连点产生多次 confirm
    if (enrollBusy) return
    setEnrollBusy(true)
    try {
      const res = await api.mfaConfirm<{ recoveryCodes?: string[] }>(totpCode.trim())
      setRecoveryCodes(res.recoveryCodes ?? [])
      setEnroll(null)
      setEnrollOpen(false)
      await qc.invalidateQueries({ queryKey: ['mfa'] })
      toastSuccess(t('security.mfaEnabled'))
    } catch (err) {
      toastError(t('security.mfaCodeInvalid'), err instanceof ApiError ? err.message : '')
    } finally {
      setEnrollBusy(false)
    }
  }

  const closeEnroll = () => {
    setEnrollOpen(false)
    setEnroll(null)
    setTotpCode('')
  }

  const openPrompt = (action: 'disable' | 'regenerate') => {
    setPromptAction(action)
    setPromptCode('')
    setPromptError('')
    setPromptOpen(true)
  }

  const submitPrompt = async () => {
    if (promptCode.trim().length !== 6) {
      setPromptError(t('security.mfaCodeInvalid'))
      return
    }
    setPromptBusy(true)
    setPromptError('')
    try {
      if (promptAction === 'disable') {
        await api.mfaDisable(promptCode.trim())
        qc.invalidateQueries({ queryKey: ['mfa'] })
        setPromptOpen(false)
        setPromptCode('')
        toastSuccess(t('security.mfaDisabled'))
      } else {
        const res = await api.mfaRecoveryCodes<{ recoveryCodes?: string[] }>(promptCode.trim())
        setRecoveryCodes(res.recoveryCodes ?? [])
        setPromptOpen(false)
        setPromptCode('')
        toastSuccess(t('security.mfaCodesRegenerated'))
      }
    } catch (err) {
      // 只有真正的「验证码错误」才提示验证码错误。网络失败、限流、
      // 服务重启导致的 CSRF 失效都该给出各自的原因，否则用户无法判断下一步。
      if (err instanceof ApiError && (err.status === 400 || err.status === 401)) {
        setPromptError(err.message || t('security.mfaCodeInvalid'))
      } else {
        setPromptError(err instanceof ApiError ? err.message : t('security.mfaActionFailed'))
      }
    } finally {
      setPromptBusy(false)
    }
  }

  const disableMfa = async () => {
    const ok = await confirm({
      title: t('security.mfaDisableTitle'),
      description: t('security.mfaDisableDesc'),
      confirmText: t('common.confirm'),
    })
    if (!ok) return
    // 真正的验证码在随后的 prompt 弹窗里收，避免在一个弹窗里堆两个步骤。
    openPrompt('disable')
  }

  // 重新生成会让所有旧恢复码立即失效，属破坏性操作，需要二次确认。
  const regenerateCodes = async () => {
    const ok = await confirm({
      title: t('security.mfaRegenerateConfirmTitle'),
      description: t('security.mfaRegenerateConfirmDesc'),
      confirmText: t('security.mfaRegenerate'),
    })
    if (!ok) return
    openPrompt('regenerate')
  }

  // 复制成功提示的计时器统一在卸载时清理，避免在卸载后 setState。
  const copyTimer = React.useRef<number | null>(null)
  React.useEffect(() => () => {
    if (copyTimer.current) window.clearTimeout(copyTimer.current)
  }, [])

  const flashCopied = () => {
    setCopied(true)
    if (copyTimer.current) window.clearTimeout(copyTimer.current)
    copyTimer.current = window.setTimeout(() => setCopied(false), 2000)
  }

  const copyCodes = async () => {
    if (!recoveryCodes) return
    try {
      await navigator.clipboard.writeText(recoveryCodes.join('\n'))
      flashCopied()
    } catch {
      toastError(t('security.mfaCopyFailed'))
    }
  }

  const copySecret = async () => {
    if (!enroll?.secret) return
    try {
      await navigator.clipboard.writeText(enroll.secret)
      flashCopied()
    } catch {
      toastError(t('security.mfaCopyFailed'))
    }
  }

  return (
    <div className="space-y-6">
      {/* 页头：左侧色条 + 标题 */}
      <div className="flex flex-wrap items-end justify-between gap-4 border-b pb-6">
        <div className="border-l-2 border-primary pl-3">
          <h1 className="text-2xl font-bold md:text-3xl">{t('security.title')}</h1>
        </div>
      </div>

      {/* 修改密码 */}
      <Card>
        <CardHeader>
          <CardTitle>{t('security.changePassword')}</CardTitle>
        </CardHeader>
        <CardContent>
          <form id="change-password-form" onSubmit={submit} className="max-w-md space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="security-old-password">{t('security.currentPassword')}</Label>
              <Input id="security-old-password" type="password" value={oldPassword} onChange={(e) => setOldPassword(e.target.value)} autoComplete="current-password" required placeholder={t('security.emailChangePasswordPlaceholder')} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="security-new-password">{t('security.newPassword')}</Label>
              <Input id="security-new-password" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} autoComplete="new-password" required placeholder={t('security.newPasswordPlaceholder', { min: passwordReqs.minimumLength })} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="security-confirm-password">{t('security.confirmPassword')}</Label>
              <Input id="security-confirm-password" type="password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} autoComplete="new-password" required placeholder={t('security.confirmPasswordPlaceholder')} />
            </div>
          </form>
        </CardContent>
        <CardFooter className="justify-end border-t bg-muted/20">
          <Button type="submit" form="change-password-form" disabled={changePw.isPending}>{t('security.updatePassword')}</Button>
        </CardFooter>
      </Card>

      {/* 邮箱登录 */}
      <EmailLoginCard />

      {/* 手机号验证 */}
      <PhoneVerifyCard />

      {/* 导出个人数据 */}
      <ExportCard />

      {/* 第三方登录 */}
      <ThirdPartyCard />

      {/* 登录凭据：通行密钥与双因素认证是同一类「备用凭据」，
          并排两列，避免纵向堆叠把页面拉得过长（窄屏回落单列）。
          默认 items-stretch：两卡片始终等高，避免内容多少导致高度不一致。 */}
      <div className="grid gap-6 lg:grid-cols-2">
      {/* 通行密钥 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Fingerprint className="size-4" /> {t('security.passkeys')}</CardTitle>
        </CardHeader>
        <CardContent>
          {!passkeyEnabled ? (
            <div className="text-sm text-muted-foreground">{t('security.passkeysUnavailable')}</div>
          ) : passkeyList.length === 0 ? (
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="text-sm text-muted-foreground">{t('security.noPasskeys')}</div>
              <Button variant="outline" onClick={openAddPasskey} disabled={passkeyBusy}>
                {passkeyBusy ? <Loader2 className="size-4 animate-spin" /> : <KeyRound className="size-4" />}
                {t('security.addPasskey')}
              </Button>
            </div>
          ) : (
            <div className="divide-y">
              {passkeyList.map((pk: any) => (
                <div key={pk.id} className="flex flex-wrap items-center justify-between gap-3 py-3">
                  <div className="flex min-w-0 items-center gap-3">
                    <div className="grid size-9 place-items-center rounded-md bg-muted text-muted-foreground">
                      <KeyRound className="size-4" />
                    </div>
                    <div>
                      <div className="text-sm font-medium">{pk.name}</div>
                      <div className="text-xs text-muted-foreground">
                        {t('security.passkeyAddedAt')} {formatDateTimeI18n(pk.createdAt, lang)}
                      </div>
                    </div>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    className="border-destructive/30 text-destructive hover:border-destructive/50 hover:bg-destructive/10 hover:text-destructive"
                    disabled={pendingPasskeyId === pk.id}
                    onClick={() => deletePasskey(pk.id, pk.name)}
                  >
                    {pendingPasskeyId === pk.id ? (
                      <Loader2 className="size-4 animate-spin" />
                    ) : (
                      <Trash2 className="size-4" />
                    )}
                    {t('common.delete')}
                  </Button>
                </div>
              ))}
              {/* 与「尚未添加」状态保持一致的右对齐，避免添加按钮在两个状态间左右跳动 */}
              <div className="flex justify-end pt-3">
                <Button variant="outline" onClick={openAddPasskey} disabled={passkeyBusy}>
                  {passkeyBusy ? <Loader2 className="size-4 animate-spin" /> : <KeyRound className="size-4" />}
                  {t('security.addPasskey')}
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* 双因素认证 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><ShieldCheck className="size-4" /> {t('security.twoFactor')}</CardTitle>
        </CardHeader>
        <CardContent>
          {recoveryCodes ? (
            <div className="space-y-4">
              <div className="rounded-md border border-success/30 bg-success/5 p-4">
                <div className="text-sm font-semibold text-success">{t('security.mfaRecoveryTitle')}</div>
                <p className="mt-1 text-xs text-muted-foreground">{t('security.mfaRecoveryDesc')}</p>
                <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-2">
                  {recoveryCodes.map((c) => (
                    <code key={c} className="rounded-md bg-muted px-2 py-1 text-xs font-mono">{c}</code>
                  ))}
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  <Button size="sm" variant="outline" onClick={copyCodes}>
                    {copied ? <Check className="size-4 text-success" /> : <Copy className="size-4" />} {t('security.mfaCopyCodes')}
                  </Button>
                  <Button size="sm" variant="outline" onClick={regenerateCodes}><RefreshCw className="size-4" /> {t('security.mfaRegenerate')}</Button>
                  <Button size="sm" onClick={() => setRecoveryCodes(null)}>{t('common.close')}</Button>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-start gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex min-w-0 items-center gap-3">
                <Smartphone className="size-5 shrink-0 text-muted-foreground" />
                <div className="min-w-0">
                  <div className="text-sm font-medium">{t('security.mfaStatus')}</div>
                  <div className="text-xs text-muted-foreground">
                    {mfaEnabled ? t('security.mfaEnabledStatus') : t('security.noTwoFactor')}
                  </div>
                </div>
              </div>
              {mfaEnabled ? (
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" onClick={regenerateCodes}><RefreshCw className="size-4" /> {t('security.mfaCodes')}</Button>
                  <Button variant="destructive" onClick={disableMfa}>{t('security.mfaDisable')}</Button>
                </div>
              ) : (
                <Button variant="outline" onClick={startEnroll} disabled={enrollBusy}>
                    {enrollBusy ? <Loader2 className="size-4 animate-spin" /> : <ShieldCheck className="size-4" />}
                    {t('security.enableTwoFactor')}
                  </Button>
              )}
            </div>
          )}
        </CardContent>
      </Card>
      </div>

      {/* 添加通行密钥：先命名，避免多个通行密钥同名无法区分 */}
      {nameOpen && (
        <div
          data-slot="alert-dialog-overlay"
          className="fixed inset-0 z-[115] flex items-center justify-center bg-black/50 p-4 animate-[fade-in_0.15s_ease-out]"
          onClick={() => { if (!passkeyBusy) closeNameDialog() }}
        >
          <div
            role="dialog"
            aria-modal="true"
            className="w-full max-w-sm overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-2xl animate-[zoom-in_0.15s_ease-out]"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b px-5 py-4">
              <div>
                <h2 className="font-semibold leading-6">{t('security.passkeyNameTitle')}</h2>
                <p className="mt-1 text-xs text-muted-foreground">{t('security.passkeyNameDesc')}</p>
              </div>
              <button
                onClick={() => { if (!passkeyBusy) closeNameDialog() }}
                aria-label={t('common.close')}
                disabled={passkeyBusy}
                className="flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-50"
              >
                <X className="size-4" />
              </button>
            </div>
            <div className="space-y-3 p-5">
              <div className="grid gap-2">
                <Label htmlFor="passkey-name">{t('security.passkeyName')}</Label>
                <Input
                  id="passkey-name"
                  value={passkeyName}
                  maxLength={64}
                  onChange={(e) => setPasskeyName(e.target.value)}
                  placeholder={t('security.passkeyNamePlaceholder')}
                  autoFocus
                  onKeyDown={(e) => { if (e.key === 'Enter') confirmAddPasskey() }}
                />
              </div>
            </div>
            <div className="flex justify-end gap-2 border-t p-4">
              <Button variant="outline" onClick={() => closeNameDialog()} disabled={passkeyBusy}>
                {t('common.cancel')}
              </Button>
              <Button onClick={confirmAddPasskey} disabled={passkeyBusy}>
                {passkeyBusy && <Loader2 className="size-4 animate-spin" />}
                {t('security.passkeyNameSubmit')}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* MFA 绑定弹窗 */}
      {enrollOpen && enroll && (
        <div data-slot="alert-dialog-overlay" className="fixed inset-0 z-[110] flex items-center justify-center bg-black/50 p-4 animate-[fade-in_0.15s_ease-out]" onClick={closeEnroll}>
          <div
            role="dialog"
            aria-modal="true"
            className="w-full max-w-md overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-2xl animate-[zoom-in_0.15s_ease-out]"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b px-5 py-4">
              <div>
                <h2 className="font-semibold leading-6">{t('security.enableTwoFactor')}</h2>
                <p className="mt-1 text-xs text-muted-foreground">{t('security.mfaEnrollDesc')}</p>
              </div>
              <button onClick={closeEnroll} aria-label={t('common.close')} className="flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground">
                <X className="size-4" />
              </button>
            </div>
            <div className="max-h-[70vh] space-y-4 overflow-y-auto p-5">
              <div className="flex flex-col items-center gap-4 rounded-md border bg-muted/20 p-4">
                {/* 二维码：便于扫码添加（使用 provisioningUri，未提供时用 otpauth URI 兜底） */}
                <MfaQrCode value={enroll.provisioningUri || mfaProvisioningUri(enroll)} />
                <div className="flex w-full items-center justify-between gap-3">
                  <code className="min-w-0 flex-1 break-all text-xs font-mono">{enroll.secret}</code>
                  <Button size="sm" variant="outline" className="shrink-0" onClick={copySecret}>
                    {copied ? <Check className="size-4 text-success" /> : <Copy className="size-4" />}
                  </Button>
                </div>
              </div>
              <div className="grid gap-2">
                <Label>{t('security.mfaCode')}</Label>
                <Input value={totpCode} onChange={(e) => setTotpCode(e.target.value)} placeholder={t('common.codePlaceholder')} inputMode="numeric" maxLength={6} />
              </div>
            </div>
            <div className="flex justify-end gap-2 border-t p-4">
              <Button variant="outline" onClick={closeEnroll}>{t('common.cancel')}</Button>
              <Button onClick={confirmEnroll} disabled={enrollBusy || totpCode.trim().length !== 6}>
                {enrollBusy && <Loader2 className="size-4 animate-spin" />}
                {t('security.mfaConfirm')}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* MFA 验证码输入弹窗（关闭/重新生成恢复码） */}
      {promptOpen && (
        <div data-slot="alert-dialog-overlay" className="fixed inset-0 z-[110] flex items-center justify-center bg-black/50 p-4 animate-[fade-in_0.15s_ease-out]" onClick={() => { if (!promptBusy) setPromptOpen(false) }}>
          <div
            role="dialog"
            aria-modal="true"
            className="w-full max-w-sm overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-2xl animate-[zoom-in_0.15s_ease-out]"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b px-5 py-4">
              <h2 className="font-semibold leading-6">
                {promptAction === 'disable' ? t('security.mfaDisableTitle') : t('security.mfaRegenerate')}
              </h2>
              <button onClick={() => { if (!promptBusy) setPromptOpen(false) }} aria-label={t('common.close')} className="flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground">
                <X className="size-4" />
              </button>
            </div>
            <div className="space-y-3 p-5">
              <p className="text-sm text-muted-foreground">{t('security.mfaEnterCode')}</p>
              <Input
                value={promptCode}
                onChange={(e) => { setPromptCode(e.target.value); if (promptError) setPromptError('') }}
                placeholder={t('common.codePlaceholder')}
                inputMode="numeric"
                maxLength={6}
                autoFocus
              />
              {promptError && <p className="text-sm text-destructive">{promptError}</p>}
            </div>
            <div className="flex justify-end gap-2 border-t p-4">
              <Button variant="outline" onClick={() => { if (!promptBusy) setPromptOpen(false) }} disabled={promptBusy}>{t('common.cancel')}</Button>
              <Button onClick={submitPrompt} disabled={promptBusy || promptCode.trim().length !== 6}>
                {t('common.confirm')}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* 身份重验证弹窗（删除通行密钥的前置） */}
      {reauthDialog}

      {/* 注销账号（管理员不可见） */}
      {!isAdmin && <DeleteAccountCard />}

    </div>
  )
}


/* ------------------------------- 邮箱登录 ------------------------------- */
// 展示当前登录邮箱与验证状态。
// 添加/更换邮箱：先完成二次验证（step-up），随后直接向新邮箱发送验证码，
// 输入验证码校验通过才写入并标记已验证；弹窗内可在「填写邮箱」与「输入验证码」
// 两步间自由切换。验证是强制的：没有「先保存、稍后再验证」的旁路 ——
// 未验证邮箱不带来任何能力，却会让用户以为已经绑定成功。
function EmailLoginCard() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { success: toastSuccess, error: toastError } = useToast()
  const { capabilities } = useSession()
  const { data: profile } = useQuery({ queryKey: ['profile'], queryFn: () => api.profile<ProfileData>() })

  const emailChangeEnabled = capabilities?.personal?.emailChange !== false
  const email = profile?.email ?? ''
  const verified = !!profile?.emailVerified

  // 二次验证方式由后端 /api/v1/capabilities 统一下发：MFA 优先，
  // 两种方式都在时允许切换；都没有则只校验密码。
  const sf = useSecondFactor('stepUp')

  const [open, setOpen] = React.useState(false)
  const [step, setStep] = React.useState<'verify' | 'email' | 'code'>('verify')
  const [password, setPassword] = React.useState('')
  const [code, setCode] = React.useState('')
  const [newEmail, setNewEmail] = React.useState('')
  const [stepUpToken, setStepUpToken] = React.useState('')
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState('')
  // 新邮箱验证码发送状态：冷却倒计时 + 是否已发送
  const [emailCodeSent, setEmailCodeSent] = React.useState(false)
  const [emailCodeCooldown, setEmailCodeCooldown] = React.useState(0)

  const passwordSet = profile?.passwordSet !== false

  // 发送冷却倒计时
  React.useEffect(() => {
    if (emailCodeCooldown <= 0) return
    const timer = setTimeout(() => setEmailCodeCooldown((c) => c - 1), 1000)
    return () => clearTimeout(timer)
  }, [emailCodeCooldown])

  // 重发邮箱验证邮件（未验证邮箱的「验证邮箱」按钮）
  const [verifyBusy, setVerifyBusy] = React.useState(false)
  const resendVerification = async () => {
    setVerifyBusy(true)
    try {
      await api.sendEmailVerify()
      toastSuccess(t('security.emailVerifySent'))
    } catch (e) {
      toastError(t('security.emailVerifyFailed'), e instanceof ApiError ? e.message : '')
    } finally {
      setVerifyBusy(false)
    }
  }

  const openDialog = () => {
    setStep('verify')
    setPassword('')
    setCode('')
    setNewEmail('')
    setStepUpToken('')
    setError('')
    setEmailCodeSent(false)
    setEmailCodeCooldown(0)
    sf.reset()
    setOpen(true)
  }

  const closeDialog = () => {
    if (busy) return
    setOpen(false)
  }

  // 第一步：完成二次验证（密码 + 验证码），换取短效 step-up 令牌
  const verify = async () => {
    setBusy(true)
    setError('')
    try {
      const res: any = await api.stepUp(password, code.trim(), sf.method === 'none' ? undefined : sf.method)
      setStepUpToken(res?.stepUpToken ?? '')
      setStep('email')
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t('security.emailLoginCodeInvalid'))
    } finally {
      setBusy(false)
    }
  }

  // 第二步：向新邮箱发送验证码（需 step-up 令牌）
  const sendNewEmailCode = async () => {
    if (!newEmail.trim() || !stepUpToken || emailCodeCooldown > 0) return
    setBusy(true)
    setError('')
    try {
      await api.sendNewEmailCode({ email: newEmail.trim(), stepUpToken })
      setEmailCodeSent(true)
      setEmailCodeCooldown(60)
      setStep('code')
      setError('')
    } catch (e) {
      if (e instanceof ApiError && (e.status === 401 || e.code === 'stepup.expired' || e.code === 'stepup.invalid')) {
        setStepUpToken('')
        setStep('verify')
        setCode('')
        sf.reset()
        setError(t('security.stepUpExpired'))
      } else {
        setError(e instanceof ApiError ? e.message : t('security.emailLoginCodeFailed'))
      }
    } finally {
      setBusy(false)
    }
  }

  // 第三步：提交新邮箱。必须携带验证码 —— 校验通过才写入并标记已验证。
  const submitEmail = async () => {
    const emailCode = code.trim()
    if (!emailCode) return
    setBusy(true)
    setError('')
    try {
      await api.changeEmail({ email: newEmail.trim(), stepUpToken, emailCode })
      qc.invalidateQueries({ queryKey: ['profile'] })
      qc.invalidateQueries({ queryKey: ['session'] })
      setOpen(false)
      // 提示分场景：对空邮箱说「更换」会让「添加」流程自相矛盾
      toastSuccess(email ? t('security.emailChangeVerified') : t('security.emailAddVerified'))
    } catch (e) {
      // step-up 令牌是短效的：用户停留过久后会过期。此时退回第一步重新验证，
      // 而不是把错误塞在第二步——否则用户既提交不了，也没有回到第一步的入口。
      if (e instanceof ApiError && (e.status === 401 || e.code === 'stepup.expired' || e.code === 'stepup.invalid')) {
        setStepUpToken('')
        setStep('verify')
        setCode('')
        sf.reset()
        setError(t('security.stepUpExpired'))
      } else {
        setError(e instanceof ApiError ? e.message : (email ? t('security.emailChangeFailed') : t('security.emailAddFailed')))
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Mail className="size-4" /> {t('security.emailLogin')}</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <Field label={t('security.emailLoginCurrent')}>
            <div className="flex h-9 w-full items-center rounded-md border bg-muted px-3 text-sm text-muted-foreground">
              {email || '—'}
            </div>
          </Field>
          <Field label={t('security.emailLoginStatus')}>
            <div>
              {verified
                ? <Badge variant="outline" className="text-success"><Check className="size-3" /> {t('security.emailLoginVerified')}</Badge>
                : email
                  ? <Badge variant="outline" className="text-warning"><MailCheck className="size-3" /> {t('security.emailLoginUnverified')}</Badge>
                  : <Badge variant="outline" className="text-muted-foreground"><MailCheck className="size-3" /> {t('security.emailLoginNotSet')}</Badge>}
            </div>
          </Field>
        </CardContent>
        <CardFooter className="justify-end gap-2 border-t bg-muted/20">
          {/* 已绑定但未验证的邮箱：提供「验证邮箱」入口，点击重发验证邮件 */}
          {email && !verified && (
            <Button variant="outline" disabled={verifyBusy} onClick={resendVerification}>
              {verifyBusy ? <Loader2 className="size-4 animate-spin" /> : <MailCheck className="size-4" />}
              {t('security.emailVerify')}
            </Button>
          )}
          {/* 邮件服务未配置时按钮保持可点，点击以右下角弹窗通知不可用原因；
              提示与按钮文案同场景（未绑定邮箱时按钮是「添加邮箱」）。 */}
          <Button
            variant="outline"
            onClick={() => {
              if (!emailChangeEnabled) {
                toastError(email ? t('security.emailChangeUnavailable') : t('security.emailAddUnavailable'))
                return
              }
              openDialog()
            }}
          >
            {email ? t('security.emailChange') : t('security.emailAdd')}
          </Button>
        </CardFooter>
      </Card>

      {open && (
        <div data-slot="alert-dialog-overlay" className="fixed inset-0 z-[110] flex items-center justify-center bg-black/50 p-4 animate-[fade-in_0.15s_ease-out]" onClick={closeDialog}>
          <div
            role="dialog"
            aria-modal="true"
            className="w-full max-w-md overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-2xl animate-[zoom-in_0.15s_ease-out]"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b px-5 py-4">
              <div>
                {/* 未绑定邮箱时是「添加」流程，标题与说明同步换文案 */}
                <h2 className="font-semibold leading-6">{email ? t('security.emailChangeTitle') : t('security.emailAddTitle')}</h2>
                <p className="mt-1 text-xs text-muted-foreground">
                  {step === 'verify'
                    ? (email ? t('security.emailChangeStepCodeDesc') : t('security.emailAddStepCodeDesc'))
                    : step === 'email'
                      ? (email ? t('security.emailChangeStepEmailDesc') : t('security.emailAddStepEmailDesc'))
                      : (email ? t('security.emailChangeStepCodeDesc2') : t('security.emailAddStepCodeDesc2'))}
                </p>
              </div>
              <button onClick={closeDialog} aria-label={t('common.close')} className="flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground">
                <X className="size-4" />
              </button>
            </div>

            <div className="space-y-4 p-5">
              {step === 'verify' ? (
                <>
                  {passwordSet && (
                    <div className="grid gap-2">
                      <Label htmlFor="email-stepup-password">{t('security.currentPassword')}</Label>
                      <Input
                        id="email-stepup-password"
                        type="password"
                        value={password}
                        onChange={(e) => { setPassword(e.target.value); if (error) setError('') }}
                        autoComplete="current-password"
                        placeholder={t('security.emailChangePasswordPlaceholder')}
                        autoFocus
                      />
                    </div>
                  )}
                  {/* 无可用第二因素时组件不渲染：后端此时只校验密码 */}
                  <SecondFactorField
                    id="email-stepup-code"
                    method={sf.method}
                    value={code}
                    onChange={(v) => { setCode(v); if (error) setError('') }}
                    canSwitch={sf.canSwitch}
                    onSwitch={sf.switchMethod}
                    sent={sf.sent}
                    sending={sf.sending}
                    cooldown={sf.cooldown}
                    onSendCode={sf.requestCode}
                    disabled={busy}
                  />
                </>
              ) : step === 'email' ? (
                <>
                  <div className="grid gap-2">
                    <Label htmlFor="security-new-email">{email ? t('security.emailChangeNew') : t('security.emailAddNew')}</Label>
                    {/* type="email" + name + autoComplete 组合让浏览器可以自动填充邮箱 */}
                    <Input
                      id="security-new-email"
                      type="email"
                      name="email"
                      value={newEmail}
                      onChange={(e) => { setNewEmail(e.target.value); if (error) setError('') }}
                      placeholder={email ? t('security.emailChangeNewPlaceholder') : t('security.emailAddNewPlaceholder')}
                      autoComplete="email"
                      autoFocus
                    />
                  </div>
                </>
              ) : (
                <>
                  <div className="grid gap-2">
                    <Label htmlFor="security-new-email-code">{t('security.emailChangeCodeLabel')}</Label>
                    <Input
                      id="security-new-email-code"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      maxLength={6}
                      value={code}
                      onChange={(e) => { setCode(e.target.value); if (error) setError('') }}
                      placeholder={t('security.emailChangeCodePlaceholder')}
                      autoFocus
                    />
                    <Button
                      variant="ghost"
                      size="sm"
                      className="justify-start px-0 text-muted-foreground"
                      disabled={busy || emailCodeCooldown > 0}
                      onClick={sendNewEmailCode}
                    >
                      {emailCodeCooldown > 0
                        ? t('security.emailChangeCodeResendCooldown', { time: emailCodeCooldown })
                        : t('security.emailChangeCodeResend')}
                    </Button>
                  </div>
                </>
              )}
              {/* 弹窗内的字段级错误保留在弹窗内，不放右下角 */}
              {error && <p className="text-sm text-destructive">{error}</p>}
            </div>

            <div className="flex justify-end gap-2 border-t p-4">
              <Button variant="outline" onClick={closeDialog} disabled={busy}>{t('common.cancel')}</Button>
              {step === 'verify' ? (
                <Button
                  disabled={busy || (sf.required && !code.trim()) || (passwordSet && !password)}
                  onClick={verify}
                >
                  {t('common.next')}
                </Button>
              ) : step === 'email' ? (
                <>
                  <Button disabled={busy || !newEmail.trim() || !stepUpToken} onClick={sendNewEmailCode}>
                    {t('security.emailChangeSendCode')}
                  </Button>
                </>
              ) : (
                <>
                  {/* 弹窗内自由切换：回上一步改邮箱 / 重新发送验证码 */}
                  <Button variant="ghost" disabled={busy} onClick={() => { setStep('email'); setCode('') }}>
                    {t('security.emailChangeBackToEmail')}
                  </Button>
                  <Button disabled={busy || !code.trim() || !stepUpToken} onClick={submitEmail}>
                    {email ? t('security.emailChangeVerifySubmit') : t('security.emailAddVerifySubmit')}
                  </Button>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  )
}

/* ------------------------------- 手机号验证 ------------------------------- */
// 展示当前手机号与验证状态，仅提供「更换 / 验证」两项操作（与邮箱卡片保持一致）。
// 手机号由用户自行填写，未验证时第三方应用按 OIDC 标准收到
// phone_number_verified=false，本页面不额外提示「不可信」。
function PhoneVerifyCard() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { success: toastSuccess, error: toastError } = useToast()
  const { capabilities } = useSession()
  const { data: profile } = useQuery({ queryKey: ['profile'], queryFn: () => api.profile<ProfileData>() })

  const phoneVerifyEnabled = capabilities?.personal?.phoneVerify !== false
  // 管理员策略开关：关闭后整个手机号模块（含已保存的号码与验证状态）都不展示，
  // 后端也会拒绝写入（见 requirePhoneAdd）。
  const phoneAddAllowed = capabilities?.personal?.phoneAdd !== false
  const currentPhone = profile?.phone ?? ''
  const verified = !!(profile as any)?.phoneVerified

  const [open, setOpen] = React.useState(false)
  const [step, setStep] = React.useState<'phone' | 'code'>('phone')
  const [newPhone, setNewPhone] = React.useState('')
  const [code, setCode] = React.useState('')
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState('')
  const [codeSent, setCodeSent] = React.useState(false)
  const [cooldown, setCooldown] = React.useState(0)

  React.useEffect(() => {
    if (cooldown <= 0) return
    const timer = setTimeout(() => setCooldown((c) => c - 1), 1000)
    return () => clearTimeout(timer)
  }, [cooldown])

  // 条件渲染放在所有 hook 之后，避免提前 return 打乱 hook 调用顺序。
  if (!phoneAddAllowed) return null

  const openDialog = () => {
    setStep('phone')
    setNewPhone(currentPhone)
    setCode('')
    setError('')
    setCodeSent(false)
    setCooldown(0)
    setOpen(true)
  }

  const closeDialog = () => {
    if (busy) return
    setOpen(false)
  }

  // 发送验证码：先保存手机号（未验证），再请求短信下发。
  const sendCode = async () => {
    const phone = newPhone.trim()
    if (!phone || cooldown > 0) return
    setBusy(true)
    setError('')
    try {
      await api.patchPhone(phone)
      await api.sendPhoneCode(phone)
      qc.invalidateQueries({ queryKey: ['profile'] })
      setCodeSent(true)
      setCooldown(60)
      setStep('code')
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t('security.phoneCodeFailed'))
    } finally {
      setBusy(false)
    }
  }

  // 提交验证码：校验通过后手机号标记为已验证。
  const verify = async () => {
    const phone = newPhone.trim()
    if (!phone || !code.trim()) return
    setBusy(true)
    setError('')
    try {
      await api.verifyPhone(phone, code.trim())
      qc.invalidateQueries({ queryKey: ['profile'] })
      qc.invalidateQueries({ queryKey: ['session'] })
      setOpen(false)
      toastSuccess(t('security.phoneVerified'))
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t('security.phoneCodeInvalid'))
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><Smartphone className="size-4" /> {t('security.phoneLogin')}</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <Field label={t('security.phoneCurrent')}>
            <div className="flex h-9 w-full items-center rounded-md border bg-muted px-3 text-sm text-muted-foreground">
              {currentPhone || '—'}
            </div>
          </Field>
          <Field label={t('security.phoneStatus')}>
            <div>
              {verified
                ? <Badge variant="outline" className="text-success"><Check className="size-3" /> {t('security.phoneVerifiedLabel')}</Badge>
                : currentPhone
                  ? <Badge variant="outline" className="text-warning"><Smartphone className="size-3" /> {t('security.phoneUnverifiedLabel')}</Badge>
                  : <Badge variant="outline" className="text-muted-foreground"><Smartphone className="size-3" /> {t('security.phoneNotSet')}</Badge>}
            </div>
          </Field>
        </CardContent>
        <CardFooter className="justify-end gap-2 border-t bg-muted/20">
          {/* 已填写但未验证：提供「验证手机号」入口。纯验证动作依赖短信服务，
              未配置时直接说明原因，不让用户点进去才发现走不通。 */}
          {currentPhone && !verified && (
            <Button
              variant="outline"
              disabled={busy}
              onClick={() => {
                if (!phoneVerifyEnabled) {
                  toastError(t('security.phoneVerifyUnavailable'))
                  return
                }
                openDialog()
              }}
            >
              <ShieldCheck className="size-4" />
              {t('security.phoneVerify')}
            </Button>
          )}
          {/* 添加 / 更换入口不再因短信未配置而拦截：弹窗内的「暂不验证，直接保存」
              不依赖短信，是这类站点维护手机号的唯一可用路径。 */}
          {currentPhone && !verified ? (
            <Button variant="ghost" onClick={openDialog}>
              {t('security.phoneChange')}
            </Button>
          ) : (
            <Button variant="outline" onClick={openDialog}>
              {currentPhone ? t('security.phoneChange') : t('security.phoneAdd')}
            </Button>
          )}
        </CardFooter>
      </Card>

      {open && (
        <div data-slot="alert-dialog-overlay" className="fixed inset-0 z-[110] flex items-center justify-center bg-black/50 p-4 animate-[fade-in_0.15s_ease-out]" onClick={closeDialog}>
          <div
            role="dialog"
            aria-modal="true"
            className="w-full max-w-md overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-2xl animate-[zoom-in_0.15s_ease-out]"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b px-5 py-4">
              <div>
                <h2 className="font-semibold leading-6">{currentPhone ? t('security.phoneChangeTitle') : t('security.phoneAddTitle')}</h2>
                <p className="mt-1 text-xs text-muted-foreground">
                  {step === 'phone'
                    ? (currentPhone ? t('security.phoneChangeStepPhoneDesc') : t('security.phoneAddStepPhoneDesc'))
                    : t('security.phoneChangeStepCodeDesc')}
                </p>
              </div>
              <button onClick={closeDialog} aria-label={t('common.close')} className="flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground">
                <X className="size-4" />
              </button>
            </div>

            <div className="space-y-4 p-5">
              {step === 'phone' ? (
                <div className="grid gap-2">
                  <Label htmlFor="security-new-phone">{currentPhone ? t('security.phoneChangeNew') : t('security.phoneAddNew')}</Label>
                  <Input
                    id="security-new-phone"
                    type="tel"
                    name="tel"
                    inputMode="tel"
                    value={newPhone}
                    onChange={(e) => { setNewPhone(e.target.value); if (error) setError('') }}
                    placeholder={currentPhone ? t('security.phoneChangeNewPlaceholder') : t('security.phoneAddNewPlaceholder')}
                    autoComplete="tel"
                    autoFocus
                  />
                </div>
              ) : (
                <div className="grid gap-2">
                  <Label htmlFor="security-phone-code">{t('security.phoneChangeCodeLabel')}</Label>
                  <InputOTP
                    id="security-phone-code"
                    value={code}
                    onChange={(v) => { setCode(v); if (error) setError('') }}
                    maxLength={6}
                    autoFocus
                  />
                  <Button
                    variant="ghost"
                    size="sm"
                    className="justify-start px-0 text-muted-foreground"
                    disabled={busy || cooldown > 0 || !phoneVerifyEnabled}
                    onClick={sendCode}
                  >
                    {cooldown > 0
                      ? t('security.phoneChangeCodeResendCooldown', { time: cooldown })
                      : t('security.phoneChangeCodeResend')}
                  </Button>
                </div>
              )}
              {/* 短信未配置：明确告知，但「暂不验证，直接保存」仍可用 */}
              {!phoneVerifyEnabled && (
                <p className="text-xs text-muted-foreground">
                  {currentPhone ? t('security.phoneVerifyUnavailable') : t('security.phoneAddUnavailable')}
                </p>
              )}
              {error && <p className="text-sm text-destructive">{error}</p>}
            </div>

            <div className="flex justify-end gap-2 border-t p-4">
              <Button variant="outline" onClick={closeDialog} disabled={busy}>{t('common.cancel')}</Button>
              {step === 'phone' ? (
                <>
                  {/* 仅保存手机号（未验证），稍后再验证 */}
                  <Button
                    variant="ghost"
                    disabled={busy || !newPhone.trim() || newPhone.trim() === currentPhone}
                    onClick={async () => {
                      setBusy(true)
                      try {
                        await api.patchPhone(newPhone.trim())
                        qc.invalidateQueries({ queryKey: ['profile'] })
                        setOpen(false)
                        toastSuccess(t('security.phoneChangeSubmitted'))
                      } catch (e) {
                        setError(e instanceof ApiError ? e.message : t('security.phoneChangeFailed'))
                      } finally {
                        setBusy(false)
                      }
                    }}
                  >
                    {t('security.phoneChangeSaveOnly')}
                  </Button>
                  {/* 短信服务未配置时只置灰「发验证码」，「暂不验证，直接保存」仍可用 */}
                  <Button disabled={busy || !newPhone.trim() || !phoneVerifyEnabled} onClick={sendCode}>
                    {t('security.phoneChangeSendCode')}
                  </Button>
                </>
              ) : (
                <>
                  <Button variant="ghost" disabled={busy} onClick={() => { setStep('phone'); setCode('') }}>
                    {t('security.phoneChangeBackToPhone')}
                  </Button>
                  <Button disabled={busy || !codeSent || !code.trim() || !phoneVerifyEnabled} onClick={verify}>
                    {currentPhone ? t('security.phoneChangeVerifySubmit') : t('security.phoneAddVerifySubmit')}
                  </Button>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  )
}

/* --------------------------- 导出个人数据 --------------------------- */
function ExportCard() {
  const { t } = useI18n()
  const { success: toastSuccess, error: toastError } = useToast()
  const [busy, setBusy] = React.useState(false)

  const download = async () => {
    setBusy(true)
    try {
      const data = await api.export()
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      // 文件名带日期，便于用户区分多次导出
      const day = formatDayKey(Date.now())
      a.href = url
      a.download = `openidp-account-export-${day}.json`
      document.body.appendChild(a)
      a.click()
      a.remove()
      // 数据量大时下载可能尚未真正开始，同步 revoke 会把它掐断。
      window.setTimeout(() => URL.revokeObjectURL(url), 10_000)
      toastSuccess(t('security.exportDone'))
    } catch (e) {
      toastError(t('security.exportFailed'), e instanceof ApiError ? e.message : '')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t('security.exportData')}</CardTitle>
        <CardDescription>{t('security.exportDataDesc')}</CardDescription>
      </CardHeader>
      <CardContent>
      </CardContent>
      <CardFooter className="justify-end border-t bg-muted/20">
        <Button variant="outline" onClick={download} disabled={busy}>
          {busy ? <Loader2 className="size-4 animate-spin" /> : <Download className="size-4" />}
          {t('security.exportData')}
        </Button>
      </CardFooter>
    </Card>
  )
}

/* ----------------------------- 注销账号 ----------------------------- */
// 注销走「申请 → 冷静期 → 管理员审核」：提交需当前密码 + 二次验证，
// 冷静期内可撤回；通过后账号才会被真正删除。
function DeleteAccountCard() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { success: toastSuccess, error: toastError } = useToast()
  const { confirm } = useConfirm()
  const { capabilities, session } = useSession()
  const passwordSet = session?.user?.passwordSet !== false
  const accountDeletionEnabled = capabilities?.personal?.accountDeletion !== false

  const { data: status, refetch } = useQuery({
    queryKey: ['account-deletion'],
    queryFn: () => api.accountDeletion<DeletionData>(),
    enabled: !!session,
  })
  const pending = status && status.status !== 'none' && status.status !== 'rejected'

  const [open, setOpen] = React.useState(false)
  const [password, setPassword] = React.useState('')
  const [code, setCode] = React.useState('')
  const [reason, setReason] = React.useState('')
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState('')

  // 二次验证方式由后端统一下发：MFA 优先、可切换；都没有则只校验密码。
  // 发送验证码走注销专用端点（后端按用途分别限流与记审计）。
  const sf = useSecondFactor('deletion')

  const openDialog = () => {
    setPassword('')
    setCode('')
    setReason('')
    setError('')
    sf.reset()
    setOpen(true)
  }

  const closeDialog = () => {
    if (busy) return
    setOpen(false)
  }

  const submit = async () => {
    setBusy(true)
    setError('')
    try {
      await api.requestAccountDeletion({
        ...(passwordSet ? { password } : {}),
        code: code.trim(),
        reason: reason.trim() || undefined,
        ...(sf.method === 'none' ? {} : { method: sf.method }),
      })
      qc.invalidateQueries({ queryKey: ['account-deletion'] })
      setOpen(false)
      toastSuccess(t('security.deleteAccountRequested'))
    } catch (e) {
      setError(e instanceof ApiError ? e.message : t('security.deleteAccountFailed'))
    } finally {
      setBusy(false)
    }
  }

  const cancel = async () => {
    const ok = await confirm({
      title: t('security.deleteAccountCancelTitle'),
      description: t('security.deleteAccountCancelDesc'),
      confirmText: t('security.deleteAccountCancel'),
    })
    if (!ok) return
    try {
      await api.cancelAccountDeletion()
      qc.invalidateQueries({ queryKey: ['account-deletion'] })
      toastSuccess(t('security.deleteAccountCancelled'))
    } catch (e) {
      toastError(t('security.deleteAccountCancelFailed'), e instanceof ApiError ? e.message : '')
    }
  }

  return (
    <>
      <Card className="border-destructive/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive">
            <ShieldAlert className="size-4" /> {t('security.deleteAccount')}
          </CardTitle>
          <CardDescription>{t('security.deleteAccountDesc')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {pending ? (
            <div className="space-y-2 rounded-lg border border-destructive/30 bg-destructive/5 p-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="secondary">
                  <Clock className="size-3" /> {t(`security.deleteAccountStatus.${status?.status ?? 'pending'}`)}
                </Badge>
                {!!status?.cooldownRemaining && (
                  <span className="text-xs text-muted-foreground">
                    {t('security.deleteAccountCooldown', { time: formatDateTimeI18n(status?.scheduledAt ?? '', 'zh-CN') })}
                  </span>
                )}
              </div>
              <p className="text-sm text-muted-foreground">{t('security.deleteAccountPendingDesc')}</p>
            </div>
          ) : (
            // 未提交状态不再重复 CardDescription 已给出的说明（两处文案此前完全一致），
            // 改为提示后续流程，避免同一句话在同一张卡里出现两次。
            <p className="text-sm text-muted-foreground">{t('security.deleteAccountProcess')}</p>
          )}
        </CardContent>
        <CardFooter className="justify-end gap-2 border-t bg-destructive/5">
          {pending && (
            <Button variant="outline" onClick={cancel}>
              {t('security.deleteAccountCancel')}
            </Button>
          )}
          <Button
            variant="destructive"
            disabled={pending || !accountDeletionEnabled}
            title={accountDeletionEnabled ? undefined : t('security.deleteAccountUnavailable')}
            onClick={openDialog}
          >
            {t('security.requestDelete')}
          </Button>
        </CardFooter>
      </Card>

      {open && (
        <div data-slot="alert-dialog-overlay" className="fixed inset-0 z-[110] flex items-center justify-center bg-black/50 p-4 animate-[fade-in_0.15s_ease-out]" onClick={closeDialog}>
          <div
            role="dialog"
            aria-modal="true"
            className="w-full max-w-md overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-2xl animate-[zoom-in_0.15s_ease-out]"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b px-5 py-4">
              <div>
                <h2 className="font-semibold leading-6">{t('security.deleteAccountConfirmTitle')}</h2>
                <p className="mt-1 text-xs text-muted-foreground">{t('security.deleteAccountConfirmDesc')}</p>
              </div>
              <button onClick={closeDialog} aria-label={t('common.close')} className="flex size-7 shrink-0 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground">
                <X className="size-4" />
              </button>
            </div>

            <div className="space-y-4 p-5">
              {passwordSet && (
                <div className="grid gap-2">
                  <Label htmlFor="delete-account-password">{t('security.deleteAccountPassword')}</Label>
                  <Input
                    id="delete-account-password"
                    type="password"
                    value={password}
                    onChange={(e) => { setPassword(e.target.value); if (error) setError('') }}
                    autoComplete="current-password"
                    placeholder={t('security.deleteAccountPasswordPlaceholder')}
                    autoFocus
                  />
                </div>
              )}

              {/* 无可用第二因素时组件不渲染：后端此时只校验密码 */}
              <SecondFactorField
                id="delete-account-code"
                method={sf.method}
                value={code}
                onChange={(v) => { setCode(v); if (error) setError('') }}
                canSwitch={sf.canSwitch}
                onSwitch={sf.switchMethod}
                sent={sf.sent}
                sending={sf.sending}
                cooldown={sf.cooldown}
                onSendCode={sf.requestCode}
                disabled={busy}
              />

              <div className="grid gap-2">
                <Label htmlFor="delete-account-reason">{t('security.deleteAccountReason')}</Label>
                <Input
                  id="delete-account-reason"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder={t('security.deleteAccountReasonPlaceholder')}
                />
              </div>

              {/* 弹窗内字段级错误保留在弹窗内 */}
              {error && <p className="text-sm text-destructive">{error}</p>}
            </div>

            <div className="flex justify-end gap-2 border-t p-4">
              <Button variant="outline" onClick={closeDialog} disabled={busy}>{t('common.cancel')}</Button>
              <Button
                variant="destructive"
                disabled={busy || (sf.required && !code.trim()) || (passwordSet && !password)}
                onClick={submit}
              >
                {t('security.deleteAccountSubmit')}
              </Button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}

function ThirdPartyCard() {
  const { t } = useI18n()
  const qc = useQueryClient()
  const { success: toastSuccess, error: toastError } = useToast()
  const { confirm } = useConfirm()
  // 解绑第三方登录属敏感操作，服务端要求携带 reauthToken
  const { requestReauth, dialog: reauthDialog } = useReauth()
  const { data: identities } = useQuery({ queryKey: ['identities'], queryFn: () => api.identities<IdentityItem[]>() })
  const { data: providers } = useQuery({ queryKey: ['providers'], queryFn: () => api.loginProviders<ProviderItem[]>() })
  const bound: any[] = identities ?? []

  // 后端只下发「已开启且凭据齐备」的提供商（未配置完整的提供商不允许被开启），
  // 因此这里不再需要 ready 之分：出现在列表里的每一项都能直接发起绑定。
  const providersList: any[] = (providers ?? []).map((p: any) => ({
    providerType: p.providerType,
    displayName: p.displayName,
    logoUrl: p.logoUrl,
  }))

  const [pendingIdentity, setPendingIdentity] = React.useState<string | null>(null)

  const unbind = async (id: string, name: string) => {
    await confirm({
      title: t('security.unbindTitle'),
      description: `${t('security.unbindDesc')}（${name}）`,
      confirmText: t('common.confirm'),
      onConfirm: async () => {
        // 解绑属敏感操作：先完成身份重验证，用换取的令牌发起删除
        requestReauth(async (token) => {
          setPendingIdentity(id)
          try {
            await api.deleteIdentity(id, token)
            await qc.invalidateQueries({ queryKey: ['identities'] })
            toastSuccess(t('security.unboundOk'))
          } catch (err) {
            toastError(t('security.unbindFailed'), err instanceof ApiError ? err.message : '')
            throw err
          } finally {
            setPendingIdentity(null)
          }
        })
      },
    })
  }

  return (
    <>
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><Link2 className="size-4" /> {t('security.thirdParty')}</CardTitle>
      </CardHeader>
      <CardContent className="divide-y">
        {providersList.length === 0 && (
          <div className="py-4 text-sm text-muted-foreground">{t('security.noProviders')}</div>
        )}
        {providersList.map((p) => {
          const idn = bound.find((i) => i.provider === p.providerType)
          // 行式列表 + 状态 chip：名称旁直接标注绑定状态，用户扫一眼就知道
          // 哪些平台还没绑定，不必逐行读小字。
          return (
            <div key={p.providerType} className="flex flex-wrap items-center justify-between gap-3 py-3.5">
              <div className="flex min-w-0 items-center gap-3">
                <span className="grid size-10 shrink-0 place-items-center overflow-hidden rounded-xl border bg-background">
                  {p.logoUrl ? <img src={p.logoUrl} alt="" className="size-full object-contain" /> : <Link2 className="size-4 text-muted-foreground" />}
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="truncate text-sm font-medium">{p.displayName}</span>
                    <span
                      className={cn(
                        // max-w-full + 允许换行：窄屏下 chip 自身宽度收敛到行宽内，
                        // 不再顶破卡片（此前 360px 下溢出 5px）。
                        'max-w-full shrink-0 rounded-full border px-2 py-0.5 text-[11px]',
                        idn ? 'border-success/30 bg-success/10 text-success' : 'text-muted-foreground',
                      )}
                    >
                      {idn ? t('security.bound') : t('security.unbound')}
                    </span>
                  </div>
                </div>
              </div>
              {idn ? (
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-destructive hover:text-destructive"
                  disabled={pendingIdentity === idn.id}
                  onClick={() => unbind(idn.id, p.displayName)}
                >
                  <Unlink className="size-4" /> {t('security.unbind')}
                </Button>
              ) : (
                <Button variant="outline" size="sm" onClick={() => api.providerBind(p.providerType)}><Link2 className="size-4" /> {t('common.binding')}</Button>
              )}
            </div>
          )
        })}
      </CardContent>
    </Card>
      {reauthDialog}
    </>
  )
}

// ---- MFA 二维码（扫码添加） ----
// 使用 qrcode 库把 otpauth:// provisioning URI 渲染为 dataURL 图片。
import * as QRCode from 'qrcode'

interface PasskeyBegin { ceremonyId: string; options: unknown }
interface ProfileData { email?: string; emailVerified?: boolean; phone?: string; phoneVerified?: boolean; passwordSet?: boolean; [k: string]: unknown }
interface PasskeysData { enabled?: boolean; passkeys?: { id: string; name?: string; createdAt?: string; [k: string]: unknown }[] }
interface MfaData { enabled?: boolean; [k: string]: unknown }
interface DeletionData { status?: string; cooldownRemaining?: number; scheduledAt?: string; [k: string]: unknown }
interface IdentityItem { id?: string; provider?: string; email?: string; [k: string]: unknown }
interface ProviderItem { type?: string; displayName?: string; [k: string]: unknown }


function MfaQrCode({ value, size = 168 }: { value: string; size?: number }) {
  const [dataUrl, setDataUrl] = React.useState('')
  React.useEffect(() => {
    let cancelled = false
    QRCode.toDataURL(value, { width: size, margin: 1, errorCorrectionLevel: 'M', color: { dark: '#111111', light: '#ffffff' } })
      .then((url: string) => { if (!cancelled) setDataUrl(url) })
      .catch(() => {})
    return () => { cancelled = true }
  }, [value, size])

  if (!dataUrl) {
    return <div style={{ width: size, height: size }} className="grid place-items-center rounded-md bg-white text-xs text-muted-foreground">…</div>
  }
  return <img src={dataUrl} alt="TOTP 二维码" width={size} height={size} className="rounded-md border bg-white p-1" />
}

// defaultPasskeyName 生成默认名称（如「通行密钥 2」）。
// 已有的第 n 个通行密钥对应序号 n+1，避免与既有条目重名。
function defaultPasskeyName(existingCount: number): string {
  return `通行密钥 ${existingCount + 1}`
}

// 兜底：后端 begin 仅返回 secret 时，前端构造 otpauth:// URI
function mfaProvisioningUri(enroll: any): string {
  const issuer = enroll.issuer || 'OpenIdP'
  const account = enroll.account || ''
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${enroll.secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`
}
