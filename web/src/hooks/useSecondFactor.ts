// 二次验证（step-up / reauthenticate）的可用方式与交互状态。
//
// 背景：更换邮箱、注销账号、删除通行密钥、解绑第三方都要先过一次二次验证，
// 原先这几处各自判断「有没有开 MFA」决定展示验证器还是邮箱验证码，规则分散且
// 不一致；更关键的是，账号既没开 MFA 又没绑邮箱时（纯三方登录且未绑邮箱），
// 后端会直接返回「请先启用双因素认证或绑定邮箱」，这些操作就永远做不了。
//
// 现由后端 /api/v1/capabilities 统一下发可用方式，这里负责：
//   - 按优先级选中默认方式（MFA 优先）；
//   - 两种方式都可用时提供切换（认证器丢失/换手机时的兜底）；
//   - 托管邮箱验证码的发送与冷却倒计时。
import * as React from 'react'
import { useSession } from './useSession'
import { api } from '../lib/api'

export type SecondFactorMethod = 'mfa' | 'email'

const CODE_COOLDOWN_SECONDS = 60

/**
 * 请求邮箱验证码的目标端点。
 *
 * 更换邮箱与注销账号各有一个发送端点（后端按用途分别限流与记审计），
 * 删除通行密钥/解绑第三方走的重验证本身没有独立发码端点，复用 step-up 的。
 */
export type EmailCodeSender = 'stepUp' | 'deletion'

function sendCode(kind: EmailCodeSender): Promise<unknown> {
  return kind === 'deletion' ? api.sendDeletionEmailCode() : api.sendStepUpEmailCode()
}

export function useSecondFactor(sender: EmailCodeSender = 'stepUp') {
  const { capabilities } = useSession()
  const sf = capabilities?.secondFactor

  const mfaAvailable = !!sf?.mfaEnabled
  const emailAvailable = !!sf?.emailAvailable
  // required=false：账号没有任何第二因素，后端只校验密码，这里也不产出任何方式。
  const required = !!sf?.required

  // 默认按优先级选：MFA 优先，其次邮箱。
  const [method, setMethodState] = React.useState<SecondFactorMethod | 'none'>('none')
  const [cooldown, setCooldown] = React.useState(0)
  const [sent, setSent] = React.useState(false)
  const [sending, setSending] = React.useState(false)

  // 能力到位后再定默认方式，并跟随能力变化修正
  // （例如用户在别的标签页关闭了 MFA，当前选择就应失效）。
  React.useEffect(() => {
    if (!required) {
      setMethodState('none')
      return
    }
    setMethodState((cur) => {
      const curValid =
        (cur === 'mfa' && mfaAvailable) || (cur === 'email' && emailAvailable)
      if (curValid) return cur
      if (mfaAvailable) return 'mfa'
      if (emailAvailable) return 'email'
      return 'none'
    })
  }, [required, mfaAvailable, emailAvailable])

  React.useEffect(() => {
    if (cooldown <= 0) return
    const timer = window.setTimeout(() => setCooldown((c) => Math.max(0, c - 1)), 1000)
    return () => window.clearTimeout(timer)
  }, [cooldown])

  // switchMethod 在可用方式间切换。切换即清空发送状态：
  // 旧方式下已发出的验证码对新的校验方式无意义，保留会让用户误以为还能用。
  const switchMethod = React.useCallback(() => {
    setMethodState((cur) => (cur === 'mfa' ? 'email' : 'mfa'))
    setSent(false)
  }, [])

  const requestCode = React.useCallback(async () => {
    if (sending || cooldown > 0) return
    setSending(true)
    try {
      await sendCode(sender)
      setSent(true)
      setCooldown(CODE_COOLDOWN_SECONDS)
    } finally {
      setSending(false)
    }
  }, [sending, cooldown, sender])

  // reset 在每次打开弹窗时调用，清掉上一轮残留。
  const reset = React.useCallback(() => {
    setSent(false)
    setCooldown(0)
  }, [])

  return {
    /** 能力是否已加载；未加载前不应渲染验证区，避免闪一下又消失。 */
    loaded: !!sf,
    /** 是否真的需要第二因素。false 时调用方只应索要密码。 */
    required,
    /** 当前选中的方式；'none' 表示无需或尚不可用。 */
    method,
    /** 两种方式都可用时为 true，此时应展示切换入口。 */
    canSwitch: mfaAvailable && emailAvailable,
    mfaAvailable,
    emailAvailable,
    switchMethod,
    requestCode,
    sending,
    sent,
    cooldown,
    reset,
  }
}
