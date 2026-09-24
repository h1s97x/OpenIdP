// 统一人机验证前端接入：
// - 优先 Cloudflare Turnstile（login-policy 返回 provider=turnstile 时）
// - 回退 GeeTest v4（provider=geetest 时）
// - 未配置时 runCaptcha() 返回 null，后端跳过验证（开发模式友好）
import * as React from 'react'

export interface GeeTestProof {
  lot_number: string
  captcha_output: string
  pass_token: string
  gen_time: string
}

// 统一提交负载：后端 unifiedCaptcha 结构
export interface CaptchaPayload {
  captcha?: GeeTestProof
  turnstile?: string
}

// ---- Cloudflare Turnstile ----
declare global {
  interface Window {
    turnstile?: {
      render: (el: HTMLElement | string, opts: Record<string, unknown>) => string
      remove: (id: string) => void
      reset: (id?: string) => void
    }
  }
}

const TURNSTILE_SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
let turnstilePromise: Promise<void> | null = null

function loadTurnstile(): Promise<void> {
  if (window.turnstile) return Promise.resolve()
  if (turnstilePromise) return turnstilePromise
  turnstilePromise = new Promise((resolve, reject) => {
    const existing = document.querySelector(`script[src*="challenges.cloudflare.com/turnstile"]`)
    if (existing) {
      existing.addEventListener('load', () => resolve())
      existing.addEventListener('error', () => reject(new Error('Turnstile unavailable')))
      return
    }
    const s = document.createElement('script')
    s.src = TURNSTILE_SRC
    s.async = true
    s.defer = true
    s.onload = () => resolve()
    s.onerror = () => reject(new Error('Turnstile unavailable'))
    document.head.appendChild(s)
  })
  return turnstilePromise
}

// ---- GeeTest v4 ----
const GT4_SRC = 'https://static.geetest.com/v4/gt4.js'
let gt4Promise: Promise<void> | null = null

function loadGt4(): Promise<void> {
  if ((window as any).initGeetest4) return Promise.resolve()
  if (gt4Promise) return gt4Promise
  gt4Promise = new Promise((resolve, reject) => {
    const existing = document.querySelector(`script[src="${GT4_SRC}"]`)
    if (existing) {
      existing.addEventListener('load', () => resolve())
      existing.addEventListener('error', () => reject(new Error('GeeTest unavailable')))
      return
    }
    const s = document.createElement('script')
    s.src = GT4_SRC
    s.async = true
    s.onload = () => resolve()
    s.onerror = () => reject(new Error('GeeTest unavailable'))
    document.head.appendChild(s)
  })
  return gt4Promise
}

export interface CaptchaPolicy {
  enabled: boolean
  provider: 'turnstile' | 'geetest' | string
  siteKey?: string
  /** 极验 v4 product：bind（滑动验证·绑定模式）/ popup / float */
  product?: string
  requiredForLogin?: boolean
  requiredForSignup?: boolean
  requiredForPasswordReset?: boolean
}

/**
 * useCaptcha 根据 login-policy 返回的 captcha 配置选择验证方式。
 * runCaptcha() 未配置时返回 null；配置时返回 { turnstile } 或 { captcha } 负载。
 */
export function useCaptcha(policy?: CaptchaPolicy) {
  const enabled = !!policy?.enabled
  const provider = policy?.provider
  const siteKey = policy?.siteKey

  const instanceRef = React.useRef<any>(null)
  const widgetRef = React.useRef<string | null>(null)
  const containerRef = React.useRef<HTMLDivElement>(null)

  // 极验 bind 内嵌模式：在页面渲染滑块容器并自动展示（由页面通过 GeeTestWidget 挂载）
  const bindContainerRef = React.useRef<HTMLDivElement>(null)

  const renderTurnstile = React.useCallback(
    (onToken: (token: string) => void, onError: () => void) => {
      loadTurnstile()
        .then(() => {
          if (!containerRef.current || !window.turnstile) {
            onError()
            return
          }
          if (widgetRef.current) {
            try { window.turnstile.remove(widgetRef.current) } catch { /* noop */ }
            widgetRef.current = null
          }
          widgetRef.current = window.turnstile.render(containerRef.current, {
            sitekey: siteKey,
            theme: 'auto',
            callback: onToken,
            'error-callback': onError,
            'expired-callback': () => onError(),
          })
        })
        .catch(onError)
    },
    [siteKey]
  )

  React.useEffect(() => () => {
    if (widgetRef.current && window.turnstile) {
      try { window.turnstile.remove(widgetRef.current) } catch { /* noop */ }
    }
    instanceRef.current?.destroy?.()
  }, [])

  const runCaptcha = React.useCallback(async (): Promise<CaptchaPayload | null> => {
    if (!enabled || !siteKey) return null
    if (provider === 'turnstile') {
      // 显式渲染模式：等待用户完成，最多等 2 分钟
      await loadTurnstile()
      return new Promise<CaptchaPayload>((resolve, reject) => {
        const fail = () => reject(new Error('Turnstile verification failed'))
        // 超时保护：用户长时间未完成验证时拒绝，避免 loading 卡死
        const timer = setTimeout(() => reject(new Error('Turnstile verification timeout')), 2 * 60 * 1000)
        const done = (token: string) => { clearTimeout(timer); resolve({ turnstile: token }) }
        const wrappedFail = () => { clearTimeout(timer); fail() }
        renderTurnstile(done, wrappedFail)
      })
    }
    await loadGt4()
    // 极验 v4 bind 模式：初始化时不带 el，验证时机调用 showCaptcha() 弹出验证窗口。
    // 之前把滑块以 el 内嵌渲染，bind 模式下不会触发用户交互，表现为「弹不出来」。
    const initOptions: any = { captchaId: siteKey, product: 'bind' }
    return new Promise<CaptchaPayload>((resolve, reject) => {
      let settled = false
      const done = (captcha: any) => {
        instanceRef.current = captcha
        captcha.onReady(() => {
          if (settled) return
          // 验证时机到达：弹出 bind 模式的验证窗口
          captcha.showCaptcha()
        })
        captcha.onSuccess(() => {
          const v = captcha.getValidate()
          if (!v?.lot_number || !v.captcha_output || !v.pass_token || !v.gen_time) {
            settled = true
            reject(new Error('GeeTest result is incomplete'))
            return
          }
          settled = true
          resolve({
            captcha: {
              lot_number: v.lot_number,
              captcha_output: v.captcha_output,
              pass_token: v.pass_token,
              gen_time: v.gen_time,
            },
          })
        })
        captcha.onError(() => {
          if (settled) return
          settled = true
          reject(new Error('GeeTest verification failed'))
        })
        captcha.onClose(() => {
          // 用户关闭验证窗口：等待下一次 onReady 重新弹出，不打断流程
        })
        // 极验在部分场景不触发 onReady（实例已就绪），兜底直接弹出
        setTimeout(() => {
          if (!settled) {
            try { captcha.showCaptcha() } catch { /* noop */ }
          }
        }, 300)
      }
      const fail = () => {
        if (!settled) {
          settled = true
          reject(new Error('GeeTest init failed'))
        }
      }
      try {
        ;(window as any).initGeetest4?.(initOptions, done)
        if (!(window as any).initGeetest4) fail()
      } catch {
        fail()
      }
    })
  }, [enabled, provider, siteKey, policy?.product, renderTurnstile, bindContainerRef])

  return { runCaptcha, containerRef, bindContainerRef, widgetRef }
}

/**
 * TurnstileWidget：内联渲染的 Cloudflare Turnstile 组件（登录/注册页可见）。
 * 仅在 provider=turnstile 且启用时渲染。
 */
export function TurnstileWidget({ policy, onToken, onError }: {
  policy?: CaptchaPolicy
  onToken: (token: string) => void
  onError: () => void
}) {
  const { containerRef, widgetRef } = useCaptcha(policy)
  const mounted = React.useRef(false)
  // 用 ref 保存最新回调，避免 effect 依赖缺失导致使用过期闭包
  const onTokenRef = React.useRef(onToken)
  const onErrorRef = React.useRef(onError)
  onTokenRef.current = onToken
  onErrorRef.current = onError

  React.useEffect(() => {
    if (!policy?.enabled || policy.provider !== 'turnstile' || !policy.siteKey) return
    if (mounted.current) return
    mounted.current = true
    loadTurnstile()
      .then(() => {
        if (!containerRef.current || !window.turnstile) {
          onErrorRef.current()
          return
        }
        widgetRef.current = window.turnstile.render(containerRef.current, {
          sitekey: policy.siteKey!,
          theme: 'auto',
          callback: (token: string) => onTokenRef.current(token),
          'error-callback': () => onErrorRef.current(),
          'expired-callback': () => onErrorRef.current(),
        })
      })
      .catch(() => onErrorRef.current())
    return () => {
      if (widgetRef.current && window.turnstile) {
        try { window.turnstile.remove(widgetRef.current) } catch { /* noop */ }
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [policy?.enabled, policy?.provider, policy?.siteKey])

  if (!policy?.enabled || policy.provider !== 'turnstile') return null
  return <div ref={containerRef} className="mt-3 flex justify-center" />
}

/**
 * GeeTestWidget：极验 v4 人机验证组件。
 * bind 模式下渲染一个占位容器，实例初始化后立即在提交时机由页面调用
 * runCaptcha() 弹出验证窗口（showCaptcha），完成后通过 onSuccess 通知调用方。
 */
export function GeeTestWidget({ policy, onSuccess, onError, containerRef }: {
  policy?: CaptchaPolicy
  onSuccess: (proof: GeeTestProof) => void
  onError: () => void
  /** 复用页面 useCaptcha 的 bindContainerRef，使 runCaptcha() 能拿到同一个容器 */
  containerRef?: React.RefObject<HTMLDivElement>
}) {
  const local = useCaptcha(policy)
  const bindContainerRef = containerRef ?? local.bindContainerRef
  const mounted = React.useRef(false)
  const onSuccessRef = React.useRef(onSuccess)
  const onErrorRef = React.useRef(onError)
  onSuccessRef.current = onSuccess
  onErrorRef.current = onError

  React.useEffect(() => {
    if (!policy?.enabled || policy.provider !== 'geetest' || !policy.siteKey) return
    if (mounted.current) return
    mounted.current = true
    // 预加载 gt4.js：bind 模式的实例在 runCaptcha() 调用 showCaptcha() 时创建，
    // 这里只保证脚本就绪，缩短提交时的首次弹出等待。
    loadGt4().catch(() => onErrorRef.current())
    return () => {
      try {
        // gt4 无统一的 destroy 接口，容器清空即可
        if (bindContainerRef.current) bindContainerRef.current.innerHTML = ''
      } catch { /* noop */ }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [policy?.enabled, policy?.provider, policy?.siteKey])

  if (!policy?.enabled || policy.provider !== 'geetest') return null
  return <div ref={bindContainerRef} className="mt-3 flex justify-center" />
}
