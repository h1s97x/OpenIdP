import * as React from 'react'
import { useNavigate } from 'react-router-dom'
import { LogOut, User, Shield, Settings } from 'lucide-react'
import { useSession } from '../../hooks/useSession'
import { useI18n } from '../../i18n'
import { useConfirm } from '../ui/confirm'

export function UserMenu() {
  const { session, logout } = useSession()
  const { t } = useI18n()
  const navigate = useNavigate()
  const { confirm } = useConfirm()
  const [open, setOpen] = React.useState(false)
  const ref = React.useRef<HTMLDivElement>(null)
  const [loggingOut, setLoggingOut] = React.useState(false)

  React.useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDoc)
    return () => document.removeEventListener('mousedown', onDoc)
  }, [open])

  if (!session) return null

  const initial = (session.user.displayName || session.user.username || 'Y')[0]
  const avatarSrc = session.user.avatarUrl || '/images/avatar.svg'
  const isAdmin = session.user.isAdmin

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 rounded-full p-0.5 transition-colors hover:bg-accent"
        aria-label={t('menu.profile')}
      >
        <span className="flex h-8 w-8 items-center justify-center overflow-hidden rounded-full bg-primary text-sm font-semibold text-primary-foreground">
          {avatarSrc ? (
            <img src={avatarSrc} alt="" className="h-full w-full object-cover" />
          ) : (
            initial
          )}
        </span>
      </button>

      {open && (
        <div className="absolute right-0 top-11 z-50 w-60 overflow-hidden rounded-xl border bg-popover text-popover-foreground shadow-xl">
          <div className="border-b px-4 py-3">
            <div className="flex items-center gap-3">
              <span className="flex h-9 w-9 items-center justify-center overflow-hidden rounded-full bg-primary text-sm font-semibold text-primary-foreground">
                {avatarSrc ? (
                  <img src={avatarSrc} alt="" className="h-full w-full object-cover" />
                ) : (
                  initial
                )}
              </span>
              <div className="min-w-0">
                <div className="truncate text-sm font-semibold">{session.user.displayName}</div>
                <div className="truncate text-xs text-muted-foreground">{session.user.email}</div>
              </div>
            </div>
            {isAdmin && (
              <div className="mt-2 flex items-center gap-1 text-xs font-medium text-primary">
                <Shield className="size-3.5" /> {t('common.admin')}
              </div>
            )}
          </div>
          <div className="p-1.5">
            <button
              onClick={() => { setOpen(false); navigate('/settings') }}
              className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-accent"
            >
              <User className="size-4 text-muted-foreground" /> {t('menu.profile')}
            </button>
            <button
              onClick={() => { setOpen(false); navigate('/settings/account') }}
              className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-accent"
            >
              <Settings className="size-4 text-muted-foreground" /> {t('menu.security')}
            </button>
            {isAdmin && (
              <button
                onClick={() => { setOpen(false); navigate('/admin') }}
                className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-accent"
              >
                <Shield className="size-4 text-muted-foreground" /> {t('menu.admin')}
              </button>
            )}
            <div className="my-1 h-px bg-border" />
            <button
              // 登出期间禁用：避免连点触发多次 logout
              disabled={loggingOut}
              onClick={async () => {
                if (loggingOut) return
                setOpen(false)
                const ok = await confirm({
                  title: t('menu.logoutConfirmTitle'),
                  description: t('menu.logoutConfirmDesc'),
                  confirmText: t('menu.logoutConfirmAction'),
                })
                if (!ok) return
                setLoggingOut(true)
                await logout()
              }}
              className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-sm text-destructive hover:bg-destructive/10 disabled:pointer-events-none disabled:opacity-50"
            >
              <LogOut className="size-4" /> {t('menu.logout')}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
