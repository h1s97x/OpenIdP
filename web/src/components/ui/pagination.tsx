// 分页控件：页码 + 上一页/下一页，条目较多时展示省略号。
import * as React from 'react'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { cn } from '../../lib/utils'
import { Button } from './button'
import { useI18n } from '../../i18n'

// pageNumbers 生成带省略号的页码序列（如 1 … 4 5 6 … 12）
function pageNumbers(current: number, total: number): (number | 'gap')[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1)
  const out: (number | 'gap')[] = [1]
  const start = Math.max(2, current - 1)
  const end = Math.min(total - 1, current + 1)
  if (start > 2) out.push('gap')
  for (let i = start; i <= end; i++) out.push(i)
  if (end < total - 1) out.push('gap')
  out.push(total)
  return out
}

export function Pagination({
  page,
  totalPages,
  onPageChange,
  className,
}: {
  page: number
  totalPages: number
  onPageChange: (p: number) => void
  className?: string
}) {
  const { t } = useI18n()
  if (totalPages <= 1) return null
  const items = pageNumbers(page, totalPages)

  return (
    <div data-slot="pagination" className={cn('flex items-center justify-end gap-1', className)}>
      <Button
        variant="outline"
        size="sm"
        disabled={page <= 1}
        aria-label={t('common.prev')}
        onClick={() => onPageChange(page - 1)}
      >
        <ChevronLeft className="size-4" />
        <span className="hidden sm:inline">{t('common.prev')}</span>
      </Button>
      {items.map((it, i) =>
        it === 'gap' ? (
          <span key={`gap-${i}`} className="px-1 text-sm text-muted-foreground">…</span>
        ) : (
          <Button
            key={it}
            variant={it === page ? 'default' : 'outline'}
            size="sm"
            aria-current={it === page ? 'page' : undefined}
            onClick={() => onPageChange(it)}
          >
            {it}
          </Button>
        )
      )}
      <Button
        variant="outline"
        size="sm"
        disabled={page >= totalPages}
        aria-label={t('common.next')}
        onClick={() => onPageChange(page + 1)}
      >
        <span className="hidden sm:inline">{t('common.next')}</span>
        <ChevronRight className="size-4" />
      </Button>
    </div>
  )
}
