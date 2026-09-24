import * as React from 'react'
import { cn } from '../../lib/utils'

const TableContext = React.createContext(false)

export function Table({ className, ...props }: React.HTMLAttributes<HTMLTableElement>) {
  return (
    <div className="relative w-full overflow-x-auto">
      {/* w-full 会让列宽按百分比均分，窄屏下每列都被挤到内容换行（表头竖排、
          单元格里的「—」撑成四行）。加 min-w-full + w-max 之后列宽由内容决定，
          放不下时走外层 overflow-x-auto 横向滚动，而不是压缩文字。 */}
      <table data-slot="table" className={cn('w-max min-w-full caption-bottom text-sm', className)} {...props} />
    </div>
  )
}

export function TableHeader({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) {
  return <thead data-slot="table-header" className={cn('[&_tr]:border-b', className)} {...props} />
}

export function TableBody({ className, ...props }: React.HTMLAttributes<HTMLTableSectionElement>) {
  return <tbody data-slot="table-body" className={cn('[&_tr:last-child]:border-0', className)} {...props} />
}

export function TableRow({ className, ...props }: React.HTMLAttributes<HTMLTableRowElement>) {
  return <tr data-slot="table-row" className={cn('border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted', className)} {...props} />
}

export function TableHead({ className, ...props }: React.ThHTMLAttributes<HTMLTableCellElement>) {
  return <th data-slot="table-head" className={cn('h-10 px-2 text-left align-middle font-medium text-muted-foreground whitespace-nowrap', className)} {...props} />
}

export function TableCell({ className, ...props }: React.TdHTMLAttributes<HTMLTableCellElement>) {
  return <td data-slot="table-cell" className={cn('p-2 align-middle whitespace-nowrap', className)} {...props} />
}
