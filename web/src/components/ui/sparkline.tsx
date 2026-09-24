import * as React from 'react'
import { cn } from '../../lib/utils'

// Sparkline：统计卡内嵌的迷你趋势线（纯 SVG，不引入图表库）。
//
// 设计取舍：
// - 用 viewBox 0..100 + preserveAspectRatio="none" 随容器拉伸，卡片无需测量尺寸；
//   描边用 vector-effect: non-scaling-stroke 抵消非等比缩放，线条粗细保持一致。
// - 数据全等（含全 0）时画居中基线而不是空白：否则卡片看起来像渲染失败，
//   与「这段时间确实没有数据」无法区分。
// - 渐变 id 用 useId 隔离，同一页面多个实例不会互相覆盖。

interface SparklineProps {
  /** 按时间顺序的数值序列（旧 → 新） */
  data: number[]
  /** 线高（px）；宽度始终撑满父容器 */
  height?: number
  /** 线条与渐变基色 */
  color?: string
  /** 渐变起始透明度 */
  fillOpacity?: number
  className?: string
  /** 无障碍描述；缺省时纯装饰（aria-hidden） */
  label?: string
}

export function Sparkline({
  data, height = 40, color = 'var(--primary)', fillOpacity = 0.18, className, label,
}: SparklineProps) {
  const gradientId = React.useId()
  const values = React.useMemo(
    () => (Array.isArray(data) ? data.map((n) => (Number.isFinite(n) ? n : 0)) : []),
    [data],
  )

  // 少于两个点无法构成趋势，直接留白由调用方决定展示形式。
  if (values.length < 2) return null

  const max = Math.max(...values)
  const min = Math.min(...values)
  const span = max - min
  // 上下各留 6% 内边距，避免折线贴边被裁切。
  const toY = (v: number) => (span === 0 ? 50 : 94 - ((v - min) / span) * 88)
  const step = 100 / (values.length - 1)
  const line = values.map((v, i) => `${i === 0 ? 'M' : 'L'}${(i * step).toFixed(2)},${toY(v).toFixed(2)}`).join(' ')

  return (
    <svg
      viewBox="0 0 100 100"
      preserveAspectRatio="none"
      className={cn('w-full', className)}
      style={{ height }}
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity={fillOpacity} />
          <stop offset="100%" stopColor={color} stopOpacity={0} />
        </linearGradient>
      </defs>
      <path d={`${line} L100,100 L0,100 Z`} fill={`url(#${gradientId})`} stroke="none" />
      <path
        d={line}
        fill="none"
        stroke={color}
        strokeWidth={2}
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  )
}
