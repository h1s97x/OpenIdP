/*
 * 外观设置示意图 · 侧栏轴：floating（悬浮）
 *
 * 设计说明
 * --------
 * 本组（侧栏轴）三张图只表达侧栏形态，内容区退化为抽象色块（见
 * icon-sidebar-sidebar.tsx 的说明）。
 *
 * 本图表达 floating：侧栏**脱离**窗口边缘悬浮 —— 上下左右都留出明显间隙，
 * 侧栏更窄，并带一层错位半透明的投影来暗示「浮」在画布之上。
 * 与 inset 的区别靠两点拉开：间隙更大 + 有投影层。
 *
 * viewBox 必须与 PreviewFrame 的 aspect-[79.86/51.14] 一致。
 */
import { type SVGProps } from 'react'

export function IconSidebarFloating(props: SVGProps<SVGSVGElement>) {
  return (
    <svg
      data-name='openidp-sidebar-floating'
      xmlns='http://www.w3.org/2000/svg'
      viewBox='0 0 79.86 51.14'
      fill='currentColor'
      stroke='currentColor'
      {...props}
    >
      {/* 投影层：向右下错位，低透明度 */}
      <rect x={5} y={5.2} width={13.5} height={42.14} rx={3.2} ry={3.2} opacity={0.1} />
      {/* 侧栏本体：比 inset 更窄、留白更大 */}
      <rect x={4.2} y={4.2} width={13.5} height={42.14} rx={3.2} ry={3.2} opacity={0.3} />

      {/* 侧栏内容：品牌位 + 菜单条 + 底部账号（宽度收窄，去掉一条菜单） */}
      <rect x={7.2} y={7.6} width={3.4} height={3.4} rx={1.1} ry={1.1} opacity={0.7} />
      <rect x={11.4} y={8.3} width={4.2} height={2} rx={1} ry={1} opacity={0.45} />
      <rect x={7.2} y={15} width={7.6} height={2.3} rx={1.15} ry={1.15} opacity={0.62} />
      <rect x={7.2} y={20.4} width={5.8} height={2} rx={1} ry={1} opacity={0.38} />
      <rect x={7.2} y={25.8} width={6.6} height={2} rx={1} ry={1} opacity={0.38} />
      <circle cx={9} cy={42.6} r={1.6} opacity={0.5} />
      <rect x={11.6} y={41.6} width={4.4} height={2} rx={1} ry={1} opacity={0.38} />

      {/* 内容区：抽象色块 */}
      <rect x={27} y={6} width={21} height={4.6} rx={2.3} ry={2.3} opacity={0.4} />
      <rect x={27} y={14} width={49.9} height={16} rx={2.4} ry={2.4} opacity={0.18} />
      <rect x={27} y={33} width={49.9} height={14} rx={2.4} ry={2.4} opacity={0.18} />
    </svg>
  )
}
