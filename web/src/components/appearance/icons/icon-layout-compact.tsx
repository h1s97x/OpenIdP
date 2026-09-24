/*
 * 外观设置示意图 · 布局轴：icon（仅图标侧栏）
 *
 * 设计说明
 * --------
 * 对应外观面板中布局选项 `icon`：侧栏收窄到只放图标，文字菜单隐藏，
 * 因此内容区获得更宽的横向空间。
 *
 * 与 default 的对比要点（示意图靠这两点一眼区分）：
 *   1. 侧栏宽度明显收窄，菜单由「横条」变成「方块」；
 *   2. 内容区左边界左移、指标卡由 2 列变 3 列 —— 直观表达「内容更宽」。
 *
 * viewBox 必须与 PreviewFrame 的 aspect-[79.86/51.14] 一致。
 */
import { type SVGProps } from 'react'

export function IconLayoutCompact(props: SVGProps<SVGSVGElement>) {
  return (
    <svg
      data-name='openidp-layout-compact'
      xmlns='http://www.w3.org/2000/svg'
      viewBox='0 0 79.86 51.14'
      fill='currentColor'
      stroke='currentColor'
      {...props}
    >
      {/* 侧栏：图标态，仅方块图标 + 底部头像 */}
      <rect x={0} y={0} width={13} height={51.14} rx={3} ry={3} opacity={0.2} />
      <rect x={3.4} y={6} width={6.2} height={6.2} rx={1.6} ry={1.6} opacity={0.6} />
      <rect x={3.4} y={15} width={6.2} height={6.2} rx={1.6} ry={1.6} opacity={0.4} />
      <rect x={3.4} y={24} width={6.2} height={6.2} rx={1.6} ry={1.6} opacity={0.4} />
      <rect x={3.4} y={33} width={6.2} height={6.2} rx={1.6} ry={1.6} opacity={0.4} />
      <circle cx={6.5} cy={45.5} r={2.4} opacity={0.5} />

      {/* 内容区 · 顶栏 */}
      <rect x={18} y={6} width={21} height={4.6} rx={2.3} ry={2.3} opacity={0.5} />
      <circle cx={72.4} cy={8.3} r={2.3} opacity={0.32} />

      {/* 内容区 · 指标卡 ×3（比 default 多一列） */}
      <rect x={18} y={14} width={17} height={10} rx={2.4} ry={2.4} opacity={0.2} />
      <rect x={37.5} y={14} width={17} height={10} rx={2.4} ry={2.4} opacity={0.2} />
      <rect x={57} y={14} width={19.9} height={10} rx={2.4} ry={2.4} opacity={0.2} />

      {/* 内容区 · 主图表 */}
      <rect x={18} y={27} width={58.9} height={20} rx={2.4} ry={2.4} opacity={0.2} />
      <rect x={22} y={39} width={3.6} height={5.5} rx={1.2} ry={1.2} opacity={0.5} />
      <rect x={28.5} y={35} width={3.6} height={9.5} rx={1.2} ry={1.2} opacity={0.62} />
      <rect x={35} y={37.5} width={3.6} height={7} rx={1.2} ry={1.2} opacity={0.56} />
      <rect x={41.5} y={32} width={3.6} height={12.5} rx={1.2} ry={1.2} opacity={0.72} />
      <rect x={48} y={36.5} width={3.6} height={8} rx={1.2} ry={1.2} opacity={0.58} />
      <circle cx={67} cy={37} r={5.2} fill='none' strokeWidth={2.8} opacity={0.22} />
      <circle
        cx={67}
        cy={37}
        r={5.2}
        fill='none'
        strokeWidth={2.8}
        strokeDasharray='16 16'
        strokeLinecap='round'
        opacity={0.6}
      />
    </svg>
  )
}
