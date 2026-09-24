/*
 * 外观设置示意图 · 主题轴：dark（深色）
 *
 * 设计说明
 * --------
 * 与 icon-theme-light.tsx 共用同一套几何布局，只替换调色板 —— 这样三张主题图
 * 的「窗框形状」完全一致，用户对比时只会看到明暗差异，不会被布局差异干扰。
 *
 * 深色配色同样取自 OpenIdP 自身的中性炭灰 + 低饱和蓝：
 *   画布 #0f172a / 侧栏 #1b2437 / 卡片 #182135 / 弱化元素 #47546e
 *   强调 #5b8ec9（柱状图与环形图）
 *
 * viewBox 必须与 PreviewFrame 的 aspect-[79.86/51.14] 一致。
 */
import { type SVGProps } from 'react'

export function IconThemeDark(props: SVGProps<SVGSVGElement>) {
  return (
    <svg
      data-name='openidp-theme-dark'
      xmlns='http://www.w3.org/2000/svg'
      viewBox='0 0 79.86 51.14'
      {...props}
    >
      <defs>
        <clipPath id='openidp-theme-dark-window'>
          <rect x={0} y={0} width={79.86} height={51.14} rx={3.5} ry={3.5} />
        </clipPath>
      </defs>

      <g clipPath='url(#openidp-theme-dark-window)'>
        {/* 画布 */}
        <rect x={0} y={0} width={79.86} height={51.14} fill='#0f172a' />

        {/* 侧栏 */}
        <rect x={0} y={0} width={21} height={51.14} fill='#1b2437' />
        <rect x={5} y={6} width={4} height={4} rx={1.2} ry={1.2} fill='#7c8db0' />
        <rect x={5} y={14} width={10.5} height={2.6} rx={1.3} ry={1.3} fill='#7c8db0' />
        <rect x={5} y={19.5} width={8.5} height={2.2} rx={1.1} ry={1.1} fill='#47546e' />
        <rect x={5} y={25} width={9.5} height={2.2} rx={1.1} ry={1.1} fill='#47546e' />
        <rect x={5} y={30.5} width={7.5} height={2.2} rx={1.1} ry={1.1} fill='#47546e' />

        {/* 顶栏 */}
        <rect x={27} y={6} width={21} height={4.6} rx={2.3} ry={2.3} fill='#47546e' />
        <circle cx={72.4} cy={8.3} r={2.3} fill='#47546e' />

        {/* 指标卡 ×2 */}
        <rect x={27} y={14} width={21} height={10} rx={2.4} ry={2.4} fill='#182135' />
        <rect x={51.5} y={14} width={25.4} height={10} rx={2.4} ry={2.4} fill='#182135' />

        {/* 主图表：柱状 + 半环 */}
        <rect x={27} y={27} width={49.9} height={20} rx={2.4} ry={2.4} fill='#182135' />
        <rect x={31} y={39} width={3.4} height={5.5} rx={1.1} ry={1.1} fill='#3d5a80' />
        <rect x={37} y={35.5} width={3.4} height={9} rx={1.1} ry={1.1} fill='#4a72a3' />
        <rect x={43} y={37.5} width={3.4} height={7} rx={1.1} ry={1.1} fill='#3d5a80' />
        <rect x={49} y={32.5} width={3.4} height={12} rx={1.1} ry={1.1} fill='#5b8ec9' />
        <circle cx={67} cy={37} r={5.2} fill='none' stroke='#25324a' strokeWidth={2.8} />
        <circle
          cx={67}
          cy={37}
          r={5.2}
          fill='none'
          stroke='#5b8ec9'
          strokeWidth={2.8}
          strokeDasharray='16 16'
          strokeLinecap='round'
        />
      </g>

      {/* 窗口描边 */}
      <rect
        x={0.5}
        y={0.5}
        width={78.86}
        height={50.14}
        rx={3}
        ry={3}
        fill='none'
        stroke='#2b3852'
        strokeWidth={1}
      />
    </svg>
  )
}
