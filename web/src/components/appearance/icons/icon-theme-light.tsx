/*
 * 外观设置示意图 · 主题轴：light（浅色）
 *
 * 设计说明
 * --------
 * 主题轴是三条外观轴里唯一需要「上色」的一组：它的语义就是明暗，用
 * currentColor 单色表达不出来，因此这三张图自带调色板，与布局轴/侧栏轴
 * 的单色线框刻意区分。
 *
 * 配色取自 OpenIdP 自身的中性灰阶 + 低饱和蓝，不去对标任何外部主题：
 *   画布 #ffffff / 侧栏 #eef2f7 / 卡片 #e8eef6 / 弱化元素 #c2cede
 *   强调 #6b9bd8（柱状图与环形图）
 *
 * 全部内容包在圆角 clipPath 内，保证侧栏等元素不会把窗口的圆角切方。
 *
 * viewBox 必须与 PreviewFrame 的 aspect-[79.86/51.14] 一致。
 */
import { type SVGProps } from 'react'

export function IconThemeLight(props: SVGProps<SVGSVGElement>) {
  return (
    <svg
      data-name='openidp-theme-light'
      xmlns='http://www.w3.org/2000/svg'
      viewBox='0 0 79.86 51.14'
      {...props}
    >
      <defs>
        <clipPath id='openidp-theme-light-window'>
          <rect x={0} y={0} width={79.86} height={51.14} rx={3.5} ry={3.5} />
        </clipPath>
      </defs>

      <g clipPath='url(#openidp-theme-light-window)'>
        {/* 画布 */}
        <rect x={0} y={0} width={79.86} height={51.14} fill='#ffffff' />

        {/* 侧栏 */}
        <rect x={0} y={0} width={21} height={51.14} fill='#eef2f7' />
        <rect x={5} y={6} width={4} height={4} rx={1.2} ry={1.2} fill='#9db0c7' />
        <rect x={5} y={14} width={10.5} height={2.6} rx={1.3} ry={1.3} fill='#9db0c7' />
        <rect x={5} y={19.5} width={8.5} height={2.2} rx={1.1} ry={1.1} fill='#c2cede' />
        <rect x={5} y={25} width={9.5} height={2.2} rx={1.1} ry={1.1} fill='#c2cede' />
        <rect x={5} y={30.5} width={7.5} height={2.2} rx={1.1} ry={1.1} fill='#c2cede' />

        {/* 顶栏 */}
        <rect x={27} y={6} width={21} height={4.6} rx={2.3} ry={2.3} fill='#c2cede' />
        <circle cx={72.4} cy={8.3} r={2.3} fill='#c2cede' />

        {/* 指标卡 ×2 */}
        <rect x={27} y={14} width={21} height={10} rx={2.4} ry={2.4} fill='#e8eef6' />
        <rect x={51.5} y={14} width={25.4} height={10} rx={2.4} ry={2.4} fill='#e8eef6' />

        {/* 主图表：柱状 + 半环 */}
        <rect x={27} y={27} width={49.9} height={20} rx={2.4} ry={2.4} fill='#e8eef6' />
        <rect x={31} y={39} width={3.4} height={5.5} rx={1.1} ry={1.1} fill='#b6cde2' />
        <rect x={37} y={35.5} width={3.4} height={9} rx={1.1} ry={1.1} fill='#8fb4d8' />
        <rect x={43} y={37.5} width={3.4} height={7} rx={1.1} ry={1.1} fill='#b6cde2' />
        <rect x={49} y={32.5} width={3.4} height={12} rx={1.1} ry={1.1} fill='#6b9bd8' />
        <circle cx={67} cy={37} r={5.2} fill='none' stroke='#dbe6f2' strokeWidth={2.8} />
        <circle
          cx={67}
          cy={37}
          r={5.2}
          fill='none'
          stroke='#6b9bd8'
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
        stroke='#dbe3ec'
        strokeWidth={1}
      />
    </svg>
  )
}
