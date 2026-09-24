/*
 * 外观设置示意图 · 布局轴：default（展开侧栏）
 *
 * 设计说明
 * --------
 * 三条外观轴各自的示意图强调不同的信息，避免三组图看起来重复：
 *   - 布局轴（本文件所在组）突出「内容区结构」：顶栏、指标卡、主图表，
 *     侧栏只作为一块带菜单条的色块出现；
 *   - 侧栏轴突出「侧栏形态」：贴边 / 留白 / 悬浮，内容区退化为纯色块；
 *   - 主题轴画完整窗口剪影并着色。
 *
 * 本图表达 default：侧栏展开、正常宽度，内容区被侧栏挤压为常规宽度。
 * 侧栏菜单刻意用「色块」而非白色镂空线条表达——镂空依赖固定的深色填充，
 * 在浅色主题下会糊成一片；用 fill-opacity 叠加则随主题自动适配。
 *
 * viewBox 必须与 PreviewFrame 的 aspect-[79.86/51.14] 一致，
 * 否则 SVG 会按 meet 居中留白，两侧出现空档。
 */
import { type SVGProps } from 'react'

export function IconLayoutDefault(props: SVGProps<SVGSVGElement>) {
  return (
    <svg
      data-name='openidp-layout-default'
      xmlns='http://www.w3.org/2000/svg'
      viewBox='0 0 79.86 51.14'
      fill='currentColor'
      stroke='currentColor'
      {...props}
    >
      {/* 侧栏：展开态，带文字型菜单 */}
      <rect x={0} y={0} width={22} height={51.14} rx={3} ry={3} opacity={0.2} />
      <rect x={5} y={7} width={11} height={2.8} rx={1.4} ry={1.4} opacity={0.62} />
      <rect x={5} y={13} width={9} height={2.4} rx={1.2} ry={1.2} opacity={0.4} />
      <rect x={5} y={18.5} width={10} height={2.4} rx={1.2} ry={1.2} opacity={0.4} />
      <rect x={5} y={24} width={8} height={2.4} rx={1.2} ry={1.2} opacity={0.4} />
      <circle cx={6.6} cy={43} r={1.8} opacity={0.5} />
      <rect x={9.8} y={42} width={6.5} height={2} rx={1} ry={1} opacity={0.38} />

      {/* 内容区 · 顶栏 */}
      <rect x={27} y={6} width={21} height={4.6} rx={2.3} ry={2.3} opacity={0.5} />
      <circle cx={72.4} cy={8.3} r={2.3} opacity={0.32} />

      {/* 内容区 · 指标卡 ×2 */}
      <rect x={27} y={14} width={21} height={10} rx={2.4} ry={2.4} opacity={0.2} />
      <rect x={51.5} y={14} width={25.4} height={10} rx={2.4} ry={2.4} opacity={0.2} />

      {/* 内容区 · 主图表：柱状 + 环形，环长取半周长形成半环 */}
      <rect x={27} y={27} width={49.9} height={20} rx={2.4} ry={2.4} opacity={0.2} />
      <rect x={31} y={39} width={3.4} height={5.5} rx={1.1} ry={1.1} opacity={0.5} />
      <rect x={37} y={35.5} width={3.4} height={9} rx={1.1} ry={1.1} opacity={0.62} />
      <rect x={43} y={37.5} width={3.4} height={7} rx={1.1} ry={1.1} opacity={0.56} />
      <rect x={49} y={32.5} width={3.4} height={12} rx={1.1} ry={1.1} opacity={0.72} />
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
