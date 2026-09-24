/*
 * 外观设置示意图 · 侧栏轴：inset（内缩留白）
 *
 * 设计说明
 * --------
 * 本组（侧栏轴）三张图只表达侧栏形态，内容区退化为抽象色块（见
 * icon-sidebar-sidebar.tsx 的说明）。
 *
 * 本图表达 inset：侧栏四周保留**均匀**外边距，四角圆润，
 * 视觉上是一块「嵌在画布里的板」，与 standard 的通顶贴边形成对比。
 * 注意留白是均匀的——若只有左右留白、上下通顶，那是 floating 的观感。
 *
 * viewBox 必须与 PreviewFrame 的 aspect-[79.86/51.14] 一致。
 */
import { type SVGProps } from 'react'

export function IconSidebarInset(props: SVGProps<SVGSVGElement>) {
  return (
    <svg
      data-name='openidp-sidebar-inset'
      xmlns='http://www.w3.org/2000/svg'
      viewBox='0 0 79.86 51.14'
      fill='currentColor'
      stroke='currentColor'
      {...props}
    >
      {/* 侧栏：四周均匀留白 3.5 */}
      <rect x={3.5} y={3.5} width={17} height={44.14} rx={2.8} ry={2.8} opacity={0.28} />

      {/* 侧栏内容：品牌位 + 菜单条 + 底部账号 */}
      <rect x={7} y={7} width={3.6} height={3.6} rx={1.1} ry={1.1} opacity={0.7} />
      <rect x={11.6} y={7.7} width={5.2} height={2.2} rx={1.1} ry={1.1} opacity={0.45} />
      <rect x={7} y={14.5} width={9.5} height={2.4} rx={1.2} ry={1.2} opacity={0.62} />
      <rect x={7} y={20} width={7.5} height={2} rx={1} ry={1} opacity={0.38} />
      <rect x={7} y={25.5} width={8.5} height={2} rx={1} ry={1} opacity={0.38} />
      <rect x={7} y={31} width={6.5} height={2} rx={1} ry={1} opacity={0.38} />
      <circle cx={8.6} cy={43.5} r={1.7} opacity={0.5} />
      <rect x={11.6} y={42.5} width={5.6} height={2} rx={1} ry={1} opacity={0.38} />

      {/* 内容区：抽象色块 */}
      <rect x={27} y={6} width={21} height={4.6} rx={2.3} ry={2.3} opacity={0.4} />
      <rect x={27} y={14} width={49.9} height={16} rx={2.4} ry={2.4} opacity={0.18} />
      <rect x={27} y={33} width={49.9} height={14} rx={2.4} ry={2.4} opacity={0.18} />
    </svg>
  )
}
