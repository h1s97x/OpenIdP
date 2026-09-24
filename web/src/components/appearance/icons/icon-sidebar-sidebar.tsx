/*
 * 外观设置示意图 · 侧栏轴：standard（贴边）
 *
 * 设计说明
 * --------
 * 本组（侧栏轴）三张图**只表达侧栏形态**，内容区刻意退化为几块低透明度的
 * 纯色块，避免与布局轴示意图抢视觉重点 —— 两条轴是正交的，若两张图都画满
 * 细节，用户无法一眼分辨自己改的是哪一轴。
 *
 * 本图表达 standard：侧栏贴着窗口左缘（零外边距）、上下通顶，
 * 是「侧栏 = 页面骨架的一部分」而非「浮在内容上的卡片」。
 *
 * viewBox 必须与 PreviewFrame 的 aspect-[79.86/51.14] 一致。
 */
import { type SVGProps } from 'react'

export function IconSidebarSidebar(props: SVGProps<SVGSVGElement>) {
  return (
    <svg
      data-name='openidp-sidebar-standard'
      xmlns='http://www.w3.org/2000/svg'
      viewBox='0 0 79.86 51.14'
      fill='currentColor'
      stroke='currentColor'
      {...props}
    >
      {/* 侧栏：零外边距、通顶 */}
      <rect x={0} y={0} width={21} height={51.14} rx={3} ry={3} opacity={0.28} />

      {/* 侧栏内容：品牌位 + 菜单条 + 底部账号 */}
      <rect x={5} y={6} width={4} height={4} rx={1.2} ry={1.2} opacity={0.7} />
      <rect x={10.2} y={6.8} width={5.8} height={2.4} rx={1.2} ry={1.2} opacity={0.45} />
      <rect x={5} y={14} width={10.5} height={2.6} rx={1.3} ry={1.3} opacity={0.62} />
      <rect x={5} y={19.5} width={8.5} height={2.2} rx={1.1} ry={1.1} opacity={0.38} />
      <rect x={5} y={25} width={9.5} height={2.2} rx={1.1} ry={1.1} opacity={0.38} />
      <rect x={5} y={30.5} width={7.5} height={2.2} rx={1.1} ry={1.1} opacity={0.38} />
      <circle cx={6.6} cy={44} r={1.8} opacity={0.5} />
      <rect x={9.8} y={43} width={6.5} height={2} rx={1} ry={1} opacity={0.38} />

      {/* 内容区：抽象色块 */}
      <rect x={27} y={6} width={21} height={4.6} rx={2.3} ry={2.3} opacity={0.4} />
      <rect x={27} y={14} width={49.9} height={16} rx={2.4} ry={2.4} opacity={0.18} />
      <rect x={27} y={33} width={49.9} height={14} rx={2.4} ry={2.4} opacity={0.18} />
    </svg>
  )
}
