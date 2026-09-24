/*
 * 外观设置示意图 · 布局轴：offcanvas（侧栏收起）
 *
 * 设计说明
 * --------
 * 对应外观面板中布局选项 `offcanvas`：侧栏整体收起（改为抽屉，按需呼出），
 * 内容区独占整幅宽度。
 *
 * 与 default / icon 的对比要点：本图**没有侧栏色块**，取而代之的是左上角
 * 一个「三横线」呼出按钮 —— 这是 offcanvas 的标志性交互入口；
 * 同时内容区从最左侧铺满，指标卡可排到 4 列。
 *
 * viewBox 必须与 PreviewFrame 的 aspect-[79.86/51.14] 一致。
 */
import { type SVGProps } from 'react'

export function IconLayoutFull(props: SVGProps<SVGSVGElement>) {
  return (
    <svg
      data-name='openidp-layout-full'
      xmlns='http://www.w3.org/2000/svg'
      viewBox='0 0 79.86 51.14'
      fill='currentColor'
      stroke='currentColor'
      {...props}
    >
      {/* 呼出侧栏的三横线按钮 */}
      <g opacity={0.62}>
        <rect x={5} y={5.6} width={8.5} height={1.7} rx={0.85} ry={0.85} />
        <rect x={5} y={9.6} width={8.5} height={1.7} rx={0.85} ry={0.85} />
        <rect x={5} y={13.6} width={8.5} height={1.7} rx={0.85} ry={0.85} />
      </g>

      {/* 内容区 · 顶栏 */}
      <rect x={19} y={6} width={24} height={4.6} rx={2.3} ry={2.3} opacity={0.5} />
      <circle cx={72.4} cy={8.3} r={2.3} opacity={0.32} />

      {/* 内容区 · 指标卡 ×4（满宽后可容纳更多列） */}
      <rect x={5} y={20} width={16.2} height={10} rx={2.4} ry={2.4} opacity={0.2} />
      <rect x={24} y={20} width={16.2} height={10} rx={2.4} ry={2.4} opacity={0.2} />
      <rect x={43} y={20} width={16.2} height={10} rx={2.4} ry={2.4} opacity={0.2} />
      <rect x={62} y={20} width={12.9} height={10} rx={2.4} ry={2.4} opacity={0.2} />

      {/* 内容区 · 主图表铺满整行 */}
      <rect x={5} y={33} width={69.9} height={14} rx={2.4} ry={2.4} opacity={0.2} />
      <rect x={9} y={39.5} width={3.6} height={4.5} rx={1.2} ry={1.2} opacity={0.5} />
      <rect x={15.5} y={37} width={3.6} height={7} rx={1.2} ry={1.2} opacity={0.62} />
      <rect x={22} y={38.5} width={3.6} height={5.5} rx={1.2} ry={1.2} opacity={0.56} />
      <rect x={28.5} y={35.5} width={3.6} height={8.5} rx={1.2} ry={1.2} opacity={0.72} />
      <rect x={35} y={37.5} width={3.6} height={6.5} rx={1.2} ry={1.2} opacity={0.58} />
      <circle cx={62} cy={40} r={5.2} fill='none' strokeWidth={2.8} opacity={0.22} />
      <circle
        cx={62}
        cy={40}
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
