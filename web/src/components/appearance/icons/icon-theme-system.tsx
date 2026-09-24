/*
 * 外观设置示意图 · 主题轴：system（跟随系统）
 *
 * 设计说明
 * --------
 * 语义是「跟随系统明暗」，所以这张图必须让明、暗两种状态**同时可见** ——
 * 只画一种颜色就无法表达「跟随」。做法是对角线分割：右上为深色、左下为浅色，
 * 共用同一套几何布局，与 light / dark 两张图保持同一窗框。
 *
 * 实现上用两层 clipPath：外层裁出窗口圆角剪影（否则侧栏方形色块会把圆角切方），
 * 内层裁出深色三角区域。两层嵌套后，深色部分连同它自己的内容一起被裁，
 * 不会出现「深色只盖了底色、内容还是浅色」的穿帮。
 *
 * clipPath 的 id 在一个页面里全局唯一；本组件在抽屉中只渲染一次，
 * 即便重复渲染，同名 id 指向的定义完全相同，视觉结果依旧正确。
 *
 * viewBox 必须与 PreviewFrame 的 aspect-[79.86/51.14] 一致。
 */
import { type SVGProps } from 'react'

export function IconThemeSystem(props: SVGProps<SVGSVGElement>) {
  return (
    <svg
      data-name='openidp-theme-system'
      xmlns='http://www.w3.org/2000/svg'
      viewBox='0 0 79.86 51.14'
      {...props}
    >
      <defs>
        <clipPath id='openidp-theme-system-window'>
          <rect x={0} y={0} width={79.86} height={51.14} rx={3.5} ry={3.5} />
        </clipPath>
        {/* 右上三角：起点 (79.86,0) 沿右边到 (79.86,51.14)，再水平回到 (20,51.14) */}
        <clipPath id='openidp-theme-system-dark'>
          <path d='M79.86 0v51.14H20z' />
        </clipPath>
      </defs>

      <g clipPath='url(#openidp-theme-system-window)'>
        {/* ---- 底层：完整浅色窗 ---- */}
        <rect x={0} y={0} width={79.86} height={51.14} fill='#ffffff' />
        <rect x={0} y={0} width={21} height={51.14} fill='#eef2f7' />
        <rect x={5} y={6} width={4} height={4} rx={1.2} ry={1.2} fill='#9db0c7' />
        <rect x={5} y={14} width={10.5} height={2.6} rx={1.3} ry={1.3} fill='#9db0c7' />
        <rect x={5} y={19.5} width={8.5} height={2.2} rx={1.1} ry={1.1} fill='#c2cede' />
        <rect x={5} y={25} width={9.5} height={2.2} rx={1.1} ry={1.1} fill='#c2cede' />
        <rect x={5} y={30.5} width={7.5} height={2.2} rx={1.1} ry={1.1} fill='#c2cede' />
        <rect x={27} y={6} width={21} height={4.6} rx={2.3} ry={2.3} fill='#c2cede' />
        <circle cx={72.4} cy={8.3} r={2.3} fill='#c2cede' />
        <rect x={27} y={14} width={21} height={10} rx={2.4} ry={2.4} fill='#e8eef6' />
        <rect x={51.5} y={14} width={25.4} height={10} rx={2.4} ry={2.4} fill='#e8eef6' />
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

        {/* ---- 覆盖层：右上深色窗，随三角裁切 ---- */}
        <g clipPath='url(#openidp-theme-system-dark)'>
          <rect x={0} y={0} width={79.86} height={51.14} fill='#0f172a' />
          <rect x={0} y={0} width={21} height={51.14} fill='#1b2437' />
          <rect x={5} y={6} width={4} height={4} rx={1.2} ry={1.2} fill='#7c8db0' />
          <rect x={5} y={14} width={10.5} height={2.6} rx={1.3} ry={1.3} fill='#7c8db0' />
          <rect x={5} y={19.5} width={8.5} height={2.2} rx={1.1} ry={1.1} fill='#47546e' />
          <rect x={5} y={25} width={9.5} height={2.2} rx={1.1} ry={1.1} fill='#47546e' />
          <rect x={5} y={30.5} width={7.5} height={2.2} rx={1.1} ry={1.1} fill='#47546e' />
          <rect x={27} y={6} width={21} height={4.6} rx={2.3} ry={2.3} fill='#47546e' />
          <circle cx={72.4} cy={8.3} r={2.3} fill='#47546e' />
          <rect x={27} y={14} width={21} height={10} rx={2.4} ry={2.4} fill='#182135' />
          <rect x={51.5} y={14} width={25.4} height={10} rx={2.4} ry={2.4} fill='#182135' />
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
      </g>

      {/* 窗口描边：右侧偏深、左侧偏浅，呼应分割 */}
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
