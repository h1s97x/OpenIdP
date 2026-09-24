// 密码策略（来自 /api/v1/login-policy）的统一读取与文案生成。
//
// 背景：修改密码、初始化、后台建号三处的密码提示词原先都写死「至少 8 位」，
// 其中「修改密码」还宣称必须含大小写字母与数字——而服务端默认只校验最小长度，
// 管理员在后台改了策略后，这些提示既不跟着变，也与实际校验规则不符。
// 这里把策略读取与规则文案收敛到一处，各处共用同一份来源。
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'

export interface PasswordRequirements {
  minimumLength: number
  requireUppercase: boolean
  requireLowercase: boolean
  requireNumber: boolean
  requireSymbol: boolean
}

// DEFAULT_PASSWORD_REQUIREMENTS 与服务端默认策略保持一致，
// 仅在接口不可用（请求失败 / 未取到策略）时兜底。
export const DEFAULT_PASSWORD_REQUIREMENTS: PasswordRequirements = {
  minimumLength: 8,
  requireUppercase: false,
  requireLowercase: false,
  requireNumber: false,
  requireSymbol: false,
}

// usePasswordPolicy 返回当前生效的密码策略。
//
// 用 react-query 而非各页自行 useState + useEffect：多页共享同一份缓存，
// 同一会话内不会重复请求 /login-policy。
export function usePasswordPolicy(): PasswordRequirements {
  const { data } = useQuery({
    queryKey: ['login-policy'],
    queryFn: () => api.loginPolicy<{ passwordRequirements?: PasswordRequirements }>(),
    staleTime: 5 * 60 * 1000,
  })
  return data?.passwordRequirements ?? DEFAULT_PASSWORD_REQUIREMENTS
}

// passwordRequirementList 生成可直接展示的规则清单（已按实际策略裁剪）。
//
// 复用 signup.passwordReq* 文案键：它们只是纯粹的规则描述，不限于注册场景，
// 不必为修改密码再复制一套同义文案。
export function passwordRequirementList(
  reqs: PasswordRequirements,
  t: (key: string, vars?: Record<string, string | number>) => string
): string[] {
  return [
    t('signup.passwordReqLength', { min: reqs.minimumLength }),
    ...(reqs.requireUppercase ? [t('signup.passwordReqUppercase')] : []),
    ...(reqs.requireLowercase ? [t('signup.passwordReqLowercase')] : []),
    ...(reqs.requireNumber ? [t('signup.passwordReqNumber')] : []),
    ...(reqs.requireSymbol ? [t('signup.passwordReqSymbol')] : []),
  ]
}
