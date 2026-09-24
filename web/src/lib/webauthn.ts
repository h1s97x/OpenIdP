// 浏览器端 WebAuthn 辅助：把后端返回的 options 转成可用的 PublicKeyCredential
// 请求/断言，并处理二进制 ID 的 base64url 编解码。

function b64urlToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/')
  const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4))
  const bin = atob(b64 + pad)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

function bytesToB64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// decodeId 把 base64url 字符串解码为 Uint8Array。
// 非字符串（例如后端直接下发数字 id）原样返回，避免 atob 抛错。
function decodeId(v: any): any {
  return typeof v === 'string' ? b64urlToBytes(v) : v
}

// parseOptions 解析后端下发的认证参数。
//
// 后端 json.Marshal 的是 go-webauthn 的 protocol.CredentialCreation /
// CredentialAssertion，二者结构均为：
//
//	{ "publicKey": { "rp": …, "user": …, "challenge": …, … }, "mediation": … }
//
// 这正好就是 navigator.credentials.create() / get() 期望的顶层结构，
// 因此这里只把 publicKey 内部的二进制字段（challenge、user.id、
// excludeCredentials[].id、allowCredentials[].id）从 base64url 解码为
// Uint8Array，随后整体原样透传给浏览器 API（mediation 等字段一并保留）。
//
// 早期实现把整个对象又包了一层 publicKey，形成 publicKey.publicKey.challenge，
// 浏览器读到的 challenge 是 undefined，内部读取其 .buffer 时抛
// "Cannot read properties of undefined (reading 'buffer')"，添加通行密钥必然失败。
function parseOptions(raw: any): any {
  const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw
  if (!parsed || typeof parsed !== 'object') return parsed
  // 兼容带/不带 publicKey 包装两种输入
  const opts = parsed.publicKey ?? parsed
  if (!opts || typeof opts !== 'object') return parsed
  if (opts.challenge) opts.challenge = decodeId(opts.challenge)
  if (opts.user?.id) opts.user.id = decodeId(opts.user.id)
  if (Array.isArray(opts.excludeCredentials)) {
    opts.excludeCredentials = opts.excludeCredentials.map((c: any) => ({
      ...c,
      id: decodeId(c.id),
    }))
  }
  if (Array.isArray(opts.allowCredentials)) {
    opts.allowCredentials = opts.allowCredentials.map((c: any) => ({
      ...c,
      id: decodeId(c.id),
    }))
  }
  return parsed
}

// assertWebAuthnAvailable 校验运行环境是否可用 WebAuthn，不可用时抛出可诊断的错误。
//
// 必须区分两种情况，否则排查方向会被误导：
//  1. 非安全上下文（http 且非 localhost）：浏览器根本不暴露 PublicKeyCredential，
//     此时若提示「浏览器不支持」会让用户以为要换浏览器，实际应使用 HTTPS 访问。
//  2. 安全上下文但浏览器本身不支持：才是真正的浏览器兼容性问题。
function assertWebAuthnAvailable() {
  if (typeof window !== 'undefined' && window.isSecureContext === false) {
    throw new Error('当前站点未通过 HTTPS 访问，浏览器已禁用通行密钥（localhost 除外）')
  }
  if (!window.PublicKeyCredential) {
    throw new Error('当前浏览器不支持 WebAuthn 通行密钥')
  }
}

// 把浏览器返回的凭证序列化成后端可解析的 JSON
function serializeCredential(cred: any) {
  return {
    id: cred.id,
    rawId: bytesToB64url(new Uint8Array(cred.rawId)),
    type: cred.type,
    response: {
      clientDataJSON: bytesToB64url(new Uint8Array(cred.response.clientDataJSON)),
      attestationObject: cred.response.attestationObject
        ? bytesToB64url(new Uint8Array(cred.response.attestationObject))
        : undefined,
      authenticatorData: cred.response.authenticatorData
        ? bytesToB64url(new Uint8Array(cred.response.authenticatorData))
        : undefined,
      signature: cred.response.signature ? bytesToB64url(new Uint8Array(cred.response.signature)) : undefined,
      userHandle: cred.response.userHandle ? bytesToB64url(new Uint8Array(cred.response.userHandle)) : undefined,
    },
    clientExtensionResults: cred.getClientExtensionResults?.(),
  }
}

// detectPlatformType 从 User-Agent 推断操作系统。
// 顺序敏感：Android / ChromeOS 的 UA 里都含 Linux，必须先判。
function detectPlatformType(ua: string): 'windows' | 'android' | 'apple' | 'chromeos' | 'linux' | 'unknown' {
  const s = (ua || '').toLowerCase()
  if (/windows/.test(s)) return 'windows'
  if (/android/.test(s)) return 'android'
  if (/cros/.test(s)) return 'chromeos'
  if (/iphone|ipad|ipod/.test(s)) return 'apple'
  if (/mac os x|macintosh/.test(s)) return 'apple'
  if (/linux/.test(s)) return 'linux'
  return 'unknown'
}

// 未提供 i18n 时的兜底标签（与 security.passkeySource* 键对应）。
const FALLBACK_SOURCE_LABELS: Record<string, string> = {
  'security.passkeySourceSecurityKey': '外置安全密钥',
  'security.passkeySourceOtherDevice': '跨设备通行密钥',
  'security.passkeyDefaultName': '通行密钥',
}

// detectPasskeySource 推断通行密钥保存在哪里，返回可直接作为名称的文案。
//
// 重要：这里只能"推断"，做不到精确识别。原因是 WebAuthn 默认的 attestation
// 为 none（实测下发的 attestationType 即为 "none"），认证器不会返回任何型号
// 信息，服务端无从判断用的是哪个密码管理器。可用的只有浏览器端这几个信号：
//   - authenticatorAttachment：platform（设备内置）还是 cross-platform（外置）
//   - response.getTransports()：internal / hybrid / usb / nfc / ble
//   - User-Agent：操作系统
//
// 已知局限：在 Windows 的 Chrome 上，Windows Hello 与 Google 密码管理工具
// 都会报 platform，两者无法区分，此时统一按 Windows Hello 命名。用户可在
// 保存前直接改名，因此推断偏差可人工纠正。
export function detectPasskeySource(
  cred: any,
  ua: string,
  t?: (key: string) => string,
): string {
  const label = (k: string) => (t ? t(k) : FALLBACK_SOURCE_LABELS[k] ?? '通行密钥')

  let transports: string[]
  try {
    transports = cred?.response?.getTransports?.() ?? []
  } catch {
    transports = []
  }
  const attachment = cred?.authenticatorAttachment
  const platform = detectPlatformType(ua)

  // 扫码/蓝牙借用其它设备上的通行密钥
  if (transports.includes('hybrid')) {
    return label('security.passkeySourceOtherDevice')
  }
  // 外置安全密钥（USB / NFC / BLE）
  if (
    attachment === 'cross-platform' ||
    transports.includes('usb') ||
    transports.includes('nfc') ||
    transports.includes('ble')
  ) {
    return label('security.passkeySourceSecurityKey')
  }

  // 平台内置：按操作系统对应到常见的密码管理器
  switch (platform) {
    case 'windows':
      return 'Windows Hello'
    case 'android':
    case 'chromeos':
      return 'Google 密码管理工具'
    case 'apple':
      return 'iCloud 钥匙串'
    default:
      return label('security.passkeyDefaultName')
  }
}

export async function createPasskey(
  optionsRaw: any,
  t?: (key: string) => string,
): Promise<{ credential: any; suggestedName: string }> {
  const opts = parseOptions(optionsRaw)
  assertWebAuthnAvailable()
  const cred = await navigator.credentials.create(opts as CredentialCreationOptions)
  if (!cred) {
    throw new Error('用户取消了操作')
  }
  return {
    credential: serializeCredential(cred),
    suggestedName: detectPasskeySource(cred, navigator.userAgent, t),
  }
}

export async function assertPasskey(optionsRaw: any): Promise<any> {
  const opts = parseOptions(optionsRaw)
  assertWebAuthnAvailable()
  const cred = await navigator.credentials.get(opts as CredentialRequestOptions)
  if (!cred) {
    throw new Error('用户取消了操作')
  }
  return serializeCredential(cred)
}
