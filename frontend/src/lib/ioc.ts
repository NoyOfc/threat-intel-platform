import type { IocType, NetworkScope } from './api'

// Keep in sync with the backend: app/services/ioc.py and app/schemas/ioc.py.
export const MAX_IOC_LENGTH = 2048
export const MAX_BULK_IOCS = 500

export const IOC_TYPE_LABELS: Record<IocType, string> = {
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  domain: 'Domain',
  url: 'URL',
  md5: 'MD5',
  sha1: 'SHA1',
  sha256: 'SHA256',
}

export const SCOPE_LABELS: Record<NetworkScope, string> = {
  public: 'Public',
  private: 'Private',
  loopback: 'Loopback',
  link_local: 'Link-local',
  multicast: 'Multicast',
  unspecified: 'Unspecified',
  reserved: 'Reserved',
  internal_hostname: 'Internal hostname',
}

/** Split pasted text into one IOC per non-blank line. */
export function splitIocLines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
}
