import type { Profile } from './api'

export const profileCatalog: Array<{ id: Profile; title: string; description: string }> = [
  { id: 'browser_sso_idp', title: 'Web Browser SSO — IdP', description: 'Browser sign-in provided by an Identity Provider.' },
  { id: 'browser_sso_sp', title: 'Web Browser SSO — SP', description: 'Browser sign-in consumed by a Service Provider.' },
  { id: 'metadata_idp', title: 'Metadata — IdP', description: 'Identity Provider metadata and trust management.' },
  { id: 'metadata_sp', title: 'Metadata — SP', description: 'Service Provider metadata and trust management.' },
  { id: 'single_logout_idp', title: 'Single Logout — IdP', description: 'Identity Provider logout behavior.' },
  { id: 'single_logout_sp', title: 'Single Logout — SP', description: 'Service Provider logout behavior.' },
  { id: 'ecp_idp', title: 'ECP — IdP', description: 'Enhanced Client or Proxy sign-in.' },
]

export function profileLabel(id: string) {
  const normalized = id.replaceAll('-', '_')
  return profileCatalog.find(profile => profile.id === normalized)?.title ?? id
}

export function profileRole(profile: Profile): 'IDP' | 'SP' {
  return profile.endsWith('_idp') ? 'IDP' : 'SP'
}
