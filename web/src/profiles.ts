import { t } from './i18n'
import type { Profile } from './api'

export const profileCatalog: Array<{ id: Profile; title: string; description: string }> = [
  { id: 'browser_sso_idp', title: t('Web Browser SSO — IdP'), description: t('Browser sign-in provided by an Identity Provider.') },
  { id: 'browser_sso_sp', title: t('Web Browser SSO — SP'), description: t('Browser sign-in consumed by a Service Provider.') },
  { id: 'metadata_idp', title: t('Metadata — IdP'), description: t('Identity Provider metadata and trust management.') },
  { id: 'metadata_sp', title: t('Metadata — SP'), description: t('Service Provider metadata and trust management.') },
  { id: 'single_logout_idp', title: t('Single Logout — IdP'), description: t('Identity Provider logout behavior.') },
  { id: 'single_logout_sp', title: t('Single Logout — SP'), description: t('Service Provider logout behavior.') },
  { id: 'ecp_idp', title: t('ECP — IdP'), description: t('Enhanced Client or Proxy sign-in.') },
]

/** Language-independent titles for names that are saved with a Plan. */
const englishTitles: Record<Profile, string> = {
  browser_sso_idp: 'Web Browser SSO — IdP',
  browser_sso_sp: 'Web Browser SSO — SP',
  metadata_idp: 'Metadata — IdP',
  metadata_sp: 'Metadata — SP',
  single_logout_idp: 'Single Logout — IdP',
  single_logout_sp: 'Single Logout — SP',
  ecp_idp: 'ECP — IdP',
}

export function profileEnglishLabel(profile: Profile) {
  return englishTitles[profile]
}

export function profileLabel(id: string) {
  const normalized = id.replaceAll('-', '_')
  return profileCatalog.find(profile => profile.id === normalized)?.title ?? id
}

export function profileRole(profile: Profile): 'IDP' | 'SP' {
  return profile.endsWith('_idp') ? 'IDP' : 'SP'
}
