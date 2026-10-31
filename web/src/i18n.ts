import { ja } from './ja'

export type Lang = 'en' | 'ja'

const storageKey = 'samlscope.lang'

/** Saved choice first, then the browser language. English is the source language and the fallback. */
export function preferredLang(): Lang {
  try {
    const saved = window.localStorage.getItem(storageKey)
    if (saved === 'en' || saved === 'ja') return saved
  } catch { /* private mode */ }
  return typeof navigator !== 'undefined' && navigator.language?.toLowerCase().startsWith('ja') ? 'ja' : 'en'
}

let current: Lang = preferredLang()

export function currentLang(): Lang {
  return current
}

/** Tests only: switch the module language without reloading. */
export function setLangForTests(lang: Lang) {
  current = lang
}

/** The page reloads so every string is rendered once, in one language. */
export function chooseLang(lang: Lang) {
  try { window.localStorage.setItem(storageKey, lang) } catch { /* private mode */ }
  window.location.reload()
}

export function applyDocumentLang() {
  document.documentElement.lang = current
}

/**
 * The English text is the key. A missing Japanese entry falls back to the English text,
 * so an untranslated string is never blank. `{name}` placeholders are replaced from params.
 */
export function t(text: string, params?: Record<string, string | number>): string {
  const template = current === 'ja' ? ja[text] ?? text : text
  return params
    ? template.replace(/\{(\w+)\}/g, (whole, name: string) => name in params ? String(params[name]) : whole)
    : template
}
