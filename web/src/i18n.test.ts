import { afterEach, expect, test } from 'vitest'
import { setLangForTests, t } from './i18n'
import { ja } from './ja'

afterEach(() => setLangForTests('en'))

test('returns the English source text and fills placeholders', () => {
  expect(t('Hello {name}', { name: 'x' })).toBe('Hello x')
  expect(t('No placeholders')).toBe('No placeholders')
})

test('falls back to English when there is no Japanese entry', () => {
  setLangForTests('ja')
  expect(t('Surely untranslated text')).toBe('Surely untranslated text')
})

test('every Japanese entry is non-empty and keeps the same placeholders', () => {
  const names = (text: string) => (text.match(/\{\w+\}/g) ?? []).sort().join(',')
  for (const [key, value] of Object.entries(ja)) {
    expect(value.trim(), key).not.toBe('')
    expect(names(value), key).toBe(names(key))
  }
})
