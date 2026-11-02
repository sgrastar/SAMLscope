import { expect, test } from 'vitest'
import { ja } from './ja'

const sources = import.meta.glob<string>(['./**/*.ts', './**/*.tsx', '!./**/*.test.*', '!./ja.ts'], {
  query: '?raw', import: 'default', eager: true,
})

/** Keys are the string literals passed as the first argument to t(...) or tx(...). */
export function collectKeys(source: string): string[] {
  const keys: string[] = []
  const call = /(?<![\w.$])tx?\(\s*(?:'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)")/g
  for (const match of source.matchAll(call)) {
    const raw = match[1] ?? match[2]
    keys.push(raw.replace(/\\(['"\\])/g, '$1'))
  }
  return keys
}

test('every t() key used by the app has a Japanese entry', () => {
  const keys = new Set(Object.values(sources).flatMap(collectKeys))
  expect(keys.size).toBeGreaterThan(0)
  const missing = [...keys].filter(key => !(key in ja)).sort()
  expect(missing, `${missing.length} keys without a Japanese entry`).toEqual([])
})
