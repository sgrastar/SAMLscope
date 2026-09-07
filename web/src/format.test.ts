import { expect, test } from 'vitest'
import { formatDate } from './format'

test('renders numeric API Instant seconds like exported ISO timestamps', () => {
  const iso = '2026-09-07T03:03:36.704Z'
  const expected = new Date(iso).toLocaleString()
  expect(formatDate(1788750216.704)).toBe(expected)
  expect(formatDate(iso)).toBe(expected)
  expect(formatDate(0)).toBe(new Date('1970-01-01T00:00:00Z').toLocaleString())
})

test('uses the caller fallback for invalid timestamps', () => {
  expect(formatDate('invalid')).toBe('Updated recently')
  expect(formatDate(Number.NaN, 'Unknown')).toBe('Unknown')
})
