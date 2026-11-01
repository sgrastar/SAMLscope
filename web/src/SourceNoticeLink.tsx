import { t } from './i18n'
/** Context uses public catalog identifiers only; no Run or target data is sent. */
export function SourceNoticeLink({ kind, id }: { kind: 'case' | 'profile' | 'requirement'; id: string }) {
  return <a href={`/licenses?${kind}=${encodeURIComponent(id)}`}>{t('Sources and license notices')}</a>
}
