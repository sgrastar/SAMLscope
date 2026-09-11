/** Context uses public catalog identifiers only; no Run or target data is sent. */
export function SourceNoticeLink({ kind, id }: { kind: 'case' | 'profile' | 'requirement'; id: string }) {
  return <a href={`/licenses?${kind}=${encodeURIComponent(id)}`}>Sources and license notices</a>
}
