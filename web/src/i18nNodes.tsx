import { Fragment, type ReactNode } from 'react'
import { t } from './i18n'

/**
 * Translates a whole sentence that also contains inline elements (code, strong, links).
 * The English text is the key; `{name}` placeholders are replaced by the given nodes,
 * so translators can reorder the elements freely.
 */
export function tx(text: string, nodes: Record<string, ReactNode>): ReactNode {
  return <>{t(text).split(/(\{\w+\})/).map((part, index) => {
    const name = /^\{(\w+)\}$/.exec(part)?.[1]
    return name !== undefined && name in nodes ? <Fragment key={index}>{nodes[name]}</Fragment> : part
  })}</>
}
