import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './App'
import { applyPreferredTheme } from './AppShell'
import { applyDocumentLang } from './i18n'
import './styles.css'

applyPreferredTheme()
applyDocumentLang()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
