import type { ReactNode } from 'react'

type StatusTone = 'error' | 'empty' | 'info'

interface Props {
  tone: StatusTone
  title: string
  children?: ReactNode
  actionLabel?: string
  onAction?: () => void
  compact?: boolean
}

export default function StatusMessage({ tone, title, children, actionLabel, onAction, compact = false }: Props) {
  return (
    <div className={`status-message status-${tone}${compact ? ' status-compact' : ''}`} role={tone === 'error' ? 'alert' : 'status'}>
      <div className="status-title">{title}</div>
      {children && <div className="status-description">{children}</div>}
      {actionLabel && onAction && (
        <button className="status-action" onClick={onAction}>{actionLabel}</button>
      )}
    </div>
  )
}
