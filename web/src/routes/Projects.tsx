import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, type Project } from '../api/client'
import { SEV_ORDER, SEV, sevStyle } from '../lib/severity'
import { VD_ORDER, VERDICT, verdictStyle } from '../lib/verdict'
import { ConfirmModal } from '../components/ConfirmModal'
import StatusMessage from '../components/StatusMessage'

function SevBar({ counts }: { counts: Partial<Record<string, number>> }) {
  const total = SEV_ORDER.reduce((s, k) => s + (counts[k] ?? 0), 0) || 1
  return (
    <div className="sevbar">
      {SEV_ORDER.map(s => counts[s] ? (
        <i key={s} style={{ width: `${(counts[s]! / total) * 100}%`, background: SEV[s].c }} />
      ) : null)}
    </div>
  )
}

function VBar({ counts }: { counts: Partial<Record<string, number>> }) {
  const total = VD_ORDER.reduce((s, k) => s + (counts[k] ?? 0), 0) || 1
  return (
    <div className="vbar">
      {VD_ORDER.map(v => counts[v] ? (
        <i key={v} style={{ width: `${(counts[v]! / total) * 100}%`, background: VERDICT[v].c }} />
      ) : null)}
    </div>
  )
}

function triagePct(cvd: Partial<Record<string, number>>) {
  const all = VD_ORDER.reduce((s, k) => s + (cvd[k] ?? 0), 0)
  const unmarked = cvd.unmarked ?? 0
  return all ? Math.round((all - unmarked) / all * 100) : 0
}

function ProjectCard({ p, onClick, onDelete }: { p: Project; onClick: () => void; onDelete: (e: React.MouseEvent) => void }) {
  const counts = p.counts as Record<string, number> ?? {}
  const cvd = p.counts_by_verdict as Record<string, number> ?? {}
  const all = counts.all ?? SEV_ORDER.reduce((s, k) => s + (counts[k] ?? 0), 0)

  return (
    <div className="card" onClick={onClick} style={{ position: 'relative' }}>
      <button
        className="card-delete-btn"
        onClick={onDelete}
        title="Удалить проект"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="16" height="16">
          <path d="M3 6h18M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2M10 11v6M14 11v6"/>
        </svg>
      </button>
      <div className="card-top">
        <div className="repo-ic">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M4 4h11l5 5v11H4z"/><path d="M15 4v5h5"/>
          </svg>
        </div>
        <div style={{ minWidth: 0 }}>
          <div className="nm">{p.name}</div>
          <div className="rp">{p.repo}</div>
        </div>
      </div>

      <div className="meta-row">
        <span>Находок: <b>{all}</b></span>
        {p.last_run && <span>Инструмент: <b>{p.last_run.tool}</b></span>}
        {p.last_run && <span>Коммит: <b className="mono">{p.last_run.commit}</b></span>}
      </div>

      <SevBar counts={counts} />
      <div className="sevleg">
        {SEV_ORDER.filter(s => counts[s]).map(s => (
          <span key={s}>
            <i className="dot" style={{ background: SEV[s].c }} />
            {SEV[s].label} {counts[s]}
          </span>
        ))}
      </div>

      <div className="triage-line">
        <div className="tl-h">
          <span>Триаж</span>
          <span>{triagePct(cvd)}% размечено</span>
        </div>
        <VBar counts={cvd} />
      </div>
    </div>
  )
}

function SkeletonGrid() {
  return (
    <div className="grid">
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="sk-card">
          <div className="skel" style={{ width: '60%', height: 16, marginBottom: 14 }} />
          <div className="skel" style={{ width: '90%', height: 10, marginBottom: 8 }} />
          <div className="skel" style={{ width: '100%', height: 7, marginBottom: 12 }} />
          <div className="skel" style={{ width: '70%', height: 10 }} />
        </div>
      ))}
    </div>
  )
}

export default function Projects() {
  const navigate = useNavigate()

  const qc = useQueryClient()

  // Состояние для модального окна удаления
  const [deleteModal, setDeleteModal] = useState<{
    isOpen: boolean
    projectId: string | null
    projectName: string
  }>({ isOpen: false, projectId: null, projectName: '' })
  const [pageNotice, setPageNotice] = useState<string | null>(null)

  // Мутация удаления проекта
  const deleteProjectMutation = useMutation({
    mutationFn: (projectId: string) => api.deleteProject(projectId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['projects'] })
      setPageNotice(null)
      setDeleteModal({ isOpen: false, projectId: null, projectName: '' })
    },
    onError: (error) => {
      console.error('Failed to delete project:', error)
      setPageNotice(`Не удалось удалить проект: ${error.message}`)
      setDeleteModal({ isOpen: false, projectId: null, projectName: '' })
    }
  })

  const handleDeleteClick = (e: React.MouseEvent, projectId: string, projectName: string) => {
    e.stopPropagation() // Чтобы не сработал onClick карточки
    setDeleteModal({ isOpen: true, projectId, projectName })
  }

  const handleDeleteConfirm = () => {
    if (deleteModal.projectId) {
      deleteProjectMutation.mutate(deleteModal.projectId)
    }
  }

  const handleDeleteCancel = () => {
    setDeleteModal({ isOpen: false, projectId: null, projectName: '' })
  }

  const { data, isLoading, error } = useQuery({
    queryKey: ['projects'],
    queryFn: api.projects,
    refetchInterval: 30_000,
  })

  if (isLoading) {
    return (
      <>
        <div className="page-h">
          <div className="skel" style={{ width: 160, height: 26 }} />
        </div>
        <SkeletonGrid />
      </>
    )
  }

  if (error) {
    return (
      <StatusMessage tone="error" title="Не удалось загрузить проекты">
        {String(error)}
      </StatusMessage>
    )
  }

  const projects = data?.projects ?? []

  if (projects.length === 0) {
    return (
      <>
        <div className="page-h">
          <h1>Проекты</h1>
        </div>
        {pageNotice && <StatusMessage tone="error" title="Действие не выполнено">{pageNotice}</StatusMessage>}
        <StatusMessage tone="empty" title="Проектов пока нет">
          Загрузите SARIF через <code className="mono">swb-cli enrich</code> и <code className="mono">swb-cli upload</code>.
        </StatusMessage>
      </>
    )
  }

  return (
    <>
      <div className="page-h">
        <h1>Проекты</h1>
        <p>{projects.length} {projects.length === 1 ? 'проект' : 'проектов'} · последние прогоны SAST · данные загружены через swb-cli</p>
      </div>
      {pageNotice && <StatusMessage tone="error" title="Действие не выполнено">{pageNotice}</StatusMessage>}
      <div className="grid">
        {projects.map(p => (
          <ProjectCard
            key={p.id}
            p={p}
            onClick={() => p.last_run
              ? navigate(`/projects/${p.id}/runs/${p.last_run.id}`)
              : navigate(`/projects/${p.id}`)
            }
            onDelete={(e) => handleDeleteClick(e, p.id, p.name)}
          />
        ))}
      </div>
      <ConfirmModal
        isOpen={deleteModal.isOpen}
        onClose={handleDeleteCancel}
        onConfirm={handleDeleteConfirm}
        title="Удаление проекта"
        message={`Вы уверены, что хотите удалить проект "${deleteModal.projectName}"? Это действие нельзя отменить. Все прогоны, находки и связанные данные будут удалены безвозвратно.`}
        isLoading={deleteProjectMutation.isPending}
      />
    </>
  )
}
