/**
 * Trajectory reuse labels: review what the rules decided and settle it.
 *
 * The page exists because the automatic verdicts are not trustworthy on their
 * own. Measured on real data, the deterministic rules produced seven `bad`
 * labels and every one was wrong, so `bad` is now a verdict only a person or a
 * reviewed model may reach. Confirming is therefore not busywork: it is the
 * step that turns a guess into something an artifact can rest on.
 *
 * Both verdicts stay on screen for the same reason they stay in the database —
 * seeing what the rules said next to what a person decided is how a misfiring
 * rule gets noticed.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';

import { useI18n } from '../i18n';
import {
  confirmReuseLabels,
  decideReuseLabel,
  fetchReuseLabelStats,
  fetchReuseSessions,
  runReuseJudgements,
  runReuseTriage,
} from '../utils/apiClient';
import {
  ASSIGNABLE_LABELS,
  type ConfirmState,
  type JudgeReport,
  type LabelStatsResponse,
  type SessionLabelView,
  type TrajectoryLabel,
  type TriageReport,
} from '../types/reuse';

const LABEL_STYLES: Record<TrajectoryLabel, string> = {
  good: 'bg-green-100 text-green-800 border-green-300',
  bad: 'bg-red-100 text-red-800 border-red-300',
  useless: 'bg-gray-100 text-gray-600 border-gray-300',
  unknown: 'bg-amber-50 text-amber-800 border-amber-300',
};

const STATE_STYLES: Record<ConfirmState, string> = {
  unconfirmed: 'text-gray-500',
  confirmed: 'text-green-700',
  overridden: 'text-blue-700',
};

/** Rows per request. The list is for working through, not for browsing. */
const PAGE_LIMIT = 200;

/**
 * A label for a trajectory that has no title.
 *
 * Real Qoder transcripts often record only the tool loop, with no user text to
 * lift a title from. A bare UUID is unrecognisable, so fall back to the project
 * and the day it ran — enough to place the session — and only to the id when
 * even those are missing.
 */
function fallbackName(row: SessionLabelView): string {
  const parts: string[] = [];
  if (row.project) parts.push(row.project);
  if (row.started_at) parts.push(row.started_at.slice(0, 10));
  return parts.length > 0 ? parts.join(' · ') : row.session_id;
}

const LabelBadge: React.FC<{ label: TrajectoryLabel; title?: string }> = ({ label, title }) => (
  <span
    title={title}
    className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${LABEL_STYLES[label]}`}
  >
    {label}
  </span>
);

export const ReuseLabelsPage: React.FC = () => {
  const { t } = useI18n();
  const [rows, setRows] = useState<SessionLabelView[]>([]);
  const [labelFilter, setLabelFilter] = useState<TrajectoryLabel | ''>('');
  const [stateFilter, setStateFilter] = useState<ConfirmState | ''>('');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [triage, setTriage] = useState<TriageReport | null>(null);
  const [judge, setJudge] = useState<JudgeReport | null>(null);
  const [stats, setStats] = useState<LabelStatsResponse | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetchReuseSessions({
        label: labelFilter || undefined,
        confirmState: stateFilter || undefined,
        limit: PAGE_LIMIT,
      });
      setRows(response.sessions);
      // Selections that are no longer on screen would be confirmed invisibly.
      setSelected(new Set());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [labelFilter, stateFilter]);

  useEffect(() => {
    void load();
  }, [load]);

  const counts = useMemo(() => {
    const tally: Record<string, number> = {};
    rows.forEach((row) => {
      tally[row.effective_label] = (tally[row.effective_label] ?? 0) + 1;
    });
    return tally;
  }, [rows]);

  const pendingCount = useMemo(
    () => rows.filter((row) => !row.human_backed).length,
    [rows],
  );

  /** Replaces one row in place, so a decision does not reorder the list under
   * the reader's cursor. */
  const replaceRow = (updated: SessionLabelView) => {
    setRows((current) =>
      current.map((row) => (row.session_id === updated.session_id ? updated : row)),
    );
  };

  const runAction = async (key: string, action: () => Promise<void>) => {
    setBusy(key);
    setError(null);
    try {
      await action();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const onDecide = (row: SessionLabelView, label?: TrajectoryLabel) =>
    runAction(`decide:${row.session_id}`, async () => {
      const updated = await decideReuseLabel(row.session_id, {
        action: label ? 'override' : 'confirm',
        label,
      });
      replaceRow(updated);
    });

  const onConfirmSelected = () =>
    runAction('batch', async () => {
      await confirmReuseLabels(Array.from(selected));
      await load();
    });

  const onTriage = () =>
    runAction('triage', async () => {
      setTriage(await runReuseTriage(1000));
      await load();
    });

  const onJudge = () =>
    runAction('judge', async () => {
      setJudge(await runReuseJudgements({ limit: 20 }));
      await load();
    });

  const onStats = () =>
    runAction('stats', async () => {
      setStats(await fetchReuseLabelStats());
    });

  const toggle = (sessionId: string) => {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(sessionId)) next.delete(sessionId);
      else next.add(sessionId);
      return next;
    });
  };

  const toggleAllPending = () => {
    const pending = rows.filter((row) => !row.human_backed).map((row) => row.session_id);
    setSelected((current) => (current.size === pending.length ? new Set() : new Set(pending)));
  };

  return (
    <div className="p-6 space-y-4">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold text-gray-900">{t('reuse.title')}</h1>
        <p className="max-w-3xl text-sm text-gray-600">{t('reuse.intro')}</p>
      </header>

      <section className="flex flex-wrap items-center gap-3 rounded border border-gray-200 bg-white p-3">
        <button
          type="button"
          onClick={onTriage}
          disabled={busy !== null}
          className="rounded bg-blue-600 px-3 py-1.5 text-sm text-white disabled:opacity-50"
        >
          {busy === 'triage' ? t('reuse.running') : t('reuse.runTriage')}
        </button>
        <button
          type="button"
          onClick={onJudge}
          disabled={busy !== null}
          title={t('reuse.runJudgeHint')}
          className="rounded border border-blue-600 px-3 py-1.5 text-sm text-blue-700 disabled:opacity-50"
        >
          {busy === 'judge' ? t('reuse.running') : t('reuse.runJudge')}
        </button>
        <button
          type="button"
          onClick={onStats}
          disabled={busy !== null}
          className="rounded border border-gray-300 px-3 py-1.5 text-sm text-gray-700 disabled:opacity-50"
        >
          {t('reuse.showStats')}
        </button>

        <span className="mx-2 h-5 w-px bg-gray-200" />

        <select
          value={labelFilter}
          onChange={(e) => setLabelFilter(e.target.value as TrajectoryLabel | '')}
          className="rounded border border-gray-300 px-2 py-1 text-sm"
        >
          <option value="">{t('reuse.filterAllLabels')}</option>
          {(['good', 'bad', 'useless', 'unknown'] as TrajectoryLabel[]).map((label) => (
            <option key={label} value={label}>
              {label}
            </option>
          ))}
        </select>
        <select
          value={stateFilter}
          onChange={(e) => setStateFilter(e.target.value as ConfirmState | '')}
          className="rounded border border-gray-300 px-2 py-1 text-sm"
        >
          <option value="">{t('reuse.filterAllStates')}</option>
          {(['unconfirmed', 'confirmed', 'overridden'] as ConfirmState[]).map((state) => (
            <option key={state} value={state}>
              {state}
            </option>
          ))}
        </select>

        <span className="ml-auto text-sm text-gray-600">
          {t('reuse.summary', {
            total: rows.length,
            pending: pendingCount,
          })}
        </span>
      </section>

      {error && (
        <div className="rounded border-l-4 border-l-red-500 bg-red-50 p-3 text-sm text-red-800">
          {error}
        </div>
      )}

      {triage && (
        <div className="rounded border border-gray-200 bg-gray-50 p-3 text-sm text-gray-700">
          {t('reuse.triageResult', {
            examined: triage.examined,
            labelled: triage.labelled,
            unchanged: triage.unchanged,
            good: triage.auto_good,
            bad: triage.auto_bad,
            useless: triage.auto_useless,
            unknown: triage.auto_unknown,
            version: triage.triage_version,
          })}
        </div>
      )}

      {judge && (
        <div className="rounded border border-gray-200 bg-gray-50 p-3 text-sm text-gray-700">
          {t('reuse.judgeResult', {
            examined: judge.examined,
            judged: judge.judged,
            good: judge.judged_good,
            bad: judge.judged_bad,
            unclear: judge.judged_unclear,
            downgraded: judge.downgraded,
            failed: judge.failed,
          })}
          {judge.downgraded > 0 && (
            <p className="mt-1 text-amber-800">{t('reuse.downgradedNote')}</p>
          )}
        </div>
      )}

      {stats && (
        <div className="rounded border border-gray-200 bg-white p-3">
          <h2 className="mb-2 text-sm font-medium text-gray-900">{t('reuse.statsTitle')}</h2>
          {stats.rules.length === 0 ? (
            <p className="text-sm text-gray-500">{t('reuse.statsEmpty')}</p>
          ) : (
            <table className="text-sm">
              <thead>
                <tr className="text-left text-gray-500">
                  <th className="pr-6">{t('reuse.statsRule')}</th>
                  <th className="pr-6">{t('reuse.statsConfirmed')}</th>
                  <th>{t('reuse.statsOverridden')}</th>
                </tr>
              </thead>
              <tbody>
                {stats.rules.map((rule) => (
                  <tr key={rule.rule}>
                    <td className="pr-6 font-mono text-xs">{rule.rule}</td>
                    <td className="pr-6">{rule.confirmed}</td>
                    <td className={rule.overridden > 0 ? 'font-medium text-red-700' : ''}>
                      {rule.overridden}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      <section className="rounded border border-gray-200 bg-white">
        <div className="flex items-center gap-3 border-b border-gray-200 px-3 py-2 text-sm">
          <button
            type="button"
            onClick={toggleAllPending}
            className="text-blue-700 hover:underline"
          >
            {t('reuse.selectPending')}
          </button>
          <button
            type="button"
            onClick={onConfirmSelected}
            disabled={selected.size === 0 || busy !== null}
            className="rounded bg-green-600 px-2 py-1 text-xs text-white disabled:opacity-40"
          >
            {t('reuse.confirmSelected', { count: selected.size })}
          </button>
          <span className="ml-auto text-gray-500">
            {Object.entries(counts)
              .map(([label, n]) => `${label}=${n}`)
              .join('  ')}
          </span>
        </div>

        {loading ? (
          <p className="p-4 text-sm text-gray-500">{t('reuse.loading')}</p>
        ) : rows.length === 0 ? (
          <p className="p-4 text-sm text-gray-500">{t('reuse.empty')}</p>
        ) : (
          <ul className="divide-y divide-gray-100">
            {rows.map((row) => (
              <li
                key={row.session_id}
                className={`px-3 py-3 ${row.auto_changed_since_decision ? 'border-l-4 border-l-amber-500 bg-amber-50' : ''}`}
              >
                <div className="flex items-start gap-3">
                  <input
                    type="checkbox"
                    className="mt-1"
                    checked={selected.has(row.session_id)}
                    onChange={() => toggle(row.session_id)}
                    disabled={row.human_backed}
                    title={row.human_backed ? t('reuse.alreadyDecided') : undefined}
                  />
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <LabelBadge label={row.effective_label} />
                      {/* Title first — a reviewer recognises the conversation by
                          its opening request, not by a UUID. The id drops to a
                          subtitle, and a tool-only transcript with no title
                          falls back to it. */}
                      {row.title ? (
                        <span className="truncate text-sm font-medium text-gray-900">
                          {row.title}
                        </span>
                      ) : (
                        <span
                          className="truncate text-sm text-gray-500"
                          title={t('reuse.untitledHint')}
                        >
                          {fallbackName(row)}
                        </span>
                      )}
                      {row.is_subagent && (
                        <span className="rounded bg-gray-100 px-1.5 py-0.5 text-[10px] text-gray-500">
                          {t('reuse.subagent')}
                        </span>
                      )}
                      <span className={`text-xs ${STATE_STYLES[row.confirm_state]}`}>
                        {row.confirm_state}
                        {row.decided_by ? ` · ${row.decided_by}` : ''}
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 text-xs text-gray-400">
                      <code className="truncate font-mono">{row.session_id}</code>
                      {row.source && <span>· {row.source}</span>}
                      {row.project && <span className="truncate">· {row.project}</span>}
                      {row.started_at && <span>· {row.started_at}</span>}
                    </div>

                    <p className="text-xs text-gray-600">
                      {t('reuse.metrics', {
                        steps: row.n_steps,
                        turns: row.n_user_turns,
                        tools: row.n_tool_calls,
                        findings: row.n_findings,
                      })}
                    </p>

                    {/* Both verdicts stay visible: comparing them is how a
                        misfiring rule gets noticed. */}
                    <p className="text-xs text-gray-500">
                      <span className="font-medium">{t('reuse.rulesSaid')}</span>{' '}
                      {row.auto_label} — {row.auto_reason}
                      {row.auto_rules.length > 0 && (
                        <span className="ml-1 font-mono">[{row.auto_rules.join(', ')}]</span>
                      )}
                    </p>
                    {row.llm_label && (
                      <p className="text-xs text-gray-500">
                        <span className="font-medium">{t('reuse.modelSaid')}</span>{' '}
                        {row.llm_label} — {row.llm_reason}
                        {row.llm_cited_steps && row.llm_cited_steps.length > 0 && (
                          <span className="ml-1 font-mono">
                            step {row.llm_cited_steps.join(', ')}
                          </span>
                        )}
                        {row.llm_downgraded && (
                          <span className="ml-1 text-amber-700">
                            {t('reuse.modelDowngraded')}
                          </span>
                        )}
                      </p>
                    )}
                    {row.auto_changed_since_decision && (
                      <p className="text-xs text-amber-800">{t('reuse.autoChanged')}</p>
                    )}
                  </div>

                  <div className="flex shrink-0 items-center gap-1">
                    <button
                      type="button"
                      onClick={() => onDecide(row)}
                      disabled={busy !== null}
                      className="rounded border border-green-600 px-2 py-1 text-xs text-green-700 disabled:opacity-40"
                    >
                      {t('reuse.confirm')}
                    </button>
                    {ASSIGNABLE_LABELS.map((label) => (
                      <button
                        key={label}
                        type="button"
                        onClick={() => onDecide(row, label)}
                        disabled={busy !== null}
                        className={`rounded border px-2 py-1 text-xs disabled:opacity-40 ${LABEL_STYLES[label]}`}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
};

export default ReuseLabelsPage;
