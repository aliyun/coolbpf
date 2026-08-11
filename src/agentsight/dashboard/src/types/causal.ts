//! Types for the causal attribution offline analysis pipeline.
//!
//! Matches the JSON contract defined in `agentsight_causal_attribution_DEV.md` §7.

export type CausalNodeKind =
  | 'ok'
  | 'seed'
  | 'root'
  | 'sym'
  | 'good'
  | 'env'
  | 'shipped'
  | 'cf'
  | 'user';

export type CausalEdgeType = 'n' | 'bad' | 'refute';

export type CausalAttrib = 'model' | 'skill' | 'prompt' | 'agent';

export type CausalOutcome = 'success' | 'fail';

/** One candidate attribution the evaluator considers plausible. The primary
 *  attribution lives on `CausalCase.attrib`; the rest are listed here so the
 *  user can swap in an alternative if they disagree with the top pick. */
export interface AlternativeAttrib {
  attrib: CausalAttrib;
  /** 0..1 — evaluator's self-reported confidence in this candidate. */
  confidence: number;
  /** One-line reason why this candidate is plausible. */
  rationale: string;
  /** Concrete fix targeted at this candidate's attribution object. */
  fix: string;
}

export interface CausalNode {
  id: string;
  step?: number;
  kind: CausalNodeKind;
  tag: string;
  foot?: string;
  plain: string;
  raw?: string;
}

export interface CausalEdge {
  a: string;
  b: string;
  type: CausalEdgeType;
}

export interface CausalContra {
  saw: string;
  said: string;
}

export interface CausalCase {
  id: string;
  title: string;
  task: string;
  session: string;
  trigger?: string;
  verdict: string;
  root_one: string;
  outcome: CausalOutcome;
  outcome_note?: string;
  turn_issue?: string;
  attrib: CausalAttrib;
  fix: string;
  /** Other candidates the evaluator considered plausible (sorted by confidence desc). */
  alternative_attribs?: AlternativeAttrib[];
  timeline?: string[];
  nodes: CausalNode[];
  edges: CausalEdge[];
  contra?: CausalContra;
  concl?: string;
}

export interface CausalAttributionRequest {
  session_id: string;
  round_index?: number;
  complaint: string;
  /** When true, bypass the server-side cache and rerun the LLM pipeline. */
  force?: boolean;
  /**
   * Scope hint: "conversation" means `session_id` actually carries a
   * conversation_id and the backend should attribute only that sub-conversation.
   * Unset / any other value → whole-session scope.
   */
  id_kind?: 'session' | 'conversation';
}

export interface CausalAttributionResponse {
  case: CausalCase;
  /** True when the case came from the server's in-memory cache. */
  cached: boolean;
}
