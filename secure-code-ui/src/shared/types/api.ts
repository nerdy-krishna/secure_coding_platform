// secure-code-ui/src/shared/types/api.ts

import { type UUID } from "crypto";

// For Login
export interface UserLoginData {
  username: string;
  password: string;
  grant_type?: string;
  scope?: string;
  client_id?: string;
  client_secret?: string;
}

// For Registration
export interface UserRegisterData {
  email: string;
  password: string;
  is_active?: boolean;
  is_superuser?: boolean;
  is_verified?: boolean;
}

// For User Read
export interface UserRead {
  id: string;
  email: string;
  is_active: boolean;
  is_superuser: boolean;
  is_verified: boolean;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

export interface LLMConfiguration {
  id: string;
  name: string;
  provider: string;
  model_name: string;
  input_cost_per_million: number;
  output_cost_per_million: number;
  created_at: string;
  updated_at: string;
}

export interface LLMConfigurationCreate {
  name: string;
  provider: string;
  model_name: string;
  api_key: string;
  input_cost_per_million: number;
  output_cost_per_million: number;
}

// --- Chat Schemas (NEW) ---
export interface ChatSessionCreateRequest {
  title: string;
  project_id?: string;
  llm_config_id: string;
  frameworks: string[];
}

export interface ChatSession {
  id: string;
  title: string;
  project_id?: string;
  llm_config_id?: string;
  frameworks?: string[];
  created_at: string;
}

export interface AskQuestionRequest {
  question: string;
}

export interface ChatMessage {
  id: number;
  role: "user" | "assistant";
  content: string;
  timestamp: string;
  cost?: number;
}

// --- Agent & Framework Schemas (NEW) ---
export interface AgentBase {
  name: string;
  description: string;
  domain_query: string;
}

export type AgentCreate = AgentBase;

export interface AgentUpdate {
  name?: string;
  description?: string;
  domain_query?: string;
}

export interface AgentRead {
  id: string;
  name: string;
  description: string;
  domain_query: string;
}

export interface FrameworkBase {
  name: string;
  description: string;
}

export type FrameworkCreate = FrameworkBase;

export interface FrameworkUpdate {
  name?: string;
  description?: string;
}

export interface FrameworkRead extends FrameworkBase {
  id: string;
  agents: AgentRead[];
}

export interface FrameworkAgentMappingUpdate {
  agent_ids: string[];
}

// --- RAG Management Schemas ---
export interface RAGDocument {
  id: string;
  document: string;
  metadata: Record<string, JsonValue>;
}

export interface RAGDocumentDeleteRequest {
  document_ids: string[];
}

export interface EnrichedDocument {
  id: string;
  original_document: string;
  enriched_content: string;
  metadata: Record<string, JsonValue>;
}

export interface PreprocessingResponse {
  framework_name: string;
  llm_config_name: string;
  processed_documents: EnrichedDocument[];
}

export interface RAGJobStartResponse {
  job_id: string;
  framework_name: string;
  status: string;
  estimated_cost?: { [key: string]: JsonValue };
  message: string;
}

export interface RAGJobStatusResponse {
  job_id: string;
  framework_name: string;
  status: string;
  estimated_cost?: { [key: string]: JsonValue };
  actual_cost?: number;
  processed_documents?: EnrichedDocument[];
  error_message?: string;
}

// --- Prompt Template Schemas ---
export interface PromptTemplateBase {
  name: string;
  template_type: string;
  agent_name?: string | null;
  version: number;
  template_text: string;
}

export interface PromptTemplateRead extends PromptTemplateBase {
  id: string;
}

export type PromptTemplateCreate = PromptTemplateBase;

export interface PromptTemplateUpdate {
  name?: string;
  template_type?: string;
  agent_name?: string | null;
  version?: number;
  template_text?: string;
}

// --- Submission Schemas (NEW) ---
export type ScanType = "AUDIT" | "SUGGEST" | "REMEDIATE";
export interface SubmissionFormValues {
  project_name: string;
  scan_type: ScanType;
  repo_url?: string;
  main_llm_config_id: string;
  specialized_llm_config_id: string;
  frameworks: string[];
}

export interface ScanResponse {
    scan_id: UUID;
    project_id: UUID; // ADD THIS
    message: string;
}

export interface GitRepoPreviewRequest {
    repo_url: string;
}

export interface SuggestedFix {
  description?: string;
  original_snippet?: string;
  code?: string;
}

export interface Finding {
  id: number;
  file_path: string;
  title: string;
  cwe: string;
  description: string;
  severity: string;
  line_number: number;
  remediation: string;
  confidence: string;
  agent_name?: string;
  references: string[];
  fixes?: SuggestedFix;
}

export interface SubmittedFile {
  file_path: string;
  findings: Finding[];
  language?: string;
  analysis_summary?: string;
}

export interface SeverityCounts {
  CRITICAL?: number;
  HIGH?: number;
  MEDIUM?: number;
  LOW?: number;
  INFORMATIONAL?: number;
}

export interface Summary {
  total_findings_count?: number;
  files_analyzed_count?: number;
  severity_counts?: SeverityCounts;
}

export interface OverallRiskScore {
  score: number | string;
  severity: string;
}

export interface SummaryReport {
  scan_id: string;
  project_id: string;
  project_name: string;
  scan_type: string;
  primary_language?: string;
  selected_frameworks: string[];
  analysis_timestamp: string;
  summary: Summary;
  files_analyzed: SubmittedFile[];
  overall_risk_score?: OverallRiskScore;
}

export interface ImpactReport {
  executive_summary: string;
  vulnerability_overview: string;
  high_risk_findings_summary: string[];
  remediation_strategy: string;
  vulnerability_categories: string[];
  estimated_remediation_effort: string;
  required_architectural_changes: string[];
}

export interface ScanResultResponse {
  scan_id: string;
  status: string;
  summary_report?: SummaryReport;
  impact_report?: ImpactReport;
  sarif_report?: { [key: string]: JsonValue }; // ADD THIS LINE
  original_code_map?: { [filePath: string]: string };
  fixed_code_map?: { [filePath: string]: string };
}

export interface CostDetails {
  input_cost: number;
  predicted_output_cost: number;
  total_estimated_cost: number;
  predicted_output_tokens: number;
}

export interface ScanEventItem {
  stage_name: string;
  status: string;
  timestamp: string;
}

export interface ScanHistoryItem {
  id: UUID;
  project_id: UUID;
  project_name: string;
  scan_type: string;
  status: string;
  created_at: string;
  completed_at: string | null;
  cost_details: CostDetails | null;
  events: ScanEventItem[];
  has_sarif_report: boolean;
  has_impact_report: boolean;
  llm_interactions?: LLMInteractionResponse[];
}

export interface PaginatedScanHistoryResponse {
  items: ScanHistoryItem[];
  total: number;
}

export interface ProjectHistoryItem {
    id: UUID;
    name: string;
    repository_url: string | null;
    created_at: string;
    updated_at: string;
    scans: ScanHistoryItem[];
}

export interface PaginatedProjectHistoryResponse {
    items: ProjectHistoryItem[];
    total: number;
}

// Defines a type for any valid JSON value, improving type safety over 'any'
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };


export interface LLMInteractionResponse {
  id: number;
  scan_id?: string;
  file_path?: string;
  agent_name: string;
  timestamp: string;
  cost?: number;
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
  prompt_template_name?: string | null;
  prompt_context?: Record<string, JsonValue> | null;
  parsed_output?: Record<string, JsonValue> | null;
  error?: string | null;
}