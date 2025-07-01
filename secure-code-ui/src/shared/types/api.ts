// secure-code-ui/src/shared/types/api.ts

// For Login
export interface UserLoginData {
  username: string;
  password: string;
  grant_type?: string;
  scope?: string;
  client_id?: string;
  client_secret?: string;
}

// Defines the shape of the data and functions in AuthContext
export interface AuthContextType {
  user: UserRead | null;
  accessToken: string | null;
  isLoading: boolean;
  initialAuthChecked: boolean;
  error: string | null;
  login: (loginData: UserLoginData) => Promise<void>;
  logout: () => Promise<void>;
  register: (registerData: UserRegisterData) => Promise<UserRead>;
  clearError: () => void;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
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
  id: string; // Usually UUID, so string
  email: string;
  is_active: boolean;
  is_superuser: boolean;
  is_verified: boolean;
}

export interface LLMConfiguration {
  id: string;
  name: string;
  provider: string;
  model_name: string;
  input_cost_per_million: number; // Renamed from input_token_cost
  output_cost_per_million: number; // Renamed from output_token_cost
  tokenizer_encoding: string | null; // Renamed from tokenizer_name
  created_at: string;
  updated_at: string;
}

export interface LLMConfigurationCreate {
  name: string;
  provider: string;
  model_name: string;
  api_key: string;
  input_cost_per_million: number; // Renamed from input_token_cost
  output_cost_per_million: number; // Renamed from output_token_cost
  tokenizer_encoding?: string | null; // Renamed from tokenizer_name
}

export interface TokenData {
  access_token: string;
  token_type: string;
}

export interface Message {
  message: string;
}

// For Code Submission
export interface FileForSubmission {
  filename: string;
  content: string; // File content as a string
}

export interface CodeSubmissionRequest {
  project_name: string;
  target_language: string;
  files: FileForSubmission[];
  selected_framework_ids: string[];
}

export interface CodeSubmissionResponse {
  submission_id: string;
  message: string;
}

// For Analysis Results
export interface Finding {
  id: number;
  rule_id?: string;
  file_path: string;
  title: string;
  cwe_id?: string;
  asvs_categories?: string[];
  attack_name_summary?: string;
  message: string;
  severity?: string;
  line_number?: number;
  code_snippet?: string;
  description?: string;
  remediation?: string;
  confidence?: string;
  references?: string[];
  fixes?: SuggestedFix[];
  cwe?: string;
}

export interface SuggestedFix {
  description?: string;
  original_snippet?: string; // ADDED
  suggested_fix?: string;
}

export interface SubmittedFile {
  file_path: string;
  findings: Finding[];
  language?: string;
  analysis_summary?: string;
  identified_components?: string[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  asvs_analysis?: Record<string, any>;
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
  submission_id: string;
  project_name: string;
  primary_language?: string;
  selected_frameworks: string[];
  analysis_timestamp: string; // ISO date string
  summary: Summary;
  files_analyzed: SubmittedFile[];
  overall_risk_score?: OverallRiskScore;
}

// --- DETAILED SARIF INTERFACES ---

export interface SARIFMessage {
  text?: string;
  markdown?: string;
  id?: string;
}

export interface SARIFArtifactLocation {
  uri?: string;
  uriBaseId?: string;
  index?: number;
  description?: SARIFMessage;
}

export interface SARIFRegion {
  startLine?: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
  charOffset?: number;
  charLength?: number;
  snippet?: {
    text: string;
  };
}

export interface SARIFPhysicalLocation {
  artifactLocation: SARIFArtifactLocation;
  region?: SARIFRegion;
  contextRegion?: SARIFRegion;
}

export interface SARIFLocation {
  id?: number;
  physicalLocation?: SARIFPhysicalLocation;
  logicalLocations?: {
    name: string;
    kind?: string;
    fullyQualifiedName?: string;
  }[];
  message?: SARIFMessage;
}

export interface SARIFReportingDescriptor {
  id: string;
  guid?: string;
  name?: string;
  shortDescription?: SARIFMessage;
  fullDescription?: SARIFMessage;
  helpUri?: string;
  help?: SARIFMessage;
  properties?: {
    tags?: string[];
    precision?: "very-high" | "high" | "medium" | "low";
    severity?: string;
  };
}

export interface SARIFResult {
  ruleId?: string;
  ruleIndex?: number;
  message: SARIFMessage;
  locations?: SARIFLocation[];
  level?: "none" | "note" | "warning" | "error";
  kind?: "fail" | "pass" | "open" | "review" | "informational" | "notApplicable";
  hostedViewerUri?: string;
  relatedLocations?: SARIFLocation[];
}

export interface SARIFToolComponent {
  name: string;
  version?: string;
  guid?: string;
  organization?: string;
  rules?: SARIFReportingDescriptor[];
}

export interface SARIFTool {
  driver: SARIFToolComponent;
  extensions?: SARIFToolComponent[];
}

export interface SARIFInvocation {
  exitCode?: number;
  executionSuccessful: boolean;
  commandLine?: string;
  startTimeUtc?: string;
  endTimeUtc?: string;
  toolExecutionNotifications?: SARIFNotification[];
}

export interface SARIFNotification {
  message: SARIFMessage;
  level?: "none" | "note" | "warning" | "error";
}

export interface SARIFVersionControlDetails {
  repositoryUri: string;
  revisionId?: string;
  branch?: string;
}

export interface SARIFRun {
  tool: SARIFTool;
  results?: SARIFResult[];
  artifacts?: {
    location: SARIFArtifactLocation;
    contents?: { text?: string; binary?: string };
  }[];
  invocations?: SARIFInvocation[];
  versionControlProvenance?: SARIFVersionControlDetails[];
}

export interface SARIFLog {
  version: "2.1.0";
  $schema?: string;
  runs: SARIFRun[];
}

// --- END DETAILED SARIF INTERFACES ---

export interface ImpactReport {
  executive_summary: string;
  vulnerability_overview: string;
  high_risk_findings_summary: string[];
  remediation_strategy: string;
  vulnerability_categories: string[];
  estimated_remediation_effort: string;
  required_architectural_changes: string[];
}

// --- Main response for analysis results ---
export interface AnalysisResultResponse {
  submission_id: string;
  status: string;
  summary_report?: SummaryReport;
  sarif_report?: SARIFLog;
  text_report?: string;
  original_code_map?: { [filePath: string]: string };
  fixed_code_map?: { [filePath: string]: string };
  error_message?: string;
  impact_report?: ImpactReport;
}
// --- END UPDATED RESPONSE ---

// For submission history list
export interface EstimatedCost {
  input_cost: number;
  predicted_output_cost: number;
  total_estimated_cost: number;
  predicted_output_tokens: number;
}

export interface ActualCost {
  total_cost: number;
  total_input_tokens: number;
  total_output_tokens: number;
  total_tokens: number;
}

export interface SubmissionHistoryItem {
  id: string;
  project_name: string;
  status: string;
  submitted_at: string; // ISO date string
  completed_at: string | null; // ISO date string
  estimated_cost: EstimatedCost | null;
  actual_cost: ActualCost | null;
}

export interface PaginatedSubmissionHistoryResponse {
  items: SubmissionHistoryItem[];
  total: number;
}

export interface ResultIndexItem {
  submission_id: string;
  project_name: string;
  completed_at: string | null;
  total_findings: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  risk_score: number;
}

export interface PaginatedResultsResponse {
  items: ResultIndexItem[];
  total: number;
}

export interface RemediationRequest {
  categories_to_fix: string[];
}

export interface EstimatedCost {
  input_cost: number;
  predicted_output_cost: number;
  total_estimated_cost: number;
  predicted_output_tokens: number;
}

export interface LLMInteractionResponse {
  id: number;
  submission_id?: string;
  file_path?: string;
  agent_name: string;
  timestamp: string; // ISO date string
  cost?: number;
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
}