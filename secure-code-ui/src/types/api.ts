// secure-code-ui/src/types/api.ts

// For Login
export interface UserLoginData {
  username: string;
  password: string;
  grant_type?: string;
  scope?: string;
  client_id?: string;
  client_secret?: string;
}

// Defines the shape of the data and functions in our AuthContext
export interface AuthContextType {
  user: UserRead | null;
  accessToken: string | null;
  isLoading: boolean;
  initialAuthChecked: boolean;
  error: string | null; // Added
  login: (loginData: UserLoginData) => Promise<void>;
  logout: () => Promise<void>;
  register: (registerData: UserRegisterData) => Promise<UserRead>; // Corrected return type
  clearError: () => void; // Added
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

// For reading LLM configurations (API key is not sent)
export interface LLMConfiguration {
  id: string; // UUID as string
  name: string;
  provider: string;
  model_name: string;
  created_at: string; // ISO date-time string
  updated_at: string; // ISO date-time string
}

// For creating a new LLM configuration (includes the API key)
export interface LLMConfigurationCreate {
  name: string;
  provider: string;
  model_name: string;
  api_key: string;
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
  rule_id?: string;
  cwe_id?: string;
  asvs_categories?: string[];
  attack_name_summary?: string;
  message: string;
  severity?: string;
  line_number?: number;
  code_snippet?: string;
  description?: string;
  remediation?: string;
  confidence?: string; // Added
  references?: string[]; // Added
  fixes?: SuggestedFix[]; // Added
  // cwe_id is already present as cwe_id, but ResultsPage.tsx uses finding.cwe.
  // Let's assume cwe_id is the correct one from backend and ResultsPage needs to align,
  // or if backend sends 'cwe', then it should be added here.
  // For now, I'll add 'cwe' as per ResultsPage.tsx usage.
  cwe?: string; // Added based on ResultsPage.tsx usage
}

// New interface for suggested fixes
export interface SuggestedFix {
  description?: string;
  suggested_fix?: string;
  // Add any other properties a fix object might have
}

export interface SubmittedFile {
  file_path: string;
  findings: Finding[];
  language?: string; // Added
  analysis_summary?: string; // Added
  identified_components?: string[]; // Added
  asvs_analysis?: Record<string, any>; // Added (use a more specific type if known)
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

// --- Detailed SARIF Interfaces ---
// Based on SARIF v2.1.0. These can be expanded further as needed.

export interface SARIFMessage {
  text?: string;
  markdown?: string;
  id?: string;
  // arguments?: any[]; // For parameterized messages
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
  // ... and other region properties
}

export interface SARIFPhysicalLocation {
  artifactLocation: SARIFArtifactLocation;
  region?: SARIFRegion;
  contextRegion?: SARIFRegion;
  // ... and other physical location properties
}

export interface SARIFLocation {
  id?: number;
  physicalLocation?: SARIFPhysicalLocation;
  logicalLocations?: {
    name: string;
    kind?: string;
    fullyQualifiedName?: string;
  }[]; // Simplified
  message?: SARIFMessage;
  // ... and other location properties
}

export interface SARIFReportingDescriptor {
  // This represents a "rule"
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
    severity?: string; // Can be mapped from level
    // ... other custom properties
  };
  // ... and other descriptor properties
}

export interface SARIFResult {
  ruleId?: string; // Corresponds to SARIFReportingDescriptor.id
  ruleIndex?: number;
  message: SARIFMessage; // SARIF mandates message for each result
  locations?: SARIFLocation[];
  level?: "none" | "note" | "warning" | "error";
  kind?:
    | "fail"
    | "pass"
    | "open"
    | "review"
    | "informational"
    | "notApplicable";
  hostedViewerUri?: string;
  relatedLocations?: SARIFLocation[];
  // ... and other result properties
}

export interface SARIFToolComponent {
  // Represents the driver or extensions
  name: string;
  version?: string;
  guid?: string;
  organization?: string;
  rules?: SARIFReportingDescriptor[]; // Rules are defined within the tool component (driver)
  // ... and other tool component properties
}

export interface SARIFTool {
  driver: SARIFToolComponent; // The 'driver' is the primary analysis tool
  extensions?: SARIFToolComponent[]; // Other tools or plugins
}

export interface SARIFInvocation {
  exitCode?: number;
  executionSuccessful: boolean;
  commandLine?: string;
  startTimeUtc?: string; // ISO 8601 date-time
  endTimeUtc?: string; // ISO 8601 date-time
  toolExecutionNotifications?: SARIFNotification[]; // Defined below
  // ... other invocation properties
}

export interface SARIFNotification {
  // Used by Invocation and ReportingDescriptor
  message: SARIFMessage;
  level?: "none" | "note" | "warning" | "error";
  // ... other notification properties
}

export interface SARIFVersionControlDetails {
  repositoryUri: string;
  revisionId?: string;
  branch?: string;
  // ... other version control properties
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
  // ... and other run properties
}

export interface SARIFLog {
  version: "2.1.0"; // SARIF version
  $schema?: string; // URI of the SARIF schema
  runs: SARIFRun[]; // Uses the more specific SARIFRun interface
}

// --- End Detailed SARIF Interfaces ---

export interface AnalysisResultResponse {
  submission_id: string;
  status: string;
  summary_report?: SummaryReport;
  sarif_report?: SARIFLog; // Now uses the detailed SARIFLog
  text_report?: string;
  original_code_map?: { [filePath: string]: string };
  fixed_code_map?: { [filePathFixed: string]: string };
  error_message?: string;
}

// For submission history list
export interface SubmissionHistoryItem {
  id: string;
  project_name: string;
  primary_language: string | null;
  status: string;
  submitted_at: string; // ISO date string
  completed_at: string | null; // ISO date string
  total_findings?: number; // Optional
}
