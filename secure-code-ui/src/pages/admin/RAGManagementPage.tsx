// secure-code-ui/src/pages/admin/RAGManagementPage.tsx
//
// RAG / Security-Standards knowledge-base admin page. Ported to SCCAP
// primitives. The heavy ingestion wizard (FrameworkIngestionModal)
// still uses antd — porting that end-to-end is substantial and tracked
// as a G.7 follow-up; the outer page shell, cards, job banner, and
// document viewer all move to SCCAP tokens here.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AxiosError } from "axios";
import { saveAs } from "file-saver";
import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { frameworkService } from "../../shared/api/frameworkService";
import { llmConfigService } from "../../shared/api/llmConfigService";
import { ragService } from "../../shared/api/ragService";
import type {
  EnrichedDocument,
  FrameworkRead,
  LLMConfiguration,
  PreprocessingResponse,
  RAGDocument,
  RAGJobStatusResponse,
} from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";
import { FrameworkIngestionModal } from "./FrameworkIngestionModal";

function axiosErrorDetail(err: unknown): string {
  const e = err as {
    response?: { data?: { detail?: string } };
    message?: string;
  };
  return e.response?.data?.detail || e.message || "Unknown error";
}

// -----------------------------------------------------------------------------
// Document viewer modal
// -----------------------------------------------------------------------------

const ViewDocumentsModal: React.FC<{
  frameworkName: string;
  open: boolean;
  onClose: () => void;
}> = ({ frameworkName, open, onClose }) => {
  const { data: documents, isLoading, isError } = useQuery<
    RAGDocument[],
    Error
  >({
    queryKey: ["ragDocuments", frameworkName],
    queryFn: () => ragService.getDocuments(frameworkName),
    enabled: open,
  });

  const metadataKeys = React.useMemo(
    () =>
      documents
        ? Array.from(
            new Set(documents.flatMap((d) => Object.keys(d.metadata))),
          )
        : [],
    [documents],
  );

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={`Documents in "${frameworkName}"`}
      width="min(1100px, 95vw)"
      footer={
        <button className="sccap-btn sccap-btn-sm" onClick={onClose}>
          Close
        </button>
      }
    >
      {isLoading ? (
        <div
          style={{
            padding: 40,
            textAlign: "center",
            color: "var(--fg-muted)",
          }}
        >
          Loading documents…
        </div>
      ) : isError ? (
        <div
          style={{
            padding: 20,
            color: "var(--critical)",
            fontSize: 13,
          }}
        >
          Error loading documents.
        </div>
      ) : !documents || documents.length === 0 ? (
        <div
          style={{
            padding: 20,
            color: "var(--fg-muted)",
            fontSize: 13,
          }}
        >
          No documents for this framework.
        </div>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table className="sccap-t">
            <thead>
              <tr>
                <th>ID</th>
                <th style={{ minWidth: 280 }}>Content</th>
                {metadataKeys.map((k) => (
                  <th key={k}>{k.replace(/_/g, " ")}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {documents.map((d) => (
                <tr key={d.id} style={{ cursor: "default" }}>
                  <td className="mono" style={{ fontSize: 11 }}>
                    {d.id}
                  </td>
                  <td
                    style={{
                      fontSize: 12,
                      maxWidth: 420,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                    title={d.document}
                  >
                    {d.document}
                  </td>
                  {metadataKeys.map((k) => {
                    const val = (d.metadata as Record<string, unknown>)[k];
                    if (typeof val === "boolean") {
                      return (
                        <td key={k}>
                          <span
                            className={`chip ${val ? "chip-success" : ""}`}
                          >
                            {val ? "Yes" : "No"}
                          </span>
                        </td>
                      );
                    }
                    return (
                      <td
                        key={k}
                        style={{
                          fontSize: 12,
                          color: "var(--fg-muted)",
                        }}
                      >
                        {val !== undefined && val !== null
                          ? String(val)
                          : "—"}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Modal>
  );
};

// -----------------------------------------------------------------------------
// Framework card — used for both standard and custom frameworks
// -----------------------------------------------------------------------------

type CardType = "scanning" | "knowledge" | "custom";

const FrameworkCard: React.FC<{
  name: string;
  displayName: string;
  description: string;
  docCount?: number;
  cardType: CardType;
  installed: boolean;
  isLoading?: boolean;
  onView: () => void;
  onEdit: () => void;
  onIngest: () => void;
  onDelete: () => void;
}> = ({
  displayName,
  description,
  docCount,
  cardType,
  installed,
  isLoading,
  onView,
  onEdit,
  onIngest,
  onDelete,
}) => {
  const badgeColor =
    cardType === "scanning"
      ? "chip-info"
      : cardType === "knowledge"
        ? "chip-medium"
        : "chip-ai";
  const badgeLabel =
    cardType === "scanning"
      ? "Scanning standard"
      : cardType === "knowledge"
        ? "Knowledge base"
        : "Custom";
  const badgeIcon =
    cardType === "scanning"
      ? Icon.Shield
      : cardType === "knowledge"
        ? Icon.BookOpen
        : Icon.Layers;
  const BadgeIcon = badgeIcon;

  return (
    <div className="sccap-card">
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          marginBottom: 8,
        }}
      >
        <div style={{ fontWeight: 600, color: "var(--fg)" }}>
          {displayName}
        </div>
        {docCount !== undefined && docCount > 0 && (
          <span className="chip chip-success">{docCount} docs</span>
        )}
      </div>
      <div style={{ marginBottom: 10 }}>
        <span className={`chip ${badgeColor}`}>
          <BadgeIcon size={10} /> {badgeLabel}
        </span>
      </div>
      <div
        style={{
          fontSize: 12.5,
          color: "var(--fg-muted)",
          lineHeight: 1.5,
          marginBottom: 14,
          minHeight: 46,
          display: "-webkit-box",
          WebkitLineClamp: 3,
          WebkitBoxOrient: "vertical",
          overflow: "hidden",
        }}
      >
        {description}
      </div>
      <div
        style={{
          display: "flex",
          gap: 4,
          paddingTop: 10,
          borderTop: "1px solid var(--border)",
          justifyContent: "space-between",
        }}
      >
        <div style={{ display: "flex", gap: 4 }}>
          {installed && (
            <>
              <button
                className="sccap-btn sccap-btn-icon sccap-btn-ghost sccap-btn-sm"
                aria-label="View documents"
                title="View documents"
                onClick={onView}
              >
                <Icon.Eye size={13} />
              </button>
              <button
                className="sccap-btn sccap-btn-icon sccap-btn-ghost sccap-btn-sm"
                aria-label="Edit or add languages"
                title="Edit or re-ingest"
                onClick={onEdit}
              >
                <Icon.Edit size={13} />
              </button>
            </>
          )}
          <button
            className="sccap-btn sccap-btn-ghost sccap-btn-sm"
            aria-label={installed ? "Re-upload" : "Upload"}
            title={installed ? "Re-upload source" : "Upload framework"}
            onClick={onIngest}
            disabled={isLoading}
          >
            <Icon.Upload size={13} />{" "}
            {isLoading ? "Working…" : installed ? "Re-upload" : "Upload"}
          </button>
        </div>
        {installed && (
          <button
            className="sccap-btn sccap-btn-icon sccap-btn-ghost sccap-btn-sm"
            aria-label="Delete"
            title="Delete documents"
            onClick={onDelete}
            style={{ color: "var(--critical)" }}
          >
            <Icon.Trash size={13} />
          </button>
        )}
      </div>
    </div>
  );
};

// -----------------------------------------------------------------------------
// Main page
// -----------------------------------------------------------------------------

const RAGManagementPage: React.FC = () => {
  const toast = useToast();
  const queryClient = useQueryClient();

  const [pollingJobId, setPollingJobId] = useState<string | null>(null);
  const [ingestionModalOpen, setIngestionModalOpen] = useState(false);
  const [ingestionInitialValues, setIngestionInitialValues] = useState<
    { frameworkName: string; isEdit?: boolean } | undefined
  >(undefined);
  const [ingestLoading, setIngestLoading] = useState<string | null>(null);

  const [proactiveOpen, setProactiveOpen] = useState(false);
  const [cheatsheetOpen, setCheatsheetOpen] = useState(false);
  const [proactiveUrl, setProactiveUrl] = useState(
    "https://github.com/OWASP/www-project-proactive-controls/tree/master/docs/the-top-10",
  );
  const [cheatsheetUrl, setCheatsheetUrl] = useState(
    "https://github.com/OWASP/CheatSheetSeries/tree/master/cheatsheets",
  );

  const [scanReady, setScanReady] = useState(true);
  const [viewName, setViewName] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<{
    name: string;
    isCustom: boolean;
    id?: string;
  } | null>(null);

  useEffect(() => {
    const stored = sessionStorage.getItem("rag_processing_job_id");
    if (stored) setPollingJobId(stored);
  }, []);

  // Deep-link from the Compliance page: /admin/rag?framework=proactive_controls&action=git-ingest
  // auto-opens the relevant ingestion dialog so admins can act immediately.
  const [searchParams, setSearchParams] = useSearchParams();
  useEffect(() => {
    const framework = searchParams.get("framework");
    const action = searchParams.get("action");
    if (action !== "git-ingest" || !framework) return;
    if (framework === "proactive_controls") setProactiveOpen(true);
    if (framework === "cheatsheets") setCheatsheetOpen(true);
    // ASVS opens the hidden file input (CSV-only).
    if (framework === "asvs") {
      document.getElementById("hidden-asvs-input")?.click();
    }
    // Strip the params so a reload doesn't re-trigger.
    const next = new URLSearchParams(searchParams);
    next.delete("framework");
    next.delete("action");
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams]);

  const { data: frameworks = [], isLoading: isLoadingFrameworks } = useQuery<
    FrameworkRead[]
  >({
    queryKey: ["frameworks"],
    queryFn: frameworkService.getFrameworks,
  });

  const { data: llmConfigs = [] } = useQuery<LLMConfiguration[]>({
    queryKey: ["llmConfigs"],
    queryFn: llmConfigService.getLlmConfigs,
  });

  const {
    data: stats = { asvs: 0, proactive_controls: 0, cheatsheets: 0 },
    isLoading: isLoadingStats,
    refetch: refetchStats,
  } = useQuery<Record<string, number>>({
    queryKey: ["ragStats"],
    queryFn: ragService.getStats,
  });

  const {
    data: jobStatus,
    isFetching: isPolling,
    refetch: pollStatus,
  } = useQuery<RAGJobStatusResponse, Error>({
    queryKey: ["ragJobStatus", pollingJobId],
    queryFn: () => {
      if (!pollingJobId) throw new Error("No job ID to poll");
      return ragService.getJobStatus(pollingJobId);
    },
    enabled: !!pollingJobId,
    refetchOnWindowFocus: true,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "PROCESSING" || status === "PENDING_APPROVAL"
        ? 3000
        : false;
    },
  });

  const approveMutation = useMutation({
    mutationFn: (jobId: string) => ragService.approveJob(jobId),
    onSuccess: () => {
      toast.success("Job approved; processing in background.");
      pollStatus();
    },
  });

  const ingestMutation = useMutation({
    mutationFn: (payload: PreprocessingResponse) =>
      ragService.ingestProcessed(payload),
    onSuccess: (data: { message: string }) => {
      toast.success(data.message);
      queryClient.invalidateQueries({ queryKey: ["frameworks"] });
      handleReset();
    },
    onError: (error: AxiosError) => {
      const detail =
        (error.response?.data as { detail?: string })?.detail || error.message;
      toast.error(`Ingestion failed: ${detail}`);
    },
  });

  const deleteCustomMutation = useMutation({
    mutationFn: (id: string) => frameworkService.deleteFramework(id),
    onSuccess: () => {
      toast.success("Custom framework deleted.");
      queryClient.invalidateQueries({ queryKey: ["frameworks"] });
    },
    onError: (error: AxiosError) =>
      toast.error(`Delete failed: ${error.message}`),
  });

  const handleOpenIngestionModal = (
    frameworkName?: string,
    isEdit = false,
  ) => {
    setIngestionInitialValues(
      frameworkName ? { frameworkName, isEdit } : undefined,
    );
    setIngestionModalOpen(true);
  };

  const handleIngestionSuccess = (jobId: string) => {
    setPollingJobId(jobId);
    sessionStorage.setItem("rag_processing_job_id", jobId);
    pollStatus();
  };

  const handleReset = () => {
    setPollingJobId(null);
    sessionStorage.removeItem("rag_processing_job_id");
    setScanReady(true);
  };

  const handleDownload = () => {
    if (!jobStatus?.processed_documents?.length) return;
    const { processed_documents, framework_name } = jobStatus;
    const metaKeys = Object.keys(processed_documents[0].metadata || {}).sort();
    const header = ["id", "document", ...metaKeys].join(",");
    const rows = processed_documents.map((doc: EnrichedDocument) => {
      const metaVals = metaKeys.map((k) => {
        const v = doc.metadata[k as keyof typeof doc.metadata] ?? "";
        return `"${String(v).replace(/"/g, '""')}"`;
      });
      return [
        `"${doc.id}"`,
        `"${doc.enriched_content.replace(/"/g, '""')}"`,
        ...metaVals,
      ].join(",");
    });
    const csv = `${header}\n${rows.join("\n")}`;
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    saveAs(blob, `${framework_name}_processed.csv`);
  };

  const handleUploadASVS = async (file: File) => {
    setIngestLoading("asvs");
    try {
      // ragService.ingestASVS accepts any File-shaped object; antd RcFile
      // inherits from File at runtime, so a native File is equivalent.
      const res = await ragService.ingestASVS(
        file as unknown as Parameters<typeof ragService.ingestASVS>[0],
      );
      toast.success(res.message);
      refetchStats();
      queryClient.invalidateQueries({ queryKey: ["ragDocuments", "asvs"] });
    } catch (error) {
      toast.error(`ASVS ingestion failed: ${axiosErrorDetail(error)}`);
    } finally {
      setIngestLoading(null);
    }
  };

  const handleFetchProactive = async () => {
    setIngestLoading("proactive");
    try {
      const res = await ragService.ingestProactiveControls(proactiveUrl);
      toast.success(res.message);
      refetchStats();
      setProactiveOpen(false);
      queryClient.invalidateQueries({
        queryKey: ["ragDocuments", "proactive_controls"],
      });
    } catch (error) {
      toast.error(`Proactive Controls fetch failed: ${axiosErrorDetail(error)}`);
    } finally {
      setIngestLoading(null);
    }
  };

  const handleFetchCheatsheets = async () => {
    setIngestLoading("cheatsheet");
    try {
      const res = await ragService.ingestCheatsheet(cheatsheetUrl);
      toast.success(res.message);
      refetchStats();
      setCheatsheetOpen(false);
      queryClient.invalidateQueries({
        queryKey: ["ragDocuments", "cheatsheets"],
      });
    } catch (error) {
      toast.error(`Cheatsheets fetch failed: ${axiosErrorDetail(error)}`);
    } finally {
      setIngestLoading(null);
    }
  };

  const handleDeleteStandard = async (frameworkName: string) => {
    try {
      const docs = await ragService.getDocuments(frameworkName);
      if (docs && docs.length > 0) {
        await ragService.deleteDocuments(docs.map((d) => d.id));
        toast.success(`Deleted ${docs.length} documents for ${frameworkName}.`);
        refetchStats();
      } else {
        toast.info("No documents to delete.");
      }
    } catch (error) {
      toast.error(`Delete failed: ${axiosErrorDetail(error)}`);
    }
  };

  const customFrameworks = frameworks.filter(
    (fw) => !["asvs", "proactive_controls", "cheatsheets"].includes(fw.name),
  );

  // -------- Job status banner --------
  const renderJobBanner = () => {
    if (!pollingJobId || !jobStatus) return null;

    if (jobStatus.status === "PENDING_APPROVAL") {
      return (
        <div
          className="sccap-card"
          style={{
            background: "var(--medium-weak)",
            borderColor: "var(--medium)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: 16,
          }}
        >
          <div>
            <div
              style={{
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: ".06em",
                color: "var(--medium)",
                fontWeight: 600,
              }}
            >
              Pending approval
            </div>
            <div style={{ color: "var(--fg)", marginTop: 2 }}>
              {jobStatus.framework_name}
            </div>
          </div>
          <button
            className="sccap-btn sccap-btn-primary sccap-btn-sm"
            onClick={() => approveMutation.mutate(pollingJobId)}
            disabled={approveMutation.isPending}
          >
            <Icon.Check size={12} /> Approve
          </button>
        </div>
      );
    }

    if (jobStatus.status === "PROCESSING" || isPolling) {
      return (
        <div
          className="sccap-card"
          style={{
            background: "var(--info-weak)",
            borderColor: "var(--info)",
            padding: 16,
          }}
        >
          <div
            style={{
              fontSize: 11,
              textTransform: "uppercase",
              letterSpacing: ".06em",
              color: "var(--info)",
              fontWeight: 600,
            }}
          >
            Processing
          </div>
          <div style={{ color: "var(--fg)", marginTop: 2 }}>
            {jobStatus.framework_name || "…"}
          </div>
          <div style={{ fontSize: 12.5, color: "var(--fg-muted)", marginTop: 4 }}>
            Enriching documents with LLM patterns. This may take a few minutes.
          </div>
        </div>
      );
    }

    if (jobStatus.status === "COMPLETED") {
      const finalPayload: PreprocessingResponse = {
        framework_name: jobStatus.framework_name,
        llm_config_name: "",
        processed_documents: jobStatus.processed_documents || [],
        scan_ready: scanReady,
      };
      return (
        <div
          className="sccap-card"
          style={{
            borderColor: "var(--success)",
            padding: 16,
            display: "grid",
            gap: 12,
          }}
        >
          <div>
            <div
              style={{
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: ".06em",
                color: "var(--success)",
                fontWeight: 600,
              }}
            >
              Preprocessing complete
            </div>
            <div style={{ color: "var(--fg)", marginTop: 2 }}>
              {jobStatus.framework_name}
            </div>
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
            }}
          >
            <div
              className={`sccap-switch ${scanReady ? "on" : ""}`}
              role="switch"
              aria-checked={scanReady}
              tabIndex={0}
              onClick={() => setScanReady(!scanReady)}
              onKeyDown={(e) => {
                if (e.key === " " || e.key === "Enter") {
                  e.preventDefault();
                  setScanReady(!scanReady);
                }
              }}
            />
            <span style={{ fontSize: 13, color: "var(--fg)" }}>
              {scanReady
                ? "Scan-ready (used by the scanner agent)"
                : "Chat-context only"}
            </span>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={handleDownload}
            >
              <Icon.Download size={12} /> Download CSV
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={() => ingestMutation.mutate(finalPayload)}
              disabled={ingestMutation.isPending}
            >
              <Icon.Plus size={12} /> Finalize ingestion
            </button>
            <button className="sccap-btn sccap-btn-sm" onClick={handleReset}>
              Cancel
            </button>
          </div>
        </div>
      );
    }

    if (jobStatus.status === "FAILED") {
      return (
        <div
          className="sccap-card"
          style={{
            background: "var(--critical-weak)",
            borderColor: "var(--critical)",
            padding: 16,
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <div>
            <div
              style={{
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: ".06em",
                color: "var(--critical)",
                fontWeight: 600,
              }}
            >
              Job failed
            </div>
            <div style={{ color: "var(--fg)", marginTop: 2, fontSize: 13 }}>
              {jobStatus.error_message}
            </div>
          </div>
          <button className="sccap-btn sccap-btn-sm" onClick={handleReset}>
            Close
          </button>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="fade-in" style={{ display: "grid", gap: 18 }}>
      <div>
        <h1 style={{ color: "var(--fg)" }}>
          <Icon.BookOpen size={18} /> Knowledge base
        </h1>
        <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
          Security standards and RAG sources used for scanning and advisor
          context.
        </div>
      </div>

      {renderJobBanner()}

      {isLoadingFrameworks || isLoadingStats ? (
        <div
          className="sccap-card"
          style={{
            padding: 40,
            textAlign: "center",
            color: "var(--fg-muted)",
          }}
        >
          Loading frameworks…
        </div>
      ) : (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
            gap: 14,
          }}
        >
          <div
            className="sccap-card"
            onClick={() => handleOpenIngestionModal()}
            style={{
              display: "grid",
              placeItems: "center",
              minHeight: 200,
              borderStyle: "dashed",
              borderColor: "var(--border-strong)",
              background: "var(--bg-soft)",
              cursor: "pointer",
              textAlign: "center",
            }}
          >
            <div>
              <Icon.Plus size={20} />
              <div
                style={{
                  fontWeight: 500,
                  color: "var(--fg)",
                  marginTop: 8,
                }}
              >
                Add custom framework
              </div>
              <div
                style={{
                  fontSize: 12,
                  color: "var(--fg-muted)",
                  marginTop: 2,
                }}
              >
                Upload CSV or define a new standard.
              </div>
            </div>
          </div>

          <FrameworkCard
            name="asvs"
            displayName="OWASP ASVS"
            description="Application Security Verification Standard. Best for comprehensive auditing."
            docCount={stats.asvs || 0}
            cardType="scanning"
            installed={(stats.asvs || 0) > 0}
            isLoading={ingestLoading === "asvs"}
            onView={() => setViewName("asvs")}
            onEdit={() => handleOpenIngestionModal("asvs", true)}
            onIngest={() =>
              document.getElementById("hidden-asvs-input")?.click()
            }
            onDelete={() =>
              setConfirmDelete({ name: "asvs", isCustom: false })
            }
          />
          <input
            type="file"
            id="hidden-asvs-input"
            accept=".csv"
            style={{ display: "none" }}
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) handleUploadASVS(file);
              e.target.value = "";
            }}
          />

          <FrameworkCard
            name="proactive_controls"
            displayName="OWASP Proactive Controls"
            description="Developer-focused controls (C1-C10). Great for chat context."
            docCount={stats.proactive_controls || 0}
            cardType="knowledge"
            installed={(stats.proactive_controls || 0) > 0}
            isLoading={ingestLoading === "proactive"}
            onView={() => setViewName("proactive_controls")}
            onEdit={() => setProactiveOpen(true)}
            onIngest={() => setProactiveOpen(true)}
            onDelete={() =>
              setConfirmDelete({ name: "proactive_controls", isCustom: false })
            }
          />

          <FrameworkCard
            name="cheatsheets"
            displayName="OWASP Cheatsheets"
            description="Topic-specific security cheatsheets."
            docCount={stats.cheatsheets || 0}
            cardType="knowledge"
            installed={(stats.cheatsheets || 0) > 0}
            isLoading={ingestLoading === "cheatsheet"}
            onView={() => setViewName("cheatsheets")}
            onEdit={() => setCheatsheetOpen(true)}
            onIngest={() => setCheatsheetOpen(true)}
            onDelete={() =>
              setConfirmDelete({ name: "cheatsheets", isCustom: false })
            }
          />

          {customFrameworks.map((fw) => (
            <FrameworkCard
              key={fw.id}
              name={fw.name}
              displayName={fw.name}
              description={fw.description}
              cardType="custom"
              installed
              onView={() => setViewName(fw.name)}
              onEdit={() => handleOpenIngestionModal(fw.name, true)}
              onIngest={() => handleOpenIngestionModal(fw.name, true)}
              onDelete={() =>
                setConfirmDelete({
                  name: fw.name,
                  isCustom: true,
                  id: fw.id,
                })
              }
            />
          ))}
        </div>
      )}

      {viewName && (
        <ViewDocumentsModal
          frameworkName={viewName}
          open={viewName !== null}
          onClose={() => setViewName(null)}
        />
      )}

      {/* Ingestion wizard — left on antd for now; tracked in G.7. */}
      <FrameworkIngestionModal
        visible={ingestionModalOpen}
        onCancel={() => setIngestionModalOpen(false)}
        onSuccess={handleIngestionSuccess}
        initialValues={ingestionInitialValues}
        llmConfigs={llmConfigs}
      />

      <Modal
        open={proactiveOpen}
        onClose={() => setProactiveOpen(false)}
        title="Fetch Proactive Controls"
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setProactiveOpen(false)}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={handleFetchProactive}
              disabled={ingestLoading === "proactive"}
            >
              {ingestLoading === "proactive" ? "Fetching…" : "Start fetch"}
            </button>
          </>
        }
      >
        <label style={{ display: "grid", gap: 6 }}>
          <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
            GitHub URL
          </span>
          <input
            className="sccap-input mono"
            value={proactiveUrl}
            onChange={(e) => setProactiveUrl(e.target.value)}
            style={{ fontSize: 12 }}
          />
        </label>
      </Modal>

      <Modal
        open={cheatsheetOpen}
        onClose={() => setCheatsheetOpen(false)}
        title="Fetch Cheatsheets"
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setCheatsheetOpen(false)}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={handleFetchCheatsheets}
              disabled={ingestLoading === "cheatsheet"}
            >
              {ingestLoading === "cheatsheet" ? "Fetching…" : "Start fetch"}
            </button>
          </>
        }
      >
        <label style={{ display: "grid", gap: 6 }}>
          <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
            GitHub URL
          </span>
          <input
            className="sccap-input mono"
            value={cheatsheetUrl}
            onChange={(e) => setCheatsheetUrl(e.target.value)}
            style={{ fontSize: 12 }}
          />
        </label>
      </Modal>

      <Modal
        open={confirmDelete !== null}
        onClose={() => setConfirmDelete(null)}
        title={
          confirmDelete?.isCustom
            ? "Delete custom framework?"
            : "Delete standard documents?"
        }
        width={460}
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setConfirmDelete(null)}
              disabled={deleteCustomMutation.isPending}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-danger sccap-btn-sm"
              onClick={() => {
                if (!confirmDelete) return;
                if (confirmDelete.isCustom && confirmDelete.id) {
                  deleteCustomMutation.mutate(confirmDelete.id);
                } else {
                  handleDeleteStandard(confirmDelete.name);
                }
                setConfirmDelete(null);
              }}
              disabled={deleteCustomMutation.isPending}
            >
              {deleteCustomMutation.isPending ? "Deleting…" : "Delete"}
            </button>
          </>
        }
      >
        <div style={{ color: "var(--fg-muted)", fontSize: 13 }}>
          {confirmDelete?.isCustom
            ? `This removes the framework "${confirmDelete?.name}" and all of its ingested documents. The action cannot be undone.`
            : `This removes every ingested document for "${confirmDelete?.name}". You can re-ingest from source at any time.`}
        </div>
      </Modal>
    </div>
  );
};

export default RAGManagementPage;
