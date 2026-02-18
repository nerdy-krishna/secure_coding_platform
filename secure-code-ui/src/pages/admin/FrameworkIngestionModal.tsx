import React, { useState, useEffect } from "react";
import {
    Modal,
    Form,
    Input,
    Upload,
    Button,
    Select,
    Checkbox,
    Typography,
    Space,
    Alert,
    message,
    Steps,
    Divider,
} from "antd";
import {
    UploadOutlined,
    CloudUploadOutlined,
    FileTextOutlined,
    DollarOutlined,
} from "@ant-design/icons";
import { ragService } from "../../shared/api/ragService";
import type { LLMConfiguration, RAGJobStartResponse } from "../../shared/types/api";
import type { RcFile } from "antd/es/upload";
import { saveAs } from "file-saver";

const { Title, Text, Paragraph } = Typography;
const { Option } = Select;
const { Step } = Steps;

interface FrameworkIngestionModalProps {
    visible: boolean;
    onCancel: () => void;
    onSuccess: (jobId: string) => void;
    initialValues?: {
        frameworkName: string;
        isEdit?: boolean;
    };
    llmConfigs: LLMConfiguration[];
}

const SUPPORTED_LANGUAGES = [
    { label: "Python", value: "python" },
    { label: "JavaScript / TypeScript", value: "javascript" },
    { label: "Java", value: "java" },
    { label: "C# / .NET", value: "csharp" },
    { label: "Go", value: "go" },
    { label: "C / C++", value: "cpp" },
    { label: "Ruby", value: "ruby" },
    { label: "PHP", value: "php" },
    { label: "Swift", value: "swift" },
    { label: "Kotlin", value: "kotlin" },
];

export const FrameworkIngestionModal: React.FC<FrameworkIngestionModalProps> = ({
    visible,
    onCancel,
    onSuccess,
    initialValues,
    llmConfigs,
}) => {
    const [form] = Form.useForm();
    const [currentStep, setCurrentStep] = useState(0);
    const [loading, setLoading] = useState(false);
    const [jobData, setJobData] = useState<RAGJobStartResponse | null>(null);
    const [fileList, setFileList] = useState<RcFile[]>([]);

    const isEdit = !!initialValues?.isEdit;

    // Reset state when modal opens/closes
    useEffect(() => {
        if (visible) {
            form.resetFields();
            if (initialValues) {
                form.setFieldsValue({
                    frameworkName: initialValues.frameworkName,
                });
            }
            setJobData(null);
            setCurrentStep(0);
            setFileList([]);
        }
    }, [visible, initialValues, form]);

    const handleDownloadTemplate = () => {
        const csvContent = "id,document\n1,Authentication guidelines...\n2,Input validation rules...";
        const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
        saveAs(blob, "framework_template.csv");
    };

    const onGetEstimate = async () => {
        try {
            const values = await form.validateFields();
            setLoading(true);

            const { frameworkName, targetLanguages, llmConfigId } = values;

            let response: RAGJobStartResponse;

            if (fileList.length > 0) {
                // Option A: File Upload (New or Edit with File)
                const formData = new FormData();
                formData.append("file", fileList[0]);
                formData.append("framework_name", frameworkName);
                formData.append("llm_config_id", llmConfigId);

                response = await ragService.startPreprocessing(formData, targetLanguages || []);
            } else if (isEdit) {
                // Option B: Reprocess existing content (Edit without File)
                response = await ragService.reprocessFramework(
                    frameworkName,
                    targetLanguages || [],
                    llmConfigId
                );
            } else {
                message.error("Please upload a CSV file.");
                setLoading(false);
                return;
            }

            setJobData(response);
            setCurrentStep(1); // Move to review step
        } catch (error: any) {
            console.error("Estimation failed:", error);
            message.error(error.response?.data?.detail || "Failed to get cost estimate.");
        } finally {
            setLoading(false);
        }
    };

    const onSubmitJob = async () => {
        if (!jobData) return;
        try {
            setLoading(true);
            await ragService.approveJob(jobData.job_id);
            message.success("Ingestion job started successfully!");
            onSuccess(jobData.job_id);
            onCancel();
        } catch (error: any) {
            console.error("Job approval failed:", error);
            message.error("Failed to start job.");
        } finally {
            setLoading(false);
        }
    };

    const uploadProps = {
        onRemove: () => {
            setFileList([]);
        },
        beforeUpload: (file: RcFile) => {
            setFileList([file]);
            return false; // Prevent automatic upload
        },
        fileList,
        maxCount: 1,
        accept: ".csv",
    };

    return (
        <Modal
      title= { isEdit? "Update Framework": "Add Custom Framework" }
    open = { visible }
    onCancel = { onCancel }
    footer = { null}
    width = { 700}
    maskClosable = { false}
    destroyOnClose
        >
        <Steps current={ currentStep } style = {{ marginBottom: 24 }
}>
    <Step title="Configuration" icon = {< FileTextOutlined />} />
        < Step title = "Review Cost" icon = {< DollarOutlined />} />
            < Step title = "Processing" icon = {< CloudUploadOutlined />} />
                </Steps>

{
    currentStep === 0 && (
        <Form form={ form } layout = "vertical" initialValues = {{ }
}>
    <Alert
            message="Secure Coding Guidelines"
description = {
    isEdit
    ? "Update your framework by adding language-specific patterns. You can use the existing documents or upload a new CSV."
        : "Upload a CSV file containing your security standards. We will generate code patterns for your selected languages."
}
type = "info"
showIcon
style = {{ marginBottom: 24 }}
          />

    < Form.Item
name = "frameworkName"
label = "Framework Name"
rules = {
    [
        { required: true, message: "Please enter a framework name" },
        { pattern: /^[a-zA-Z0-9_-]+$/, message: "Use only letters, numbers, underscores, and hyphens." },
            ]}
    >
    <Input placeholder="e.g., custom_security_standard" disabled = { isEdit } />
        </Form.Item>

        < Form.Item label = "Source File (CSV)" >
            <Space direction="vertical" style = {{ width: "100%" }}>
                <Upload { ...uploadProps } >
                <Button icon={
    <UploadOutlined />}>Select CSV File</Button >
        </Upload>
    {
        !fileList.length && isEdit && (
            <Text type="secondary" style = {{ fontSize: 12 }
    }>
                  * Leave empty to re - use existing documents from previous jobs.
                </Text>
              )
}
<Button type="link" size = "small" onClick = { handleDownloadTemplate } style = {{ paddingLeft: 0 }}>
    Download Sample Template
        </Button>
        </Space>
        </Form.Item>

        < Form.Item
name = "targetLanguages"
label = "Target Languages for Code Patterns"
extra = "Select languages to generate secure/vulnerable code examples for."
    >
    <Checkbox.Group options={ SUPPORTED_LANGUAGES } style = {{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px' }} />
        </Form.Item>

        < Form.Item
name = "llmConfigId"
label = "LLM Configuration"
rules = { [{ required: true, message: "Please select an LLM configuration" }]}
extra = "Select the model to use for analyzing documents and generating patterns."
    >
    <Select placeholder="Select LLM Configuration" >
    {
        llmConfigs.map((config) => (
            <Option key= { config.id } value = { config.id } >
            { config.name }({ config.provider } - { config.model_name })
            </Option>
        ))
    }
        </Select>
        </Form.Item>

        < Divider />
        <div style={ { textAlign: "right" } }>
            <Button onClick={ onCancel } style = {{ marginRight: 8 }}>
                Cancel
                </Button>
                < Button type = "primary" onClick = { onGetEstimate } loading = { loading } >
                    Get Cost Estimate
                        </Button>
                        </div>
                        </Form>
      )}

{
    currentStep === 1 && jobData && (
        <div>
        <Alert
            message="Ready to Process"
    description = "Please review the estimated cost before starting the job."
    type = "success"
    showIcon
    style = {{ marginBottom: 24 }
}
          />

    < div style = {{ background: "#f5f5f5", padding: 16, borderRadius: 8, marginBottom: 24 }}>
        <Title level={ 4 } style = {{ marginTop: 0 }}> Job Summary </Title>
            < Paragraph > <strong>Framework: </strong> {jobData.framework_name}</Paragraph >
                <Paragraph>
                <strong>Estimated Cost: </strong> $
{
    jobData.estimated_cost?.total_estimated_cost
        ? (Number(jobData.estimated_cost.total_estimated_cost) > 0 && Number(jobData.estimated_cost.total_estimated_cost) < 0.0001 ? "< 0.0001" : Number(jobData.estimated_cost.total_estimated_cost).toFixed(4))
        : "0.0000"
}
</Paragraph>
    < Paragraph >
    <strong>Input Tokens: </strong> {Number(jobData.estimated_cost?.total_input_tokens) || 0} |
        < strong > Output Tokens: </strong> {Number(jobData.estimated_cost?.predicted_output_tokens) || 0}
            </Paragraph>
            </div>

            < div style = {{ textAlign: "right" }}>
                <Button onClick={ () => setCurrentStep(0) } style = {{ marginRight: 8 }}>
                    Back
                    </Button>
                    < Button type = "primary" onClick = { onSubmitJob } loading = { loading } >
                        Submit Job
                            </Button>
                            </div>
                            </div>
      )}
</Modal>
  );
};
