// secure-code-ui/src/pages/SubmitCodePage.tsx
import { CodeOutlined, InboxOutlined } from '@ant-design/icons'; // Removed unused UploadOutlined
import {
  Button,
  Card,
  Checkbox,
  Col,
  Form,
  Input,
  message,
  Row,
  Select,
  Typography,
  Upload,
} from 'antd';
import type { RcFile, UploadFile, UploadProps } from 'antd/es/upload/interface';
import React, { useCallback, useState } from 'react'; // Added useCallback
import { useNavigate } from 'react-router-dom';
import { submissionService } from '../services/submissionService';
import { type CodeSubmissionRequest, type FileForSubmission } from '../types/api';

const { Title } = Typography;
const { Dragger } = Upload;
const { Option } = Select;

const supportedLanguages = [
  { value: 'python', label: 'Python' },
  { value: 'javascript', label: 'JavaScript' },
  { value: 'typescript', label: 'TypeScript' },
  { value: 'java', label: 'Java' },
  { value: 'go', label: 'Go' },
  { value: 'rust', label: 'Rust' },
  { value: 'php', label: 'PHP' },
];

const availableFrameworks = [
  { id: 'OWASP_TOP_10_2021', name: 'OWASP Top 10 2021' },
  { id: 'ASVS_L1', name: 'OWASP ASVS Level 1' },
  { id: 'ASVS_L2', name: 'OWASP ASVS Level 2' },
  { id: 'ASVS_L3', name: 'OWASP ASVS Level 3' },
  // Add more frameworks as needed
];

const SubmitCodePage: React.FC = () => {
  const [form] = Form.useForm();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [fileList, setFileList] = useState<UploadFile[]>([]);

  const handleFileRead = useCallback(async (file: RcFile): Promise<FileForSubmission> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.readAsText(file, 'UTF-8'); // Specify encoding
      reader.onload = () => {
        if (typeof reader.result === 'string') {
          resolve({
            filename: file.name,
            content: reader.result,
          });
        } else {
          reject(new Error(`Failed to read file ${file.name} as text.`));
        }
      };
      reader.onerror = (errorEvent) => {
        console.error("FileReader error:", errorEvent);
        reject(new Error(`Error reading file ${file.name}: ${reader.error?.message || 'Unknown error'}`));
      };
    });
  }, []);

  const onFinish = async (values: {
    projectName: string;
    targetLanguage: string;
    frameworks: string[];
  }) => {
    if (fileList.length === 0) {
      message.error('Please upload at least one code file.');
      return;
    }

    setLoading(true);
    // Key for message.loading must be unique or managed if you have multiple loading messages
    const processingMessageKey = 'fileProcessing';
    message.loading({ content: 'Processing files...', key: processingMessageKey, duration: 0 }); // duration 0 for manual dismissal

    try {
      const filesToSubmit: FileForSubmission[] = await Promise.all(
        fileList.map(async (uploadFile) => {
          // Ensure originFileObj exists; it should if beforeUpload is setting it correctly.
          if (uploadFile.originFileObj) {
            return handleFileRead(uploadFile.originFileObj as RcFile);
          }
          // This path should ideally not be reached if fileList is managed correctly
          console.error('Error: originFileObj missing for file:', uploadFile.name);
          throw new Error(`Could not prepare file for submission: ${uploadFile.name}. It might be corrupted or was not added correctly.`);
        }),
      );

      message.success({ content: 'Files processed. Submitting for analysis...', key: processingMessageKey, duration: 2 });

      const payload: CodeSubmissionRequest = {
        project_name: values.projectName,
        target_language: values.targetLanguage,
        files: filesToSubmit,
        selected_framework_ids: values.frameworks,
      };

      const response = await submissionService.submitCode(payload);
      message.success(`Analysis submitted successfully! Submission ID: ${response.submission_id}`, 5);
      form.resetFields();
      setFileList([]);
      navigate(`/results/${response.submission_id}`);
    } catch (error: unknown) {
      message.destroy(processingMessageKey); // Dismiss loading message on error
      console.error('Submission failed:', error);
      let errorMessage = 'Submission failed.';
      if (error instanceof Error) {
        errorMessage = error.message;
      }
      message.error(errorMessage, 5);
    } finally {
      setLoading(false);
      // Ensure message is cleared if it wasn't replaced by success/error
      // This might not be necessary if success/error messages always replace it or it auto-dismisses.
      // message.destroy(processingMessageKey); 
    }
  };

  const uploadProps: UploadProps = {
    onRemove: (file) => {
      setFileList((prevFileList) => {
        const index = prevFileList.findIndex(item => item.uid === file.uid);
        if (index === -1) return prevFileList;
        const newFileList = prevFileList.slice();
        newFileList.splice(index, 1);
        return newFileList;
      });
    },
    beforeUpload: (file: RcFile /*, currentFileList: RcFile[]*/) => {
      // Check for duplicate file names before adding, if desired
      // if (fileList.some(f => f.name === file.name)) {
      //   message.error(`File "${file.name}" is already in the list.`);
      //   return Upload.LIST_IGNORE; // Prevents adding to the list
      // }

      // Create a proper UploadFile object to add to our state
      // Ant Design's UploadFile needs a uid, name, and often status.
      // originFileObj holds the actual File/RcFile.
      const newUploadFile: UploadFile = {
        uid: file.uid, // RcFile has uid
        name: file.name,
        originFileObj: file, // CRITICAL: Store the RcFile here
        status: 'done', // Set status to 'done' as we handle it manually
                        // Or use a custom status like 'selected' or 'manual'
        size: file.size,
        type: file.type,
      };

      setFileList((prevFileList) => [...prevFileList, newUploadFile]);
      return false; // Prevent antd from uploading automatically
    },
    fileList, // Controlled component: uses our fileList state
    multiple: true,
    accept: '.py,.js,.ts,.java,.go,.php,.txt,text/*,application/zip,application/x-zip-compressed',
  };

  return (
    <div style={{ maxWidth: '800px', margin: '40px auto', padding: '20px' }}>
      <Card>
        <Title level={2} style={{ textAlign: 'center', marginBottom: '30px' }}>
          <CodeOutlined /> Submit Code for Analysis
        </Title>
        <Form
          form={form}
          layout="vertical"
          onFinish={onFinish}
          initialValues={{ frameworks: ['OWASP_TOP_10_2021'] }}
        >
          <Form.Item
            name="projectName"
            label="Project Name"
            rules={[{ required: true, message: 'Please input the project name!' }]}
          >
            <Input placeholder="e.g., My Awesome Web App" />
          </Form.Item>

          <Form.Item
            name="targetLanguage"
            label="Primary Target Language"
            rules={[{ required: true, message: 'Please select the target language!' }]}
          >
            <Select placeholder="Select language">
              {supportedLanguages.map((lang) => (
                <Option key={lang.value} value={lang.value}>
                  {lang.label}
                </Option>
              ))}
            </Select>
          </Form.Item>

          <Form.Item
            name="frameworks"
            label="Security Frameworks / Guidelines"
            rules={[{ required: true, message: 'Please select at least one framework!' }]}
          >
             <Checkbox.Group style={{ width: '100%' }}>
                <Row gutter={[16,16]}> {/* Added gutter for spacing */}
                {availableFrameworks.map(fw => (
                    <Col xs={24} sm={12} md={8} key={fw.id}> {/* Responsive columns */}
                    <Checkbox value={fw.id}>{fw.name}</Checkbox>
                    </Col>
                ))}
                </Row>
            </Checkbox.Group>
          </Form.Item>

          <Form.Item
            name="upload"
            label="Upload Code Files"
            // valuePropName="fileList" // Not needed when list is controlled externally and validated
            rules={[
                {
                    // eslint-disable-next-line @typescript-eslint/no-unused-vars
                    validator: async (_rule, _value) => {
                        if (fileList.length === 0) {
                            return Promise.reject(new Error('Please upload at least one file.'));
                        }
                        return Promise.resolve();
                    },
                },
            ]}
          >
            <Dragger {...uploadProps}>
              <p className="ant-upload-drag-icon">
                <InboxOutlined />
              </p>
              <p className="ant-upload-text">Click or drag file(s) to this area to upload</p>
              <p className="ant-upload-hint">
                Support for single or multiple files. Only text-based files will be read.
              </p>
            </Dragger>
          </Form.Item>

          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} block>
              Submit for Analysis
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </div>
  );
};

export default SubmitCodePage;