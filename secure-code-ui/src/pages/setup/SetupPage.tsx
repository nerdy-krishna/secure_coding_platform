import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import apiClient from '../../shared/api/apiClient';
import { useAuth } from '../../shared/hooks/useAuth';
import { type SetupRequest } from '../../shared/types/api';

const SetupPage: React.FC = () => {
    const navigate = useNavigate();
    const { isSetupCompleted, isLoading } = useAuth(); // Get setup status from auth context
    const [step, setStep] = useState(1);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Redirect to login if setup is already completed
    React.useEffect(() => {
        if (!isLoading && isSetupCompleted) {
            navigate('/login');
        }
    }, [isSetupCompleted, isLoading, navigate]);

    // Show loading state while checking status
    if (isLoading) {
        return <div style={ { display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' } }> Loading...</div>;
    }

    const [formData, setFormData] = useState<SetupRequest>({
        admin_email: '',
        admin_password: '',
        llm_provider: 'openai',
        llm_api_key: '',
        llm_model: 'gpt-4o',
    });

    const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError(null);

        try {
            await apiClient.post('/setup', formData);
            navigate('/login');
        } catch (err: any) {
            console.error("Setup failed details:", err);
            const msg = err.response?.data?.detail
                ? (typeof err.response.data.detail === 'string' ? err.response.data.detail : JSON.stringify(err.response.data.detail))
                : (err.message || "Setup failed. Please try again.");
            setError(msg);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style= {{
        display: 'flex',
            justifyContent: 'center',
                alignItems: 'center',
                    minHeight: '100vh',
                        backgroundColor: '#f3f4f6',
                            fontFamily: 'Inter, sans-serif'
    }
}>
    <div style={
    {
        backgroundColor: 'white',
            padding: '2rem',
                borderRadius: '8px',
                    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
                        width: '100%',
                            maxWidth: '500px'
    }
}>
    <h1 style={ { textAlign: 'center', marginBottom: '1.5rem', color: '#111827' } }>
        Secure Coding Platform Setup
            </h1>

{
    error && (
        <div style={
        {
            backgroundColor: '#fee2e2',
                color: '#b91c1c',
                    padding: '1rem',
                        borderRadius: '4px',
                            marginBottom: '1rem'
        }
    }>
        { error }
        </div>
                )
}

<div style={ { marginBottom: '1.5rem', display: 'flex', justifyContent: 'center' } }>
    <div style={ { display: 'flex', gap: '1rem' } }>
        <span style={ { fontWeight: step === 1 ? 'bold' : 'normal', color: step === 1 ? '#2563eb' : '#9ca3af' } }> 1. Admin </span>
            < span style = {{ color: '#9ca3af' }}>& rarr; </span>
                < span style = {{ fontWeight: step === 2 ? 'bold' : 'normal', color: step === 2 ? '#2563eb' : '#9ca3af' }}> 2. LLM Config </span>
                    </div>
                    </div>

                    < form onSubmit = { handleSubmit } >
                        { step === 1 && (
                            <>
                            <div style={ { marginBottom: '1rem' } }>
                                <label style={ { display: 'block', marginBottom: '0.5rem', color: '#374151' } }> Admin Email </label>
                                    < input
type = "email"
name = "admin_email"
value = { formData.admin_email }
onChange = { handleChange }
required
style = {{
    width: '100%',
        padding: '0.75rem',
            borderRadius: '4px',
                border: '1px solid #d1d5db'
}}
                                />
    </div>
    < div style = {{ marginBottom: '1.5rem' }}>
        <label style={ { display: 'block', marginBottom: '0.5rem', color: '#374151' } }> Admin Password </label>
            < input
type = "password"
name = "admin_password"
value = { formData.admin_password }
onChange = { handleChange }
required
minLength = { 8}
style = {{
    width: '100%',
        padding: '0.75rem',
            borderRadius: '4px',
                border: '1px solid #d1d5db'
}}
                                />
    </div>
    < button
type = "button"
onClick = {() => setStep(2)}
disabled = {!formData.admin_email || !formData.admin_password}
style = {{
    width: '100%',
        backgroundColor: '#2563eb',
            color: 'white',
                padding: '0.75rem',
                    borderRadius: '4px',
                        border: 'none',
                            cursor: 'pointer',
                                opacity: (!formData.admin_email || !formData.admin_password) ? 0.5 : 1
}}
                            >
    Next
    </button>
    </>
                    )}

{
    step === 2 && (
        <>
        <div style={ { marginBottom: '1rem' } }>
            <label style={ { display: 'block', marginBottom: '0.5rem', color: '#374151' } }> LLM Provider </label>
                < select
    name = "llm_provider"
    value = { formData.llm_provider }
    onChange = { handleChange }
    style = {{
        width: '100%',
            padding: '0.75rem',
                borderRadius: '4px',
                    border: '1px solid #d1d5db'
    }
}
                                >
    <option value="openai" > OpenAI </option>
        < option value = "anthropic" > Anthropic </option>
            < option value = "gemini" > Google Gemini </option>
                </select>
                </div>
                < div style = {{ marginBottom: '1rem' }}>
                    <label style={ { display: 'block', marginBottom: '0.5rem', color: '#374151' } }> Model Name </label>
                        < input
type = "text"
name = "llm_model"
value = { formData.llm_model }
onChange = { handleChange }
required
style = {{
    width: '100%',
        padding: '0.75rem',
            borderRadius: '4px',
                border: '1px solid #d1d5db'
}}
                                />
    </div>
    < div style = {{ marginBottom: '1.5rem' }}>
        <label style={ { display: 'block', marginBottom: '0.5rem', color: '#374151' } }> API Key </label>
            < input
type = "password"
name = "llm_api_key"
value = { formData.llm_api_key }
onChange = { handleChange }
required
style = {{
    width: '100%',
        padding: '0.75rem',
            borderRadius: '4px',
                border: '1px solid #d1d5db'
}}
                                />
    </div>
    < div style = {{ display: 'flex', gap: '1rem' }}>
        <button
                                    type="button"
onClick = {() => setStep(1)}
style = {{
    flex: 1,
        backgroundColor: '#9ca3af',
            color: 'white',
                padding: '0.75rem',
                    borderRadius: '4px',
                        border: 'none',
                            cursor: 'pointer'
}}
                                >
    Back
    </button>
    < button
type = "submit"
disabled = { loading || !formData.llm_api_key}
style = {{
    flex: 1,
        backgroundColor: '#2563eb',
            color: 'white',
                padding: '0.75rem',
                    borderRadius: '4px',
                        border: 'none',
                            cursor: 'pointer',
                                opacity: (loading || !formData.llm_api_key) ? 0.5 : 1
}}
                                >
    { loading? 'Completing Setup...': 'Complete Setup' }
    </button>
    </div>
    </>
                    )}
</form>
    </div>
    </div>
    );
};

export default SetupPage;
