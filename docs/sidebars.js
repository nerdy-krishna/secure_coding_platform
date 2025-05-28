// secure-code-platform/docs/sidebars.js
// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docsSidebar: [
    {
      type: 'category',
      label: 'Introduction',
      link: {
        type: 'generated-index',
        title: 'Introduction',
        description: 'Learn about the Secure Coding Platform.',
        slug: '/introduction',
      },
      collapsible: true,
      collapsed: false,
      items: [
        'intro', // Will map to docs/docs/intro.md
        'overview/features', // Will map to docs/docs/overview/features.md
        'overview/technology-stack',
        'overview/security-philosophy',
      ],
    },
    {
      type: 'category',
      label: 'Getting Started',
      link: {
        type: 'generated-index',
        title: 'Getting Started',
        description: 'Set up and run the platform.',
        slug: '/getting-started',
      },
      collapsible: true,
      collapsed: false,
      items: [
        'getting-started/installation',
        'getting-started/configuration',
        'getting-started/running-the-platform',
      ],
    },
    {
      type: 'category',
      label: 'User Guide',
      link: {
        type: 'generated-index',
        title: 'User Guide',
        description: 'How to use the Secure Coding Platform features.',
        slug: '/user-guide',
      },
      collapsible: true,
      collapsed: true,
      items: [
        'user-guide/dashboard-overview',
        {
          type: 'category',
          label: 'Code Analysis Portal',
          link: {type: 'generated-index', slug: '/user-guide/code-analysis'},
          items: [
            'user-guide/code-analysis/submitting-code',
            'user-guide/code-analysis/understanding-results',
            'user-guide/code-analysis/managing-findings',
            'user-guide/code-analysis/multi-framework-scanning',
          ],
        },
        {
          type: 'category',
          label: 'Chat Interfaces',
          link: {type: 'generated-index', slug: '/user-guide/chat-interfaces'},
          items: [
            'user-guide/chat-interfaces/guideline-provision',
            'user-guide/chat-interfaces/secure-code-generation',
          ],
        },
        'user-guide/unit-test-integration',
        'user-guide/reporting',
      ],
    },
    {
      type: 'category',
      label: 'Security Frameworks',
      link: {type: 'generated-index', title: 'Security Frameworks', slug: '/security-frameworks'},
      collapsible: true,
      collapsed: true,
      items: ['security-frameworks/supported-frameworks'],
    },
    {
      type: 'category',
      label: 'Platform Architecture',
      link: {type: 'generated-index', title: 'Platform Architecture', slug: '/architecture'},
      collapsible: true,
      collapsed: true,
      items: [
        'architecture/overview',
        'architecture/agent-system',
        'architecture/backend-services',
        'architecture/frontend-services',
        'architecture/data-flow',
        'architecture/llm-integration',
        'architecture/rag-system',
      ],
    },
    {
      type: 'category',
      label: 'Development',
      link: {type: 'generated-index', title: 'Development Guide', slug: '/development'},
      collapsible: true,
      collapsed: true,
      items: [
        'development/contributing',
        'development/coding-standards',
        'development/testing-strategy',
        'development/adding-new-agents',
        'development/updating-framework-knowledge',
      ],
    },
    {
      type: 'category',
      label: 'API Reference',
      link: {type: 'generated-index', title: 'API Reference', slug: '/api-reference'},
      collapsible: true,
      collapsed: true,
      items: [
         'api-reference/authentication',
         'api-reference/code-analysis-endpoints',
         'api-reference/results-endpoints',
      ],
    },
    'roadmap',
    'faq',
  ],
};

module.exports = sidebars;