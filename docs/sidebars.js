// docs/sidebars.js
/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docsSidebar: [
    {
      type: 'category',
      label: 'Introduction',
      items: ['intro'], 
    },
    {
      type: 'category',
      label: 'Getting Started',
      items: [
        'getting-started/installation',
        'getting-started/configuration',
      ],
    },
    {
      type: 'category',
      label: 'User Guide',
      items: [
        'user-guide/index', // Link to the new placeholder
      ],
    },
    {
      type: 'category',
      label: 'Developer Guide',
      items: [
        'developer-guide/index', // Link to the new placeholder
      ],
    },
    {
      type: 'category',
      label: 'API Reference',
      items: [
        'api-reference/index', // Link to the new placeholder
      ],
    },
    {
      type: 'category',
      label: 'Security Frameworks',
      items: [
        'security-frameworks/index', // Link to the new placeholder
      ],
    }
  ],
};

module.exports = sidebars;