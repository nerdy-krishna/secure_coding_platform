// docs/src/pages/index.js
import React from 'react';
import clsx from 'clsx';
import Layout from '@theme/Layout';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import styles from './index.module.css';

function HomepageHeader() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <h1 className="hero__title">{siteConfig.title}</h1>
        <p className="hero__subtitle">{siteConfig.tagline}</p>
        <div className={styles.buttons}>
          <Link
            className="button button--secondary button--lg"
            to="/docs/"> {/* Links to your intro.md via slug: / */}
            Get Started - Read the Docs
          </Link>
        </div>
      </div>
    </header>
  );
}

export default function Home() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title={`Welcome to ${siteConfig.title}`}
      description="Secure Coding Platform - AI-powered open-source platform for secure code analysis, generation, and multi-framework compliance.">
      <HomepageHeader />
      <main>
        <section className={styles.features}>
          <div className="container">
            <div className="row">
              <div className={clsx('col col--4')}>
                {/* You can add more feature blocks here */}
                <h3>Proactive Security</h3>
                <p>Get AI-driven guidance and generate secure code snippets based on leading security frameworks.</p>
              </div>
              <div className={clsx('col col--4')}>
                <h3>Comprehensive Analysis</h3>
                <p>Utilize multi-path vulnerability detection including LLMs, SAST/SCA tools, and custom queries.</p>
              </div>
              <div className={clsx('col col--4')}>
                <h3>Open Source & Extensible</h3>
                <p>Built as a full-scope open-source platform, the Secure Coding Platform is ready for community contributions and custom integrations.</p>
              </div>
            </div>
          </div>
        </section>
      </main>
    </Layout>
  );
}