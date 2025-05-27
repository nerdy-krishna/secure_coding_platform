# Contributing to the Secure Coding Platform

First off, thank you for considering contributing to the Secure Coding Platform! We welcome contributions from everyone and are excited to see this project grow with the help of the community. Your contributions, whether big or small, are valuable to us.

This document provides guidelines for contributing to the platform. Please take a moment to review it.

## Table of Contents

- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements or Features](#suggesting-enhancements-or-features)
  - [Submitting Code Changes](#submitting-code-changes)
  - [Improving Documentation](#improving-documentation)
- [Setting Up Your Development Environment](#setting-up-your-development-environment)
- [Coding Standards](#coding-standards)
- [Pull Request Process](#pull-request-process)
- [Code of Conduct](#code-of-conduct)
- [Getting Help](#getting-help)

## How Can I Contribute?

There are many ways to contribute to the Secure Coding Platform:

### Reporting Bugs

If you encounter a bug, please help us by reporting it. Before creating a bug report, please check existing issues to see if someone has already reported it.

When creating a bug report, please include:
* A clear and descriptive title.
* Steps to reproduce the bug.
* What you expected to happen.
* What actually happened (including any error messages or screenshots).
* Your environment details (e.g., OS, Docker version, browser version if frontend related).

You can report bugs by [opening an issue](https://github.com/your-username/secure-code-platform/issues) on GitHub. ### Suggesting Enhancements or Features

We welcome suggestions for new features or enhancements to existing ones.
* Clearly describe the feature or enhancement you are proposing.
* Explain why this feature would be useful to users of the Secure Coding Platform.
* If possible, provide examples or mockups.

You can suggest enhancements by [opening an issue](https://github.com/your-username/secure-code-platform/issues) on GitHub, labeling it as an "enhancement" or "feature request". ### Submitting Code Changes

If you'd like to contribute code:
1.  Fork the repository.
2.  Create a new branch for your feature or bug fix (`git checkout -b feature/your-feature-name` or `git checkout -b fix/your-bug-fix`).
3.  Make your changes, adhering to the [Coding Standards](#coding-standards).
4.  Write tests for your changes if applicable.
5.  Ensure your changes pass all existing tests.
6.  Commit your changes with clear and descriptive commit messages.
7.  Push your branch to your fork.
8.  Open a pull request against the `main` branch of the upstream repository.

### Improving Documentation

Clear and comprehensive documentation is vital. If you find areas for improvement, typos, or missing information in our [documentation](./docs/docs/intro.md) (TODO: update link to live docs site), please feel free to submit a pull request or open an issue.

## Setting Up Your Development Environment

To set up the platform for local development, please follow the [Installation Guide](./docs/docs/getting-started/installation.md).

For development, ensure you install all dependencies, including development dependencies:
* **Backend (Poetry):** `poetry install` (from the project root)
* **Frontend (npm/yarn):** `npm install` or `yarn install` (from the `secure-code-ui` directory)

Further details on the development workflow and specific setup for different components can be found in the [Development Guide](./docs/docs/development/contributing.md) (once created).

## Coding Standards

Please adhere to the coding standards outlined in our [Coding Standards Document](./docs/docs/development/coding-standards.md) (to be created). This generally includes:
* Following linters and formatters (e.g., Ruff, Black for Python; ESLint, Prettier for TypeScript/React).
* Writing clear, maintainable, and well-commented code where necessary.
* Ensuring code is secure by design.

## Pull Request Process

1.  Ensure any install or build dependencies are removed before the end of the layer when doing a build.
2.  Update the `README.md` or other relevant documentation if your changes impact installation, configuration, or usage.
3.  Increase the version numbers in any examples and the `pyproject.toml` (if applicable) to the new version that this PR would represent. The maintainers will specify the new version number.
4.  Your PR will be reviewed by maintainers. You may be asked to make changes.
5.  Once your PR is approved and passes any CI checks, it will be merged.

## Code of Conduct

This project and everyone participating in it is governed by the [Secure Coding Platform Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior.

## Getting Help

If you have questions about contributing, need clarification, or want to discuss an idea, please:
* [Open an issue](https://github.com/your-username/secure-code-platform/issues) on GitHub. * (Optional: Add other communication channels like a Discord server or mailing list if you plan to set them up).

Thank you for contributing to making software more secure!