# CONTRIBUTING to `@bsv/templates`

Thank you for considering contributing to the BSV Blockchain Script Templates Project! This document outlines the processes and practices we expect contributors to adhere to.

## Table of Contents

1. [General Guidelines](#general-guidelines)
2. [Code of Conduct](#code-of-conduct)
3. [Getting Started](#getting-started)
4. [Pull Request Process](#pull-request-process)
5. [Coding Conventions](#coding-conventions)
6. [Documentation and Testing](#documentation-and-testing)
7. [Contact & Support](#contact--support)

## General Guidelines

- **Issues First**: If you're planning to add a new template or change existing behavior, please open an issue first. This allows us to avoid multiple people working on similar templates and provides a place for discussion.
  
- **Stay Updated**: Always pull the latest changes from the main branch before creating a new branch or starting on new code.
  
- **Simplicity Over Complexity**: Your template should be as simple as possible, given the requirements.

## Code of Conduct

### Posting Issues and Comments

- **Be Respectful**: Everyone is here to help and grow. Avoid any language that might be considered rude or offensive.
  
- **Be Clear and Concise**: Always be clear about what you're suggesting or reporting. If an issue is related to a particular piece of code or a specific error message, include that in your comment.
  
- **Stay On Topic**: Keep the conversation relevant to the issue at hand. If you have a new idea or unrelated question, please open a new issue.

### Coding and PRs

- **Stay Professional**: Avoid including "fun" code, comments, or irrelevant file changes in your commits and pull requests.

## Getting Started

1. **Fork the Repository**: Click on the "Fork" button at the top-right corner of this repository.
  
2. **Clone the Forked Repository**: `git clone https://github.com/YOUR_USERNAME/ts-templates.git`

3. **Navigate to the Directory**: `cd ts-templates`

4. **Install Dependencies**: Always run `npm i` after pulling to ensure tooling is up to date.

## Pull Request Process

1. **Create a Branch**: For every new feature or bugfix, create a new branch.
  
2. **Commit Your Changes**: Make your changes and commit them. Commit messages should be clear and concise to explain what was done.
  
3. **Run Tests**: Ensure all tests pass using Jest: `npm test`.
  
4. **Documentation**: All code must be fully annotated with comments.
  
5. **Push to Your Fork**: `git push origin your-new-branch`.
  
6. **Open a Pull Request**: Go to your fork on GitHub and click "New Pull Request". Fill out the PR template, explaining your changes.
  
7. **Code Review**: At least one maintainer must review and approve the PR before it's merged. Address any feedback or changes requested.
  
8. **Merge**: Once approved, the PR will be merged into the main branch.

## Coding Conventions

- **Code Style**: We use `ts-standard` for our TypeScript coding style. Run `npm run lint` to ensure your code adheres to this style.
  
- **Minimal Runtime Dependencies**: Code should not depend on external systems where possible, with a strong preference for maintaining things internally. The one exception is the `@bsv/sdk` library dependency.
  
- **Testing**: Always include tests for new code or changes. We aim for industry-standard levels of test coverage.
  
- **Documentation**: All functions, classes, and modules should be documented. Use annotation comments to describe the purpose, parameters, and return values.

## Documentation and Testing

- **Documentation**: Update the documentation whenever you add or modify the code.
  
- **Testing**: We use Jest for all tests. Write comprehensive tests, ensuring edge cases are covered. All PRs should maintain or improve the current test coverage.

## Contact & Support

If you have any questions or need assistance with your contributions, feel free to reach out. Remember, we're here to help each other grow and improve the `@bsv/templates`.

Thank you for being a part of this journey. Your contributions help shape the future of the BSV Blockchain!
