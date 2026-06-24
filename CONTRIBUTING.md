# Contributing to W.H.Agent

First off, thank you for considering contributing to W.H.Agent! It's people like you that make W.H.Agent such a powerful tool for securing AI agents. We welcome any contributions, whether it's fixing bugs, improving documentation, or adding new features.

## Getting Started

1. **Fork the repository** on GitHub.
2. **Clone your fork** locally.
3. **Install dependencies**. W.H.Agent uses `pnpm` as its package manager.
   ```bash
   pnpm install
   ```

## Development Workflow

Before you start writing code, please familiarize yourself with the [Architecture Document](ARCHITECTURE.md) to understand where your changes should go.

### Building

To build all packages in the monorepo, run:
```bash
pnpm build
```

### Testing

Please ensure that you add tests for any new features or bug fixes. To run the test suite:
```bash
pnpm test
```

### Code Style

We enforce code style using standard tooling. Before submitting a pull request, please run:
```bash
pnpm lint
pnpm format
```

## Pull Request Process

1. **Create a new branch** for your feature or bugfix (e.g., `feature/awesome-new-thing` or `fix/annoying-bug`).
2. Make your changes and commit them with clear, descriptive commit messages.
3. **Push your branch** to your fork.
4. **Open a Pull Request** against the `main` branch of the upstream repository.
5. Provide a clear description of the problem you are solving and how you solved it.
6. A maintainer will review your code. Please be open to feedback and make any requested changes.

## Reporting Issues

If you find a bug or have a feature request, please open an issue on GitHub. Before doing so, check existing issues to avoid duplicates. Please provide as much context as possible, including steps to reproduce bugs.

## Code of Conduct

Please note that this project is released with a Contributor Code of Conduct. By participating in this project you agree to abide by its terms.

Thank you again for contributing!
