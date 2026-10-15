# PowerShell Administration Console (PAC)

A local-first administration and learning application built with
Python, FastAPI, PowerShell 7, Vue 3, Bootstrap 5, and SQLite.

## Project goals

- Run a defined catalogue of approved administrative tasks.
- Start with harmless, read-only diagnostics.
- Validate all task parameters in the backend.
- Record task execution metadata and outcomes locally.
- Provide automated tests and documented security controls.

## Security principles

- Never expose arbitrary shell or PowerShell execution.
- Run the backend as the normal logged-in user.
- Bind the backend to 127.0.0.1 by default.
- Validate inputs and enforce process timeouts and output limits.
- Avoid storing secrets and unnecessary sensitive output.

## Development environment

- Manjaro Linux
- VS Code
- Python 3
- FastAPI
- PowerShell 7
- Vue 3 and Bootstrap 5
- SQLite and pytest

## Project status

Phase 1: Foundation.