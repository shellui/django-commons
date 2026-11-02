# Security

Shellui treats security issues in this library seriously. The MCP module handles multi-tenant agent authentication and must fail closed when tokens or assertions are invalid.

## Reporting a vulnerability

Email [security@shellui.com](mailto:security@shellui.com) with:

- A description of the issue and affected components
- Steps to reproduce or a proof of concept
- Impact assessment if known

Please do not open public GitHub issues for undisclosed vulnerabilities.

We aim to acknowledge reports within two business days and will coordinate disclosure and credit with you when appropriate.

## Scope

This repository contains shared Django code used by Shellui services. Vulnerabilities in how a specific service wires settings or URLs should be reported to that service's maintainers as well.
