# 🧠 How This Project Works

## The Problem

Imagine you are a Security Engineer responsible for keeping applications secure.

Your team has built a Docker image that will be deployed to production.

Before deployment, you need to answer an important question:

> **"Does this Docker image contain any known security vulnerabilities?"**

Manually inspecting every installed package inside a Docker image is practically impossible.

Instead, security teams use automated vulnerability scanners like **Trivy**.

A typical Trivy scan can produce **hundreds of vulnerabilities**.

Example:

```
Total Vulnerabilities Found : 376

Critical : 2
High     : 70
Medium   : 139
Low      : 128
Unknown  : 37
```

Reading a report containing hundreds of vulnerabilities is difficult, repetitive, and time-consuming.

This project automates that entire process.

Instead of manually reading hundreds of CVEs, the application generates a concise AI-powered security report highlighting the most important risks and recommended actions.

---

# High Level Workflow

```
Docker Image
      │
      ▼
Trivy Vulnerability Scan
      │
      ▼
JSON Report
      │
      ▼
Python Parser
      │
      ▼
Security Statistics
      │
      ▼
Prioritize Findings
      │
      ▼
Build AI Prompt
      │
      ▼
Amazon Bedrock
      │
      ▼
AI Security Report
      │
      ▼
Markdown Report
```

Each block has a single responsibility.

Let's understand what happens inside every step.

---

# Step 1 — Docker Image

A Docker image is a packaged application.

It contains:

- Operating System
- Installed software packages
- Libraries
- Application code

Example Docker images:

```
nginx:latest

python:3.12

ubuntu:24.04
```

Every installed package may contain publicly known security vulnerabilities.

Our goal is to discover them before deploying the application.

---

# Step 2 — Trivy Scans the Image

The first tool used in this project is **Trivy**.

Command:

```bash
trivy image nginx:latest --format json -o reports/sample_trivy.json
```

### What Trivy does

Trivy opens the Docker image.

↓

Reads every installed package.

↓

Checks every package against public vulnerability databases.

↓

Finds matching CVEs.

↓

Produces a JSON report.

At this stage **no AI is used**.

Everything comes from official vulnerability databases.

---

# Step 3 — JSON Report

After scanning, Trivy generates a JSON file.

Example:

```json
{
  "VulnerabilityID": "CVE-2026-12064",
  "PkgName": "curl",
  "Severity": "HIGH",
  "InstalledVersion": "8.14.1",
  "FixedVersion": "8.14.2"
}
```

A real report may contain **hundreds of entries** like this.

Humans don't enjoy reading raw JSON.

Computers do.

---

# Step 4 — Python Parser

File:

```
parser.py
```

This module reads the JSON report.

Instead of keeping the entire JSON structure, it extracts only the important information.

For every vulnerability, it creates a Python object.

Example:

```python
Vulnerability(
    cve="CVE-2026-12064",
    package="curl",
    severity="HIGH",
    installed_version="8.14.1",
    fixed_version="8.14.2"
)
```

Think of this step as converting machine-readable data into clean Python objects.

---

# Step 5 — Security Statistics

File:

```
statistics.py
```

Now that the vulnerabilities exist as Python objects, the application calculates useful statistics.

Example:

```
Total Vulnerabilities : 376

Critical : 2

High : 70

Medium : 139

Low : 128

Unknown : 37
```

These statistics are displayed in the Streamlit dashboard.

They are also included in the prompt sent to the AI model.

---

# Step 6 — Prioritization

File:

```
prioritizer.py
```

Not every vulnerability is equally dangerous.

A Critical vulnerability should be reviewed before a Medium vulnerability.

This module sorts vulnerabilities by severity.

Current priority:

```
Critical

↓

High

↓

Medium

↓

Low

↓

Unknown
```

Instead of sending all 376 vulnerabilities to the AI, only the highest priority findings are selected.

This makes the prompt smaller and focuses the AI on the most important issues.

---

# Step 7 — Summary Builder

File:

```
summary_builder.py
```

The AI does **not** receive the raw Trivy JSON.

Instead, Python prepares a summarized version.

Example:

```
Critical : 2

High : 70

Top Packages

curl

libcurl

perl-base
```

This preprocessing step is important.

Rather than asking the AI to understand a massive JSON file, Python organizes the information first.

The AI is only responsible for reasoning and summarization.

---

# Step 8 — Prompt Builder

File:

```
prompts.py
```

The summarized information is converted into natural language.

Example:

```
You are a cybersecurity documentation assistant.

Generate:

Executive Summary

Business Impact

Recommended Remediation

Priority Action Plan
```

This instruction is called the **prompt**.

The prompt tells the AI exactly what task it should perform.

---

# Step 9 — Amazon Bedrock

File:

```
bedrock_client.py
```

This is where Artificial Intelligence is actually used.

The application sends the prompt to **Amazon Bedrock**, which hosts Amazon Nova Lite.

The communication happens over the internet.

```
Your Computer

↓

Amazon Bedrock

↓

Nova Lite Model

↓

Generated Security Report

↓

Back to Your Computer
```

The AI analyzes the summarized vulnerability information and generates a professional Markdown report.

---

# Step 10 — Streamlit Dashboard

Instead of printing everything in the terminal, the application displays each stage using Streamlit.

The dashboard allows the user to:

- Upload a Trivy JSON report
- View vulnerability statistics
- View highest priority vulnerabilities
- Generate an AI security report
- Download the generated Markdown report

This makes the application much easier to understand and demonstrate.

---

# Step 11 — Final AI Report

The generated report contains sections such as:

```
# Executive Summary

# Highest Risk Vulnerabilities

# Business Impact

# Recommended Remediation

# Priority Action Plan
```

Instead of reading hundreds of vulnerabilities manually, security engineers receive a concise report explaining:

- What is most important
- What should be fixed first
- Business impact
- Recommended actions

---

# Why Use AI?

A common question is:

> "Why not just use Trivy?"

Trivy is excellent at **detecting** vulnerabilities.

However, it does not explain:

- Which vulnerabilities should be fixed first
- Business impact
- Executive summary
- Recommended remediation order

This project combines deterministic security tooling with AI.

```
Trivy

↓

Detects vulnerabilities

↓

Python

↓

Processes and prioritizes findings

↓

Amazon Bedrock

↓

Generates a human-readable security assessment
```

The AI does **not** replace Trivy.

It makes Trivy's output easier for humans to understand.

---

# Complete End-to-End Flow

When a user uploads a Trivy report, the following happens automatically:

```
1. Docker image is scanned using Trivy

↓

2. Trivy generates a JSON vulnerability report

↓

3. Python parses the JSON

↓

4. Security statistics are calculated

↓

5. Highest priority vulnerabilities are selected

↓

6. A structured AI prompt is created

↓

7. The prompt is sent to Amazon Bedrock

↓

8. Amazon Nova Lite generates a professional security report

↓

9. The report is displayed in the Streamlit dashboard

↓

10. The report can be downloaded as a Markdown file
```

The entire workflow transforms a large, difficult-to-read vulnerability report into a concise security assessment suitable for developers, security engineers, and engineering managers.

my goddd idk what i am doing ? at the emoment  where ot go , wh=tich whoom to go . i should og to have some conecettion 
