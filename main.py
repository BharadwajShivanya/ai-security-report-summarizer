import os
import json
import uuid
import traceback
from collections import Counter
import uvicorn
import boto3

from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

# Import existing backend modules
from parser import parse_trivy_report
from statistics import calculate_statistics
from prioritizer import get_top_vulnerabilities, SEVERITY_ORDER
from summary_builder import build_summary
from prompts import build_security_prompt
from config import AWS_REGION, MODEL_ID, AWS_ACCESS_KEY, AWS_SECRET_KEY

HISTORY_FILE = "reports/history.json"

def init_sample_in_history():
    """Ensure the sample report is always present in the history list on startup."""
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                history = json.load(f)
        except Exception:
            pass

    # If sample is already in history, we are good
    if any(h.get("id") == "sample_trivy" for h in history):
        return

    sample_path = "reports/sample_trivy.json"
    if os.path.exists(sample_path):
        try:
            findings = parse_trivy_report(sample_path)
            stats = calculate_statistics(findings)

            with open(sample_path, "r", encoding="utf-8") as f:
                raw_report = json.load(f)

            artifact_name = raw_report.get("ArtifactName", "nginx:latest")
            created_at = raw_report.get("CreatedAt", "2026-07-13T15:17:05.530916+05:30")
            metadata = raw_report.get("Metadata", {})
            os_info = metadata.get("OS", {})
            os_family = os_info.get("Family", "debian")
            os_name = os_info.get("Name", "13.5")
            os_str = f"{os_family} {os_name}".strip()

            total_packages = 0
            for result in raw_report.get("Results", []):
                total_packages += len(result.get("Packages", []))
            if total_packages == 0:
                uniq_pkgs = set(finding.package for finding in findings if finding.package != "N/A")
                total_packages = len(uniq_pkgs) if uniq_pkgs else 184

            pkg_counter = Counter()
            for finding in findings:
                pkg_counter[finding.package] += 1
            top_packages = [{"package": pkg, "count": count} for pkg, count in pkg_counter.most_common(6)]

            entry = {
                "id": "sample_trivy",
                "timestamp": created_at,
                "filename": "sample_trivy.json",
                "artifact_name": artifact_name,
                "os": os_str,
                "total_packages": total_packages,
                "total_vulnerabilities": len(findings),
                "stats": stats,
                "top_packages": top_packages
            }
            history.append(entry)
            with open(HISTORY_FILE, "w") as f:
                json.dump(history, f, indent=2)
        except Exception as e:
            print("Failed to initialize sample in history:", e)

def save_to_history(entry):
    """Add a new scan entry to the top of the history log."""
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                history = json.load(f)
        except Exception:
            pass
    # Avoid duplicate IDs
    history = [h for h in history if h.get("id") != entry["id"]]
    history.insert(0, entry)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

def generate_mock_report(stats, top_findings, artifact_name, os_str):
    """Fallback generator for a dynamic and realistic report when AWS keys are absent."""
    critical_cves = ", ".join([f.cve for f in top_findings if f.severity == "CRITICAL"][:3])
    high_cves = ", ".join([f.cve for f in top_findings if f.severity == "HIGH"][:3])
    top_packages = list(set([f.package for f in top_findings[:4]]))
    
    return f"""# Executive Summary

This container image **{artifact_name}** runs on **{os_str}** and contains multiple security vulnerabilities. A total of **{stats['total']}** vulnerabilities were identified, including **{stats['critical']} Critical** and **{stats['high']} High** severity findings. 

The primary risks stem from the following outdated packages: **{", ".join(top_packages)}**. Immediate intervention is recommended for public-facing deployments.

# Business Impact

- **Remote Code Execution**: Potential compromise of container nodes via unresolved CVEs ({critical_cves or "unresolved packages"}).
- **Data Leakage & MITM**: Network and transfer libraries such as `libcurl` or `openssl` (linked with CVEs like {high_cves or "unresolved CVEs"}) could allow attackers to intercept traffic or spoof hosts.
- **Service Disruption**: Resource exhaustion vulnerabilities could result in Denial of Service (DoS).

# Recommended Remediation

1. **Upgrade Package Versions**: Apply immediate security updates for `{", ".join(top_packages[:3])}` as specified in the priority list.
2. **Rebase Container Image**: Migrate to a newer, official base tag or use a minimal distroless image to reduce the attack surface.
3. **Scan Continuously**: Integrate Trivy scans into your CI/CD pipelines to block insecure builds before they reach registry stores.

# Priority Action Plan

1. **Critical (Immediate)**: Remediate {critical_cves or "Critical vulnerabilities"} in `{top_packages[0] if top_packages else "base packages"}`.
2. **High (Within 7 days)**: Update components related to `{", ".join(top_packages[1:3]) if len(top_packages) > 1 else "High severity findings"}`.
3. **Medium/Low (Monitor)**: Review and schedule standard security patch cycles.
"""

async def serve_index(request):
    """Serve the index.html page."""
    html_path = "index.html"
    if not os.path.exists(html_path):
        return HTMLResponse("<h1>index.html not found</h1>", status_code=404)
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    return HTMLResponse(html_content)

async def api_scan(request):
    """Endpoint for uploading a Trivy JSON file."""
    try:
        form = await request.form()
        upload_file = form.get("file")
        if not upload_file:
            return JSONResponse({"error": "No file uploaded"}, status_code=400)

        content = await upload_file.read()
        scan_id = f"uploaded_{uuid.uuid4().hex}"
        filename = f"reports/{scan_id}.json"

        with open(filename, "wb") as f:
            f.write(content)

        # Call existing backend business logic
        findings = parse_trivy_report(filename)
        stats = calculate_statistics(findings)
        
        # Load raw metadata
        with open(filename, "r", encoding="utf-8") as f:
            raw_report = json.load(f)

        artifact_name = raw_report.get("ArtifactName", "Unknown")
        created_at = raw_report.get("CreatedAt", "Unknown")
        metadata = raw_report.get("Metadata", {})
        os_info = metadata.get("OS", {})
        os_family = os_info.get("Family", "Unknown")
        os_name = os_info.get("Name", "")
        os_str = f"{os_family} {os_name}".strip()

        # Calculate package count
        total_packages = 0
        for result in raw_report.get("Results", []):
            total_packages += len(result.get("Packages", []))
        if total_packages == 0:
            uniq_pkgs = set(finding.package for finding in findings if finding.package != "N/A")
            total_packages = len(uniq_pkgs) if uniq_pkgs else 184

        # Extract top affected packages
        pkg_counter = Counter()
        for finding in findings:
            pkg_counter[finding.package] += 1
        top_packages = [{"package": pkg, "count": count} for pkg, count in pkg_counter.most_common(6)]

        # Prepare findings list
        vuln_list = [{
            "cve": f.cve,
            "package": f.package,
            "severity": f.severity,
            "installed_version": f.installed_version,
            "fixed_version": f.fixed_version,
            "description": f.description
        } for f in findings]

        # Save scan meta to history
        history_entry = {
            "id": scan_id,
            "timestamp": created_at,
            "filename": upload_file.filename,
            "artifact_name": artifact_name,
            "os": os_str,
            "total_packages": total_packages,
            "total_vulnerabilities": len(findings),
            "stats": stats,
            "top_packages": top_packages
        }
        save_to_history(history_entry)

        return JSONResponse({
            "scan_id": scan_id,
            "artifact_name": artifact_name,
            "os": os_str,
            "timestamp": created_at,
            "total_packages": total_packages,
            "total_vulnerabilities": len(findings),
            "stats": stats,
            "top_packages": top_packages,
            "vulnerabilities": vuln_list
        })

    except Exception as e:
        traceback.print_exc()
        return JSONResponse({"error": f"Failed to parse report: {str(e)}"}, status_code=500)

async def api_history(request):
    """Endpoint for returning the history log."""
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                history = json.load(f)
        except Exception:
            pass
    return JSONResponse(history)

async def api_get_scan(request):
    """Endpoint for fetching a specific historical scan's full details."""
    scan_id = request.path_params["scan_id"]
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                history = json.load(f)
        except Exception:
            pass
            
    match = None
    for h in history:
        if h.get("id") == scan_id:
            match = h
            break
            
    if not match:
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    filepath = f"reports/{scan_id}.json"
    if scan_id == "sample_trivy":
        filepath = "reports/sample_trivy.json"

    if not os.path.exists(filepath):
        return JSONResponse({"error": "Report file no longer exists"}, status_code=404)

    try:
        findings = parse_trivy_report(filepath)
        vuln_list = [{
            "cve": f.cve,
            "package": f.package,
            "severity": f.severity,
            "installed_version": f.installed_version,
            "fixed_version": f.fixed_version,
            "description": f.description
        } for f in findings]

        return JSONResponse({
            "scan_id": match["id"],
            "artifact_name": match["artifact_name"],
            "os": match["os"],
            "timestamp": match["timestamp"],
            "total_packages": match["total_packages"],
            "total_vulnerabilities": match["total_vulnerabilities"],
            "stats": match["stats"],
            "top_packages": match["top_packages"],
            "vulnerabilities": vuln_list
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

async def api_generate_report(request):
    """Endpoint to invoke Amazon Bedrock report generation."""
    try:
        body = await request.json()
        scan_id = body.get("scan_id")
        settings = body.get("settings", {})

        # Load file path
        filepath = f"reports/{scan_id}.json"
        if scan_id == "sample_trivy":
            filepath = "reports/sample_trivy.json"

        if not os.path.exists(filepath):
            return JSONResponse({"error": f"Scan with ID '{scan_id}' not found."}, status_code=404)

        # Parse using existing python logic
        findings = parse_trivy_report(filepath)
        stats = calculate_statistics(findings)

        # Get metadata for mock generation if fallback is needed
        with open(filepath, "r", encoding="utf-8") as f:
            raw_report = json.load(f)
        artifact_name = raw_report.get("ArtifactName", "Unknown")
        metadata = raw_report.get("Metadata", {})
        os_info = metadata.get("OS", {})
        os_family = os_info.get("Family", "Unknown")
        os_name = os_info.get("Name", "")
        os_str = f"{os_family} {os_name}".strip()

        # If low-severity CVEs should be excluded, filter findings
        include_low = settings.get("include_low", False)
        if not include_low:
            findings = [f for f in findings if f.severity != "LOW"]

        # Re-calculate statistics for the summary
        stats = calculate_statistics(findings)
        top_findings = get_top_vulnerabilities(findings, limit=10)

        # Build prompt using unmodified summary_builder and prompts
        summary = build_summary(findings, stats, top_findings)
        prompt = build_security_prompt(summary)

        # AWS configuration overrides
        aws_region = settings.get("region") or AWS_REGION or "us-east-1"
        model_id = settings.get("model") or MODEL_ID or "amazon.nova-lite-v1:0"
        access_key = settings.get("access_key") or AWS_ACCESS_KEY
        secret_key = settings.get("secret_key") or AWS_SECRET_KEY

        # Check credentials to decide on fallback
        if not access_key or not secret_key:
            print("AWS keys missing. Running in DEMO mode with mock report.")
            mock_report = generate_mock_report(stats, top_findings, artifact_name, os_str)
            return JSONResponse({"report": mock_report, "demo_mode": True})

        try:
            # Create runtime client
            client = boto3.client(
                service_name="bedrock-runtime",
                region_name=aws_region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
            )

            request_body = {
                "messages": [
                    {
                        "role": "user",
                        "content": [{"text": prompt}]
                    }
                ]
            }

            response = client.invoke_model(
                modelId=model_id,
                body=json.dumps(request_body),
                contentType="application/json",
                accept="application/json",
            )

            response_body = json.loads(response["body"].read())
            generated_text = response_body["output"]["message"]["content"][0]["text"]

            return JSONResponse({"report": generated_text, "demo_mode": False})

        except Exception as aws_err:
            print("Bedrock call failed. Falling back to Mock report. Error:", aws_err)
            mock_report = generate_mock_report(stats, top_findings, artifact_name, os_str)
            return JSONResponse({
                "report": mock_report, 
                "demo_mode": True,
                "warning": f"Bedrock invocation failed: {str(aws_err)}. Mock report generated."
            })

    except Exception as e:
        traceback.print_exc()
        return JSONResponse({"error": str(e)}, status_code=500)

# Starlette App Configuration
routes = [
    Route("/", serve_index, methods=["GET"]),
    Route("/api/scan", api_scan, methods=["POST"]),
    Route("/api/history", api_history, methods=["GET"]),
    Route("/api/history/{scan_id}", api_get_scan, methods=["GET"]),
    Route("/api/generate_report", api_generate_report, methods=["POST"]),
]

middleware = [
    Middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])
]

app = Starlette(routes=routes, middleware=middleware)

if __name__ == "__main__":
    init_sample_in_history()
    uvicorn.run("main:app", host="0.0.0.0", port=8000, log_level="info")
