
from fastapi import FastAPI, UploadFile, File
import shutil

from parser import parse_trivy_report
from statistics import calculate_statistics
from prioritizer import get_top_vulnerabilities

app = FastAPI(
    title="AI Security Report Summarizer API",
    description="Backend API for AI Security Report Summarizer",
    version="1.0.0"
)

@app.get("/")
def health_check():
    return {
        "message": "AI Security Report Summarizer API",
        "status": "running"
    }

@app.post("/api/upload")
async def upload_report(file: UploadFile = File(...)):
    file_path = f"reports/{file.filename}"

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    findings = parse_trivy_report(file_path)

    stats = calculate_statistics(findings)

    top_findings = get_top_vulnerabilities(findings)

    return {
        "filename": file.filename,
        "total_vulnerabilities": len(findings),
        "statistics": stats,
        "top_findings": [
            {
                "cve": item.cve,
                "package": item.package,
                "severity": item.severity,
                "installed_version": item.installed_version,
                "fixed_version": item.fixed_version,
            }
            for item in top_findings
        ],
    }