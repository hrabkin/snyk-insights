#!/usr/bin/env python3
"""
Script to read Snyk security issues CSV file and generate HTML reports.
"""
import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class SnykIssue(BaseModel):
    """Pydantic model representing a Snyk security issue."""

    model_config = {"populate_by_name": True}

    issue_severity_rank: int = Field(alias="ISSUE_SEVERITY_RANK")
    issue_severity: str = Field(alias="ISSUE_SEVERITY")
    score: int = Field(alias="SCORE")
    problem_title: str = Field(alias="PROBLEM_TITLE")
    cve: List[str] = Field(alias="CVE", default_factory=list)
    cve_url: List[str] = Field(alias="CVE_URL", default_factory=list)
    cwe: List[str] = Field(alias="CWE", default_factory=list)
    project_name: str = Field(alias="PROJECT_NAME")
    project_url: str = Field(alias="PROJECT_URL")
    exploit_maturity: Optional[str] = Field(
        alias="EXPLOIT_MATURITY", default=None)
    computed_fixability: str = Field(alias="COMPUTED_FIXABILITY")
    first_introduced: Optional[datetime] = Field(
        alias="FIRST_INTRODUCED", default=None)
    product_name: Optional[str] = Field(alias="PRODUCT_NAME", default=None)
    issue_url: str = Field(alias="ISSUE_URL")
    issue_status_indicator: str = Field(alias="ISSUE_STATUS_INDICATOR")
    issue_type: str = Field(alias="ISSUE_TYPE")

    @field_validator("cve", "cve_url", "cwe", mode="before")
    @classmethod
    def parse_json_array(cls, v):
        """Parse JSON array strings into Python lists."""
        if isinstance(v, str):
            try:
                # Handle the format: ["item1", "item2"]
                parsed = json.loads(v)
                return parsed if isinstance(parsed, list) else []
            except json.JSONDecodeError:
                return []
        return v if isinstance(v, list) else []

    @field_validator("first_introduced", mode="before")
    @classmethod
    def parse_datetime(cls, v):
        """Parse datetime string."""
        if v is None or v == '':
            return None
        if isinstance(v, str):
            try:
                return datetime.strptime(v, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                try:
                    return datetime.strptime(v, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    raise ValueError(f"Unable to parse datetime: {v}")
        return v


def read_csv_to_models(csv_path: Path) -> List[SnykIssue]:
    """
    Read CSV file and convert rows to SnykIssue models.

    Args:
        csv_path: Path to the CSV file

    Returns:
        List of SnykIssue model instances
    """
    issues = []

    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        # start=2 because row 1 is header
        for row_num, row in enumerate(reader, start=2):
            try:
                issue = SnykIssue(**row)
                issues.append(issue)
            except Exception as e:
                print(
                    f"Warning: Failed to parse row {row_num}: {e}", file=sys.stderr)
                continue

    return issues


def main():
    """Main function to parse arguments and process CSV file."""
    parser = argparse.ArgumentParser(
        description="Generate HTML report of Snyk security issues grouped by CVE-CWE pairs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s issues.csv                                  # Generates output/report_cve_cwe.html
  %(prog)s issues.csv --group-by project               # Generates output/report_project.html
  %(prog)s issues.csv -o custom/report.html            # Custom output path
  %(prog)s issues.csv --group-by project -o proj.html  # Custom output with project grouping
        """
    )

    parser.add_argument(
        'csv_file',
        type=Path,
        help='Path to the CSV file to read'
    )

    parser.add_argument(
        '-o', '--output-file',
        type=Path,
        default=None,
        help='Output HTML file path (default: output/report_<groupby>.html)'
    )

    parser.add_argument(
        '--group-by',
        choices=['cve-cwe', 'project'],
        default='cve-cwe',
        help='Group issues by CVE-CWE pairs or by project (default: cve-cwe)'
    )

    args = parser.parse_args()

    # Validate file exists
    if not args.csv_file.exists():
        print(f"Error: File not found: {args.csv_file}", file=sys.stderr)
        sys.exit(1)

    # Determine output path
    if args.output_file is None:
        # Default: output folder with template name
        output_dir = Path('output')
        output_dir.mkdir(exist_ok=True)

        if args.group_by == 'project':
            output_path = output_dir / 'report_project.html'
        else:
            output_path = output_dir / 'report_cve_cwe.html'
    else:
        # User-specified output path
        output_path = args.output_file
        # Create parent directory if it doesn't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)

    # Read and parse CSV
    print(f"Reading CSV file: {args.csv_file}")
    issues = read_csv_to_models(args.csv_file)
    print(f"Successfully parsed {len(issues)} issues")

    # Generate HTML report
    generate_html_report(issues, output_path, args.group_by)
    print(f"HTML report generated: {output_path}")


def generate_html_report(issues: List[SnykIssue], output_path: Path, group_by: str = 'cve-cwe'):
    """Generate an HTML report with accordion grouping using Jinja2."""
    from html_report import HTMLReportGenerator

    generator = HTMLReportGenerator()
    generator.generate(issues, output_path, group_by=group_by)


if __name__ == "__main__":
    main()
