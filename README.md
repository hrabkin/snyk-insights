# Snyk Insights

A uv run tool to generate interactive HTML reports from Snyk security issues CSV files.

## Features

- 📊 **Interactive HTML Reports** - Beautiful, responsive reports with accordion-style grouping
- 🔍 **Dual Grouping Modes**:
  - Group by CVE-CWE pairs to see vulnerability patterns
  - Group by Project to see issues per project
- 🎯 **Client-Side Filtering** - Filter by severity (Critical, High, Medium, Low) in the browser
- 📈 **Visual Summary** - Dashboard with severity counts and statistics
- 🎨 **Modern UI** - Clean, gradient design with smooth animations
- 💪 **Type-Safe** - Uses Pydantic for data validation and modeling
- 🚀 **Fast** - Powered by Jinja2 templates

## Installation

### Using UV (Recommended)

```bash
# Sync dependencies
uv venv
source .venv/bin/activate
uv sync
```

## Usage

### Basic Usage

Generate a report grouped by CVE-CWE pairs (default):

```bash
uv run snyk_insights.py your_snyk_export.csv
```

This will create `snyk_report.html` in the current directory.

### Group by Project

Generate a report grouped by project:

```bash
uv run snyk_insights.py your_snyk_export.csv --group-by project
```

### Custom Output File

Specify a custom output filename:

```bash
uv run snyk_insights.py your_snyk_export.csv -o output/my_report.html
```

### Complete Example

```bash
# Create output directory
mkdir -p output

# Generate CVE-CWE grouped report
uv run snyk_insights.py snyk_issues.csv -o output/report_cve_cwe.html --group-by cve-cwe

# Generate project grouped report
uv run snyk_insights.py snyk_issues.csv -o output/report_project.html --group-by project
```

## Report Features

### CVE-CWE Grouping Mode
Groups security issues by vulnerability patterns (CVE + CWE combinations), showing:
- Total issues per vulnerability
- Severity breakdown
- Problem titles
- Affected projects with links

### Project Grouping Mode
Groups security issues by project, showing:
- Total issues per project
- Severity breakdown
- Problem titles
- All CVE-CWE pairs affecting the project

### Interactive Filtering
Both report types include browser-based filtering:
- **All** - Show all issues
- **Critical** - Show only groups with Critical severity issues
- **High** - Show only groups with High severity issues
- **Medium** - Show only groups with Medium severity issues
- **Low** - Show only groups with Low severity issues

The filter counter dynamically updates to show how many groups are visible.

## Data Model

The tool uses Pydantic models to validate and structure Snyk security data:

```python
class SnykIssue(BaseModel):
    issue_severity_rank: int
    issue_severity: str
    score: int
    problem_title: str
    cve: List[str]                    # JSON array from CSV
    cve_url: List[str]                # JSON array from CSV
    cwe: List[str]                    # JSON array from CSV
    project_name: str
    project_url: str
    exploit_maturity: Optional[str]   # Optional field
    computed_fixability: str
    first_introduced: Optional[datetime]  # Optional field
    product_name: Optional[str]       # Optional field
    issue_url: str
    issue_status_indicator: str
    issue_type: str
```

## CSV Format

The script expects Snyk CSV exports with these columns:

**Required:**
- ISSUE_SEVERITY_RANK
- ISSUE_SEVERITY
- SCORE
- PROBLEM_TITLE
- CVE (JSON array format: `["CVE-2023-1234"]`)
- CVE_URL (JSON array)
- CWE (JSON array format: `["CWE-79"]`)
- PROJECT_NAME
- PROJECT_URL
- COMPUTED_FIXABILITY
- ISSUE_URL
- ISSUE_STATUS_INDICATOR
- ISSUE_TYPE

**Optional:**
- EXPLOIT_MATURITY
- FIRST_INTRODUCED
- PRODUCT_NAME

## Architecture

```
snyk_insights.py       # Main CLI script
html_report.py         # Report generation class
templates/
  ├── report_cve_cwe.html    # CVE-CWE grouping template
  └── report_project.html    # Project grouping template
```

### HTMLReportGenerator Class

The `HTMLReportGenerator` class handles:
- Data preparation and grouping
- Template selection based on grouping mode
- HTML generation with Jinja2

```python
from html_report import HTMLReportGenerator

generator = HTMLReportGenerator()
generator.generate(issues, output_path='report.html', group_by='cve-cwe')
```

## Command-Line Options

```bash
uv run snyk_insights.py --help
```

**Arguments:**
- `csv_file` - Path to Snyk CSV export file (required)
- `-o, --output-file` - Output HTML file path (default: `snyk_report.html`)
- `--group-by` - Grouping mode: `cve-cwe` or `project` (default: `cve-cwe`)

## Example Workflow

```bash
# 1. Export issues from Snyk as CSV
# 2. Generate reports
uv run snyk_insights.py snyk_export.csv -o output/vulnerabilities.html --group-by cve-cwe
uv run snyk_insights.py snyk_export.csv -o output/projects.html --group-by project

# 3. Open reports in browser
open output/vulnerabilities.html
open output/projects.html

# 4. Use browser filters to focus on Critical issues
```

## Technologies

- **uv run 3.13+**
- **Pydantic 2.0+** - Data validation and modeling
- **Jinja2 3.0+** - HTML templating
- **UV** - Fast uv run package manager

## Development

Built with modern uv run tooling and best practices:
- Type hints throughout
- Pydantic for data validation
- Jinja2 for template rendering
- Clean separation of concerns (CLI, logic, presentation)

## Contributing

To extend the tool:
1. Add new grouping modes in `html_report.py`
2. Create corresponding Jinja2 templates in `templates/`
3. Update CLI arguments in `snyk_insights.py`

## License

This project is for analyzing Snyk security data exports.
