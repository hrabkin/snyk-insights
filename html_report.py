"""
HTML Report Generator for Snyk Security Issues.
"""
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape


class HTMLReportGenerator:
    """Generate HTML reports for Snyk security issues using Jinja2 templates."""

    def __init__(self, template_dir: Path = None):
        """
        Initialize the HTML report generator.

        Args:
            template_dir: Directory containing Jinja2 templates.
                         Defaults to 'templates' in the current directory.
        """
        if template_dir is None:
            template_dir = Path(__file__).parent / "templates"

        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )

    def prepare_data_cve_cwe(self, issues: List) -> Dict:
        """Prepare data grouped by CVE-CWE pairs."""
        cve_cwe_groups = defaultdict(lambda: {
            'issues': [],
            'severity_counts': defaultdict(int),
            'projects': {},
            'problem_titles': set(),
            'fixable_count': 0
        })

        for issue in issues:
            cves = issue.cve if issue.cve else ['No CVE']
            cwes = issue.cwe if issue.cwe else ['No CWE']

            for cve in cves:
                for cwe in cwes:
                    key = (cve, cwe)
                    cve_cwe_groups[key]['issues'].append(issue)
                    cve_cwe_groups[key]['severity_counts'][issue.issue_severity] += 1
                    cve_cwe_groups[key]['projects'][issue.project_name] = issue.project_url
                    cve_cwe_groups[key]['problem_titles'].add(issue.problem_title)
                    if issue.computed_fixability == "Fixable":
                        cve_cwe_groups[key]['fixable_count'] += 1

        sorted_groups = sorted(
            cve_cwe_groups.items(),
            key=lambda x: len(x[1]['issues']),
            reverse=True
        )

        groups = []
        for (cve, cwe), data in sorted_groups:
            groups.append({
                'cve': cve,
                'cwe': cwe,
                'total_issues': len(data['issues']),
                'fixable_count': data['fixable_count'],
                'severity_counts': dict(data['severity_counts']),
                'problem_titles': sorted(data['problem_titles']),
                'projects': [
                    {'name': name, 'url': url}
                    for name, url in sorted(data['projects'].items())
                ]
            })

        return groups

    def prepare_data_project(self, issues: List) -> Dict:
        """Prepare data grouped by project."""
        project_groups = defaultdict(lambda: {
            'issues': [],
            'severity_counts': defaultdict(int),
            'cve_cwe_pairs': set(),
            'problem_titles': set(),
            'fixable_count': 0
        })

        for issue in issues:
            key = (issue.project_name, issue.project_url)
            project_groups[key]['issues'].append(issue)
            project_groups[key]['severity_counts'][issue.issue_severity] += 1
            project_groups[key]['problem_titles'].add(issue.problem_title)

            # Track CVE-CWE pairs for this project
            cves = issue.cve if issue.cve else ['No CVE']
            cwes = issue.cwe if issue.cwe else ['No CWE']
            for cve in cves:
                for cwe in cwes:
                    project_groups[key]['cve_cwe_pairs'].add(f"{cve} + {cwe}")

            if issue.computed_fixability == "Fixable":
                project_groups[key]['fixable_count'] += 1

        sorted_groups = sorted(
            project_groups.items(),
            key=lambda x: len(x[1]['issues']),
            reverse=True
        )

        groups = []
        for (project_name, project_url), data in sorted_groups:
            groups.append({
                'project_name': project_name,
                'project_url': project_url,
                'total_issues': len(data['issues']),
                'fixable_count': data['fixable_count'],
                'severity_counts': dict(data['severity_counts']),
                'problem_titles': sorted(data['problem_titles']),
                'cve_cwe_pairs': sorted(data['cve_cwe_pairs'])
            })

        return groups

    def prepare_data(self, issues: List, group_by: str = 'cve-cwe') -> Dict:
        """
        Prepare data for the HTML template.

        Args:
            issues: List of SnykIssue model instances
            group_by: Grouping strategy ('cve-cwe' or 'project')

        Returns:
            Dictionary containing prepared data for the template
        """
        # Calculate summary statistics
        severity_counts = defaultdict(int)
        for issue in issues:
            severity_counts[issue.issue_severity] += 1

        fixable_count = sum(1 for i in issues if i.computed_fixability == "Fixable")

        # Group based on strategy
        if group_by == 'project':
            groups = self.prepare_data_project(issues)
        else:
            groups = self.prepare_data_cve_cwe(issues)

        return {
            'total_issues': len(issues),
            'total_groups': len(groups),
            'severity_counts': dict(severity_counts),
            'fixable_count': fixable_count,
            'groups': groups,
            'group_by': group_by
        }

    def generate(self, issues: List, output_path: Path, group_by: str = 'cve-cwe'):
        """
        Generate an HTML report.

        Args:
            issues: List of SnykIssue model instances
            output_path: Path where the HTML report should be saved
            group_by: Grouping strategy ('cve-cwe' or 'project')
        """
        # Select template based on grouping strategy
        if group_by == 'project':
            template_name = 'report_project.html'
        else:
            template_name = 'report_cve_cwe.html'

        # Prepare data
        data = self.prepare_data(issues, group_by=group_by)

        # Render template
        template = self.env.get_template(template_name)
        html_content = template.render(**data)

        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
