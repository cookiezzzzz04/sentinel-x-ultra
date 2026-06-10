"""CLI Launcher - Command-line interface for SENTINEL-X ULTRA."""

from __future__ import annotations

import sys
import click
import webbrowser
import uvicorn

from .config import load_settings, save_default_config
from .server import app


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """SENTINEL-X ULTRA - Autonomous Security Analysis Intelligence Framework."""
    pass


@cli.command()
@click.option("--host", default=None, help="Host to bind to")
@click.option("--port", default=None, type=int, help="Port to bind to")
@click.option("--open-browser/--no-open-browser", default=True, help="Open browser after server starts")
@click.option("--save-config", is_flag=True, help="Save default configuration file")
def start(host, port, open_browser, save_config):
    """Start the SENTINEL-X ULTRA web server."""
    settings = load_settings()

    # Save default config if requested
    if save_config:
        save_default_config()

    # Use CLI options or fall back to config
    bind_host = host or settings.server.host
    bind_port = port or settings.server.port

    click.echo("=" * 66)
    click.echo("  SENTINEL-X ULTRA v0.1.0 - Autonomous Security Analysis Intelligence")
    click.echo("=" * 66)

    click.echo(f"Starting server at http://{bind_host}:{bind_port}")
    click.echo("Press Ctrl+C to stop the server")
    click.echo("")

    if open_browser:
        import threading
        def open_browser_delayed():
            import time
            time.sleep(2)
            webbrowser.open(f"http://{bind_host}:{bind_port}")
        threading.Thread(target=open_browser_delayed, daemon=True).start()

    try:
        uvicorn.run(
            app,
            host=bind_host,
            port=bind_port,
            log_level="info",
        )
    except KeyboardInterrupt:
        click.echo("\nServer stopped.")


@cli.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option("--scope", "-s", help="Scope definition file (JSON or YAML)")
@click.option("--output", "-o", help="Output file for report")
@click.option("--format", "-f", type=click.Choice(["json", "md", "html"]), default="json", help="Report format")
def analyze(input_path, scope, output, format):
    """Run analysis on a code repository or file."""
    click.echo(f"Analyzing: {input_path}")

    if scope:
        click.echo(f"Using scope: {scope}")

    click.echo("")
    click.echo("Note: Headless analysis not yet implemented.")
    click.echo("Please use the web UI for full functionality.")
    click.echo("")
    click.echo("Start the web server with: sentinel-x start")


@cli.command()
def init():
    """Initialize SENTINEL-X configuration."""
    save_default_config()
    click.echo("Configuration file created. Edit it to set your API keys.")


@cli.command()
@click.argument("project_id")
def info(project_id):
    """Show information about a project."""
    from .memory import MemoryEngine
    from .config import load_settings

    settings = load_settings()
    memory = MemoryEngine(settings.storage.base_path / settings.storage.projects_dir)

    project = memory.load_project(project_id)
    if project is None:
        click.echo(f"Project not found: {project_id}")
        sys.exit(1)

    click.echo(f"""
Project: {project.name}
ID: {project.project_id}
Created: {project.created_at}
Updated: {project.updated_at}

Scope:
  Program: {project.scope.program_name or "Not set"}
  Authorized assets: {len(project.scope.authorized_assets)}
  Excluded assets: {len(project.scope.excluded_assets)}

Findings: {len(project.findings)}
  Critical: {len([f for f in project.findings if f.severity == 'Critical'])}
  High: {len([f for f in project.findings if f.severity == 'High'])}
  Medium: {len([f for f in project.findings if f.severity == 'Medium'])}
  Low: {len([f for f in project.findings if f.severity == 'Low'])}

Anomalies: {len(project.anomaly_register)}
""")


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()