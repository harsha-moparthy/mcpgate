from __future__ import annotations

import asyncio
import json

import typer

from .benchmark import run_benchmark
from .runtime import create_runtime
from .server import create_server

app = typer.Typer(no_args_is_help=True, help="Governed MCP ticketing server.")


@app.command()
def serve(
    transport: str = typer.Option("streamable-http", help="streamable-http or stdio"),
) -> None:
    """Run the OAuth-protected MCP server."""
    server = create_server()
    if transport == "streamable-http":
        server.run(transport="streamable-http")
    elif transport == "stdio":
        server.run(transport="stdio")
    else:
        raise typer.BadParameter("transport must be streamable-http or stdio")


@app.command("issue-token")
def issue_token(
    client_id: str,
    client_secret: str = typer.Option(..., prompt=True, hide_input=True),
    scopes: str = typer.Option("", help="Space-separated scopes; defaults to client policy"),
) -> None:
    """Issue a short-lived local demo token after client credential validation."""
    runtime = create_runtime()
    pair = runtime.provider.issue_for_client(
        client_id, client_secret, scopes.split() if scopes else None
    )
    print(json.dumps(pair.model_dump(), indent=2))


@app.command()
def audit(session_id: str, verify: bool = True) -> None:
    """Reconstruct one session and optionally verify the complete hash chain."""
    runtime = create_runtime()
    print(json.dumps(runtime.audit.reconstruct(session_id), indent=2))
    if verify:
        print(f"chain_valid={runtime.audit.verify_chain()}")


@app.command()
def benchmark(iterations: int = 500) -> None:
    """Measure governed gateway overhead against direct SQLite access."""
    print(json.dumps(asyncio.run(run_benchmark(iterations)), indent=2))
