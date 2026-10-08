"""MCP stdio smoke tests: spawn the real server over stdio, list tools, and
check that instructive errors reach the client (MCPServer hides any
exception that isn't a ToolError behind 'Error executing tool X')."""

import sys

import pytest

pytest.importorskip("mcp")

from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

EXPECTED_TOOLS = {
    "uefi_status",
    "uefi_guid",
    "uefi_log",
    "uefi_image",
    "uefi_volume",
    "uefi_boot",
}

PARAMS = StdioServerParameters(command=sys.executable, args=["-m", "uefi_mcp"])


@pytest.mark.anyio
async def test_stdio_handshake_lists_expected_tools():
    async with stdio_client(PARAMS) as (read, write), ClientSession(read, write) as session:
        init_result = await session.initialize()
        assert init_result.server_info.name == "uefi"
        tools = await session.list_tools()
        names = {t.name for t in tools.tools}
        assert names == EXPECTED_TOOLS, (
            f"missing: {EXPECTED_TOOLS - names}, unexpected: {names - EXPECTED_TOOLS}"
        )


@pytest.mark.anyio
async def test_instructive_errors_reach_the_agent():
    async with stdio_client(PARAMS) as (read, write), ClientSession(read, write) as session:
        await session.initialize()

        result = await session.call_tool("uefi_status", {"code": "6"})
        assert result.is_error and "Pass EFI_NOT_READY" in result.content[0].text

        result = await session.call_tool("uefi_image", {"path": "missing.efi"})
        assert result.is_error and "no such file: missing.efi" in result.content[0].text

        result = await session.call_tool("uefi_guid", {"query": "zzzqqq"})
        assert result.is_error and "try a shorter fragment" in result.content[0].text


@pytest.mark.anyio
async def test_a_real_answer_over_stdio():
    async with stdio_client(PARAMS) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        result = await session.call_tool("uefi_status", {"code": "Not Found"})
        assert not result.is_error and "EFI_NOT_FOUND" in result.content[0].text


@pytest.fixture
def anyio_backend():
    return "asyncio"
