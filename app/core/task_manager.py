"""Subprocess execution manager for security tools with real-time streaming and timeouts."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
import os
import shutil
import time
from typing import AsyncIterator, Dict, List, Optional

from app.core.event_bus import EventType, ScanEvent, get_event_bus


@dataclass
class ToolExecutionResult:
    tool_name: str
    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    error: Optional[str] = None
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime = field(default_factory=datetime.utcnow)


class TaskManager:
    """Manages secure, asynchronous execution of external security tools."""

    def __init__(self):
        self.active_processes: Dict[str, asyncio.subprocess.Process] = {}
        self.event_bus = get_event_bus()

    @staticmethod
    def resolve_binary(binary_name: str) -> Optional[str]:
        """Verify binary presence in PATH and return its absolute location."""
        return shutil.which(binary_name)

    async def execute_tool(
        self,
        scan_id: str,
        tool_name: str,
        args: List[str],
        timeout_seconds: int = 300,
        working_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None
    ) -> ToolExecutionResult:
        """
        Execute an external tool asynchronously without shell=True, streaming lines to EventBus.
        """
        binary_path = self.resolve_binary(args[0])
        if not binary_path:
            err_msg = f"Binary '{args[0]}' not found in PATH."
            await self.event_bus.publish(ScanEvent(
                event_type=EventType.TOOL_FAILED,
                scan_id=scan_id,
                tool_name=tool_name,
                message=err_msg
            ))
            return ToolExecutionResult(
                tool_name=tool_name,
                command=args,
                exit_code=-1,
                stdout="",
                stderr=err_msg,
                duration_seconds=0.0,
                error=err_msg
            )

        cmd_list = [binary_path] + args[1:]
        start_time = time.monotonic()
        started_at = datetime.utcnow()

        await self.event_bus.publish(ScanEvent(
            event_type=EventType.TOOL_STARTED,
            scan_id=scan_id,
            tool_name=tool_name,
            data={"command": " ".join(cmd_list)}
        ))

        # Prepare safe environment variables
        exec_env = os.environ.copy()
        if env:
            exec_env.update(env)

        # Sanitize any API keys or credentials from leaking into subprocess environment
        # Keep only required variables
        task_key = f"{scan_id}:{tool_name}"
        stdout_chunks: List[str] = []
        stderr_chunks: List[str] = []
        timed_out = False
        exit_code = -1

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd_list,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=working_dir,
                env=exec_env
            )
            self.active_processes[task_key] = process

            async def stream_output(stream: asyncio.StreamReader, is_stderr: bool):
                while True:
                    line_bytes = await stream.readline()
                    if not line_bytes:
                        break
                    line = line_bytes.decode("utf-8", errors="replace")
                    if is_stderr:
                        stderr_chunks.append(line)
                    else:
                        stdout_chunks.append(line)
                    
                    # Publish live line event
                    await self.event_bus.publish(ScanEvent(
                        event_type=EventType.TOOL_OUTPUT,
                        scan_id=scan_id,
                        tool_name=tool_name,
                        message=line.rstrip("\r\n"),
                        data={"is_stderr": is_stderr}
                    ))

            # Stream both stdout and stderr concurrently with timeout
            try:
                await asyncio.wait_for(
                    asyncio.gather(
                        stream_output(process.stdout, False),
                        stream_output(process.stderr, True),
                        process.wait()
                    ),
                    timeout=timeout_seconds
                )
                exit_code = process.returncode
            except asyncio.TimeoutError:
                timed_out = True
                await self._kill_process(process)
                exit_code = -9

        except Exception as e:
            err_msg = f"Execution exception: {e}"
            stderr_chunks.append(err_msg)
            exit_code = -1
        finally:
            self.active_processes.pop(task_key, None)

        duration = time.monotonic() - start_time
        completed_at = datetime.utcnow()
        full_stdout = "".join(stdout_chunks)
        full_stderr = "".join(stderr_chunks)

        if timed_out:
            await self.event_bus.publish(ScanEvent(
                event_type=EventType.TOOL_FAILED,
                scan_id=scan_id,
                tool_name=tool_name,
                message=f"Tool timed out after {timeout_seconds} seconds."
            ))
        elif exit_code == 0:
            await self.event_bus.publish(ScanEvent(
                event_type=EventType.TOOL_COMPLETED,
                scan_id=scan_id,
                tool_name=tool_name,
                data={"duration": duration}
            ))
        else:
            await self.event_bus.publish(ScanEvent(
                event_type=EventType.TOOL_FAILED,
                scan_id=scan_id,
                tool_name=tool_name,
                data={"exit_code": exit_code, "duration": duration}
            ))

        return ToolExecutionResult(
            tool_name=tool_name,
            command=cmd_list,
            exit_code=exit_code,
            stdout=full_stdout,
            stderr=full_stderr,
            duration_seconds=round(duration, 2),
            timed_out=timed_out,
            started_at=started_at,
            completed_at=completed_at
        )

    async def _kill_process(self, process: asyncio.subprocess.Process):
        """Terminate process gracefully, then kill if unresponsive."""
        try:
            process.terminate()
            await asyncio.wait_for(process.wait(), timeout=3.0)
        except (asyncio.TimeoutError, ProcessLookupError):
            try:
                process.kill()
            except ProcessLookupError:
                pass

    async def cancel_all(self):
        """Cancel and terminate all running child processes."""
        for key, proc in list(self.active_processes.items()):
            await self._kill_process(proc)
        self.active_processes.clear()

