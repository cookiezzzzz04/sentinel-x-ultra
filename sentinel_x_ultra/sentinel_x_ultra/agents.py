"""Multi-Agent Framework - Base agent class and message bus."""

from __future__ import annotations

import asyncio
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class MessageType(str, Enum):
    TASK = "task"
    RESPONSE = "response"
    EVENT = "event"
    ERROR = "error"
    HEARTBEAT = "heartbeat"


class AgentType(str, Enum):
    RECON = "recon"
    DOCUMENTATION = "documentation"
    ARCHITECTURE = "architecture"
    CODE_REVIEW = "code_review"
    DEPENDENCY = "dependency"
    THREAT_MODELING = "threat_modeling"
    WORKFLOW = "workflow"
    PERMISSION = "permission"
    BUSINESS_LOGIC = "business_logic"
    CORRELATION = "correlation"
    EVIDENCE = "evidence"
    DEBATE = "debate"
    QA = "qa"
    REPORT = "report"


@dataclass
class AgentMessage:
    id: str
    source_agent: AgentType
    target_agent: AgentType | None  # None = broadcast
    message_type: MessageType
    payload: dict[str, Any]
    timestamp: datetime
    conversation_id: str
    reply_to: str | None = None

    @classmethod
    def create(
        cls,
        source: AgentType,
        target: AgentType | None,
        msg_type: MessageType,
        payload: dict[str, Any],
        conversation_id: str | None = None,
        reply_to: str | None = None,
    ) -> "AgentMessage":
        return cls(
            id=str(uuid.uuid4()),
            source_agent=source,
            target_agent=target,
            message_type=msg_type,
            payload=payload,
            timestamp=datetime.utcnow(),
            conversation_id=conversation_id or str(uuid.uuid4()),
            reply_to=reply_to,
        )


@dataclass
class TaskPayload:
    task_id: str
    task_type: str
    input_data: dict[str, Any]
    context: dict[str, Any] = field(default_factory=dict)
    routing_hints: dict[str, Any] = field(default_factory=dict)


class MessageHandler:
    """Handler for agent messages."""

    def __init__(self, agent: "BaseAgent"):
        self.agent = agent

    async def handle(self, message: AgentMessage):
        """Handle an incoming message."""
        try:
            if message.message_type == MessageType.TASK:
                await self.agent.handle_task(message)
            elif message.message_type == MessageType.RESPONSE:
                await self.agent.handle_response(message)
            elif message.message_type == MessageType.EVENT:
                await self.agent.handle_event(message)
            elif message.message_type == MessageType.ERROR:
                await self.agent.handle_error(message)
            elif message.message_type == MessageType.HEARTBEAT:
                await self.agent.handle_heartbeat(message)
        except Exception as e:
            logger.error("message_handler_error", agent=self.agent.agent_type, error=str(e))
            await self.agent.error_handler(message, e)


class BaseAgent(ABC):
    """Base class for all agents."""

    def __init__(
        self,
        agent_type: AgentType,
        message_bus: "MessageBus",
        llm_router: Any,  # MultiProviderRouter
    ):
        self.agent_type = agent_type
        self.message_bus = message_bus
        self.llm_router = llm_router
        self.handler = MessageHandler(self)
        self._running = False
        self._message_handlers: dict[MessageType, Callable] = {}

        # Register default handlers
        self._register_default_handlers()

    def _register_default_handlers(self):
        """Register default message handlers."""
        self._message_handlers[MessageType.TASK] = self.default_task_handler
        self._message_handlers[MessageType.RESPONSE] = self.default_response_handler

    async def default_task_handler(self, message: AgentMessage):
        """Default task handling - subclasses override this."""
        payload = TaskPayload(**message.payload)
        result = await self.execute_task(payload)
        await self.send_response(message, {"status": "completed", "result": result})

    async def default_response_handler(self, message: AgentMessage):
        """Default response handling."""
        logger.info(
            "agent_response_received",
            agent=self.agent_type,
            original_msg=message.reply_to,
        )

    @abstractmethod
    async def execute_task(self, task: TaskPayload) -> dict[str, Any]:
        """Execute a task. Subclasses must implement this."""
        pass

    async def handle_task(self, message: AgentMessage):
        handler = self._message_handlers.get(MessageType.TASK, self.default_task_handler)
        await handler(message)

    async def handle_response(self, message: AgentMessage):
        handler = self._message_handlers.get(MessageType.RESPONSE, self.default_response_handler)
        await handler(message)

    async def handle_event(self, message: AgentMessage):
        logger.info("agent_event", agent=self.agent_type, payload=message.payload)

    async def handle_error(self, message: AgentMessage):
        logger.error("agent_error", agent=self.agent_type, payload=message.payload)

    async def handle_heartbeat(self, message: AgentMessage):
        await self.send_heartbeat()

    async def error_handler(self, message: AgentMessage, error: Exception):
        """Handle errors during message processing."""
        error_msg = AgentMessage.create(
            source=self.agent_type,
            target=message.source_agent,
            msg_type=MessageType.ERROR,
            payload={
                "original_message_id": message.id,
                "error": str(error),
                "error_type": type(error).__name__,
            },
            conversation_id=message.conversation_id,
        )
        await self.message_bus.publish(error_msg)

    async def send_task(
        self,
        target: AgentType,
        task_type: str,
        input_data: dict[str, Any],
        context: dict[str, Any] | None = None,
    ) -> str:
        """Send a task to another agent."""
        conversation_id = str(uuid.uuid4())
        message = AgentMessage.create(
            source=self.agent_type,
            target=target,
            msg_type=MessageType.TASK,
            payload={
                "task_id": str(uuid.uuid4()),
                "task_type": task_type,
                "input_data": input_data,
                "context": context or {},
            },
            conversation_id=conversation_id,
        )
        await self.message_bus.publish(message)
        return conversation_id

    async def send_response(
        self,
        original_message: AgentMessage,
        payload: dict[str, Any],
    ):
        """Send a response to a message."""
        response = AgentMessage.create(
            source=self.agent_type,
            target=original_message.source_agent,
            msg_type=MessageType.RESPONSE,
            payload=payload,
            conversation_id=original_message.conversation_id,
            reply_to=original_message.id,
        )
        await self.message_bus.publish(response)

    async def broadcast_event(
        self,
        event_type: str,
        payload: dict[str, Any],
    ):
        """Broadcast an event to all agents."""
        message = AgentMessage.create(
            source=self.agent_type,
            target=None,  # broadcast
            msg_type=MessageType.EVENT,
            payload={"event_type": event_type, **payload},
        )
        await self.message_bus.publish(message)

    async def send_heartbeat(self):
        """Send a heartbeat message."""
        message = AgentMessage.create(
            source=self.agent_type,
            target=None,
            msg_type=MessageType.HEARTBEAT,
            payload={"timestamp": datetime.utcnow().isoformat()},
        )
        await self.message_bus.publish(message)

    async def start(self):
        """Start the agent."""
        self._running = True
        await self.message_bus.subscribe(self.agent_type, self.handler.handle)
        logger.info("agent_started", agent=self.agent_type)

    async def stop(self):
        """Stop the agent."""
        self._running = False
        await self.message_bus.unsubscribe(self.agent_type)
        logger.info("agent_stopped", agent=self.agent_type)


class MessageBus:
    """In-memory message bus for agent communication."""

    def __init__(self):
        self._subscriptions: dict[AgentType, list[Callable]] = {}
        self._global_handlers: list[Callable] = []
        self._message_queue: asyncio.Queue[AgentMessage] = asyncio.Queue()
        self._running = False

    async def start(self):
        """Start the message bus."""
        self._running = True
        asyncio.create_task(self._process_messages())
        logger.info("message_bus_started")

    async def stop(self):
        """Stop the message bus."""
        self._running = False
        logger.info("message_bus_stopped")

    async def subscribe(self, agent_type: AgentType, handler: Callable):
        """Subscribe an agent to receive messages."""
        if agent_type not in self._subscriptions:
            self._subscriptions[agent_type] = []
        self._subscriptions[agent_type].append(handler)

    async def unsubscribe(self, agent_type: AgentType):
        """Unsubscribe an agent from messages."""
        if agent_type in self._subscriptions:
            del self._subscriptions[agent_type]

    async def subscribe_global(self, handler: Callable):
        """Subscribe a handler to all messages."""
        self._global_handlers.append(handler)

    async def publish(self, message: AgentMessage):
        """Publish a message to the bus."""
        await self._message_queue.put(message)

    async def _process_messages(self):
        """Process messages from the queue."""
        while self._running:
            try:
                message = await asyncio.wait_for(self._message_queue.get(), timeout=1.0)

                # Deliver to target agent
                if message.target_agent:
                    handlers = self._subscriptions.get(message.target_agent, [])
                    for handler in handlers:
                        try:
                            await handler(message)
                        except Exception as e:
                            logger.error(
                                "message_handler_error",
                                agent=message.target_agent,
                                error=str(e),
                            )

                # Broadcast to all if no target
                if message.target_agent is None:
                    for agent_type, handlers in self._subscriptions.items():
                        if agent_type != message.source_agent:
                            for handler in handlers:
                                try:
                                    await handler(message)
                                except Exception as e:
                                    logger.error(
                                        "broadcast_handler_error",
                                        agent=agent_type,
                                        error=str(e),
                                    )

                # Deliver to global handlers
                for handler in self._global_handlers:
                    try:
                        await handler(message)
                    except Exception as e:
                        logger.error("global_handler_error", error=str(e))

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("message_bus_error", error=str(e))


class AgentRegistry:
    """Registry for managing all agents."""

    def __init__(self, message_bus: MessageBus, llm_router: Any):
        self.message_bus = message_bus
        self.llm_router = llm_router
        self._agents: dict[AgentType, BaseAgent] = {}

    def register(self, agent: BaseAgent):
        """Register an agent."""
        self._agents[agent.agent_type] = agent

    def get(self, agent_type: AgentType) -> BaseAgent | None:
        """Get an agent by type."""
        return self._agents.get(agent_type)

    def get_all(self) -> list[BaseAgent]:
        """Get all registered agents."""
        return list(self._agents.values())

    async def start_all(self):
        """Start all registered agents."""
        for agent in self._agents.values():
            await agent.start()

    async def stop_all(self):
        """Stop all registered agents."""
        for agent in self._agents.values():
            await agent.stop()
