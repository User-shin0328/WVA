from abc import ABC, abstractmethod
import httpx
from core.graph.blackboard import SecurityBlackboard
from core.safety.governance import SafetyGovernance

class BaseAuditor(ABC):
    def __init__(self, blackboard: SecurityBlackboard, governance: SafetyGovernance):
        self.blackboard = blackboard
        self.governance = governance

    @abstractmethod
    async def audit(self, client: httpx.AsyncClient):
        """Execute audit routine and record findings/artifacts onto the blackboard."""
        pass
