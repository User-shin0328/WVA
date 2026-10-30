from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class PrivilegeLevel(str, Enum):
    UNAUTHENTICATED = "unauthenticated"
    USER_ROLE_A = "user_role_a"
    USER_ROLE_B = "user_role_b"
    ADMIN = "admin"
    SYSTEM = "system"

class LeakedArtifactType(str, Enum):
    USER_ID = "user_id"
    API_KEY = "api_key"
    AUTH_TOKEN = "auth_token"
    INTERNAL_PATH = "internal_path"
    DEBUG_INFO = "debug_info"
    SECRET_KEY = "secret_key"
    PARAM_CANDIDATE = "param_candidate"

class LeakedArtifact(BaseModel):
    artifact_type: LeakedArtifactType
    key: str
    value: str
    source_endpoint: str
    confidence: float = 1.0
    description: str = ""

class SecurityState(BaseModel):
    current_privilege: PrivilegeLevel = PrivilegeLevel.UNAUTHENTICATED
    accessible_endpoints: List[str] = Field(default_factory=list)
    known_artifacts: Dict[str, LeakedArtifact] = Field(default_factory=dict)
    active_tokens: Dict[str, str] = Field(default_factory=dict)

    def add_artifact(self, artifact: LeakedArtifact):
        self.known_artifacts[f"{artifact.artifact_type}:{artifact.key}:{artifact.value}"] = artifact

    def has_artifact_type(self, artifact_type: LeakedArtifactType) -> bool:
        return any(a.artifact_type == artifact_type for a in self.known_artifacts.values())

    def get_artifacts_by_type(self, artifact_type: LeakedArtifactType) -> List[LeakedArtifact]:
        return [a for a in self.known_artifacts.values() if a.artifact_type == artifact_type]
