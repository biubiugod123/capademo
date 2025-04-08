# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Models for Frida log data.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, model_validator


class FridaEvent(BaseModel):
    """Model for a Frida event"""

    type: Optional[str] = None
    api: Optional[str] = None
    args: Optional[List[Any]] = None
    timestamp: Optional[str] = None
    return_value: Optional[Any] = None


class FridaLog(BaseModel):
    """Model for a complete Frida log"""

    events: List[FridaEvent] = []

    @model_validator(mode="before")
    @classmethod
    def handle_list_format(cls, data: Any) -> Dict[str, Any]:
        """Handle case where log is just a list of events"""
        if isinstance(data, list):
            return {"events": data}
        elif "events" not in data and isinstance(data, dict):
            return {"events": [data]}
        return data
