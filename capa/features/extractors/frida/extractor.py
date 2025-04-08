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

import logging
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple, Iterator, Optional
from collections import namedtuple

from capa.features.common import String, Feature, Characteristic
from capa.features.freeze import Address
from capa.features.extractors.base_extractor import SampleHashes, DynamicFeatureExtractor

logger = logging.getLogger(__name__)

ProcessAddress = namedtuple("ProcessAddress", ["pid"])
ThreadAddress = namedtuple("ThreadAddress", ["tid", "process"])
ThreadHandle = namedtuple("ThreadHandle", ["address"])
ProcessHandle = namedtuple("ProcessHandle", ["address"])


class FridaExtractor(DynamicFeatureExtractor):
    """
    Extract features from Frida logs of Android applications.

    This enables Android application analysis with CAPA using Frida-based instrumentation.
    """

    def __init__(self, frida_log: Dict[str, Any], hashes: Optional[SampleHashes] = None):
        """
        Args:
            frida_log: The parsed Frida log JSON
            hashes: Sample hashes if available
        """
        super().__init__(hashes or SampleHashes("", "", ""))
        self.frida_log = frida_log
        self.events = self._parse_events()

    def extract_thread_features(self, process: int, thread: int) -> Iterator[Tuple[Feature, Address]]:
        # Since Frida logs do not contain thread-specific features,
        # we simply return an empty iterator.
        return iter(())

    def _parse_events(self) -> List[Dict[str, Any]]:
        """Extract events from the Frida log format"""
        if "events" in self.frida_log:
            return self.frida_log["events"]
        # Handle case where the log is just a list of events
        elif isinstance(self.frida_log, list):
            return self.frida_log
        # Handle single event case
        else:
            return [self.frida_log]

    def get_threads(self, process: int) -> Iterator[ThreadHandle]:
        # Create a hashable thread address.
        # Here, we use 0 as a dummy thread ID.
        thread_address = ThreadAddress(tid=0, process=ProcessAddress(pid=process if isinstance(process, int) else 0))
        # Yield a thread handle with that address.
        yield ThreadHandle(address=thread_address)

    def get_calls(self, process: int, thread: int) -> Iterator[SimpleNamespace]:
        for event in self.events:
            if event.get("type") == "api_call":
                # Ensure there is an 'address' key with a default value
                if "address" not in event:
                    event["address"] = 0
                yield SimpleNamespace(**event)

    def extract_call_features(self, ph: int, th: int, call: SimpleNamespace) -> Iterator[Tuple[Feature, Address]]:
        api_name = getattr(call, "api", "")
        if api_name:
            yield Feature("api", api_name), Address.from_capa(0)

            # For each argument, create a separate string feature
            if hasattr(call, "args") and call.args:
                for arg in call.args:
                    if isinstance(arg, str):
                        # Just yield the string feature for the argument
                        yield String(arg), Address.from_capa(0)

    @classmethod
    def from_log(cls, log: Dict[str, Any]) -> "FridaExtractor":
        """
        Construct a Frida feature extractor from a JSON log.

        Args:
            log: The parsed Frida log JSON

        Returns:
            FridaExtractor: The feature extractor
        """
        return cls(log)

    def extract_global_features(self) -> Iterator[Tuple[Feature, Address]]:
        """
        Extract features that apply to the entire sample.
        """
        # Indicate this is an Android application
        yield Characteristic("android"), Address.from_capa(0x0)

        # If we have API calls that indicate specific behaviors
        api_behaviors = set()
        for event in self.events:
            if event.get("type") == "api_call" or "api" in event:
                api = event.get("api", "")

                # Map API calls to behaviors
                if "URL.openConnection" in api or "HttpURLConnection" in api:
                    api_behaviors.add("network_communication")
                elif "SmsManager" in api:
                    api_behaviors.add("sms_functionality")
                elif "TelephonyManager.getDeviceId" in api:
                    api_behaviors.add("collects_device_info")
                elif "Cipher" in api:
                    api_behaviors.add("uses_encryption")
                # Add more mappings as needed

        # Yield behaviors as characteristics
        for behavior in api_behaviors:
            yield Characteristic(behavior), Address.from_capa(0x0)

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        """
        Extract file-level features.
        """
        # Yield any string literals captured in API calls
        for event in self.events:
            if event.get("type") == "api_call" or "api" in event:
                if "args" in event and isinstance(event["args"], list):
                    for arg in event["args"]:
                        if isinstance(arg, str):
                            yield String(arg), Address.from_capa(0x0)

    def get_processes(self) -> Iterator[ProcessHandle]:
        # Return a dummy process handle with pid 0
        yield ProcessHandle(address=ProcessAddress(pid=0))

    def extract_process_features(self, process_id: int) -> Iterator[Tuple[Feature, Address]]:
        """
        Extract features at the process level, mainly API calls.
        """
        for event in self.events:
            if event.get("type") == "api_call" or "api" in event:
                api = event.get("api", "")

                # Yield the API call as a feature
                yield Feature("api", api), Address.from_capa(0x0)

                # If there are arguments with sensitive information, yield strings
                if "args" in event and isinstance(event["args"], list):
                    for arg in event["args"]:
                        if isinstance(arg, str):
                            if "http://" in arg or "https://" in arg:
                                yield String(arg), Address.from_capa(0x0)
                                yield Feature("api", "network_communication"), Address.from_capa(0x0)
                            elif ".apk" in arg:
                                yield String(arg), Address.from_capa(0x0)
                                yield Feature("api", "file_operations"), Address.from_capa(0x0)
                            # Add more patterns as needed
