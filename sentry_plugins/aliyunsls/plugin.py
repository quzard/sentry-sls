import logging
from collections.abc import MutableMapping
from typing import Any, Dict, List, Tuple, Optional

from sentry import tagstore
from sentry.eventstore.models import Event
from sentry.integrations.base import FeatureDescription, IntegrationFeatures
from sentry.plugins.bases.data_forwarding import DataForwardingPlugin
from sentry.shared_integrations.exceptions import ApiError, ApiHostError, ApiTimeoutError
from sentry.utils import metrics
from sentry.utils.hashlib import md5_text
from sentry_plugins.anonymizeip import anonymize_ip # If you need IP anonymization
from sentry_plugins.base import CorePluginMixin
from sentry_plugins.utils import get_secret_field_config

# Import your client
from .client import AliyunSLSClient, LogException # LogException for specific handling if needed

logger = logging.getLogger(__name__)

# Update with actual links to your setup instructions for this plugin
SETUP_URL = "https://www.aliyun.com/product/sls" # Placeholder, update this

DESCRIPTION = """
Forward Sentry events to Alibaba Cloud Log Service (SLS).

Configure your Alibaba Cloud SLS Endpoint, Project, Logstore, AccessKey ID, and AccessKey Secret.
"""


class AliyunSLSPlugin(CorePluginMixin, DataForwardingPlugin):
    title = "Alibaba Cloud SLS"
    slug = "aliyunsls"
    description = DESCRIPTION
    conf_key = "aliyunsls" # Use a unique key
    required_field = "endpoint"
    # Update resource_links if you have setup instructions
    resource_links = [("Alibaba Cloud SLS", "https://www.aliyun.com/product/sls"),
                      ("Python SDK Docs", "https://aliyun-log-python-sdk.readthedocs.io/")] + CorePluginMixin.resource_links
    
    feature_descriptions = [
        FeatureDescription(
            """
            Forward Sentry errors and events to your configured Alibaba Cloud SLS instance.
            """,
            IntegrationFeatures.DATA_FORWARDING,
        )
    ]

    # --- Configuration ---
    project_endpoint: Optional[str] = None
    project_sls_project_name: Optional[str] = None
    project_sls_logstore_name: Optional[str] = None
    project_access_key_id: Optional[str] = None
    project_access_key_secret: Optional[str] = None
    project_sls_topic: Optional[str] = None


    def get_config(self, project, user=None, initial=None, add_additional_fields: bool = False, **kwargs):
        return [
            {
                "name": "endpoint",
                "label": "SLS Endpoint",
                "type": "url",
                "required": True,
                "help": "Your Alibaba Cloud SLS endpoint (e.g., cn-hangzhou.log.aliyuncs.com).",
                "placeholder": "e.g., cn-hangzhou.log.aliyuncs.com",
            },
            {
                "name": "sls_project_name",
                "label": "SLS Project Name",
                "type": "string",
                "required": True,
                "help": "The name of your SLS Project.",
            },
            {
                "name": "sls_logstore_name",
                "label": "SLS Logstore Name",
                "type": "string",
                "required": True,
                "help": "The name of your SLS Logstore within the project.",
            },
            {
                "name": "access_key_id",
                "label": "AccessKey ID",
                "type": "string",
                "required": True,
                "help": "Your Alibaba Cloud AccessKey ID.",
            },
            get_secret_field_config(
                name="access_key_secret",
                label="AccessKey Secret",
                secret=self.get_option("access_key_secret", project),
                help_text="Your Alibaba Cloud AccessKey Secret.",
                required=True,
            ),
            {
                "name": "sls_topic",
                "label": "SLS Topic (Optional)",
                "type": "string",
                "required": False,
                "help": "Optional topic for organizing logs within the Logstore.",
            },
        ]

    def initialize_variables(self, event: Event) -> None:
        self.project_endpoint = self.get_option("endpoint", event.project)
        self.project_sls_project_name = self.get_option("sls_project_name", event.project)
        self.project_sls_logstore_name = self.get_option("sls_logstore_name", event.project)
        self.project_access_key_id = self.get_option("access_key_id", event.project)
        self.project_access_key_secret = self.get_option("access_key_secret", event.project)
        self.project_sls_topic = self.get_option("sls_topic", event.project) or ""


    def get_rate_limit(self) -> tuple[int, int]:
        # Adjust as needed, (number of requests, number of seconds (window))
        return (100, 1)

    def get_rl_key(self, event: Event) -> Optional[str]:
        # Rate limit per SLS project and logstore combination
        if self.project_access_key_id and self.project_sls_project_name and self.project_sls_logstore_name:
            return f"{self.conf_key}:{md5_text(self.project_access_key_id, self.project_sls_project_name, self.project_sls_logstore_name).hexdigest()}"
        return None

    def is_ratelimited(self, event: Event) -> bool:
        if super().is_ratelimited(event):
            metrics.incr(
                "integrations.aliyunslsaliyunsls.forward_event.rate_limited",
                tags={"event_type": event.get_event_type()},
            )
            return True
        return False

    def get_source_ip_for_sls(self, event: Event) -> Optional[str]:
        """
        Determines a source IP. This could be the IP of the user causing the event,
        or the server name. SLS uses this for the 'source' field in PutLogsRequest.
        It's often the IP of the machine *sending* the log.
        For now, let's try to get it from the event, like server_name or user IP.
        """
        # Option 1: Server name (if it's an IP or resolvable) - less common to be just an IP
        # host = event.get_tag("server_name")
        # if host:
        #     return host

        # Option 2: User's IP address (potentially PII, consider anonymization or policy)
        user_interface = event.interfaces.get("user")
        if user_interface and user_interface.ip_address:
            # You might want to anonymize this if sending user IP
            # return anonymize_ip(user_interface.ip_address)
            return user_interface.ip_address

        # Fallback: None, SLS SDK might use the machine's IP where this code runs.
        return None


    def get_event_payload_properties(self, event: Event) -> Dict[str, Any]:
        """
        Extracts properties from the Sentry event.
        This is largely similar to the Splunk plugin's method.
        Ensure values are appropriate for SLS (e.g. strings, or simple types that can be stringified).
        """
        props = {
            "event_id": event.event_id,
            "issue_id": str(event.group_id), # group_id can be int
            "project_slug": event.project.slug, # project_id is int, slug is string
            "project_name": event.project.name,
            "platform": event.platform or "unknown",
            "transaction": event.get_tag("transaction") or "",
            "release": event.get_tag("sentry:release") or "",
            "dist": event.get_tag("sentry:dist") or "",
            "environment": event.get_tag("environment") or "",
            "type": event.get_event_type(),
            "timestamp": event.datetime.isoformat(), # ISO format string for timestamp
            "level": event.get_tag("level") or "error", # Sentry levels
            "culprit": event.culprit or "",
            "message": event.message, # The primary message of the event
        }

        # Tags
        # SLS prefers flat key-value. We can prefix tags.
        for k, v in event.tags:
            # Standardize key if necessary, ensure it's SLS compatible
            # Example: tagstore.backend.get_standardized_key(k) if you use that
            props[f"tag_{k.replace('.', '_').replace(':', '_')}"] = str(v)


        # Interfaces (Request, Exception, User, etc.)
        if "request" in event.interfaces:
            request_data = event.interfaces["request"]
            props["request_url"] = request_data.url
            props["request_method"] = request_data.method
            if isinstance(request_data.headers, (list, tuple)): # headers can be list of tuples
                 props["request_headers"] = str(dict(request_data.headers)) # Convert to string
            elif isinstance(request_data.headers, dict):
                 props["request_headers"] = str(request_data.headers) # Convert to string

            if request_data.data:
                props["request_body"] = str(request_data.data) # Be cautious with large bodies


        if "exception" in event.interfaces:
            exc_data = event.interfaces["exception"]
            if exc_data.values:
                exc = exc_data.values[0] # Primary exception
                props["exception_type"] = exc.type
                props["exception_value"] = exc.value
                if exc.stacktrace and exc.stacktrace.frames:
                    # Simplistic stacktrace: just the last few frames' details
                    # SLS is not primarily for stack trace visualization like Sentry.
                    # You could join frame details into a single string or pick top/bottom.
                    frames_summary = []
                    for frame in reversed(exc.stacktrace.frames[-3:]): # Last 3 frames
                        frames_summary.append(f"{frame.filename_short or frame.filename}:{frame.lineno} in {frame.function or '?'}")
                    props["exception_stacktrace_summary"] = " -> ".join(frames_summary)


        if "logentry" in event.interfaces:
            logentry_data = event.interfaces["logentry"]
            props["logentry_message"] = logentry_data.formatted or logentry_data.message
            if logentry_data.params:
                props["logentry_params"] = str(logentry_data.params)


        if "user" in event.interfaces:
            user_data = event.interfaces["user"]
            if user_data.id:
                props["user_id"] = str(user_data.id)
            if user_data.email:
                props["user_email_hash"] = md5_text(user_data.email).hexdigest() # Hash PII
            if user_data.username:
                props["user_username"] = user_data.username
            if user_data.ip_address:
                # Anonymize if necessary, or if you have consent.
                props["user_ip_address_trunc"] = anonymize_ip(user_data.ip_address)

        # Breadcrumbs (could be too verbose for every event, consider sampling or summarizing)
        # if "breadcrumbs" in event.interfaces and event.interfaces["breadcrumbs"].values:
        #    breadcrumbs_summary = []
        #    for crumb in event.interfaces["breadcrumbs"].values[-5:]: # last 5
        #        breadcrumbs_summary.append(f"{crumb.get('timestamp')}|{crumb.get('category', '')}|{crumb.get('message', '')}")
        #    props["breadcrumbs_summary"] = " ;; ".join(breadcrumbs_summary)


        # SDK info
        sdk_info = event.data.get("sdk")
        if sdk_info:
            props["sdk_name"] = sdk_info.get("name")
            props["sdk_version"] = sdk_info.get("version")

        # Ensure all values are strings for SLS LogItem contents
        # SLS LogItem contents must be list of (string, string) tuples
        final_props = {}
        for k, v in props.items():
            if v is None:
                final_props[k] = "" # SLS expects string values
            elif isinstance(v, (dict, list, tuple)):
                try:
                    import json
                    final_props[k] = json.dumps(v) # Serialize complex types to JSON string
                except TypeError:
                    final_props[k] = str(v) # Fallback to string conversion
            else:
                final_props[k] = str(v)
        return final_props


    def get_event_payload(self, event: Event) -> List[Tuple[str, str]]:
        """
        Transforms the Sentry event into the format expected by AliyunSLSClient.
        SLS LogItem `contents` expects a list of (key, value) string tuples.
        """
        logger.info(f"get_event_payload: {self.project_access_key_id}, {self.project_sls_project_name}, {self.project_sls_logstore_name}")
        # properties = self.get_event_payload_properties(event)
        
        # Convert dictionary to list of (key, value) tuples
        # Ensure keys are valid for SLS (usually alphanumeric, underscores)
        sls_contents = []
        sls_contents.append(("time", event.datetime.strftime("%s")))

        return sls_contents


    def forward_event(self, event: Event, payload: List[Tuple[str, str]]) -> bool:
        """
        Forwards the event payload to Aliyun SLS.
        The 'payload' argument here is already processed by get_event_payload.
        """
        # Initialize variables if not already done (might be called multiple times)
        self.initialize_variables(event)

        if not all([
            self.project_endpoint,
            self.project_sls_project_name,
            self.project_sls_logstore_name,
            self.project_access_key_id,
            self.project_access_key_secret,
        ]):
            metrics.incr(
                "integrations.aliyunsls.forward_event.unconfigured",
                tags={"event_type": event.get_event_type()},
            )
            logger.info(
                "integrations.aliyunsls.forward_event.unconfigured",
                extra={
                    "project_id": event.project_id,
                    "organization_id": event.project.organization_id,
                }
            )
            return False # Not configured

        # Determine source IP for SLS log item
        # This IP is for the 'source' field in PutLogsRequest, often the server sending the log.
        # It's distinct from user_ip_address which might be part of the log payload.
        # For simplicity, we can let the SLS SDK auto-detect or pass a configured Sentry server IP if available.
        # Here, `get_source_ip_for_sls` tries to get a relevant IP from the event data itself.
        sls_source_ip = self.get_source_ip_for_sls(event)


        try:
            client = AliyunSLSClient(
                endpoint=self.project_endpoint,
                access_key_id=self.project_access_key_id,
                access_key_secret=self.project_access_key_secret,
                project=self.project_sls_project_name,
                logstore=self.project_sls_logstore_name,
                topic=self.project_sls_topic,
                source_ip=sls_source_ip,
            )
            # The `payload` is already the list of (key, value) tuples from `get_event_payload`
            client.send_log(contents=payload)

        except Exception as exc:
            metric = "integrations.aliyunsls.forward_event.error"
            tags = {"event_type": event.get_event_type()}
            if isinstance(exc, ApiError) and exc.code:
                tags["error_code"] = exc.code

            metrics.incr(metric, tags=tags)
            logger.info(
                metric,
                extra={
                    "endpoint": self.project_endpoint,
                    "sls_project": self.project_sls_project_name,
                    "sls_logstore": self.project_sls_logstore_name,
                    "project_id": event.project_id,
                    "organization_id": event.project.organization_id,
                    "error": str(exc),
                },
            )

            # Decide whether to re-raise based on error type, similar to Splunk plugin
            if isinstance(exc, (ApiHostError, ApiTimeoutError)):
                return False # Already handled by client or too noisy
            if isinstance(exc, ApiError) and (
                (exc.code is not None and (400 <= exc.code <= 404)) # 400, 401, 403, 404 usually not retried
            ):
                return False
            raise # Re-raise other errors for Sentry to handle (e.g. retry)

        metrics.incr(
            "integrations.aliyunsls.forward_event.success",
            tags={"event_type": event.get_event_type()},
        )
        return True