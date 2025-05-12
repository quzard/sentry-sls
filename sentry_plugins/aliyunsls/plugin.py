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
from sentry_plugins.anonymizeip import anonymize_ip
from sentry_plugins.base import CorePluginMixin
from sentry_plugins.utils import get_secret_field_config

from .client import AliyunSLSClient, LogException
logger = logging.getLogger(__name__)

SETUP_URL = "https://www.aliyun.com/product/sls"

DESCRIPTION = """
Forward Sentry events to Alibaba Cloud Log Service (SLS).

Configure your Alibaba Cloud SLS Endpoint, Project, Logstore, AccessKey ID, and AccessKey Secret.
"""


class AliyunSLSPlugin(CorePluginMixin, DataForwardingPlugin):
    title = "Alibaba Cloud SLS"
    slug = "aliyunsls"
    description = DESCRIPTION
    conf_key = slug
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

    def get_rate_limit(self) -> tuple[int, int]:
        # number of requests, number of seconds (window)
        return (100, 1)

    def get_config(self, project, user=None, initial=None, add_additional_fields: bool = False, **kwargs):
        return [
            {
                "name": "endpoint",
                "label": "SLS Endpoint",
                "type": "url",
                "required": True,
                "help": "Your Alibaba Cloud SLS endpoint (e.g., https://cn-hangzhou.log.aliyuncs.com).",
                "placeholder": "e.g., https://cn-hangzhou.log.aliyuncs.com",
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

    def get_event_payload_properties(self, event):
        props = {
            "event_id": event.event_id,
            "issue_id": event.group_id,
            "project_id": event.project.slug,
            "transaction": event.get_tag("transaction") or "",
            "release": event.get_tag("sentry:release") or "",
            "environment": event.get_tag("environment") or "",
            "type": event.get_event_type(),
        }
        props["tags"] = [
            [k.format(tagstore.backend.get_standardized_key(k)), v] for k, v in event.tags
        ]
        for key, value in event.interfaces.items():
            if key == "request":
                headers = value.headers
                if not isinstance(headers, dict):
                    headers = dict(headers or ())

                props.update(
                    {
                        "request_url": value.url,
                        "request_method": value.method,
                        "request_referer": headers.get("Referer", ""),
                    }
                )
            elif key == "exception":
                exc = value.values[0]
                props.update({"exception_type": exc.type, "exception_value": exc.value})
            elif key == "logentry":
                props.update({"message": value.formatted or value.message})
            elif key in ("csp", "expectct", "expectstable", "hpkp"):
                props.update(
                    {
                        "{}_{}".format(key.rsplit(".", 1)[-1].lower(), k): v
                        for k, v in value.to_json().items()
                    }
                )
            elif key == "user":
                user_payload = {}
                if value.id:
                    user_payload["user_id"] = value.id
                if value.email:
                    user_payload["user_email_hash"] = md5_text(value.email).hexdigest()
                if value.ip_address:
                    user_payload["user_ip_trunc"] = anonymize_ip(value.ip_address)
                if user_payload:
                    props.update(user_payload)
        return props

    def initialize_variables(self, event):
        self.project_endpoint = self.get_option("endpoint", event.project)
        self.project_sls_project_name = self.get_option("sls_project_name", event.project)
        self.project_sls_logstore_name = self.get_option("sls_logstore_name", event.project)
        self.project_access_key_id = self.get_option("access_key_id", event.project)
        self.project_access_key_secret = self.get_option("access_key_secret", event.project)
        self.project_sls_topic = self.get_option("sls_topic", event.project) or ""

    def get_rl_key(self, event: Event) -> Optional[str]:
        if self.project_access_key_id and self.project_sls_project_name and self.project_sls_logstore_name:
            return f"{self.conf_key}:{md5_text(self.project_access_key_id, self.project_sls_project_name, self.project_sls_logstore_name).hexdigest()}"
        return None

    def is_ratelimited(self, event: Event) -> bool:
        if super().is_ratelimited(event):
            metrics.incr(
                "integrations.aliyunsls.forward_event.rate_limited",
                tags={"event_type": event.get_event_type()},
            )
            return True
        return False

    def get_event_payload(self, event):
        """
        Transforms the Sentry event into the format expected by AliyunSLSClient.
        SLS LogItem `contents` expects a list of (key, value) string tuples.
        """
        print(f"get_event_payload: {self.project_access_key_id}, {self.project_sls_project_name}, {self.project_sls_logstore_name}")
        properties = self.get_event_payload_properties(event)
        
        # Convert dictionary to list of (key, value) tuples
        # Ensure keys are valid for SLS (usually alphanumeric, underscores)
        sls_contents = []
        for key, value in properties.items():
            # Basic key sanitization: replace characters not ideal for keys
            # SLS keys are fairly flexible but good practice to keep them clean.
            clean_key = str(key).replace(".", "_").replace("-", "_").replace(":", "_")
            sls_contents.append((clean_key, str(value))) # Ensure value is string

        return sls_contents

    def forward_event(self, event: Event, payload: MutableMapping[str, Any]) -> bool:
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
            return False


        try:
            client = AliyunSLSClient(
                endpoint=self.project_endpoint,
                access_key_id=self.project_access_key_id,
                access_key_secret=self.project_access_key_secret,
                project=self.project_sls_project_name,
                logstore=self.project_sls_logstore_name,
                topic=self.project_sls_topic,
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

            if isinstance(exc, ApiError) and (
                # These two are already handled by the API client, Just log and return.
                isinstance(exc, (ApiHostError, ApiTimeoutError))
                # Most 4xxs are not errors or actionable for us do not re-raise.
                or (exc.code is not None and (401 <= exc.code <= 404))
                # 502s are too noisy.
                or exc.code == 502
            ):
                return False
            raise

        metrics.incr(
            "integrations.aliyunsls.forward_event.success",
            tags={"event_type": event.get_event_type()},
        )
        return True
