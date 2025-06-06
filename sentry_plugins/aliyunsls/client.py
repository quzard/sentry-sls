import logging
import time
from typing import List, Tuple, Optional

from aliyun.log import LogClient, LogItem, PutLogsRequest, LogException

from sentry.shared_integrations.exceptions import ApiError, ApiHostError, ApiTimeoutError

logger = logging.getLogger(__name__)

class AliyunSLSClient:
    def __init__(
        self,
        endpoint: str,
        access_key_id: str,
        access_key_secret: str,
        project: str,
        logstore: str,
        topic: Optional[str] = "",
        source_ip: Optional[str] = None,
    ):
        self.endpoint = endpoint
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.project = project
        self.logstore = logstore
        self.topic = topic
        self.source_ip = source_ip

        try:
            self.client = LogClient(self.endpoint, self.access_key_id, self.access_key_secret)
        except Exception as e:
            logger.error(f"Failed to initialize AliyunSLSClient: {e}")
            raise ApiHostError(f"Failed to connect to SLS endpoint: {self.endpoint}")

    def send_log(self, contents: List[Tuple[str, str]]) -> None:
        log_items = [LogItem(int(time.time()), contents=contents)]

        request = PutLogsRequest(
            project=self.project,
            logstore=self.logstore,
            topic=self.topic,
            logitems=log_items,
            source=self.source_ip,
        )

        try:
            response = self.client.put_logs(request)
            response.log_print()
        except LogException as e:
            logger.error(
                "Aliyun SLS API Error: status=%s, error_code=%s, error_message=%s, request_id=%s",
                e.http_status_code,
                e.get_error_code(),
                e.get_error_message(),
                e.get_request_id(),
                extra={
                    "project": self.project,
                    "logstore": self.logstore,
                }
            )
            # Map to Sentry's ApiError for consistent handling if needed
            # You might want to customize this based on specific LogException error codes
            if e.http_status_code == 401 or e.http_status_code == 403:
                raise ApiError(f"SLS Authentication Error: {e.get_error_message()}", code=e.http_status_code)
            elif e.http_status_code == 400:
                 raise ApiError(f"SLS Bad Request: {e.get_error_message()}", code=e.http_status_code)
            elif e.http_status_code and 500 <= e.http_status_code < 600 :
                 raise ApiTimeoutError(f"SLS Server Error: {e.get_error_message()}", code=e.http_status_code) # Or ApiHostError
            else:
                raise ApiError(f"SLS Error: {e.get_error_message()}", code=e.http_status_code)
        except Exception as e:
            # Catch other potential errors (network issues, etc.)
            logger.error(
                "Failed to send log to Aliyun SLS: %s", e,
                extra={"project": self.project, "logstore": self.logstore}
            )
            raise ApiHostError(f"Network or unknown error sending to SLS: {e}")