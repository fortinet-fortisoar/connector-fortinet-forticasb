"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

"""
FortiCASB REST Client implementation
Updated to consolidate token management, API call handling, and additional header support
into the FortiCASBClient class.
"""

import requests
from time import time
from datetime import datetime
from connectors.core.connector import get_logger, ConnectorError
from requests_toolbelt.utils import dump

logger = get_logger('fortinet-FortiCASB')


class FortiCASBClient:
    def __init__(self, config):
        """
        Initialize the API client using the provided configuration.

        - Ensures the server URL has the proper scheme and no trailing slash.
        - Retrieves the API key (secret) and SSL verification flag.
        """
        self.server_url = config.get('server_url').strip('/')
        if not self.server_url.startswith('https://') and not self.server_url.startswith('http://'):
            self.server_url = 'https://' + self.server_url
        self.secret = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')
        self.request_timeout = 20  # seconds
        self.logger = logger

    def convert_ts_epoch(self, ts):
        """
        Converts a timestamp in milliseconds (as provided by the API)
        to an epoch timestamp in seconds.
        """
        dt = datetime.fromtimestamp(ts / 1000)
        return dt.timestamp()

    def generate_token(self):
        """
        Generates a new token using client credentials.
        This method uses a basic-auth approach and expects a JSON response
        with at least 'access_token' and 'expires' keys.
        """
        try:
            data = {
                "grant_type": "client_credentials"
            }
            url = f"{self.server_url}/api/v1/auth/credentials/token/"
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Authorization": f"Basic {self.secret}"
            }
            self.logger.info("Generating new token with URL: %s", url)
            response = requests.request(
                method="POST",
                url=url,
                headers=headers,
                data=data,
                verify=self.verify_ssl,
                timeout=self.request_timeout
            )
            self.logger.debug("Token generation response: %s",
                              dump.dump_all(response).decode('utf-8'))
            if response.status_code in [200, 201]:
                token_resp = response.json()
                return token_resp
            else:
                err_msg = f"Token generation failed [{response.status_code}:{response.reason}]"
                if response.text:
                    try:
                        error_details = response.json()
                        err_msg += f" Details: {error_details.get('message', '')}"
                    except Exception:
                        pass
                self.logger.error(err_msg)
                raise ConnectorError(err_msg)
        except Exception as err:
            self.logger.exception("Failed to generate token")
            raise ConnectorError(str(err))

    def validate_token(self, config):
        """
        Validates and returns a valid bearer token.

        If a token is absent or expired (based on the 'expiresAt' timestamp in the config),
        a new token is generated. The token (and expiration) is then stored back into config.
        """
        ts_now = time()
        if not config.get('token'):
            self.logger.info(
                "Token does not exist in config, generating new token.")
            token_resp = self.generate_token()
            config['token'] = token_resp['access_token']
            config['expiresAt'] = token_resp['expires']
            return f"Bearer {config['token']}"
        else:
            expires = config.get('expiresAt')
            expires_ts = self.convert_ts_epoch(expires)
            if ts_now > float(expires_ts):
                self.logger.info(
                    "Token expired at %s. Generating new token.", expires)
                token_resp = self.generate_token()
                config['token'] = token_resp['access_token']
                config['expiresAt'] = token_resp['expires']
                return f"Bearer {config['token']}"
            else:
                self.logger.info("Token is valid until %s.", expires)
                return f"Bearer {config['token']}"

    def make_api_call(self, config=None, endpoint=None, params=None, method='GET', data=None,
                      additional_headers=None, is_token_call=False, is_next_page=False):
        """
        Makes an API call to the specified endpoint.

        - When is_token_call is True, the method bypasses token validation and uses basic
          authentication to fetch a new token.
        - For regular calls, the method validates the token and builds the Bearer token header.
        - If is_next_page is True, the endpoint is treated as a fully qualified URL.
        """
        if is_next_page:
            url = endpoint
        else:
            url = f"{self.server_url}/api/v1/{endpoint}"
        self.logger.info("Making API call to URL: %s", url)

        try:
            if is_token_call:
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": f"Basic {self.secret}"
                }
                response = requests.request(
                    method=method,
                    url=url,
                    params=params,
                    headers=headers,
                    data=data,
                    verify=self.verify_ssl,
                    timeout=self.request_timeout
                )
            else:
                token = self.validate_token(config)
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": token
                }
                if additional_headers:
                    headers = {**headers, **additional_headers}

                response = requests.request(
                    method=method,
                    url=url,
                    params=params,
                    headers=headers,
                    json=data,
                    verify=self.verify_ssl,
                    timeout=self.request_timeout
                )

            if response.status_code in [200, 201]:
                if response.text != "":
                    return response.json()
            elif response.status_code == 204:
                return {"status": "ok", "message": "No content"}
            else:
                if response.text != "":
                    try:
                        err_resp = response.json()
                        failure_msg = err_resp.get('message', '')
                    except Exception:
                        failure_msg = ""
                    error_msg = f"Response [{response.status_code}:{response.reason}] Details: {failure_msg}"
                else:
                    error_msg = f"Response [{response.status_code}:{response.reason}]"
                self.logger.error("API call failed: %s", error_msg)
                raise ConnectorError(error_msg)
        except Exception as e:
            self.logger.exception("Request failed")
            raise ConnectorError(f"Request Failed: {str(e)}")
