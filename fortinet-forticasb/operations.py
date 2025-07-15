"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

"""
operations.py

This module implements the business logic for the connector using the new
FortiCASBClient class (from forticasb_api.py) to handle low-level API interactions,
including token management and HTTP request handling.

It provides operations for:
  - Retrieving the resource URL map
  - Searching alerts (with pagination and file summary enrichment)
  - Searching activity logs
  - Fetching file summaries and policies
  - Checking connector health

"""

import requests
from time import time
from datetime import datetime, timedelta
from .constants import ACTIVITY_TYPES
from connectors.core.utils import update_connnector_config
from connectors.core.connector import get_logger, ConnectorError
from .forticasb_api import FortiCASBClient

logger = get_logger('fortinet-forticasb')


def build_params(params):
    """Filter out empty parameters from the given dictionary."""
    return {k: v for k, v in params.items() if v is not None and v != ''}


def str_to_list(param):
    """Convert a comma separated string into a list."""
    if ',' in param:
        return [item.strip() for item in param.split(',')]
    return [param.strip()]


def search_alerts(config, params):
    """
    Searches for alerts by constructing a payload with the provided parameters.
    Uses pagination to collect all alerts from each business unit defined in the resource map.
    Enriches each alert with file summary details.
    """
    payload = {}
    params = build_params(params)
    if params:
        payload.update(params)

    # Process startTime and endTime as epoch milliseconds
    if params.get('startTime'):
        try:
            dt = datetime.strptime(params.get(
                'startTime'), "%Y-%m-%dT%H:%M:%S.%f%z")
            payload['startTime'] = str(round(dt.timestamp()) * 1000)
        except Exception as e:
            raise ConnectorError("Invalid startTime format: {}".format(e))
    else:
        now = datetime.utcnow()
        # Default to 7 days ago
        start_time = (now - timedelta(days=7)).strftime("%s") + "000"
        payload['startTime'] = int(start_time)
    if params.get('endTime'):
        try:
            dt = datetime.strptime(params.get(
                'endTime'), "%Y-%m-%dT%H:%M:%S.%f%z")
            payload['endTime'] = str(round(dt.timestamp()) * 1000)
        except Exception as e:
            raise ConnectorError("Invalid endTime format: {}".format(e))
    else:
        now = datetime.utcnow()
        end_time = now.strftime("%s") + "000"
        payload['endTime'] = int(end_time)

    payload['skip'] = int(params.get('skip')) if params.get('skip') else 0
    payload['limit'] = int(params.get('limit')) if params.get('limit') else 100
    if params.get('policy') and isinstance(params.get('policy'), list):
        params['policy'] = ",".join(str(x) for x in params.get('policy'))
    # Process additional optional parameters
    for key in ['user', 'policy', 'activity', 'objectIdList', 'severity', 'status', 'idList', 'alertType', 'countryList', 'asc', 'desc']:
        if params.get(key):
            # For list-type parameters, split by comma; otherwise use the provided value.
            if key in ['user', 'policy', 'activity', 'objectIdList', 'severity', 'status', 'idList', 'alertType', 'countryList']:
                payload[key] = [s.strip() for s in str(params.get(key)).split(",")]
            else:
                payload[key] = params.get(key)
        else:
            payload[key] = [] if key not in ['asc', 'desc'] else ""

    endpoint = 'alert/list'

    # Ensure resource map is loaded in config
    if not config.get('resourceMap'):
        get_resource_url_map(config, params)

    resource_map = config.get('resourceMap')
    if not resource_map:
        raise ConnectorError("Resource map is empty. Cannot proceed.")

    user_id = resource_map[0]['roleId']
    business_units = [bu for bu in resource_map[0].get('buMapSet', [])]
    all_data = []
    fc = FortiCASBClient(config)
    for bu in business_units:
        additional_headers = {
            "companyId": str(bu.get('companyId')),
            "roleId": str(user_id),
            "buId": str(bu.get('buId'))
        }
        result = fetch_paginated_data(config, endpoint, method='POST', data=payload,
                                      additional_headers=additional_headers, client=fc)
        all_data.extend(result)

    # Enrich alert data with file summary details
    files = []
    file_data = {}
    for alert in all_data:
        file_info = {"buId": alert.get("buId"), "companyId": alert.get(
            "companyId"), "fileId": alert.get("fileId")}
        if file_info["fileId"] not in files:
            files.append(file_info["fileId"])
            params_fs = {
                "companyId": str(file_info["companyId"]),
                "roleId": str(user_id),
                "buId": str(file_info["buId"]),
                "service": payload.get("service"),
                "fileId": str(file_info["fileId"])
            }
            summary = get_file_summary(config, params=params_fs)
            file_data[file_info["fileId"]] = summary.get(
                "data", {}).get("fileSummary")
    return {
        "alerts": all_data,
        "file_details": file_data,
    }


def search_activity(config, params):
    """
    Retrieves activity logs based on provided parameters, using pagination across business units.
    Translates human-readable activity names into IDs where applicable.
    """
    payload = {}
    params = build_params(params)
    if params:
        payload.update(params)

    if params.get('startTime'):
        try:
            dt = datetime.strptime(params.get(
                'startTime'), "%Y-%m-%dT%H:%M:%S.%f%z")
            payload['startTime'] = str(round(dt.timestamp()) * 1000)
        except Exception as e:
            raise ConnectorError("Invalid startTime format: {}".format(e))
    else:
        now = datetime.utcnow()
        start_time = (now - timedelta(days=7)).strftime("%s") + "000"
        payload['startTime'] = int(start_time)
    if params.get('endTime'):
        try:
            dt = datetime.strptime(params.get(
                'endTime'), "%Y-%m-%dT%H:%M:%S.%f%z")
            payload['endTime'] = str(round(dt.timestamp()) * 1000)
        except Exception as e:
            raise ConnectorError("Invalid endTime format: {}".format(e))
    else:
        now = datetime.utcnow()
        end_time = now.strftime("%s") + "000"
        payload['endTime'] = int(end_time)

    payload['skip'] = int(params.get('skip')) if params.get('skip') else 0
    payload['limit'] = int(params.get('limit')) if params.get('limit') else 100

    if params.get('cityList'):
        payload["cityList"] = [s.strip()
                               for s in params.get('cityList').split(",")]
    if params.get('idList'):
        payload["idList"] = [s.strip()
                             for s in params.get('idList').split(",")]
    if params.get('activity'):
        # Translate activity names to IDs using ACTIVITY_TYPES lookup
        payload["activity"] = []
        for name in [s.strip() for s in params.get('activity').split(",")]:
            for activity in ACTIVITY_TYPES:
                if name in activity.values():
                    payload["activity"].append(activity["id"])
    if params.get('ipList'):
        payload["ipList"] = [s.strip()
                             for s in params.get('ipList').split(",")]
    if params.get('objectName'):
        payload["objectName"] = params.get('objectName')

    endpoint = 'activity/data'
    if not config.get('resourceMap'):
        get_resource_url_map(config, params)
    resource_map = config.get('resourceMap')
    user_id = resource_map[0]['roleId']
    business_units = [bu for bu in resource_map[0].get('buMapSet', [])]
    all_data = []
    fc = FortiCASBClient(config)
    for bu in business_units:
        additional_headers = {
            "companyId": str(bu.get('companyId')),
            "roleId": str(user_id),
            "buId": str(bu.get('buId')),
            "service": params.get('service', "AWSS3")
        }
        result = fetch_paginated_data(config, endpoint, method='POST', data=payload,
                                      additional_headers=additional_headers, client=fc)
        all_data.extend(result)
    return {"activities": all_data}


def get_file_summary(config, params):
    """
    Retrieves a file summary for the given fileId.
    """
    fc = FortiCASBClient(config)
    params = build_params(params)
    additional_headers = {
        "companyId": params.get('companyId'),
        "roleId": params.get('roleId'),
        "buId": params.get('buId'),
        "service": params.get('service'),
        "fileId": params.get('fileId'),
        "timezone": params.get('timezone', "-0800")
    }
    result = fc.make_api_call(config=config, endpoint="profile/document/fileSummary",
                              method='POST', data={}, additional_headers=additional_headers)
    return result


def get_policies(config, params):
    """
    Retrieves policy data across all business units.
    """
    fc = FortiCASBClient(config)
    params = build_params(params)
    if not config.get('resourceMap'):
        get_resource_url_map(config, params)
    endpoint = "scan/policy/list"
    resource_map = config.get('resourceMap')
    user_id = resource_map[0]['roleId']
    all_data = []
    for bu in resource_map[0].get('buMapSet', []):
        additional_headers = {
            "companyId": str(bu.get('companyId')),
            "roleId": str(user_id),
            "buId": str(bu.get('buId')),
            "timezone": params.get('timezone', "-0800")
        }
        result = fc.make_api_call(config=config, endpoint=endpoint, method='GET', data=None,
                                  additional_headers=additional_headers)
        if isinstance(result, list):
            all_data.extend(result)
        else:
            all_data.append(result)
        break
    return {"policies": all_data}


def get_datapatterns(config, params):
    """
    Retrieves datapattern details across all business units.
    """
    fc = FortiCASBClient(config)
    params = build_params(params)
    if not config.get('resourceMap'):
        get_resource_url_map(config, params)
    endpoint = "datapattern/list"
    resource_map = config.get('resourceMap')
    user_id = resource_map[0]['roleId']
    all_data = []
    for bu in resource_map[0].get('buMapSet', []):
        additional_headers = {
            "companyId": str(bu.get('companyId')),
            "roleId": str(user_id),
            "buId": str(bu.get('buId')),
            "timezone": params.get('timezone', "-0800")
        }
        result = fc.make_api_call(config=config, endpoint=endpoint, method='GET', data=None,
                                  additional_headers=additional_headers)
        if isinstance(result, list):
            all_data.extend(result)
        else:
            all_data.append(result)
        break
    return {"datapatterns": all_data}


def get_resource_url_map(config, params):
    """
    Retrieves the resource URL map and stores it in the config.
    """
    fc = FortiCASBClient(config)
    params = build_params(params)
    endpoint = "resourceURLMap"
    response = fc.make_api_call(config=config, endpoint=endpoint)
    config['resourceMap'] = response
    return response


def fetch_paginated_data(config, endpoint, method='GET', data=None, additional_headers=None, client=None):
    """
    Repeatedly calls the API to fetch all paginated data.
    """
    if client is None:
        client = FortiCASBClient(config)
    all_data = []
    while True:
        result = client.make_api_call(config=config, endpoint=endpoint, method=method,
                                      data=data, additional_headers=additional_headers)
        result_data = result.get('data', [])
        if isinstance(result_data, list):
            all_data.extend(result_data)
        elif isinstance(result_data, dict):
            all_data.extend(result_data.get('datas', []))
        limit = result.get('limit', 10)
        skip = result.get('skip', 0)
        total_count = result.get('totalCount', 0)
        if skip + limit >= total_count:
            break
        data['skip'] = skip + limit
    return all_data


def check_health(config):
    """
    Validates the connector health by ensuring a valid token exists.
    If absent or expired, a new token is generated.
    """
    try:
        fc = FortiCASBClient(config)
        if not config.get('token'):
            token_resp = fc.generate_token()
            config['token'] = token_resp.get('access_token')
            config['expiresAt'] = token_resp.get('expires')
            connector_info = config.get('connector_info')
            update_connnector_config(connector_info['connector_name'],
                                     connector_info['connector_version'],
                                     config, config['config_id'])
            return True
        else:
            # Validate and refresh if necessary
            _ = fc.validate_token(config)
            return True
    except Exception as err:
        raise ConnectorError(str(err))


# Define the operations mapping exposed via the connector interface.
operations = {
    'get_resource_url_map': get_resource_url_map,
    'search_alerts': search_alerts,
    'get_file_summary': get_file_summary,
    'search_activity': search_activity,
    'get_policies': get_policies,
    'get_datapatterns': get_datapatterns,
    'check_health': check_health
}
