""" Copyright start
  Copyright (C) 2008 - 2025 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError
from .operations import operations, check_health

logger = get_logger('fortinet-FortiCASB')


class FortiCASB(Connector):
    def execute(self, config, operation, params, **kwargs):
        try:
            logger.info("In execute() Operation: [{}]".format(operation))
            # Insert connector info for later use by operations (eg: token update calls)
            config['connector_info'] = {
                "connector_name": self._info_json.get("name"),
                "connector_version": self._info_json.get("version")
            }
            op_func = operations.get(operation)
            if not op_func:
                logger.error("Unsupported operation [{}]".format(operation))
                raise ConnectorError("Unsupported operation")
            result = op_func(config, params)
            return result
        except Exception as err:
            logger.error("Exception occurred: {}".format(err))
            raise ConnectorError(err)

    def check_health(self, config):
        logger.info("In check_health()")
        config['connector_info'] = {
            "connector_name": self._info_json.get("name"),
            "connector_version": self._info_json.get("version")
        }
        return check_health(config)
