# -----------------------------------------
# FireEye Detection On Demand
# -----------------------------------------

from .operations import *
from connectors.core.connector import Connector, get_logger, ConnectorError

logger = get_logger('fireeye-detection-on-demand')


class FireEyeDOD(Connector):
    def execute(self, config, operations, params, **kwargs):
        try:
            operation = operations.get(operations, None)
            if not operation:
                    logger.info('Unsupported operation [{0}]'.format(operations))
                    raise ConnectorError('Unsupported operation [{0}]'.format(operations))
            result = operation(config, params)
            return result
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)


    def check_health(self, config):
        logger.info('starting health check')
        check_health(config)
        logger.info('completed health check no errors')
