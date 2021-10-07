import requests
import json
from requests import exceptions as req_exceptions
from integrations.crudhub import make_request
from connectors.core.connector import get_logger, ConnectorError, api_health_check
from os.path import join
try:
    from integrations.crudhub import download_file_from_cyops
except:
    from connectors.cyops_utilities.builtins import download_file_from_cyops

logger = get_logger('fireeye-detection-on-demand')


class FireeyeClient:
    api_key = None

    def __init__(self, config):
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')
        self.host = config.get('server_url').strip('/')
        if self.host[:7] == "http://":
            self.host = "https://{0}".format(self.host)
        elif self.host[:8] == "https://":
            self.host = "{0}".format(self.host)
        else:
            self.host = "https://{0}".format(self.host)

        self.headers = {'feye-auth-key': self.api_key}

    def authenticate(self):
        try:

            self.make_rest_api_call('GET','/health', )
        except Exception as e:
            raise e

    def make_rest_api_call(self, method, endpoint, payload=None, files=None, data=None):
        try:
            response = None
            request_url = "{0}{1}".format(self.host, endpoint)

            if method == 'GET':
                response = requests.get(request_url,
                                        headers=self.headers,
                                        params=payload,
                                        verify=self.verify_ssl)

            elif method == 'POST':
                response = requests.post(request_url,
                                         headers=self.headers,
                                         params=payload,
                                         files=files,
                                         data=data,
                                         verify=self.verify_ssl)

            if response.ok:
                return response.json()

            else:
                logger.debug("Requested URL: {0}".format(response.url))
                error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.text)

                logger.error(error_msg)
                raise ConnectorError(error_msg)

        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            logger.error(str(err))
            raise ConnectorError(str(err))

    def convert_str_list(self, param):
        param_list = list(map(lambda x: x.strip(' '), param.split(','))) if isinstance(param, str) else param
        return param_list


def from_cyops_download_file(iri):
    try:
        file_name = None
        attachment_data = make_request(iri, 'GET')
        if iri.startswith('/api/3/attachments/'):
            file_iri = attachment_data['file']['@id']
            file_name = attachment_data['file']['filename']
            logger.info('file id = {0}, file_name = {1}'.format(file_iri, file_name))
        else:
            file_iri = iri
        dw_file_md = download_file_from_cyops(file_iri)
        file_path = join('/tmp', dw_file_md['cyops_file_path'])
        if file_name == None:
            file_name = dw_file_md['filename'] if dw_file_md['filename'] != None else "Upload_from_the_FortiSOAR"
        return file_path, file_name
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def get_hashes(config, params):
    try:
        dod = FireeyeClient(config)
        res = dod.make_rest_api_call('GET', '/hashes/{0}'.format(params.get(hash)))
        return res
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_report(config, params):
    try:
        dod = FireeyeClient(config)
        report_id = params.get("report_id")
        extended = params.get("extended", False)
        res = dod.make_rest_api_call('GET', '/reports/{0}'.format(report_id), payload={'extended': extended})
        return res
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def submit_file(config, params):
    try:
        dod = FireeyeClient(config)
        attachment_iri = params.get("attachment_iri")
        file_path, file_name = from_cyops_download_file(attachment_iri)
        file = {'file': (file_name, open(file_path, 'rb'))}

        optional_params = ['password', 'param', 'screenshot', 'video', 'fileExtraction', 'memoryDump', 'pcap']
        data = {}
        for param in optional_params:
            value = params.get(param)
            if value:
                data[param] = value
        res = dod.make_rest_api_call('POST', '/files', files=file, data=data)
        return res
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def submit_urls(config, params):
    try:
        dod = FireeyeClient(config)
        urls = dod.convert_str_list(params.get('urls'))

        # Format the URLs into a string list, which the API understands
        formatted_urls = "[" + ",".join(list(map(lambda url: url.replace(url, "{url}").format(url), urls))) + "]"
        data = {'urls': formatted_urls}
        res = dod.make_rest_api_call('POST', '/urls', files=data)
        return res
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_report_url(config, params):
    try:
        report_id = params.get("report_id")
        expiration = params.get("expiration")
        if expiration:
            if expiration < 1 or expiration > 8760:
                raise ConnectorError ("Expiration must be between 1 and 8760 hours.")
        else:
            expiration = 72    #Default value is 72 hours

        payload = {
            'expiry': expiration
        }

        dod = FireeyeClient(config)
        res = dod.make_rest_api_call('GET', '/presigned-url/{0}'.format(report_id), payload)
        return res
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_artifacts(config, params):
    try:
        dod = FireeyeClient(config)
        report_id = params.get("report_id")
        payload = {'artifacts_type': params.get("artifacts_type")}
        artifacts_uuid = params.get("artifacts_uuid")
        if artifacts_uuid:
            payload['artifacts_uuid'] = artifacts_uuid

        res = dod.make_rest_api_call('GET', '/reports/{0}'.format(report_id), payload=payload)
        return res
    except Exception as err:
        logger.error("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def check_health(config):
    dod = FireeyeClient(config)
    res = dod.authenticate()
    return True


operations_dict = {
    'get_hashes': get_hashes,
    'get_report': get_report,
    'submit_file': submit_file,
    'submit_urls': submit_urls,
    'get-report_url': get_report_url,
    'get_artifacts': get_artifacts

}