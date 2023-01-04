import requests
import json
import configparser
import os
import redis
from termcolor import colored

# Get environment variables
REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = os.environ.get('REDIS_PORT')


def post_log_to_capif(capif_ip, ccf_url, aef_id, service_api_id):
    print(colored("Post Log to CAPIF", "yellow"))

    url = 'https://{}/{}'.format(capif_ip, ccf_url)
    payload = open('invocation_log.json', 'rb')

    headers = {
        'Content-Type': 'application/json'
    }

    try:
        print(colored("''''''''''REQUEST'''''''''''''''''", "blue"))
        print(colored(f"Request: to {url}", "blue"))
        print(colored(f"Request Headers: {headers}", "blue"))
        print(colored(f"''''''''''REQUEST'''''''''''''''''", "blue"))

        response = requests.request("POST", url, headers=headers, data=payload, cert=('exposer.crt', 'private.key'),
                                    verify='ca.crt')
        response.raise_for_status()
        response_payload = json.loads(response.text)

        print(colored("''''''''''RESPONSE'''''''''''''''''", "green"))
        print(colored(f"Response to: {response.url}", "green"))
        print(colored(f"Response Headers: {response.headers}", "green"))
        print(colored(f"Response: {response.json()}", "green"))
        print(colored(f"Response Status code: {response.status_code}", "green"))
        print(colored("Success, registered api service to CAPIF", "green"))
        print(colored("''''''''''RESPONSE'''''''''''''''''", "green"))
        return response_payload
    except requests.exceptions.HTTPError as err:
        message = json.loads(err.response.text)
        status = err.response.status_code
        raise Exception(message, status)


if __name__ == '__main__':

    r = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        decode_responses=True,
    )

    config = configparser.ConfigParser()
    config.read('credentials.properties')

    username = config.get("credentials", "exposer_username")
    password = config.get("credentials", "exposer_password")
    role = config.get("credentials", "exposer_role")
    description = config.get("credentials", "exposer_description")
    cn = config.get("credentials", "exposer_cn")

    capif_ip = os.getenv('CAPIF_HOSTNAME')
    capif_port = os.getenv('CAPIF_PORT')

    api_prov_dom_id = r.get('api_prov_dom_id')
    serviceapiid = r.get('serviceapiid1')

    if api_prov_dom_id and serviceapiid:
        ccf_log_url = "api-invocation-logs/v1/" + str(api_prov_dom_id) + "/logs"
        log_res = post_log_to_capif(capif_ip, ccf_log_url, api_prov_dom_id, serviceapiid)
        print(colored(f"Log response: {log_res}", "yellow"))