import requests
import json
import configparser
import os
import redis

# Get environment variables
REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = os.environ.get('REDIS_PORT')

def get_capif_auth(capif_ip, capif_port, username, password, role):

    print("Geting Auth to exposer")
    url = "http://{}:{}/getauth".format(capif_ip, capif_port)

    payload = dict()
    payload['username'] = username
    payload['password'] = password
    payload['role'] = role

    headers = {
        'Content-Type': 'application/json'
    }

    try:
        print("''''''''''REQUEST'''''''''''''''''")
        print("Request: to ",url) 
        print("Request Headers: ",  headers) 
        print("Request Body: ", json.dumps(payload))
        print("''''''''''REQUEST'''''''''''''''''")

        response = requests.request("POST", url, headers=headers, data=json.dumps(payload))

        response.raise_for_status()
        response_payload = json.loads(response.text)
        certification_file = open('exposer.crt', 'wb+')
        private_key_file = open("private.key", 'wb+')
        certification_file.write(bytes(response_payload['cert'], 'utf-8'))
        private_key_file.write(bytes(response_payload['private_key'], 'utf-8'))
        certification_file.close()
        private_key_file.close()

        print("''''''''''RESPONSE'''''''''''''''''")
        print("Response to: ",response.url) 
        print("Response Headers: ",  response.headers) 
        print("Response: ", response.json())
        print("Response Status code: ", response.status_code)
        print("Get AUTH Success. Created private key and cert file ")
        print("''''''''''RESPONSE'''''''''''''''''")
        return
    except requests.exceptions.HTTPError as err:
        raise Exception(err.response.text, err.response.status_code)

def publish_service_api_to_capif(capif_ip, ccf_url):

    print("Publishing api service to CAPIF")

    url = 'https://{}/{}'.format(capif_ip, ccf_url)
    payload = open('service_api_description.json', 'rb')
    headers = {
        'Content-Type': 'application/json'
    }

    try:
        print("''''''''''REQUEST'''''''''''''''''")
        print("Request: to ",url) 
        print("Request Headers: ",  headers) 
        #print("Request Body: ", payload)
        print("''''''''''REQUEST'''''''''''''''''")

        response = requests.request("POST", url, headers=headers, data=payload, cert=('exposer.crt', 'private.key'), verify='ca.crt')
        response.raise_for_status()
        response_payload = json.loads(response.text)

        print("''''''''''RESPONSE'''''''''''''''''")
        print("Response to: ",response.url) 
        print("Response Headers: ",  response.headers) 
        print("Response: ", response.json())
        print("Response Status code: ", response.status_code)
        print("Success, registered api service to CAPIF")
        print("''''''''''RESPONSE'''''''''''''''''")
        return response_payload['apiId']
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
    
    # capif_ip = config.get("credentials", "capif_ip")
    # capif_port = config.get("credentials", "capif_port")
    capif_ip = os.getenv('CAPIF_HOSTNAME')
    capif_port = os.getenv('CAPIF_PORT')
#Third publish service in CAPIF
    try:
        if r.exists('exposerID'):
            ccf_publish_url = r.get('ccf_publish_url')
            capif_access_token = r.get('capif_access_token_exposer')
            service_api_id = publish_service_api_to_capif(capif_ip, ccf_publish_url)
            if not r.exists('services_num'):
                services_num = 0
            else:
                services_num = int(r.get('services_num'))

            services_num += 1
            r.set('services_num', services_num)
            r.set('serviceapiid'+str(services_num), service_api_id)
            print("Service Api Id: {}".format(service_api_id))
    except Exception as e:
        status_code = e.args[0]
        if status_code == 401:
            message = e.args[0]
            if str(message).find("Token has expired") != -1:
                capif_access_token = get_capif_auth(capif_ip, capif_port, username, password, role)
                r.set('capif_access_token_exposer', capif_access_token)
                print("New Capif Token: {}".format(capif_access_token))
                print("Run the script again to publish a Service API")
            elif str(message).find("Exposer not existing") != -1:
                print("Exposer not existing. Exposer id not found")
            else:
                print(e)
        elif status_code == 403:
            print("Service already published.")
            print("Change API name and AEF Profile ID in service_api_description.json")
        else:
            print(e)