
import requests
import json
import configparser
import os
import redis

# Get environment variables
REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = os.environ.get('REDIS_PORT')


def register_exposer_to_capif(capif_ip, capif_port, username, password, role, description, cn):

    print("Registering exposer to CAPIF")
    url = "http://{}:{}/register".format(capif_ip, capif_port)

    payload = dict()
    payload['username'] = username
    payload['password'] = password
    payload['role'] = role
    payload['description'] = description
    payload['cn'] = cn

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
        print("''''''''''RESPONSE'''''''''''''''''")
        print("Response to: ",response.url) 
        print("Response Headers: ",  response.headers) 
        print("Response: ", response.json())
        print("Response Status code: ", response.status_code)
        print("Success to register new exposer")
        print("''''''''''RESPONSE'''''''''''''''''")
        return response_payload['id'], response_payload['ccf_publish_url'], response_payload['ccf_api_onboarding_url']
    except requests.exceptions.HTTPError as err:
        raise Exception(err.response.text, err.response.status_code)


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

def register_api_provider_to_capif(capif_ip, ccf_url):

    print("Registering api provider to CAPIF")

    url = 'https://{}/{}'.format(capif_ip, ccf_url)
    payload = open('api_provider_domain.json', 'rb')
    headers = {
        'Content-Type': 'application/json'
    }

    try:

        print("''''''''''REQUEST'''''''''''''''''")
        print("Request: to ",url) 
        print("Request Headers: ",  headers) 
        #print("Request Body: ", json.dumps(payload))
        print("''''''''''REQUEST'''''''''''''''''")

        response = requests.request("POST", url, headers=headers, data=payload, cert=('exposer.crt', 'private.key'), verify='ca.crt')
        response.raise_for_status()
        response_payload = json.loads(response.text)

        print("''''''''''RESPONSE'''''''''''''''''")
        print("Response to: ",response.url) 
        print("Response Headers: ",  response.headers) 
        print("Response: ", response.json())
        print("Response Status code: ", response.status_code)
        print("Success, registered api provider domain to CAPIF")
        print("''''''''''RESPONSE'''''''''''''''''")
        return response_payload['apiProvDomId']
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

    #Remove data from Redis
    keys = r.keys('*')
    r.delete(*keys)


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
    
    #First we need register exposer in CAPIF
    try:
        if not r.exists('exposerID'):
            exposerID, ccf_publish_url, ccf_api_onboarding_url = register_exposer_to_capif(capif_ip, capif_port, username, password, role, description,cn)
            r.set('exposerID', exposerID)
            r.set('ccf_publish_url', ccf_publish_url)
            r.set('ccf_api_onboarding_url', ccf_api_onboarding_url)
            print("exposer ID: {}".format(exposerID))
    except Exception as e:
        status_code = e.args[0]
        if status_code == 409:
            print("User already registed. Continue with token request\n")
        else:
            print(e)

    #Second, we need get auth, in this case create cert and private key file
    try:
        get_capif_auth(capif_ip, capif_port, username, password, role)

    except Exception as e:
        status_code = e.args[0]
        if status_code == 401:
            print("Bad credential or User not found\n")
        else:
            print(e)
        capif_access_token = None


    #Third publish service in CAPIF
    try:
        if r.exists('ccf_api_onboarding_url') and r.exists('exposerID'):
            ccf_publish_url = r.get('ccf_publish_url')
            capif_access_token = r.get('capif_access_token_exposer')
            ccf_api_onboarding_url = r.get('ccf_api_onboarding_url')
            api_prov_dom_id = register_api_provider_to_capif(capif_ip, ccf_api_onboarding_url)
    
            print("API provider domain Id: {}".format(api_prov_dom_id))
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
            print("API provider domain already registered.")
        else:
            print(e)