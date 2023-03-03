from evolved5g.sdk import CAPIFProviderConnector
import configparser
import os


def showcase_capif_nef_connector():
    """

    """
    config = configparser.ConfigParser()
    config.read('credentials.properties')

    username = config.get("credentials", "provider_username")
    password = config.get("credentials", "provider_password")
    description = config.get("credentials", "provider_description")
    cn = config.get("credentials", "provider_cn")

    capif_ip = os.getenv('CAPIF_HOSTNAME')
    capif_port = os.getenv('CAPIF_PORT')

    # capif_connector = CAPIFProviderConnector(certificates_folder="/usr/src/app",  #"/the_path_to_the_certificates_folder/",
    #                                          capif_host="capifcore",
    #                                          capif_http_port="8080",
    #                                          capif_https_port="443",
    #                                          capif_netapp_username="test_aef001",
    #                                          capif_netapp_password="test_password",
    #                                          description= "test_app_description",
    #                                          csr_common_name="apf",
    #                                          csr_organizational_unit="test_app_ou",
    #                                          csr_organization="test_app_o",
    #                                          crs_locality="Madrid",
    #                                          csr_state_or_province_name="Madrid",
    #                                          csr_country_name="ES",
    #                                          csr_email_address="test@example.com"
    #                                          )
    capif_connector = CAPIFProviderConnector(certificates_folder="/usr/src/app",  #"/the_path_to_the_certificates_folder/",
                                             capif_host=capif_ip,
                                             capif_http_port=capif_port,
                                             capif_https_port="443",
                                             capif_netapp_username=username,
                                             capif_netapp_password=password,
                                             description= description,
                                             csr_common_name=cn,
                                             csr_organizational_unit="test_app_ou",
                                             csr_organization="test_app_o",
                                             crs_locality="Madrid",
                                             csr_state_or_province_name="Madrid",
                                             csr_country_name="ES",
                                             csr_email_address="test@example.com"
                                             )

    capif_connector.register_and_onboard_provider()

    capif_connector.publish_services(
        service_api_description_json_full_path="/usr/src/app/service_api_description.json")

    capif_connector.publish_services(
        service_api_description_json_full_path="/usr/src/app/service_api_description_goodbye.json")

    capif_connector.publish_services(
        service_api_description_json_full_path="/usr/src/app/service_api_description_hello.json")


if __name__ == "__main__":
    #Let's register a NEF to CAPIF. This should happen exactly once
    showcase_capif_nef_connector()
