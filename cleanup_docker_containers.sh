#!/bin/bash

docker-compose down --rmi all --remove-orphans

# sudo rm ./python_aef/AEF_* && sudo rm ./python_aef/APF_* && sudo rm ./python_aef/AMF_* && sudo rm ./python_aef/ca.crt && sudo rm ./python_aef/domain.* && sudo rm ./python_aef/dummy* && sudo rm ./python_aef/capif_cert_server.pem && sudo rm ./python_aef/capif_provider_details.json
(
 sudo rm ./python_aef/AEF_*
 sudo rm ./python_aef/APF_*
 sudo rm ./python_aef/AMF_*
 sudo rm ./python_aef/ca.crt
 sudo rm ./python_aef/domain.*
 sudo rm ./python_aef/cert_server.pem
 sudo rm ./python_aef/dummy*
 sudo rm ./python_aef/capif_cert_server.pem
)