# dummy-aef

## Architecture

| Container          | Folder             | Description                                                     |
|--------------------|--------------------|-----------------------------------------------------------------|
| python_aef         | python_aef         | Python API Exposing Function (communication example with CAPIF) |
| redis_aef          | -                  | DB to store info exchanged with CAPIF                           |
| capif_callback_aef | capif_callback_aef | Server implementing CAPIF callback endpoints                    |

## Development status
| Development Task                    | Subtask                 | Status |
|-------------------------------------|-------------------------|--------|
| Communication with CAPIF            | Register                | ✅      |
|                                     | Provider Management API | ✅      |
|                                     | Publish Service API     | ✅      |
| Communication with dummy_netapp     | -                       | ✅      |
| Use of CAPIF SDK libraries          | -                       | ❌      |
| Callback server for CAPIF responses | -                       | ✅      |
| TLS Communication with CAPIF        | -                       | ✅      |


## Container management
Pre-condition:
- Deploy CAPIF (locally or on another server)
- Define IPs* and ports of CAPIF and callback server (in files credentails.properties)

*If CAPIF is running on the same host as dummy_aef,
then leave the IP properties as "host.docker.internal". 
Otherwise, add the IP of their host (e.g. "192.168.X.X"). 

**For communication with dummy_netapp, demo-network is created.

```shell
# Deploy and run containers
./run.sh

# Stop containers
./stop.sh

# Stop and Remove containers
./cleanup_docker_containers.sh
```

## Use Python NetApp

```shell
# Access Python NetApp
./terminal_to_py_aef.sh

# Inside the container
# Test NetApp with CAPIF and dummy_aef
python3 1_aef_register.py
python3 2_aef_publish.py
python3 2_aef_security.py
python3 2_aef_service.py

# Outside container, for clean-up
sudo rm ./python_aef/*.crt ./python_aef/*.key
```