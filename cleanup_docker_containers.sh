#!/bin/bash

sudo rm ./python_aef/*.crt ./python_aef/*.key

docker-compose down --rmi all --remove-orphans || true