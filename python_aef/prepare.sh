COUNTRY="ES"                # 2 letter country-code
STATE="Madrid"            # state or province name
LOCALITY="Madrid"        # Locality Name (e.g. city)
ORGNAME="Telefonica I+D" # Organization Name (eg, company)
ORGUNIT="Innovation"                  # Organizational Unit Name (eg. section)
COMMONNAME="python-aef"
EMAIL="inno@tid.es"    # certificate's email address
# optional extra details
CHALLENGE=""                # challenge password
COMPANY=""                  # company name

# DAYS="-days 365"

# create the certificate request
#cat <<__EOF__ | openssl req -new $DAYS -nodes -keyout client.key -out client.csr
cat <<__EOF__ | openssl req -newkey rsa:4096 -nodes -sha256 -keyout domain.key -x509 -days 365 -out domain.crt
$COUNTRY
$STATE
$LOCALITY
$ORGNAME
$ORGUNIT
$COMMONNAME
$EMAIL
$CHALLENGE
$COMPANY
__EOF__

echo '172.17.0.1      capifcore' >> /etc/hosts

curl  --connect-timeout 5 \
    --max-time 10 \
    --retry-delay 0 \
    --retry-max-time 40 \
    --request GET "http://${CAPIF_HOSTNAME}:${CAPIF_PORT}/ca-root" 2>/dev/null | jq -r '.certificate' -j > ca.crt

tail -f /dev/null