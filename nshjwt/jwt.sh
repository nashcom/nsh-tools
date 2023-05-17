#!/bin/bash

#-------------------------------------------------------------------------------
#  Copyright Nash!Com, Daniel Nashed 2023 - APACHE 2.0 see LICENSE
#
#  JWT Create/Verify application to test and understand JWTs
#
#  Check https://jwt.io/introduction
#
#  Support for asymmetric keys
#
#  - RSA   keys (RS256)
#  - ECDSA keys (ES256) -- Generate only
#  - NO support for Ed25519 keys (EdDSA)
#
#  Note: OpenSSL C SDK supports all key types, OpenSSL command line is limited.
#-------------------------------------------------------------------------------

PRIVATE_KEY=rsa_private.pem
PUBLIC_KEY=rsa_public.pem
SIG_ALG=RS256

dump()
{
  echo
  echo ----------------------------------------$1----------------------------------------
  echo $2
  echo ----------------------------------------$1----------------------------------------
  echo
}

check_create_key()
{
  if [ -e "$PRIVATE_KEY" ]; then
    return 0
  fi

  if [ "$SIG_ALG" = "RS256" ]; then

    openssl genrsa -out "$PRIVATE_KEY" 2048

    if [ "$?" != "0" ]; then
      echo "Cannot create new RSA key"
      exit 1
    fi

    echo "RSA key created"

  else

    openssl ecparam -name prime256v1 -genkey -noout -out "$PRIVATE_KEY"

    if [ "$?" != "0" ]; then
      echo "Cannot create new ECDSA key"
      exit 1
    fi

    echo "ECDSA key created"
  fi

  # Get public key
  openssl pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"
}


generate_oidc_payload()
{

  local ISSUER=https://issuer.oidc
  local AUDIENCE=https://audience.oidc
  local SCOPE=Domino.user.all
  local SUBJECT=abcd
  local EMAIL=john.doe@acme.com
  local NOW=$EPOCHSECONDS
  local EXP=$(expr $NOW + 7200)

  PAYLOAD="{\"iss\":\"$ISSUER\",\"aud\":\"$AUDIENCE\",\"iat\":$NOW,\"nbf\":$NOW,\"auth_time\":$NOW,\"exp\":$EXP,\"scope\":\"$SCOPE\",\"sub\":\"$SUBJECT\",\"email\":\"$EMAIL\"}"
}

encode_jwt()
{
  local ENC_HEADER=
  local ENC_PAYLOAD=
  local ENC_TEMP=
  local SIG_BASE64URL=
  local PAYLOAD=
  local PAYLOAD_FILE=
  local HEADER=
  local TEMP_SIG_FILE=$(mktemp).sig

  if [ "$SIG_ALG" = "RS256" ]; then
    HEADER='{"alg":"RS256","typ":"JWT"}'
  else
    HEADER='{"alg":"ES256","typ":"JWT"}'
  fi

  if [ -z "$1" ]; then
    PAYLOAD='{"hello": "world"}'
    generate_oidc_payload
  else
    PAYLOAD_FILE="$1"

    if [ ! -e "$PAYLOAD_FILE" ]; then
      echo "Payload file not found [$PAYLOAD_FILE]"
      exit 1
    fi
  fi

  # Encode header and payload base64url encoded
  ENC_HEADER=$(echo -n "$HEADER" | openssl base64 -e -A | tr -d '=' | tr '/+' '_-')

  if [ -z "$PAYLOAD_FILE" ]; then
    ENC_PAYLOAD=$(echo -n "$PAYLOAD" | openssl base64 -e -A | tr -d '=' | tr '/+' '_-')
  else
    ENC_PAYLOAD=$(openssl base64 -e -A -in "$PAYLOAD_FILE" | tr -d '=' | tr '/+' '_-')
  fi

  # Header.Payload for creating signature
  ENC_TEMP=$ENC_HEADER.$ENC_PAYLOAD

  if [ "$SIG_ALG" = "RS256" ]; then
    SIG_BASE64URL=$(echo -n $ENC_TEMP | openssl dgst -sha256 -sign $PRIVATE_KEY -binary | openssl base64 -e -A | tr -d '=' | tr '/+' '_-')
  
  else
    SIG_BASE64URL=$(echo -n $ENC_TEMP | openssl dgst -sha256 -sign $PRIVATE_KEY -binary | openssl asn1parse -inform der | awk -F "INTEGER" '{print $2}' | tr -d ' :\n' | xxd -p -r | openssl base64 -e -A | tr -d '=' | tr '/+' '_-')
  fi

  # JWT = Header.Payload.Signature
  JWT=$ENC_TEMP.$SIG_BASE64URL

  if [ -z "$2" ]; then
    dump "JWT" $JWT
  else
    echo $JWT > "$2"
  fi
}

decode_jwt()
{
  local HEADER_BASE64URL=
  local PAYLOAD_BASE64URL=
  local SIG_BASE64URL=

  local HEADER_BASE64=
  local PAYLOAD_BASE64=
  local SIG_BASE64=

  local HEADER_OUT=
  local PAYLOAD_OUT=
  local PAD_COUNT=
  local TEMP_SIG_FILE=$(mktemp).sig

  if [ -z "$1" ]; then

    # Split header.payload.signature
    HEADER_BASE64URL=$(echo -n $JWT | cut -d"." -f1)
    PAYLOAD_BASE64URL=$(echo -n $JWT | cut -d"." -f2)
    SIG_BASE64URL=$(echo -n $JWT | cut -d"." -f3)

  else

    PAYLOAD_FILE="$1"

    if [ ! -e "$PAYLOAD_FILE" ]; then
      echo "Payload file not found [$PAYLOAD_FILE]"
      exit 1
    fi

    echo "Decoding file [$PAYLOAD_FILE]"

    # Split header.payload.signature
    HEADER_BASE64URL=$(cat "$PAYLOAD_FILE" | cut -d"." -f1)
    PAYLOAD_BASE64URL=$(cat "$PAYLOAD_FILE" | cut -d"." -f2)
    SIG_BASE64URL=$(cat "$PAYLOAD_FILE" | cut -d"." -f3)
  fi

  # Decode base64 signature into binary file
  SIG_BASE64=$(echo -n $SIG_BASE64URL | tr '_-' '/+')
  PAD_COUNT=$(expr 4 - ${#SIG_BASE64} % 4)
  if [ "$PAD_COUNT" != "4" ]; then
    while ((PAD_COUNT--)); do SIG_BASE64=$SIG_BASE64=; done
  fi

  echo $SIG_BASE64 | openssl base64 -d -out "$TEMP_SIG_FILE"

  if [ ! -e "$TEMP_SIG_FILE" ]; then
    echo "Cannot read signature file [$TEMP_SIG_FILE]"
    exit 1
  fi

  if [ "$SIG_ALG" = "RS256" ]; then

    # Verify data & signature with public key
    echo -n $HEADER_BASE64URL.$PAYLOAD_BASE64URL | openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$TEMP_SIG_FILE"
    RET="$?"
    rm -f "$TEMP_SIG_FILE"

    if [ "$RET" != "0" ]; then
      exit 1
    fi

  else
    echo "Info: Verifying ECDSA signatures not supported"
  fi

  HEADER_BASE64=$(echo -n $HEADER_BASE64URL | tr '_-' '/+')

  # Add padding for valid BASE64 encoding (base64url encoding removes padding)
  PAD_COUNT=$(expr 4 - ${#HEADER_BASE64} % 4)

  if [ "$PAD_COUNT" != "4" ]; then
    while ((PAD_COUNT--)); do HEADER_BASE64=$HEADER_BASE64=; done
  fi

  HEADER_OUT=$(echo $HEADER_BASE64 | openssl base64 -d)
  dump "Header" "$HEADER_OUT"

  PAYLOAD_BASE64=$(echo -n $PAYLOAD_BASE64URL | tr '_-' '/+')

  # Add padding for valid BASE64 encoding (base64url encoding removes padding)
  PAD_COUNT=$(expr 4 - ${#PAYLOAD_BASE64} % 4)

  if [ "$PAD_COUNT" != "4" ]; then
    while ((PAD_COUNT--)); do PAYLOAD_BASE64=$PAYLOAD_BASE64=; done
  fi

  if [ -z "$2" ]; then
    PAYLOAD_OUT=$(echo $PAYLOAD_BASE64 | openssl base64 -d)
    dump "Payload" "$PAYLOAD_OUT"

    echo "$PAYLOAD_OUT" | jq

  else
    echo $PAYLOAD_BASE64 | openssl base64 -d -out "$2"
  fi
}

check_create_key

encode_jwt "$1" "$2"
decode_jwt "$2" "$3"
