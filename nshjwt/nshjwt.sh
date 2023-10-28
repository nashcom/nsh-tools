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
#  - ECDSA keys (ES256)
#  - Ed25519 keys (EdDSA)
#
#-------------------------------------------------------------------------------

SCRIPT_NAME=$0
SCRIPT_DIR=$(dirname $SCRIPT_NAME)

NSHJWT_SCRIPT_VERSION=1.0.0

LogError()
{
  echo >& 2
  echo "ERROR: $@" >& 2
  echo >& 2
}


LogMessage()
{
  echo
  echo "$@"
  echo
}


FileCheck()
{
    if [ -z "$1" ]; then

    if [ -z "$2" ]; then
      LogError "No file specified"
    else
      LogError "No $2 file specified"
    fi
    exit 1
  fi

  if [ ! -e "$1" ]; then
    if [ -z "$2" ]; then
      LogError "File note found: $1"
    else
      LogError "File ($2) not found: $1"
    fi
    exit 1
  fi


}

print_delim()
{
  echo "--------------------------------------------------------------------------------"
}

header()
{
  echo
  print_delim
  echo "$1"
  print_delim
  echo
}

DebugText()
{
  if [ "$NSHJWT_DEBUG" = "yes" ]; then
    echo
    echo "$(date '+%F %T') Debug:" $@
    echo
  fi

  return 0
}


DebugDump()
{
  if [ "$NSHJWT_DEBUG" = "yes" ]; then
    echo
    echo "-------------------- $1 --------------------"
    echo "$2"
    echo "-------------------- $1 --------------------"
    echo
  fi
}


DebugFile()
{
  if [ "$NSHJWT_DEBUG" = "yes" ]; then
    echo
    echo "-------------------- $1 --------------------"
    cat "$2"
    echo
    echo "-------------------- $1 --------------------"
    echo
  fi
}


RemoveFile()
{
  if [ -z "$1" ]; then
    return 1
  fi

  if [ ! -e "$1" ]; then
    return 2
  fi

  rm -rf "$1"
  return 0
}


CheckCreateKey()
{
  if [ -e "$PRIVATE_KEY" ]; then
    return 0
  fi

  if [ "$SIG_ALG" = "RS256" ]; then

    openssl genrsa -out "$PRIVATE_KEY" 2048

    if [ "$?" != "0" ]; then
      LogError "Cannot create new RSA key"
      exit 1
    fi

    echo "RSA key created"

  elif [ "$SIG_ALG" = "ES256" ]; then

    openssl ecparam -name prime256v1 -genkey -noout -out "$PRIVATE_KEY"

    if [ "$?" != "0" ]; then
      LogError "Cannot create new ECDSA key"
      exit 1
    fi

    echo "ECDSA key created"

  elif [ "$SIG_ALG" = "EdDSA" ]; then

    openssl genpkey -algorithm ed25519 -out "$PRIVATE_KEY"

    if [ "$?" != "0" ]; then
      LogError "Cannot create new Ed25519 key"
      exit 1
    fi

    LogMessage "Ed25519 key created"

  else
    LogError "Invalid signature algorithm: $SIG_ALG"
    exit 1
  fi

  # Get public key
  openssl pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"
}


GenerateSamplePayload()
{
  local ISSUER=https://issuer.oidc
  local AUDIENCE=https://audience.oidc
  local SCOPE=Domino.user.all
  local SUBJECT=abcd
  local EMAIL=john.doe@acme.com
  local NOW=$(date +'%s')
  local EXP=$(expr $NOW + 7200)

  echo "{\"iss\":\"$ISSUER\",\"aud\":\"$AUDIENCE\",\"iat\":$NOW,\"nbf\":$NOW,\"auth_time\":$NOW,\"exp\":$EXP,\"scope\":\"$SCOPE\",\"sub\":\"$SUBJECT\",\"email\":\"$EMAIL\"}" > "$1"
}


EncodeJWT()
{
  local PAYLOAD_FILE=$1
  local ENCODED_FILE=$2
  local SIG_BASE64URL=
  local HEADER=

  FileCheck "$PAYLOAD_FILE" "payload"
  FileCheck "$PRIVATE_KEY" "private key"

  if [ -z "$ENCODED_FILE" ]; then
    LogError "Output file when encoding"
    exit 1
  fi

  if [ "$SIG_ALG" = "RS256" ]; then
    HEADER='{"alg":"RS256","typ":"JWT"}'

  elif [ "$SIG_ALG" = "ES256" ]; then
    HEADER='{"alg":"ES256","typ":"JWT"}'

  elif [ "$SIG_ALG" = "EdDSA" ]; then
    HEADER='{"alg":"EdDSA","typ":"JWT"}'

  else
    LogError "Invalid signature algorithm: $SIG_ALG"
    exit 1
  fi

  # Encode header and payload base64url encoded
  echo -n "$HEADER" | openssl base64 -e -A | tr -d '=' | tr '/+' '_-' > "$ENCODED_FILE"

  echo -n "." >> "$ENCODED_FILE"

  openssl base64 -e -A -in "$PAYLOAD_FILE" | tr -d '=' | tr '/+' '_-' >> "$ENCODED_FILE"

  if [ "$SIG_ALG" = "RS256" ]; then
    SIG_BASE64URL=$(openssl dgst -sha256 -sign  "$PRIVATE_KEY" -binary "$ENCODED_FILE" | openssl base64 -e -A | tr -d '=' | tr '/+' '_-')

  elif [ "$SIG_ALG" = "ES256" ]; then
    SIG_BASE64URL=$(openssl pkeyutl -rawin -sign -in "$ENCODED_FILE" -inkey "$PRIVATE_KEY" | openssl base64 -e -A | tr -d '=' | tr '/+' '_-')

  elif [ "$SIG_ALG" = "EdDSA" ]; then
    SIG_BASE64URL=$(openssl pkeyutl -rawin -sign -in "$ENCODED_FILE" -inkey "$PRIVATE_KEY" | openssl base64 -e -A | tr -d '=' | tr '/+' '_-')

  else
    LogError "Invalid signature algorithm: $SIG_ALG"
    exit 1
  fi

  echo -n ".$SIG_BASE64URL" >> "$ENCODED_FILE"

  DebugFile "Encoded JWT" "$ENCODED_FILE"
}


DecodeJWT()
{
  local ENCODED_FILE=$1
  local PAYLOAD_FILE=$2

  local PAD_COUNT=
  local PAYLOAD_BASE64URL=
  local PAYLOAD_BASE64=

  FileCheck "$ENCODED_FILE" "encoded content"

  PAYLOAD_BASE64=$(cut -d"." -f2 "$ENCODED_FILE" | tr '_-' '/+')

  # Add padding for valid BASE64 encoding (base64url encoding removes padding)
  PAD_COUNT=$(expr 4 - ${#PAYLOAD_BASE64} % 4)

  if [ "$PAD_COUNT" != "4" ]; then
    while ((PAD_COUNT--)); do PAYLOAD_BASE64=$PAYLOAD_BASE64=; done
  fi

  echo $PAYLOAD_BASE64 | openssl base64 -d -A -out "$PAYLOAD_FILE"

  if [ -n "$(find "$PAYLOAD_FILE" -size -10k 2>/dev/null)" ]; then
    cat "$PAYLOAD_FILE" | jq
  fi
}


VerifyJWT()
{
  local ENCODED_FILE=$1
  local TEMP_SIG_FILE=$(mktemp).sig
  local TEMP_ENCODED_FILE=$(mktemp).temp

  local SIG_BASE64=
  local PAD_COUNT=

  local HEADER_BASE64URL=
  local HEADER_BASE64=
  local HEADER_OUT=

  FileCheck "$ENCODED_FILE" "encoded content"
  FileCheck "$PUBLIC_KEY" "public key"

  cut -d"." -f1 "$ENCODED_FILE" | awk -v ORS="" 1 > "$TEMP_ENCODED_FILE"
  echo -n "." >> "$TEMP_ENCODED_FILE"
  cut -d"." -f2 "$ENCODED_FILE" | awk -v ORS="" 1 >> "$TEMP_ENCODED_FILE"

  # Decode base64 signature into binary file
  SIG_BASE64=$(cut -d"." -f3 "$ENCODED_FILE" | tr '_-' '/+')
  PAD_COUNT=$(expr 4 - ${#SIG_BASE64} % 4)
  if [ "$PAD_COUNT" != "4" ]; then
    while ((PAD_COUNT--)); do SIG_BASE64=$SIG_BASE64=; done
  fi

  echo $SIG_BASE64 | openssl base64 -d -A -out "$TEMP_SIG_FILE"

  if [ ! -e "$TEMP_SIG_FILE" ]; then
    LogError "Cannot read signature file [$TEMP_SIG_FILE]"
    exit 1
  fi

  # Verify data & signature with public key
  if [ "$SIG_ALG" = "RS256" ]; then

    openssl dgst -sha256  -verify "$PUBLIC_KEY" -signature "$TEMP_SIG_FILE" "$TEMP_ENCODED_FILE"

  elif [ "$SIG_ALG" = "ES256" ]; then
    openssl pkeyutl -rawin -in "$TEMP_ENCODED_FILE" -verify -pubin -inkey "$PUBLIC_KEY" -sigfile "$TEMP_SIG_FILE"

  elif [ "$SIG_ALG" = "EdDSA" ]; then
    openssl pkeyutl -rawin -in "$TEMP_ENCODED_FILE" -verify -pubin -inkey "$PUBLIC_KEY" -sigfile "$TEMP_SIG_FILE"

  else
    LogError "Invalid signature algorithm: $SIG_ALG"
    RemoveFile "TEMP_ENCODED_FILE"
    exit 1
  fi

  RET="$?"

  RemoveFile "TEMP_ENCODED_FILE"
  RemoveFile "$TEMP_SIG_FILE"

  if [ "$RET" != "0" ]; then
    exit 1
  fi

  if [ ! "$NSHJWT_DEBUG" = "yes" ]; then
    return 0
  fi

  HEADER_BASE64=$(echo -n $HEADER_BASE64URL | tr '_-' '/+')

  # Add padding for valid BASE64 encoding (base64url encoding removes padding)
  PAD_COUNT=$(expr 4 - ${#HEADER_BASE64} % 4)

  if [ "$PAD_COUNT" != "4" ]; then
    while ((PAD_COUNT--)); do HEADER_BASE64=$HEADER_BASE64=; done
  fi

  HEADER_OUT=$(cut -d"." -f1 "$ENCODED_FILE" | openssl base64 -d -A)
  DebugDump "Header" "$HEADER_OUT"
}


Usage()
{
  echo
  echo Nash!Com JWT Tool $SCRIPT_SCRIPT_VERSION
  print_delim
  echo
  echo "Usage: $SCRIPT_NAME [options]"
  echo
  echo  "-encode                 Encode and sign input file"
  echo  "-decode                 Decode input file"
  echo  "-verify                 Verify input file (works also with encode and decode)"
  echo
  echo  "createkey               Create a key pair"
  echo  "-pubkey=<public.pem>    Specifies public key for verification"
  echo  "-privkey=<private.pem>  Specifies private key for signing"
  echo  "-in=<in-file>           Input file"
  echo  "-out=<out-file>         Output file"
  echo  "-demo                   Create a demo file, sign it, verify it and decode it"
  echo
  echo  "-ed                     Use Ed25519 key"
  echo  "-dsa|-ec                Use ECDSA key"
  echo  "-rsa                    Use RSA key"
  echo
  echo  "-version|--version      Print version and exit"
  echo  "-debug                  Enable debugging"
  echo

  return 0
}

# Defaults

SIG_ALG=EdDSA

# Main logic

for a in "$@"; do

  p=$(echo "$a" | /usr/bin/awk '{print tolower($0)}')

  case "$p" in

    -pubkey=*)
      PUBLIC_KEY=$(echo "$a" | /usr/bin/cut -f2 -d= -s)
      ;;

    -privkey=*)
      PRIVATE_KEY=$(echo "$a" | /usr/bin/cut -f2 -d= -s)
      ;;

    -in=*)
      INPUT_FILE=$(echo "$a" | /usr/bin/cut -f2 -d= -s)
      ;;

    -out=*)
      OUTPUT_FILE=$(echo "$a" | /usr/bin/cut -f2 -d= -s)
      ;;

    -encode)
      ENCODE=yes
      ;;

    -decode)
      DECODE=yes
      ;;

    -verify)
      VERIFY=yes
      ;;

    -createkey)
      CREATEKEY=yes
      ;;

    -demo)
      DEMO=yes
      ;;

    -ed)
      SIG_ALG=EdDSA
      ;;

    -rsa)
      SIG_ALG=RS256
      ;;

    -dsa|-ec)
      SIG_ALG=ES256
      ;;

    -version|--version)
      echo "$NSHJWT_SCRIPT_VERSION"
      exit 0
      ;;

    -debug)
      NSHJWT_DEBUG=yes
      ;;

    -h|/h|-?|/?|-help|--help|help|Usage)
      Usage
      exit 0
      ;;

    *)
      LogError "Invalid parameter [$a]"
      exit 1
      ;;
  esac

done


if [ "$DEMO" = "yes" ]; then
  PRIVATE_KEY=private.pem
  PUBLIC_KEY=public.pem
  CheckCreateKey
  EncodeJWT demo.json demo.jwt
  VerifyJWT  demo.jwt
  DecodeJWT demo.jwt demo.json
  exit 0
fi

if [ "$CREATEKEY" = "yes" ]; then
  CheckCreateKey
fi

if [ "$ENCODE" = "yes" ]; then

  EncodeJWT "$INPUT_FILE" "$OUTPUT_FILE"

  if [ "$VERIFY" = "yes" ]; then
    VerifyJWT "$OUTPUT_FILE"
  fi

  elif [ "$DECODE" = "yes" ]; then

  if [ "$VERIFY" = "yes" ]; then
    VerifyJWT "$INPUT_FILE"
  fi

  DecodeJWT "$INPUT_FILE" "$OUTPUT_FILE"

elif [ "$VERIFY" = "yes" ]; then
  VerifyJWT "$INPUT_FILE"
fi

