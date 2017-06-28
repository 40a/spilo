#!/bin/bash
set -e

prefetch=8

AWS_INSTANCE_PROFILE=0

function load_aws_instance_profile() {
    local CREDENTIALS_URL=http://169.254.169.254/latest/meta-data/iam/security-credentials/
    local INSTANCE_PROFILE=$(curl -s $CREDENTIALS_URL)
    source <(curl -s $CREDENTIALS_URL$INSTANCE_PROFILE | jq -r '"AWS_SECURITY_TOKEN=\"" + .Token + "\"\nAWS_SECRET_ACCESS_KEY=\"" + .SecretAccessKey + "\"\nAWS_ACCESS_KEY_ID=\"" + .AccessKeyId + "\""')
}

function load_region_from_aws_instance_profile() {
    # XXX
    AWS_REGION=eu-central-1
    S3_HOST=s3-$AWS_REGION.amazonaws.com
}

function usage() {
    echo "Usage: $0 wal-fetch [--prefetch PREFETCH] WAL_SEGMENT WAL_DESTINATION"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --s3-prefix )
            WALE_S3_PREFIX=$2
            shift
            ;;
        -k|--aws-access-key-id )
            AWS_ACCESS_KEY_ID=$2
            shift
            ;;
        --aws-instance-profile )
            AWS_INSTANCE_PROFILE=1
            ;;
        wal-fetch )
            ;;
        -p|--prefetch )
            prefetch=$2
            shift
            ;;
        * )
            PARAMS+=("$1")
            ;;
    esac
    shift
done

[[ ${#PARAMS[@]} == 2 ]] || usage

[[ $AWS_INSTANCE_PROFILE == 1 ]] && load_aws_instance_profile

if [[ -z $AWS_SECRET_ACCESS_KEY || -z $AWS_ACCESS_KEY_ID || -z $WALE_S3_PREFIX ]]; then
    echo bad environment
    exit 1
fi

readonly SEGMENT=${PARAMS[-2]}
readonly DESTINATION=${PARAMS[-1]}

if [[ $WALE_S3_PREFIX =~ ^s3://([^\/]+)(.+) ]]; then
    readonly BUCKET=${BASH_REMATCH[1]}
    BUCKET_PATH=${BASH_REMATCH[2]}
    readonly BUCKET_PATH=${BUCKET_PATH%/}
else
    echo bad WALE_S3_PREFIX
    exit 1
fi

if [[ -z $AWS_REGION ]]; then
    if [[ ! -z $WALE_S3_ENDPOINT && $WALE_S3_ENDPOINT =~ ^([a-z\+]{2,10}://)?(s3-([^\.]+)[^:\/?]+) ]]; then
        S3_HOST=${BASH_REMATCH[2]}
        AWS_REGION=${BASH_REMATCH[3]}
    else
        load_region_from_aws_instance_profile
    fi
else
    S3_HOST=s3-$AWS_REGION.amazonaws.com
fi

readonly SERVICE=s3
readonly REQUEST=aws4_request
readonly HOST=$BUCKET.$S3_HOST
readonly TIME=$(date +%Y%m%dT%H%M%SZ)
readonly DATE=${TIME%T*}
readonly DRSR="$DATE/$AWS_REGION/$SERVICE/$REQUEST"
readonly EMPTYHASH=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

function hmac_sha256() {
    echo -en "$2" | openssl dgst -sha256 -mac HMAC -macopt "$1" | sed 's/^.* //'
}

# Four-step signing key calculation
readonly DATE_KEY=$(hmac_sha256 key:"AWS4$AWS_SECRET_ACCESS_KEY" $DATE)
readonly DATE_REGION_KEY=$(hmac_sha256 hexkey:$DATE_KEY $AWS_REGION)
readonly DATE_REGION_SERVICE_KEY=$(hmac_sha256 hexkey:$DATE_REGION_KEY $SERVICE)
readonly SIGNING_KEY=$(hmac_sha256 hexkey:$DATE_REGION_SERVICE_KEY $REQUEST)

if [[ -z $AWS_INSTANCE_PROFILE ]]; then
    readonly SIGNED_HEADERS="host;x-amz-content-sha256;x-amz-date"
    readonly REQUEST_TOKEN=""
    readonly TOKEN_HEADER=()
else
    readonly SIGNED_HEADERS="host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
    readonly REQUEST_TOKEN="x-amz-security-token:$AWS_SECURITY_TOKEN\n"
    readonly TOKEN_HEADER=(-H "x-amz-security-token: $AWS_SECURITY_TOKEN")
fi

function s3_get() {
    local segment=$1
    local destination=$2
    local FILE=$BUCKET_PATH/wal_005/$segment.lzo
    local CANONICAL_REQUEST="GET\n$FILE\n\nhost:$HOST\nx-amz-content-sha256:$EMPTYHASH\nx-amz-date:$TIME\n$REQUEST_TOKEN\n$SIGNED_HEADERS\n$EMPTYHASH"
    local CANONICAL_REQUEST_HASH=$(echo -en $CANONICAL_REQUEST | openssl dgst -sha256 | sed 's/^.* //')
    local STRING_TO_SIGN="AWS4-HMAC-SHA256\n$TIME\n$DRSR\n$CANONICAL_REQUEST_HASH"
    local SIGNATURE=$(hmac_sha256 hexkey:$SIGNING_KEY $STRING_TO_SIGN)

    if curl -s https://$HOST$FILE "${TOKEN_HEADER[@]}" -H "x-amz-content-sha256: $EMPTYHASH" -H "x-amz-date: $TIME" \
        -H "Authorization: AWS4-HMAC-SHA256 Credential=$AWS_ACCESS_KEY_ID/$DRSR, SignedHeaders=$SIGNED_HEADERS, Signature=$SIGNATURE" \
        | lzop -dc > $destination && [[ ${PIPESTATUS[0]} == 0 ]]; then
        local size=$(stat -c%s $destination)
        [[ $? == 0 && $size == 16777216 ]] && return 0
    fi
    rm -f $destination
    return 1
}

function generate_next_segments() {
    local seg=$1
    local num=$2

    local tl=${seg:0:8}
    local sh=$((16#${seg:8:8}))
    local sl=$((16#${seg:16:8}))

    while [[ $((num--)) -gt 0 ]]; do
        sl=$((sl+1))
        printf "%s%08X%08X\n" $tl $((sh+sl/256)) $((sl%256))
    done
}

if [[ $prefetch > 0 ]]; then
    readonly PREFETCHDIR=$(dirname $DESTINATION)/.wal-e/prefetch

    for s in $(generate_next_segments $SEGMENT $prefetch); do
        (
            mkdir -p $PREFETCHDIR/running/$s
            trap "rm -fr $PREFETCHDIR/running/$s" QUIT TERM EXIT
            exec 200<$PREFETCHDIR/running/$s
            flock -ne 200 || exit
            TMPFILE=$(mktemp -p $PREFETCHDIR/running/$s)
            s3_get $s $TMPFILE && mv $TMPFILE $PREFETCHDIR/$s
        ) &
    done

    last_size=0
    while true; do
        [[ -f $PREFETCHDIR/$SEGMENT ]] && exec mv $PREFETCHDIR/$SEGMENT $DESTINATION
        [[ -d $PREFETCHDIR/running/$SEGMENT ]] || break
        size=$(du -bs $PREFETCHDIR/running/$SEGMENT 2> /dev/null | cut -f1)
        [[ ${PIPESTATUS[0]} == 0 && $size > $last_size ]] || break
        sleep 0.5
    done
fi

s3_get $SEGMENT $DESTINATION
