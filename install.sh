#!/bin/sh
# Доверие корню Минцифры только для доменов из списка.
#   ./install.sh [--dry-run] [список]      список по умолчанию — minimal.txt;
#   --dry-run только выпускает localca.crt и cross.crt, в систему не ставит
set -eu
cd "$(dirname "$0")"
ROOT_SHA256=D2:6D:2D:02:31:B7:C3:9F:92:CC:73:85:12:BA:54:10:35:19:E4:40:5D:68:B5:BD:70:3E:97:88:CA:8E:CF:31
DRY=; [ "${1:-}" = --dry-run ] && { DRY=1; shift; }
LIST=${1:-minimal.txt}

openssl x509 -in root.pem -noout -fingerprint -sha256 | grep -qi "$ROOT_SHA256" \
  || { echo "root.pem — не корень Минцифры" >&2; exit 1; }

# Свой центр. Его ключ живёт только во временном каталоге и после подписи удаляется:
# больше никто, включая вас, им ничего не подпишет.
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
openssl req -x509 -newkey rsa:3072 -nodes -keyout "$T/ca.key" -out localca.crt -days 3650 \
  -subj "/CN=Local Name Constraint CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "subjectKeyIdentifier=hash" 2>/dev/null

# Копия корня Минцифры (тот же субъект и ключ), подписанная своим центром, с ограничением
NC=$(grep -v '^#' "$LIST" | awk 'NF {printf "permitted;DNS:%s,", $1}')
cat > "$T/x.cnf" <<EOF
[x]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
nameConstraints = critical,${NC}excluded;IP:0.0.0.0/0.0.0.0,excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0
EOF
openssl x509 -in root.pem -CA localca.crt -CAkey "$T/ca.key" -clrext -set_serial "0x$(openssl rand -hex 8)" \
  -days 3650 -extfile "$T/x.cnf" -extensions x -out cross.crt 2>/dev/null
echo "localca.crt и cross.crt готовы, доменов: $(grep -v '^#' "$LIST" | awk NF | wc -l | tr -d ' ')"

[ -z "$DRY" ] || exit 0
case $(uname) in
Darwin)
  K=~/Library/Keychains/login.keychain-db
  # Прежняя пара и сам корень Минцифры. У копии тот же субъект, поэтому — по отпечатку.
  for cn in "Russian Trusted Root CA" "Local Name Constraint CA"; do
    security find-certificate -a -c "$cn" -Z "$K" 2>/dev/null | awk '/SHA-1/ {print $3}' |
      while read -r h; do security delete-certificate -Z "$h" "$K" >/dev/null; done
  done
  security add-trusted-cert -r trustRoot -p ssl -k "$K" localca.crt
  security add-certificates -k "$K" cross.crt ;;
Linux)
  if [ -d /usr/local/share/ca-certificates ]; then
    # Debian/Ubuntu — update-ca-certificates
    D=/usr/local/share/ca-certificates; U=update-ca-certificates
  else
    # ALT, Fedora, RHEL — p11-kit и update-ca-trust
    D=/etc/pki/ca-trust/source/anchors; U=update-ca-trust
  fi
  sudo cp localca.crt "$D/scoped-ru-root-localca.crt"
  sudo cp cross.crt "$D/scoped-ru-root-cross.crt"
  sudo "$U" ;;
esac
echo "установлено"
