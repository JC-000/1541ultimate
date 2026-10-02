#!/bin/zsh
# Throwaway PKI for the engine host test: mkpki.sh OUTDIR. Nothing here is trusted anywhere else.
set -e
O=$1; mkdir -p $O; cd $O
[ -f done ] && exit 0
days=(-days 3650)
cat > ca.cnf <<EOF
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ca_nobc]
keyUsage = critical, keyCertSign, cRLSign
[ca_noku]
basicConstraints = critical, CA:TRUE
[ca_ku_nosign]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature
[ca_encipher]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, keyAgreement, encipherOnly
[notca]
basicConstraints = critical, CA:FALSE
[leaf]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:server.test
[leaf_cli]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = DNS:server.test
[leaf_other]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:other.test
EOF
ec() { openssl ecparam -name ${2:-prime256v1} -genkey -noout -out $1.key 2>/dev/null; }
rsa() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$2 -out $1.key 2>/dev/null; }
root() { openssl req -new -x509 -key $1.key -subj "/CN=$1" -sha256 $days -config ca.cnf -extensions $2 -out $1.pem 2>/dev/null; }
leaf() { openssl req -new -key $1.key -subj "/CN=$1" -out $1.csr 2>/dev/null
         openssl x509 -req -in $1.csr -CA $2.pem -CAkey $2.key -CAcreateserial -sha256 $days -extfile ca.cnf -extensions $3 -out $1.pem 2>/dev/null
         cat $1.pem $2.pem > $1.chain.pem; }
der() { openssl x509 -in $1.pem -outform der -out $1.der; }
spki() { openssl x509 -in $1.pem -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary > $1.spki; }

ec ca; root ca ca                                  # the trusted root (EC P-256)
ec other; root other ca                            # a root nobody trusts
ec leaf; leaf leaf ca leaf                         # server.test under ca
rsa leafrsa 2048; leaf leafrsa ca leaf             # server.test, RSA key, under ca
ec leafother; leaf leafother other leaf            # server.test under the untrusted root
ec leafname; leaf leafname ca leaf_other           # other.test under ca
ec leafcli; leaf leafcli ca leaf_cli               # server.test under ca, extendedKeyUsage clientAuth only
for c in leaf leafrsa leafother leafname leafcli; do spki $c; done
# CUSTOM CA upload cases
rsa rsa1024 1024; root rsa1024 ca                  # RSA KEY < 2048
rsa rsa1024nca 1024; root rsa1024nca notca         # RSA KEY < 2048 before NOT A CA
ec k1 secp256k1; root k1 ca                        # CURVE
ec k1nca secp256k1; root k1nca notca               # CURVE before NOT A CA
ec notca; root notca notca                         # NOT A CA: CA:FALSE
ec nobc; root nobc ca_nobc                          # NOT A CA: v3 without basicConstraints
ec kunosign; root kunosign ca_ku_nosign            # NOT A CA: keyUsage without keyCertSign
ec kuenc; root kuenc ca_encipher                   # NOT A CA: keyCertSign with encipherOnly
ec noku; root noku ca_noku                         # accepted: CA:TRUE, no keyUsage
printf '[req]\ndistinguished_name=dn\n[dn]\n' > v1.cnf
ec v1; openssl req -new -x509 -x509v1 -config v1.cnf -key v1.key -subj "/CN=v1" -sha256 $days -out v1.pem 2>/dev/null  # accepted: X.509 v1
rsa rsa2048ca 2048; root rsa2048ca ca              # accepted: RSA-2048 root
for c in ca other rsa1024 rsa1024nca k1 k1nca notca nobc kunosign kuenc noku v1 rsa2048ca; do der $c; done
head -c 300 /dev/urandom > garbage.der
openssl x509 -in v1.pem -noout -text | grep -q "Version: 1" || { echo "v1.pem is not X.509 v1" >&2; exit 1; }
touch done
