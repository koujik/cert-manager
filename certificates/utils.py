import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def sign_with_kms(builder, kms_key_id):
    """
    Signs a Certificate or CRL builder using the KMS / vHSM server.
    We build a template signed with a dummy key of the same size,
    extract the raw TBS (To Be Signed) bytes, get them signed by the KMS,
    and then replace the dummy signature inside the DER-encoded output.
    """
    # 1. Generate a dummy 2048-bit RSA key
    dummy_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # 2. Sign the builder to generate a valid DER container structure
    dummy_obj = builder.sign(dummy_key, hashes.SHA256())
    der = dummy_obj.public_bytes(serialization.Encoding.DER)
    
    # 3. Extract the appropriate TBS bytes based on the builder class
    if isinstance(builder, x509.CertificateBuilder):
        tbs = dummy_obj.tbs_certificate_bytes
    elif isinstance(builder, x509.CertificateRevocationListBuilder):
        tbs = dummy_obj.tbs_certlist_bytes
    else:
        raise TypeError("サポートされていないビルダータイプです。")
        
    # 4. Sign the TBS bytes via KMS
    from .kms_client import kms_sign
    kms_sig = kms_sign(kms_key_id, tbs)
    
    if len(kms_sig) != 256:
        raise ValueError(f"KMSの署名サイズが無効です: {len(kms_sig)} bytes (256 bytesである必要があります)")
        
    # 5. Overwrite the dummy signature bytes (which are the last 256 bytes of the DER encoding)
    new_der = der[:-256] + kms_sig
    
    # 6. Re-load the signed ASN.1 container and serialize to PEM
    if isinstance(builder, x509.CertificateBuilder):
        cert = x509.load_der_x509_certificate(new_der)
        return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    else:
        crl = x509.load_der_x509_crl(new_der)
        return crl.public_bytes(serialization.Encoding.PEM).decode('utf-8')

def generate_ca(common_name, organization, country, validity_days=3650, use_kms=False):
    """
    Generates a new Root Certificate Authority (Root CA).
    If use_kms is True, generates the key pair in the KMS / vHSM.
    Returns (key_pem, cert_pem, kms_key_id)
    """
    if use_kms:
        from .kms_client import kms_generate_key
        kms_key_id, public_key_pem = kms_generate_key()
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        private_key = None
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        kms_key_id = None
        
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
    ])
    
    issuer = subject
    
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(public_key)\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(now)\
        .not_valid_after(now + datetime.timedelta(days=validity_days))\
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )\
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
        
    if use_kms:
        cert_pem = sign_with_kms(builder, kms_key_id)
        return None, cert_pem, kms_key_id
    else:
        cert = builder.sign(private_key, hashes.SHA256())
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        cert_pem = cert.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode('utf-8')
        
        return key_pem, cert_pem, None

def issue_cert(ca_key_pem, ca_cert_pem, common_name, organization, country, cert_type, validity_days=365, sans=None, csr_pem=None, ca_kms_key_id=None):
    """
    Issues a client or server certificate signed by the Root CA.
    Supports either a local PEM private key or a vHSM KMS key id for signing.
    """
    ca_cert = x509.load_pem_x509_certificate(
        ca_cert_pem.encode('utf-8')
    )
    
    if csr_pem:
        csr = x509.load_pem_x509_csr(csr_pem.encode('utf-8'))
        if not csr.is_signature_valid:
            raise ValueError("CSRの署名が無効です。")
        public_key = csr.public_key()
        subject = csr.subject
    else:
        client_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = client_key.public_key()
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        ])
        
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(ca_cert.subject)\
        .public_key(public_key)\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(now)\
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False
    )
    
    if not csr_pem:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        )
        
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    
    if cert_type == 'server':
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False
        )
        
        san_list = []
        if sans:
            for san in sans:
                san = san.strip()
                if not san:
                    continue
                try:
                    ip = ipaddress.ip_address(san)
                    san_list.append(x509.IPAddress(ip))
                except ValueError:
                    san_list.append(x509.DNSName(san))
                    
        if csr_pem:
            try:
                csr_sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                for san in csr_sans.value:
                    if san not in san_list:
                        san_list.append(san)
            except x509.ExtensionNotFound:
                pass
                
        if san_list:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_list),
                critical=False
            )
            
    elif cert_type == 'client':
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )
        
    if ca_kms_key_id:
        cert_pem = sign_with_kms(builder, ca_kms_key_id)
    else:
        ca_key = serialization.load_pem_private_key(
            ca_key_pem.encode('utf-8'),
            password=None
        )
        cert = builder.sign(ca_key, hashes.SHA256())
        cert_pem = cert.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode('utf-8')
        
    if csr_pem:
        return None, cert_pem
    else:
        key_pem = client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        return key_pem, cert_pem

def issue_crl(ca_key_pem, ca_cert_pem, revoked_certs_list, validity_days=30, ca_kms_key_id=None):
    """
    Generates a CRL signed by the CA containing revoked certificates.
    Supports either local private key PEM or vHSM KMS key id for signing.
    """
    ca_cert = x509.load_pem_x509_certificate(
        ca_cert_pem.encode('utf-8')
    )
    
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = x509.CertificateRevocationListBuilder()\
        .issuer_name(ca_cert.subject)\
        .last_update(now)\
        .next_update(now + datetime.timedelta(days=validity_days))
        
    for serial, revoked_at in revoked_certs_list:
        revoked_cert = x509.RevokedCertificateBuilder()\
            .serial_number(int(serial))\
            .revocation_date(revoked_at)\
            .build()
        builder = builder.add_revoked_certificate(revoked_cert)
        
    if ca_kms_key_id:
        crl_pem = sign_with_kms(builder, ca_kms_key_id)
    else:
        ca_key = serialization.load_pem_private_key(
            ca_key_pem.encode('utf-8'),
            password=None
        )
        crl = builder.sign(ca_key, hashes.SHA256())
        crl_pem = crl.public_bytes(
            encoding=serialization.Encoding.PEM
        ).decode('utf-8')
        
    return crl_pem
