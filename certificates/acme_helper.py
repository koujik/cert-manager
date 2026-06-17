import time
import datetime
import logging
from django.utils import timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import josepy as jose
from acme import client as acme_client
from acme import messages, challenges
from acme.client import ClientNetwork

logger = logging.getLogger(__name__)

def get_acme_client(email, directory_url):
    """
    Retrieves or registers an ACME account and initializes the ACME ClientV2.
    """
    from .models import AcmeAccount
    
    is_staging = "staging" in directory_url.lower()
    acc = AcmeAccount.objects.filter(email=email, is_staging=is_staging).first()
    
    if acc:
        # Load existing private key
        private_key = serialization.load_pem_private_key(
            acc.private_key_pem.encode('utf-8'),
            password=None
        )
        # Re-construct registration resource
        regr = messages.RegistrationResource.json_loads(acc.regr_json)
        
        # Initialize net and client
        jwk = jose.JWKRSA(key=private_key)
        net = ClientNetwork(key=jwk, account=regr)
        directory = acme_client.ClientV2.get_directory(directory_url, net)
        acme = acme_client.ClientV2(directory, net=net)
    else:
        # Generate new private key for account
        pkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        private_key = pkey
        
        pkey_pem = pkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Temporary client for registration
        jwk = jose.JWKRSA(key=private_key)
        net = ClientNetwork(key=jwk)
        directory = acme_client.ClientV2.get_directory(directory_url, net)
        acme = acme_client.ClientV2(directory, net=net)
        
        # Register new account
        new_regr = messages.NewRegistration.from_data(
            email=email,
            terms_of_service_agreed=True
        )
        regr = acme.new_account(new_regr)
        
        # Save to database
        acc = AcmeAccount.objects.create(
            email=email,
            private_key_pem=pkey_pem,
            regr_json=regr.json_dumps(),
            is_staging=is_staging
        )
        
        # Update client network with registered account metadata
        acme.net.account = regr
        
    return acme, acc

def request_letsencrypt_cert(domain, email, use_staging=True, timeout_seconds=60):
    """
    Submits a certificate request to Let's Encrypt (ACME).
    Provisions HTTP-01 challenge details in the database and triggers verification.
    """
    from .models import AcmeChallenge
    
    directory_url = (
        'https://acme-staging-v02.api.letsencrypt.org/directory'
        if use_staging else
        'https://acme-v02.api.letsencrypt.org/directory'
    )
    
    # 1. Get or create ACME client
    acme, account_obj = get_acme_client(email, directory_url)
    
    # 2. Generate certificate private key (PEM format)
    cert_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    cert_key_pem = cert_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # 3. Create CSR in PEM format (required by acme library's new_order)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])
    
    csr_obj = x509.CertificateSigningRequestBuilder()\
        .subject_name(subject)\
        .sign(cert_key, hashes.SHA256())
        
    csr_pem = csr_obj.public_bytes(serialization.Encoding.PEM)
    
    # 4. Request a new order
    order = acme.new_order(csr_pem)
    
    # 5. Extract HTTP-01 challenge details
    chall_to_answer = None
    for authz in order.authorizations:
        if authz.body.status == messages.STATUS_VALID:
            continue
            
        for chall_body in authz.body.challenges:
            if isinstance(chall_body.chall, challenges.HTTP01):
                chall_to_answer = chall_body
                break
        if chall_to_answer:
            break
            
    if not chall_to_answer:
        # If order is already ready (because of pre-authorization), finalize it
        if order.status == messages.STATUS_READY:
            deadline = datetime.datetime.now() + datetime.timedelta(seconds=timeout_seconds)
            finalized_order = acme.finalize_order(order, deadline)
            return cert_key_pem, finalized_order.fullchain_pem
        else:
            raise ValueError("No suitable HTTP-01 challenge was returned, and the order is not ready.")
            
    # Solve HTTP-01 challenge
    validation = chall_to_answer.validation(acme.net.key)
    token = chall_to_answer.chall.token
    
    # Save token and validation to local DB so HTTP challenge endpoint can serve it
    AcmeChallenge.objects.update_or_create(
        token=token,
        defaults={'validation': validation}
    )
    
    try:
        # Let the ACME server know we are ready to validate the challenge
        acme.answer_challenge(chall_to_answer, chall_to_answer.response(acme.net.key))
        
        # Wait/poll until authorizations are verified and final certificate is issued
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=timeout_seconds)
        finalized_order = acme.poll_and_finalize(order, deadline)
        
        return cert_key_pem, finalized_order.fullchain_pem
        
    finally:
        # Clean up database challenge entry
        AcmeChallenge.objects.filter(token=token).delete()
