from django.db import models
from django.contrib.auth.models import User
from cryptography import x509
import datetime

class CertificateAuthority(models.Model):
    name = models.CharField(max_length=100, default="Default CA")
    common_name = models.CharField(max_length=255)
    organization = models.CharField(max_length=255)
    country = models.CharField(max_length=2)
    
    # Store either private_key_pem (local) or kms_key_id (vHSM KMS)
    private_key_pem = models.TextField(help_text="PEM-encoded private key (empty if using KMS)", blank=True, null=True)
    certificate_pem = models.TextField(help_text="PEM-encoded certificate")
    kms_key_id = models.CharField(max_length=255, blank=True, null=True, help_text="vHSM KMS Key UUID")
    
    created_at = models.DateTimeField(auto_now_add=True)
    valid_until = models.DateTimeField()
    is_active = models.BooleanField(default=True)

    def __str__(self):
        type_str = "vHSM KMS" if self.kms_key_id else "Local"
        return f"{self.name} ({type_str}) - {self.common_name}"
        
    @property
    def is_expired(self):
        return datetime.datetime.now(datetime.timezone.utc) > self.valid_until

class IssuedCertificate(models.Model):
    CERT_TYPE_CHOICES = [
        ('client', 'Client Certificate'),
        ('server', 'Server Certificate'),
    ]

    common_name = models.CharField(max_length=255)
    organization = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=2, blank=True)
    cert_type = models.CharField(max_length=10, choices=CERT_TYPE_CHOICES)
    serial_number = models.CharField(max_length=100, unique=True)
    
    # Store PEM files
    certificate_pem = models.TextField()
    private_key_pem = models.TextField(blank=True, null=True, help_text="Empty if CSR was uploaded or using KMS envelope encryption")
    csr_pem = models.TextField(blank=True, null=True, help_text="Empty if private key was generated on server")
    
    # Envelope encryption fields (KMS)
    encrypted_key_b64 = models.TextField(blank=True, null=True, help_text="AES-GCM encrypted private key")
    kms_nonce_b64 = models.CharField(max_length=100, blank=True, null=True, help_text="KMS transit encryption nonce")
    
    # Issuer identification
    issuer_type = models.CharField(max_length=20, default='local', choices=[('local', 'Local CA'), ('letsencrypt', 'Let\'s Encrypt')])

    
    # Metadata
    issued_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    is_revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="certificates")

    def __str__(self):
        return f"{self.get_cert_type_display()} ({self.get_issuer_type_display()}): {self.common_name} ({self.serial_number})"

    @property
    def is_expired(self):
        return datetime.datetime.now(datetime.timezone.utc) > self.expires_at

class AcmeAccount(models.Model):
    email = models.EmailField()
    private_key_pem = models.TextField(help_text="PEM-encoded account private key")
    regr_json = models.TextField(help_text="JSON representation of registration resource")
    is_staging = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        env = "Staging" if self.is_staging else "Production"
        return f"ACME Account ({env}): {self.email}"

class AcmeChallenge(models.Model):
    token = models.CharField(max_length=255, unique=True)
    validation = models.TextField(help_text="ACME key authorization")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Challenge Token: {self.token}"

