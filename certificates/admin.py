from django.contrib import admin
from .models import CertificateAuthority, IssuedCertificate, AcmeAccount, AcmeChallenge

@admin.register(CertificateAuthority)
class CertificateAuthorityAdmin(admin.ModelAdmin):
    list_display = ('name', 'common_name', 'organization', 'country', 'created_at', 'valid_until', 'is_active')
    search_fields = ('name', 'common_name', 'organization')
    readonly_fields = ('created_at',)

@admin.register(IssuedCertificate)
class IssuedCertificateAdmin(admin.ModelAdmin):
    list_display = ('common_name', 'issuer_type', 'cert_type', 'serial_number', 'issued_at', 'expires_at', 'is_revoked')
    list_filter = ('issuer_type', 'cert_type', 'is_revoked')
    search_fields = ('common_name', 'serial_number')
    readonly_fields = ('issued_at',)

@admin.register(AcmeAccount)
class AcmeAccountAdmin(admin.ModelAdmin):
    list_display = ('email', 'is_staging', 'created_at')
    list_filter = ('is_staging',)
    search_fields = ('email',)

@admin.register(AcmeChallenge)
class AcmeChallengeAdmin(admin.ModelAdmin):
    list_display = ('token', 'created_at')
    search_fields = ('token',)

