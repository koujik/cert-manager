import datetime
from django.test import TestCase
from django.contrib.auth.models import User
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .utils import generate_ca, issue_cert, issue_crl
from .models import CertificateAuthority, IssuedCertificate

class CryptographyUtilsTestCase(TestCase):
    def setUp(self):
        self.ca_cn = "Test Root CA"
        self.ca_org = "Test Org"
        self.ca_country = "JP"
        self.ca_key, self.ca_cert = generate_ca(
            common_name=self.ca_cn,
            organization=self.ca_org,
            country=self.ca_country,
            validity_days=365
        )

    def test_generate_ca(self):
        self.assertIsNotNone(self.ca_key)
        self.assertIsNotNone(self.ca_cert)
        
        # Load and verify certificate
        cert = x509.load_pem_x509_certificate(self.ca_cert.encode('utf-8'))
        subject = cert.subject
        self.assertEqual(subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value, self.ca_cn)
        self.assertEqual(subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value, self.ca_org)
        self.assertEqual(subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value, self.ca_country)
        
        # Verify it's a CA cert
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertTrue(basic_constraints.ca)

    def test_issue_server_certificate(self):
        common_name = "server.local"
        org = "Server Org"
        country = "JP"
        sans = ["server.local", "127.0.0.1"]
        
        key_pem, cert_pem = issue_cert(
            ca_key_pem=self.ca_key,
            ca_cert_pem=self.ca_cert,
            common_name=common_name,
            organization=org,
            country=country,
            cert_type='server',
            validity_days=30,
            sans=sans
        )
        
        self.assertIsNotNone(key_pem)
        self.assertIsNotNone(cert_pem)
        
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
        
        # Verify subject
        self.assertEqual(cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value, common_name)
        
        # Verify BasicConstraints (ca=False)
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        self.assertFalse(basic_constraints.ca)
        
        # Verify SANs
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        san_names = san_ext.get_values_for_type(x509.DNSName)
        san_ips = san_ext.get_values_for_type(x509.IPAddress)
        
        self.assertIn("server.local", san_names)
        self.assertEqual(str(san_ips[0]), "127.0.0.1")

    def test_issue_client_certificate(self):
        common_name = "client-user"
        
        key_pem, cert_pem = issue_cert(
            ca_key_pem=self.ca_key,
            ca_cert_pem=self.ca_cert,
            common_name=common_name,
            organization="",
            country="JP",
            cert_type='client',
            validity_days=30
        )
        
        self.assertIsNotNone(key_pem)
        self.assertIsNotNone(cert_pem)
        
        cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
        self.assertEqual(cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value, common_name)
        
        # Extended Key Usage should contain client auth
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        self.assertIn(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH, eku)

    def test_generate_crl(self):
        revoked_list = [
            (12345, datetime.datetime.now(datetime.timezone.utc)),
            (67890, datetime.datetime.now(datetime.timezone.utc))
        ]
        
        crl_pem = issue_crl(
            ca_key_pem=self.ca_key,
            ca_cert_pem=self.ca_cert,
            revoked_certs_list=revoked_list
        )
        
        self.assertIsNotNone(crl_pem)
        
        # Load and verify CRL
        crl = x509.load_pem_x509_crl(crl_pem.encode('utf-8'))
        
        # Check if the serial numbers are revoked in CRL
        revoked_serials = [rc.serial_number for rc in crl]
        self.assertIn(12345, revoked_serials)
        self.assertIn(67890, revoked_serials)
