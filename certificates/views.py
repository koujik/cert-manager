import io
import zipfile
import datetime
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib import messages
from django.http import HttpResponse, Http404, HttpResponseForbidden
from django.utils import timezone
from django.db.models import Q

from cryptography import x509
from .models import CertificateAuthority, IssuedCertificate, AcmeChallenge
from .utils import generate_ca, issue_cert, issue_crl
from .acme_helper import request_letsencrypt_cert
from .kms_client import kms_encrypt, kms_decrypt

@login_required
def dashboard(request):
    # Check if a CA is configured
    active_ca = CertificateAuthority.objects.filter(is_active=True).first()
    if not active_ca:
        return redirect('setup_ca')
        
    # Standard users see only their own certificates; superusers see all
    if request.user.is_superuser:
        certs = IssuedCertificate.objects.all().order_by('-issued_at')
    else:
        certs = IssuedCertificate.objects.filter(user=request.user).order_by('-issued_at')

    # Quick statistics
    now = timezone.now()
    total_active = certs.filter(is_revoked=False, expires_at__gt=now).count()
    total_revoked = certs.filter(is_revoked=True).count()
    total_expired = certs.filter(is_revoked=False, expires_at__lte=now).count()

    context = {
        'active_ca': active_ca,
        'certs': certs,
        'total_active': total_active,
        'total_revoked': total_revoked,
        'total_expired': total_expired,
        'is_ca_expired': active_ca.is_expired,
    }
    return render(request, 'certificates/dashboard.html', context)

@login_required
def setup_ca_view(request):
    # Check if CA already exists
    if CertificateAuthority.objects.filter(is_active=True).exists():
        messages.warning(request, "すでに有効な認証局 (CA) が存在します。")
        return redirect('dashboard')
        
    if request.method == 'POST':
        common_name = request.POST.get('common_name')
        organization = request.POST.get('organization')
        country = request.POST.get('country')
        validity_days = int(request.POST.get('validity_days', 3650))
        use_kms = request.POST.get('use_kms') == 'true'
        
        if not (common_name and organization and country):
            messages.error(request, "すべての項目を入力してください。")
        elif len(country) != 2:
            messages.error(request, "国名は2文字の国コード (例: JP) で入力してください。")
        else:
            try:
                key_pem, cert_pem, kms_key_id = generate_ca(
                    common_name=common_name,
                    organization=organization,
                    country=country.upper(),
                    validity_days=validity_days,
                    use_kms=use_kms
                )
                
                # Expiration calculation
                valid_until = timezone.now() + datetime.timedelta(days=validity_days)
                
                CertificateAuthority.objects.create(
                    common_name=common_name,
                    organization=organization,
                    country=country.upper(),
                    private_key_pem=key_pem,
                    certificate_pem=cert_pem,
                    kms_key_id=kms_key_id,
                    valid_until=valid_until,
                    is_active=True
                )
                
                messages.success(request, "Root CA 認証局が正常に構築されました！")
                return redirect('dashboard')
            except Exception as e:
                messages.error(request, f"認証局の生成中にエラーが発生しました: {str(e)}")
                
    return render(request, 'certificates/setup_ca.html')


@login_required
def issue_cert_view(request):
    if request.method != 'POST':
        return redirect('dashboard')
        
    issuer_type = request.POST.get('issuer_type', 'local')
    
    if issuer_type == 'letsencrypt':
        domain = request.POST.get('common_name')
        acme_email = request.POST.get('acme_email')
        use_staging = request.POST.get('use_staging') == 'true'
        
        if not domain or not acme_email:
            messages.error(request, "ドメイン名とACME登録用メールアドレスを入力してください。")
            return redirect('dashboard')
            
        try:
            key_pem, cert_pem = request_letsencrypt_cert(
                domain=domain,
                email=acme_email,
                use_staging=use_staging
            )
            
            # Parse issued certificate details
            cert_obj = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
            serial_number = str(cert_obj.serial_number)
            expires_at = cert_obj.not_valid_after_utc
            
            # Envelope encrypt private key
            enc_key, nonce = None, None
            if key_pem:
                enc_key, nonce = kms_encrypt(key_pem)
            
            # Save to database
            IssuedCertificate.objects.create(
                common_name=domain,
                issuer_type='letsencrypt',
                cert_type='server',
                serial_number=serial_number,
                certificate_pem=cert_pem,
                private_key_pem=None,
                encrypted_key_b64=enc_key,
                kms_nonce_b64=nonce,
                expires_at=expires_at,
                user=request.user
            )
            messages.success(request, f"Let's Encrypt 証明書 {domain} が正常に発行されました！")
        except Exception as e:
            messages.error(request, f"Let's Encrypt 証明書発行中にエラーが発生しました: {str(e)}")
            
        return redirect('dashboard')
        
    # Local CA flow
    active_ca = CertificateAuthority.objects.filter(is_active=True).first()
    if not active_ca:
        messages.error(request, "CA が設定されていません。先に CA を作成してください。")
        return redirect('setup_ca')
        
    common_name = request.POST.get('common_name')
    organization = request.POST.get('organization', '')
    country = request.POST.get('country', '')
    cert_type = request.POST.get('cert_type')
    validity_days = int(request.POST.get('validity_days', 365))
    sans_raw = request.POST.get('sans', '')
    
    # CSR upload processing
    csr_file = request.FILES.get('csr_file')
    csr_pem = None
    if csr_file:
        csr_pem = csr_file.read().decode('utf-8')
        
    if not csr_pem and not common_name:
        messages.error(request, "Common Name または CSR ファイルのいずれかを指定してください。")
        return redirect('dashboard')
        
    # SAN list parsing
    sans = [s.strip() for s in sans_raw.split(',') if s.strip()] if sans_raw else None
    
    try:
        key_pem, cert_pem = issue_cert(
            ca_key_pem=active_ca.private_key_pem,
            ca_cert_pem=active_ca.certificate_pem,
            common_name=common_name,
            organization=organization,
            country=country.upper() if country else active_ca.country,
            cert_type=cert_type,
            validity_days=validity_days,
            sans=sans,
            csr_pem=csr_pem,
            ca_kms_key_id=active_ca.kms_key_id
        )
        
        # Parse output cert to extract details
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
        serial_number = str(cert_obj.serial_number)
        expires_at = cert_obj.not_valid_after_utc
        
        # Envelope encrypt private key
        enc_key, nonce = None, None
        if key_pem:
            enc_key, nonce = kms_encrypt(key_pem)
        
        # Save to database
        IssuedCertificate.objects.create(
            common_name=common_name or cert_obj.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
            organization=organization or (cert_obj.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value if cert_obj.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME) else ''),
            country=country.upper() or (cert_obj.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value if cert_obj.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME) else ''),
            issuer_type='local',
            cert_type=cert_type,
            serial_number=serial_number,
            certificate_pem=cert_pem,
            private_key_pem=None,
            encrypted_key_b64=enc_key,
            kms_nonce_b64=nonce,
            csr_pem=csr_pem,
            expires_at=expires_at,
            user=request.user
        )
        
        messages.success(request, f"証明書 {common_name or 'CSR-signed'} が正常に発行されました。")
    except Exception as e:
        messages.error(request, f"証明書発行中にエラーが発生しました: {str(e)}")
        
    return redirect('dashboard')



@login_required
def revoke_cert_view(request, cert_id):
    cert = get_object_or_404(IssuedCertificate, id=cert_id)
    
    # Permission check
    if cert.user != request.user and not request.user.is_superuser:
        return HttpResponseForbidden("この操作を行う権限がありません。")
        
    if cert.is_revoked:
        messages.info(request, "この証明書はすでに失効しています。")
    else:
        cert.is_revoked = True
        cert.revoked_at = timezone.now()
        cert.save()
        messages.success(request, f"証明書 {cert.common_name} が失効処理されました。")
        
    return redirect('dashboard')

@login_required
def download_ca_cert(request):
    active_ca = CertificateAuthority.objects.filter(is_active=True).first()
    if not active_ca:
        raise Http404("CA が設定されていません。")
        
    response = HttpResponse(active_ca.certificate_pem, content_type='application/x-x509-ca-cert')
    response['Content-Disposition'] = 'attachment; filename="ca.crt"'
    return response

@login_required
def download_crl(request):
    active_ca = CertificateAuthority.objects.filter(is_active=True).first()
    if not active_ca:
        raise Http404("CA が設定されていません。")
        
    # Get all revoked certificates
    revoked_certs = IssuedCertificate.objects.filter(is_revoked=True)
    revoked_list = []
    for c in revoked_certs:
        revoked_list.append((int(c.serial_number), c.revoked_at))
        
    try:
        crl_pem = issue_crl(
            ca_key_pem=active_ca.private_key_pem,
            ca_cert_pem=active_ca.certificate_pem,
            revoked_certs_list=revoked_list,
            ca_kms_key_id=active_ca.kms_key_id
        )
        response = HttpResponse(crl_pem, content_type='application/pkix-crl')
        response['Content-Disposition'] = 'attachment; filename="ca.crl"'
        return response
    except Exception as e:
        messages.error(request, f"CRL の生成中にエラーが発生しました: {str(e)}")
        return redirect('dashboard')


@login_required
def download_cert_file(request, cert_id, file_type):
    cert = get_object_or_404(IssuedCertificate, id=cert_id)
    
    # Permission check
    if cert.user != request.user and not request.user.is_superuser:
        return HttpResponseForbidden("この操作を行う権限がありません。")
        
    # Envelope Decryption for private key if encrypted via KMS
    private_key_pem = None
    if cert.encrypted_key_b64:
        try:
            private_key_pem = kms_decrypt(cert.encrypted_key_b64, cert.kms_nonce_b64)
        except Exception as e:
            messages.error(request, f"KMSでの秘密鍵復号に失敗しました: {str(e)}")
            return redirect('dashboard')
    else:
        private_key_pem = cert.private_key_pem
        
    if file_type == 'cert':
        response = HttpResponse(cert.certificate_pem, content_type='application/x-x509-user-cert')
        response['Content-Disposition'] = f'attachment; filename="{cert.common_name}.crt"'
        return response
        
    elif file_type == 'key':
        if not private_key_pem:
            messages.error(request, "この証明書は CSR から発行されたか、秘密鍵が格納されていません。")
            return redirect('dashboard')
        response = HttpResponse(private_key_pem, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{cert.common_name}.key"'
        return response
        
    elif file_type == 'zip':
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as zip_file:
            zip_file.writestr(f'{cert.common_name}.crt', cert.certificate_pem)
            if private_key_pem:
                zip_file.writestr(f'{cert.common_name}.key', private_key_pem)
                
            active_ca = CertificateAuthority.objects.filter(is_active=True).first()
            if active_ca:
                zip_file.writestr('ca.crt', active_ca.certificate_pem)
                
        buffer.seek(0)
        response = HttpResponse(buffer.read(), content_type='application/zip')
        response['Content-Disposition'] = f'attachment; filename="{cert.common_name}_bundle.zip"'
        return response
        
    raise Http404("無効なダウンロード形式です。")


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
        
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.info(request, f"ようこそ、{username} さん！")
                return redirect('dashboard')
            else:
                messages.error(request, "ユーザー名またはパスワードが無効です。")
        else:
            messages.error(request, "入力情報に誤りがあります。")
    else:
        form = AuthenticationForm()
        
    return render(request, 'certificates/login.html', {'form': form})

def logout_view(request):
    logout(request)
    messages.info(request, "ログアウトしました。")
    return redirect('login')

def register_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
        
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, "アカウントが作成され、ログインしました！")
            return redirect('dashboard')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = UserCreationForm()
        
    return render(request, 'certificates/register.html', {'form': form})

def acme_challenge_view(request, token):
    try:
        challenge = AcmeChallenge.objects.get(token=token)
        return HttpResponse(challenge.validation, content_type='text/plain')
    except AcmeChallenge.DoesNotExist:
        raise Http404("Challenge token not found.")

