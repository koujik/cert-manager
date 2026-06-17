from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('.well-known/acme-challenge/<str:token>', views.acme_challenge_view, name='acme_challenge'),
    path('setup-ca/', views.setup_ca_view, name='setup_ca'),

    path('issue/', views.issue_cert_view, name='issue_cert'),
    path('revoke/<int:cert_id>/', views.revoke_cert_view, name='revoke_cert_view'),
    path('download/ca/', views.download_ca_cert, name='download_ca'),
    path('download/crl/', views.download_crl, name='download_crl'),
    path('download/cert/<int:cert_id>/<str:file_type>/', views.download_cert_file, name='download_cert_file'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
]
