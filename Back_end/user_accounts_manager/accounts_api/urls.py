from django.urls import path

from .views import registration_view, VerifyEmail

app_name = 'accounts_api'

urlpatterns = [
    path('register/', registration_view, name='register'),
    path('verify-email/', VerifyEmail.as_view(), name='email-verfify'),
]