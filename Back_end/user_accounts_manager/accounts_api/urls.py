from django.urls import path

from .views import (
    registration_view, 
    VerifyEmail,
    ResendVerifyEmail,
    LoginView,
    LogoutView,
    ResetPasswordEmail,
    PasswordTokenCheck,
    SetNewPassword,
)

from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

#app_name = 'accounts_api'

urlpatterns = [
    path('register/', registration_view, name='register'),
    path('verify-email/', VerifyEmail.as_view(), name='email-verfify'),
    path('resend-verify-email/', ResendVerifyEmail, name='resend-verify-email'),
    path('user-login/', LoginView.as_view(), name='user-login'),
    path('user/logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('password-reset-email/', ResetPasswordEmail.as_view(), name='password-reset-email'),
    path('password-reset/<uidb64>/<token>/', PasswordTokenCheck.as_view(), name='password-reset-confirm'),
    path('password-reset-complete/', SetNewPassword().as_view(), name='password-reset-complete')
]