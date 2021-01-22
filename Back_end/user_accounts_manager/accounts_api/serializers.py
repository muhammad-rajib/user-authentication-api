from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

import hashlib
from django.contrib import auth
from django.shortcuts import get_object_or_404
from django.contrib.auth.hashers import make_password, check_password
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from .models import registered_accounts
import psycopg2


class RegistrationSerializer(serializers.ModelSerializer):

    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = registered_accounts
        fields = ['email', 'username', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def save(self):
        account = registered_accounts(
            email = self.validated_data['email'],
            username = self.validated_data['username'],
            password = make_password(self.validated_data['password'],  None),
        )

        password = self.validated_data['password']
        password2 = self.validated_data['password2']

        if len(password) != 6:
            raise serializers.ValidationError({'password': 'Password should be at least 6 character.'})

        if password != password2:
            raise serializers.ValidationError({'password': 'Password must match.'})
            
        account.save()
        return account


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=555)

    class Meta:
        model = registered_accounts
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=100, min_length=6)
    password = serializers.CharField(max_length=150, min_length=6, write_only=True)
    email = serializers.EmailField(max_length=225, read_only=True)
    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = registered_accounts.objects.get(username=obj['username'])

        return {
            'refresh': user.tokens()['refresh'],
            'access': user.tokens()['access']
        }

    class Meta:
        model = registered_accounts
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        username = attrs.get('username', '')
        password = attrs.get('password', '')
        
        try:
            user_info = registered_accounts.objects.get(username=username)
        except registered_accounts.DoesNotExist:
            raise AuthenticationFailed('User name or Password not matched, try again')
        
        match_password = user_info.password
        print(password)
        print(match_password)
        if not check_password(password, match_password):
            raise AuthenticationFailed('User name or Password not matched, try again22')

        if not user_info.is_email_verified:
            raise AuthenticationFailed('Email is not verified')

        return {
            'email': user_info.email,
            'username': user_info.username,
            'tokens': user_info.tokens
        }

        return super().validate(attrs)


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')


class ResetPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)
    redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=150, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']
    
    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = registered_accounts.objects.get(id=id)
        
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)

        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid33', 401)
        return super().validate(attrs)
