from rest_framework import serializers
import hashlib
from django.contrib.auth.hashers import make_password, check_password
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

from .models import registered_accounts


class RegistrationSerializer(serializers.ModelSerializer):

    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = registered_accounts
        fields = ['email_address', 'user_name', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def save(self):
        account = registered_accounts(
            email_address = self.validated_data['email_address'],
            user_name = self.validated_data['user_name'],
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
