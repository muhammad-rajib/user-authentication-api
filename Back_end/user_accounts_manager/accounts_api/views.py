from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings

from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status, views, generics, permissions
from rest_framework_simplejwt.tokens import RefreshToken
import jwt

from .serializers import (
    RegistrationSerializer, 
    EmailVerificationSerializer, 
    LoginSerializer,
    LogoutSerializer,
)
from .models import registered_accounts
from .utils import Util

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema


@api_view(['POST',])
def registration_view(request):

    if request.method == 'POST':
        serializer = RegistrationSerializer(data=request.data)
        data = {}
        response_data = {}

        if serializer.is_valid():
            account = serializer.save()
            
            # Send email verification mail to new user
            user_data = serializer.data
            user = registered_accounts.objects.get(username=user_data['username'])

            token = RefreshToken.for_user(user).access_token
            current_site = get_current_site(request).domain
            absurl = 'http://' + current_site + '/api/v1/accounts/' +'verify-email/' + "?token=" + str(token)
            resend_link = 'http://'+current_site+'/api/v1/accounts/'+'resend-verify-email/'+"?username="+str(user_data['username'])

            email_body = 'Hi ' + user.username + '\n' + 'Use this below link to verify your email \n\n' + absurl + '\n\nUse this below link for resend verification email:\n'+resend_link
            
            data['email_body'] = email_body
            data['to_email'] = user.email
            data['email_subject'] = 'Verify your email' 
            Util.send_mail(data)

            response_data['status'] = 'Successfully registration completed.'
            response_data['username'] = user.username
        else:
            response_data = serializer.errors
        
        return Response(response_data, status=status.HTTP_201_CREATED)


class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(jwt=token, key=settings.SECRET_KEY, algorithms=['HS256'])
            user = registered_accounts.objects.get(id=payload['user_id'])
            if not user.is_email_verified:
                user.is_email_verified = True
                user.save()
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET',])
def ResendVerifyEmail(request):
    if request.method == 'GET':
        username = request.GET.get('username')
        user = registered_accounts.objects.get(username=username)
  
        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        absurl = 'http://' + current_site + '/api/v1/accounts/' +'verify-email/' + "?token=" + str(token)
        resend_link = 'http://'+current_site+'/api/v1/accounts/' +'resend-verify-email/'+"?username="+str(username)
    
        email_body = 'Hi ' + user.username + '\n' + 'Use this below link to verify your email \n\n' + absurl + '\n\nUse this below link for resend verification email:\n'+resend_link
                
        data = {}
        data['email_body'] = email_body
        data['to_email'] = user.email
        data['email_subject'] = 'Resend: Verify your email' 
        Util.send_mail(data)
    return Response({'Resend Mail':'Sent to your mail'}, status=status.HTTP_200_OK)


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class LogoutView(generics.GenericAPIView):
    serializer_class = LogoutSerializer

    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)