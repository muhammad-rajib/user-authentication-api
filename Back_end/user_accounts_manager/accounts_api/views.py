from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.conf import settings

from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework import status, views
from rest_framework_simplejwt.tokens import RefreshToken
import jwt

from .serializers import RegistrationSerializer, EmailVerificationSerializer
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
            user = registered_accounts.objects.get(user_name=user_data['user_name'])

            token = RefreshToken.for_user(user).access_token
            current_site = get_current_site(request).domain
            #relativeLink = reverse('email-verify')
            absurl = 'http://' + current_site + '/api/v1/accounts/' +'verify-email/' + "?token=" + str(token)
            email_body = 'Hi ' + user.user_name + '\n' + 'Use this below link to verify your email \n\n' + absurl
            print(absurl)

            data['email_body'] = email_body
            data['to_email'] = user.email_address
            data['email_subject'] = 'Verify your email' 
            Util.send_mail(data)

            response_data['status'] = 'Successfully registration completed.'
            response_data['user_name'] = user.user_name
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
