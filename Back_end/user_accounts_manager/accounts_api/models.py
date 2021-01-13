from django.db import models
from django.contrib.auth.models import AbstractUser

from rest_framework_simplejwt.tokens import RefreshToken


# Create your models here.
class registered_accounts(models.Model):
    """
    An registered user accounts model
    """  
    # User Name
    user_name = models.CharField(max_length=15, unique=True)
    # User Password
    password = models.CharField(max_length=150)

    # User Email
    email_address = models.EmailField(max_length=254)
    # Email verification status
    is_email_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.user_name
