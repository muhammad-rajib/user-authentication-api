# from django.contrib import admin
# from .models import registered_accounts

# # Register your models here.
# admin.site.register(registered_accounts)

from django.contrib import admin

# Register your models here.
from .models import registered_accounts


class UserAdmin(admin.ModelAdmin):
    list_display = ['username', 'email', 'created_at']


admin.site.register(registered_accounts, UserAdmin)