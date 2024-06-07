from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import *
from .forms import CustomUserCreationForm, CustomUserChangeForm
# Register your models here.


class CustomUserAdmin(UserAdmin):
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = CustomUser
    # list_display = ["email", "username", 'is_user_verified', 'credit']
    list_display = ["email", "id", "username", 'profile_photo', 'is_user_verified', 'credit']
    def user_credit(self, obj):
            return str(obj.user.profile_photo)
    user_credit.short_description = 'Profile Photo'  # Customize the column header



admin.site.register(CustomUser, CustomUserAdmin)