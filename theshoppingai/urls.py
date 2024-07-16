"""
URL configuration for theshoppingai project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from auths.views import *

urlpatterns = [
    path('admin/', admin.site.urls),

    path('api/register/', UserRegistrationView.as_view(), name='api-register'),              # From Keywordlit Project
    path('api/verification/', UserEmailVerificationView.as_view(), name='api-verification'), # From Keywordlit Project
    path('api/resendotp/', ResendOTPView.as_view(), name='api-resendotp'),                   # From Keywordlit Project
    path('api/login/', UserLoginView.as_view(), name='api-login'),                           # From Keywordlit Project
    #path('api/refresh-token/', RefreshTokenView.as_view(), name='refresh-token'),            # From Keywordlit Project
    # path('api/profile/', UserProfileView.as_view(), name='api-profile'),                     # From Keywordlit Project

    path('api/forgot-password/', ForgotPasswordView.as_view(), name='api-forgotpassword'),    # From Keywordlit Project
    path('api/reset-password/', UserChangePasswordView.as_view(), name='api-resetpassword'),  # Change password is now RESETPASSWORD
    path('api/change-password/', UserModifyPasswordView.as_view(), name='api-changepassword'), # NEW CHANGE PASSOWRD FOR EXISTING USERS

    path('api/search-product/', ProductSearchView.as_view(), name='api-ProductSearchView'), 

    path('api/oxy-search-product/', OxylabSearchView.as_view(), name='api-oxylabSearchView'), 

    path('api/oxy-product-detail/', OxylabProductDetailView.as_view(), name='api-oxylabSearchView'), 
]
