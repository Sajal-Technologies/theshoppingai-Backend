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
from django.conf.urls.static import static

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

    path('api/oxy-product-detail/', OxylabProductDetailView.as_view(), name='api-OxylabProductDetailView'), 

    path('api/oxy-pricing-detail/', OxylabPricingView.as_view(), name='api-OxylabPricingView'), 

    path('api/add-to-cart/', AddtoCartView.as_view(), name='api-AddtoCartView'), 

    path('api/delete-from-cart/', DeletefromCartView.as_view(), name='api-DeletefromCartView'), 

    path('api/update-cart/', UpdateproductCartView.as_view(), name='api-UpdateproductCartView'), 

    path('api/add-to-saveforlater/', Addtosaveforlater.as_view(), name='api-Addtosaveforlater'), 

    path('api/delete-from-saveforlater/', Deletefromsaveforlater.as_view(), name='api-Deletefromsaveforlater'), 

    path('api/saveforlater-to-cart/', MovetoCartfromsaveforlater.as_view(), name='api-MovetoCartfromsaveforlater'), 

    path('api/get-all-cartitem/', getallcartitems.as_view(), name='api-getallcartitems'), 
    
    path('api/get-all-savelateritem/', getallsaveforlateritems.as_view(), name='api-getallsaveforlateritems'), 

    path('api/buy_product/', BuyProduct.as_view(), name='buy_product'),
    path('api/confirm_purchase/', ConfirmPurchase.as_view(), name='confirm_purchase'),


    path('api/admin/get-all-cart/', Admingetallcart.as_view(), name='Admingetallcart'),

    path('api/admin/get-all-savelateritem/', Admingetallsavelater.as_view(), name='Admingetallsavelater'),


    path('api/oxy-sale-product/', OxylabSaleView.as_view(), name='api-OxylabSaleView'), 

    path('api/oxy-page-search-product/', OxylabPageSearchView.as_view(), name='api-OxylabPageSearchView'), 
    
    path('api/get-filter/', GetFiltersView.as_view(), name='api-GetFiltersView'), 

    path('api/oxy-category-page-search/', OxylabCategoryPageView.as_view(), name='api-OxylabCategoryPageView'), 


    path('api/get-all-category-text/', GetAllcategorytext.as_view(), name='api-GetAllcategorytext'),

    path('api/create-category-text/', CreateCategoryText.as_view(), name='api-CreateCategoryText'),
    path('api/edit-category-text/', EditCategoryText.as_view(), name='api-EditCategoryText'),
    path('api/delete-category-text/', DeleteCategoryText.as_view(), name='api-DeleteCategoryText'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)