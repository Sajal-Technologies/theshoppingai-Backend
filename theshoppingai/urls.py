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


from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi


schema_view = get_schema_view(
   openapi.Info(
      title="The Shopping AI",
      default_version='v1',
    #   description="Test description",
    #   terms_of_service="https://www.google.com/policies/terms/",
    #   contact=openapi.Contact(email="contact@yourproject.local"),
    #   license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)




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


    path('api/oxy-sale-product/', OxylabPageONSale.as_view(), name='api-OxylabPageONSale'), 

    path('api/oxy-page-search-product/', OxylabPageSearchView.as_view(), name='api-OxylabPageSearchView'), 
    
    path('api/get-filter/', GetFiltersView.as_view(), name='api-GetFiltersView'), 

    path('api/oxy-category-page-search/', OxylabCategoryPageView.as_view(), name='api-OxylabCategoryPageView'), 


    path('api/get-all-category-text/', GetAllcategorytext.as_view(), name='api-GetAllcategorytext'),

    path('api/get-category-text-with-image/', Getcategorytextwithimage.as_view(), name='api-Getcategorytextwithimage'),

    path('api/create-category-text/', CreateCategoryText.as_view(), name='api-CreateCategoryText'),
    path('api/edit-category-text/', EditCategoryText.as_view(), name='api-EditCategoryText'),
    path('api/delete-category-text/', DeleteCategoryText.as_view(), name='api-DeleteCategoryText'),

    # path('api/filter-result/', filter_out_200.as_view(), name='api-filter_out_200'),

    path('api/clear-search-history/', ClearSearchHistoryView.as_view(), name='api-ClearSearchHistoryView'),

    path('api/get-search-history/', GetAllSearchHsitory.as_view(), name='api-GetAllSeachHsitory'),

    path('api/delete-one-history/', DeleteOneHistory.as_view(), name='api-DeleteOneHistory'),

    path('api/get-all-catname/', GetALLCategoryList.as_view(), name='api-GetALLCategoryList'),

    path('api/oxy-category-with-productid/', CategoryPageWithProductIDFilter.as_view(), name='api-CategoryPageWithProductIDFilter'), 

    path('api/suggestion-api/', SuggestionAPIView.as_view(), name ="api-SuggestionAPIView"),

    path('api/suggestion-keyword-api/', SearchSuggestionsView.as_view(), name ="api-SuggestionAPIView"),

    path('api/get-all-urls/', GetAllURLs.as_view(), name ="api-GetAllURLs"),

    path('api/edit-url/', EditURL.as_view(), name ="api-EditURL"),

    path('api/delete-url/', DeleteURL.as_view(), name ="api-DeleteURL"),

    path('api/add-url-list/', add_to_URL_List.as_view(), name ="api-add_to_URL_List"),

    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)