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
    list_display = ["email", "id", "username", 'is_user_verified', 'credit']
    # def user_credit(self, obj):
    #         return str(obj.user.profile_photo)
    # user_credit.short_description = 'Profile Photo'  # Customize the column header

class oxylab_accountAdmin(admin.ModelAdmin):
    list_display = ["id", "username", 'status', 'password']

class search_historyAdmin(admin.ModelAdmin):
    list_display = ["id", "query", 'created', 'updated']

class cartAdmin(admin.ModelAdmin):
    list_display = ["id", "user", 'quantity', 'product_name','price', 'seller_name']

class saveforlaterAdmin(admin.ModelAdmin):
    list_display = ["id", "user", 'quantity', 'product_name','price', 'seller_name']    

class orderhistoryAdmin(admin.ModelAdmin):
    list_display = ["id", "user", 'quantity', 'product_name','price', 'seller_name']   

class category_modelAdmin(admin.ModelAdmin):
    list_display = ['id','category_name', 'mapping_name','category_image','created','updated']

class prodid_mappingAdmin(admin.ModelAdmin):
    list_display = ['id', 'product_id', 'seller_link']

class URL_ListAdmin(admin.ModelAdmin):
    list_display = ['id','name']

admin.site.register(URL_List,URL_ListAdmin)
admin.site.register(prodid_mapping,prodid_mappingAdmin)
admin.site.register(category_model, category_modelAdmin)
admin.site.register(orderhistory, orderhistoryAdmin)
admin.site.register(saveforlater, saveforlaterAdmin)
admin.site.register(cart, cartAdmin)
admin.site.register(search_history, search_historyAdmin)
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(oxylab_account, oxylab_accountAdmin)