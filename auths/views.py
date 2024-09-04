from django.shortcuts import render
from .models import *
from rest_framework.views import APIView
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from rest_framework.response import Response
from .email import send_otp_via_email
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import generate_random_string, get_user_id_from_token
from .serializers import historySerializer, URLListSerializer, UserChangePasswordSerializer, UserLoginSerializer, UserProfileSerializer, UserRegistrationSerializer, UserChangePasswordSerializer, UserModifyPasswordSerializer
from rest_framework.permissions import BasePermission, IsAuthenticated, AllowAny
from .renderers import UserRenderer
from django.views import View
from django.http import JsonResponse, HttpResponse
import os
from django.conf import settings
from django.utils import timezone
# import pytz
import datetime
import requests, json
import random
from django.core.validators import validate_email
import threading
from queue import Queue
from django.contrib.sessions.models import Session
from django.core import serializers
import re
import uuid
# from django.utils.http import http_date
# Create your views here.




def IsSuperUser(user_id):
    user = CustomUser.objects.filter(id=user_id)
    if not user : return False, False
    user = user.first()
    return user , user.is_superuser
    
def get_or_createToken(request):
    """ 
    Create a user access token for already logged in user
    """
    if request.user.is_authenticated  :
        user = CustomUser.objects.get(email = request.user.email)
        token = get_tokens_for_user(user)
        request.session['access_token'] = token['access']
        return request.session['access_token']
    else:
        return False

def get_tokens_for_user(user):
    """ 
    Get a token access for already logged in user.
    """
    refresh = RefreshToken.for_user(user)
    return {
        # 'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
      


class UserRegistrationView(APIView):
    """ 
    An API view for user registration and return error if there is any error or insufficient data provided
    """
    renderer_classes = [UserRenderer]
    
    def post(self, request, format=None):
        if not 'username' in request.data:
            while True:
                generated_random_username = generate_random_string(15)
                if CustomUser.objects.filter(username=generated_random_username).count() == 0:
                    request.data['username'] = generated_random_username
                    break
        
        if not request.data.get('email') and not request.data.get('password'):
            return Response(
                {"Message": "The Email address and Password is Required"},status=status.HTTP_400_BAD_REQUEST)

        if not request.data.get('email'):
            # return Response({'Message': 'email field is required'}, status=status.HTTP_400_BAD_REQUEST)
            return Response(
                {"errors": {"email": ["The Email Address is Required"]}},status=status.HTTP_400_BAD_REQUEST)
        if not request.data.get('password'):
            # return Response({'Message': 'email field is required'}, status=status.HTTP_400_BAD_REQUEST)
            return Response(
                {"errors": {"password": ["The Password is Required"]}},status=status.HTTP_400_BAD_REQUEST)
        if not request.data.get('name'):
            # return Response({'Message': 'email field is required'}, status=status.HTTP_400_BAD_REQUEST)
            return Response(
                {"errors": {"name": ["The Name is Required"]}},status=status.HTTP_400_BAD_REQUEST)

        email = request.data.get("email")
        

        if CustomUser.objects.filter(email=email).exists():
            return Response({'Message': "User with this email address is already registered. Please Sign-in"}, status=status.HTTP_409_CONFLICT)

        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        is_superuser = request.data.get('isAdmin', False)
        if is_superuser:
            user = CustomUser.objects.create_superuser(**serializer.validated_data)
            user.is_user_verified = True  # ALL superuser are verified
            user.save()
            return Response({"email": 'Email is verified', 'Message': 'Admin user Created'},
                        status=status.HTTP_201_CREATED)
        
        else:
            user = serializer.save()

            verification_code = random.randint(100000, 999999)
            user.verification_code = verification_code
            user.save()

            try:
                send_otp_via_email(user.email)  # Use your send_otp_via_email function
            except ValidationError as e:
                return Response({'Message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

            return Response({"email": f'{user.email}', 'Message': ' Email verification code has been sent, Verify your account'},
                            status=status.HTTP_201_CREATED)






#---------------------------------------------------------UserEmailVerification By Adil--------------------------------------------------------
    
class UserEmailVerificationView(APIView):
    def post(self, request):
        email = request.data.get('email')
        verification_code = request.data.get('verification_code')
        # Check if required fields are provided

        if not request.data.get('email') and not request.data.get('verification_code'):
            return Response(
                {"Message": "The Email address and verification_code is Required"},status=status.HTTP_400_BAD_REQUEST)

        if not request.data.get('email') or not email:
            return Response({"errors": {"email": ["The Email Address is Required"]}},status=status.HTTP_400_BAD_REQUEST)

        if not verification_code:
            return Response({"errors": {"verification_code": ["The verification_code is Required"]}}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            validate_email(email)
        except ValidationError:
            return Response({"errors": {"email": ["Enter a valid email address."]}}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email)

            if user.is_user_verified == True:
                # If user is already verified, return a message indicating so
                return Response({'Message': 'User is already verified.'}, status=status.HTTP_400_BAD_REQUEST)
            
             # Check if verification code is a valid number
            if not verification_code.isdigit():
                return Response({'Message': 'Invalid Verification Code.'}, status=status.HTTP_400_BAD_REQUEST)

            if str(user.verification_code) == verification_code:
                user.is_user_verified = True
                token = get_tokens_for_user(user)
                verification_code = random.randint(100000, 999999)# Extra Code added to change the code after Process because same code will be used multiple times ex- same code will be used to chnage password.
                user.verification_code = verification_code# Extra Code added to change the code after Process because same code will be used multiple times ex- same code will be used to chnage password.
                user.save()
                # if user.membership:
                #     Mem=Membership.objects.filter(name=user.membership.name).first()
                #     memebership_id=Mem.id
                #     return Response({'token':token,'verified' : user.is_user_verified, 'Message':'Email verified successfully.', "membership_id":memebership_id, "membership":user.membership.name, "membership_expiry_date":str(user.membership_expiry), "subscription_status":user.is_subscribed, "stripe_customer_id":user.stripe_customer_id}, status=status.HTTP_200_OK)
                # else:
                return Response({'token':token,'verified' : user.is_user_verified, 'user name' : user.name, 'Message':'Email verified successfully.', "membership_id":None, "membership":None, "membership_expiry_date":None, "subscription_status":user.is_subscribed, "stripe_customer_id":user.stripe_customer_id}, status=status.HTTP_200_OK)
                # return Response({'token':token,'Message': 'Email verified successfully.'}, status=status.HTTP_200_OK)
            else:
                return Response({'Message': 'Entered Verification code is incorrect.'}, status=status.HTTP_401_UNAUTHORIZED)
        except CustomUser.DoesNotExist:
            # If email is not in records, prompt user to register first
            return Response({'Message': 'You are not registered with us, please sign up.'}, status=status.HTTP_404_NOT_FOUND)

#---------------------------------------------------------UserEmailVerification By Adil--------------------------------------------------------
 
#---------------------------------------------------------Resend OTP API by ADIL----------------------------------------------------------------

class ResendOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        # if not email:
        #     return Response({'Message': 'Please provide an email address.'}, status=status.HTTP_400_BAD_REQUEST)
        if not email:
            return Response(
                {"errors": {"email": ["The Email Address is Required"]}},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            validate_email(email)
        except ValidationError:
            return Response({"errors": {"email": ["Enter a valid email address."]}}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email)
            verification_code = random.randint(100000, 999999)
            user.verification_code = verification_code
            user.save()
            # Call the function to send OTP via email
            send_otp_via_email(email)
            return Response({'Message': 'New verification code sent successfully.'}, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({'Message': 'You are not registered with us, please sign up.'}, status=status.HTTP_404_NOT_FOUND)


#---------------------------------------------------------Resend OTP APY by ADIL---------------------------------------------------------------




class UserLoginView(APIView):
    """ 
    send an username and exist user's password to get user's accesstoken.
    """
    renderer_classes = [UserRenderer]
    def post(self, request, format=None):

        if not request.data.get('email') and not request.data.get('password'):
            return Response(
                {"Message": "The Email address and Password is Required"},status=status.HTTP_400_BAD_REQUEST)
        
        if not request.data.get('email'):
            # return Response({'Message': 'email field is required'}, status=status.HTTP_400_BAD_REQUEST)
            return Response(
                {"errors": {"email": ["The Email Address is Required"]}},status=status.HTTP_400_BAD_REQUEST)
        
        if not request.data.get('password'):
            # return Response({'Message': 'email field is required'}, status=status.HTTP_400_BAD_REQUEST)
            return Response(
                {"errors": {"password": ["The Password is Required"]}},status=status.HTTP_400_BAD_REQUEST)

        try:
            validate_email(request.data.get('email'))
        except ValidationError:
            return Response({"errors": {"email": ["Enter a valid email address."]}}, status=status.HTTP_400_BAD_REQUEST)


        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        password = serializer.data.get('password')
        #user = CustomUser.objects.get(email = email)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            # If the email is not found in records, return a 404 NotFound response
            return Response({'Message': 'You are not registered with us, please sign up.'}, status=status.HTTP_404_NOT_FOUND)

        if user.check_password(password)  :
            if user.is_user_verified:
                token = get_tokens_for_user(user)
                user, is_superuser = IsSuperUser(user.id)
                # if user.membership:
                #     Mem=Membership.objects.filter(name=user.membership.name).first()
                #     memebership_id=Mem.id
                #     return Response({'token':token,'verified' : user.is_user_verified, "user name":user.name, 'admin' : is_superuser, 'Message':'Login Success', "membership_id":memebership_id, "membership":user.membership.name, "membership_expiry_date":str(user.membership_expiry), "subscription_status":user.is_subscribed, "stripe_customer_id":user.stripe_customer_id}, status=status.HTTP_200_OK)
                # else:
                return Response({'token':token,'verified' : user.is_user_verified, "user name":user.name, 'admin' : is_superuser, 'Message':'Login Success', "membership_id":None, "membership":None, "membership_expiry_date":None, "subscription_status":user.is_subscribed, "stripe_customer_id":user.stripe_customer_id}, status=status.HTTP_200_OK)

            else:
#--------------------------If user is not verified then OTP is sent to user-----------------------------------------------------------
                verification_code = random.randint(100000, 999999)
                user.verification_code = verification_code
                user.save()
                try:
                    send_otp_via_email(user.email)  # Use your send_otp_via_email function
                except ValidationError as e:
                    return Response({'Message': str(e)}, status=status.HTTP_400_BAD_REQUEST)
#--------------------------If user is not verified then OTP is sent to user-----------------------------------------------------------
                return Response({'verified' : user.is_user_verified, 'Message':'Verify your account First!', 'email': user.email}, status=status.HTTP_200_OK)
        else:
            return Response({
                                    "Message": 
                                        'Sorry, your password is incorrect.'
                                    
                                }
                            , status=status.HTTP_401_UNAUTHORIZED)
            # return Response({'Message':'Password is not Valid'}, status=status.HTTP_404_NOT_FOUND)

class RefreshTokenView(APIView):
    """
    Send a refresh token to get a new access token.
    """
    def post(self, request, format=None):
        refresh_token = request.data.get('refresh_token')

        if not refresh_token:
            return Response({'Message': 'No refresh token provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            refresh_token = RefreshToken(refresh_token)
            access_token = refresh_token.access_token
        except Exception as e:
            return Response({'Message': 'Invalid refresh token'}, status=status.HTTP_400_BAD_REQUEST)

        return Response({'access_token': str(access_token)}, status=status.HTTP_200_OK)




class UserModifyPasswordView(APIView):
    """ 
    Change existing user password.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):

        if not request.data.get('old_password'):
            return Response({
                    "errors": {
                        "old_password": [
                            "This is required field*"
                        ]
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
        
        if not request.data.get('new_password'):
            return Response({
                    "errors": {
                        "new_password": [
                            "This is required field*"
                        ]
                    }
                }, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserModifyPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = request.user

        old_password = serializer.validated_data.get('old_password')
        new_password = serializer.validated_data.get('new_password')

        # Check if the old password matches the user's current password
        if not user.check_password(old_password):
            return Response(
                                            {
                                "errors": {
                                    "password": [
                                        'Old password is incorrect.'
                                    ]
                                }
                            }

                # {'Message': 'Old password is incorrect.'}
                            
                            , status=status.HTTP_400_BAD_REQUEST)

        # Check if the old and new passwords are the same
        if old_password == new_password:
            return Response(
                            {
                                            "errors": {
                                                "password": [
                                                    'New password must be different from the old password.'
                                                ]
                                            }
                                        }
                
                
                # {'Message': 'New password must be different from the old password.'}
                
                
                , status=status.HTTP_400_BAD_REQUEST)

        # Change the user's password
        user.set_password(new_password)
        user.save()

        return Response({'Message': 'Password changed successfully.'}, status=status.HTTP_200_OK)



#---------------------------------------------Change Password by Adil------------------------------------------------------------

class UserChangePasswordView(APIView):
    """ 
    Reset user password
    """
    renderer_classes = [UserRenderer]
    permission_classes = [AllowAny]  # Allow any user to access this endpoint

    def post(self, request, format=None):
        email = request.data.get('email')
        verification_code = request.data.get('verification_code')
        new_password = request.data.get('new_password')

        # Check if required fields are provided

        if not email:
            return Response({
                    "errors": {
                        "email": [
                            "The Email Address is Required"
                        ]
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
        
        if not new_password:
            return Response({
                    "errors": {
                        "new_password": [
                            "The Password is Required"
                        ]
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
        
        if len(new_password) <=8:
            return Response({
                    "errors": {
                        "password": [
                            "password length should be more than 8 characters."
                        ]
                    }
                }, status=status.HTTP_400_BAD_REQUEST)

        if not verification_code:
            return Response({
                    "errors": {
                        "verification_code": [
                            "The Verification Code is Required"
                        ]
                    }
                }, status=status.HTTP_400_BAD_REQUEST)

        if not email or not verification_code or not new_password:
            return Response({'Message': 'Please provide the Email, Verification code and New Password'}, status=status.HTTP_400_BAD_REQUEST)

         # Check if verification code is a valid number
        if not verification_code.isdigit():
            return Response({'Message': 'Invalid Verification Code.'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            user = CustomUser.objects.get(email=email, verification_code=verification_code)
            verification_code = random.randint(100000, 999999)# Extra Code added to change the code after Process because same code will be used multiple times.
            user.verification_code = verification_code# Extra Code added to change the code after Process because same code will be used multiple times.
            user.save()# Extra Code added to change the code after Process because same code will be used multiple times.
        except CustomUser.DoesNotExist:
            return Response({'Message': 'Invalid email or verification code.'}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = UserChangePasswordSerializer(instance=user, data={'password': new_password, 'password2': new_password})
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({'Message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            # Handle validation errors
            return Response({'Message': e.detail}, status=status.HTTP_400_BAD_REQUEST)


#---------------------------------------------Change Password by Adil------------------------------------------------------------






#---------------------------------Forgot Password by Adil--------------------------------------------------------------------

class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        # if not email:
        #     return Response({'Message': 'Please provide the Email'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not email:
            return Response(
                {"errors": {"email": ["The Email Address is Required"]}},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate email format
        try:
            validate_email(email)
        except ValidationError:
            return Response(
                # {'Message': 'Please provide a valid Email'
                             
                             {
                                "errors": {
                                    "email": [
                                        "Enter a valid email address."
                                    ]
                                }
                            }

                            #  }
                             , status=status.HTTP_400_BAD_REQUEST)

        try:
            # Check if user exists in records
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            # If user is not in records, prompt user to register first
            return Response({'Message': 'You are not registered with us, please sign up.'}, status=status.HTTP_404_NOT_FOUND)

        # Generate a verification code
        verification_code = random.randint(100000, 999999)
        user.verification_code = verification_code
        user.save()

        # Send verification code via email
        send_otp_via_email(email)

        return Response({'Message': 'Password Reset code sent successfully. Use it to reset your password.'}, status=status.HTTP_200_OK)

#------------------------------------Forgot Password by Adil---------------------------------------------------------------
    

from selenium.webdriver import Chrome
from selenium.webdriver.chrome.options import Options
import time
# import requests
from bs4 import BeautifulSoup
import urllib.parse
from urllib.parse import parse_qs, urlparse

import asyncio
import aiohttp
from asgiref.sync import sync_to_async
from concurrent.futures import ThreadPoolExecutor
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ProductSearchView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def fetch_html_content(self, url):
        options = Options()
        options.add_argument("--headless")
        options.add_argument("window-size=1400,1500")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("start-maximized")
        options.add_argument("enable-automation")
        options.add_argument("--disable-infobars")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-popup-blocking")
        options.add_argument("--disable-notifications")
        options.add_argument("--disable-background-timer-throttling")
        options.add_argument("--disable-backgrounding-occluded-windows")
        options.add_argument("--disable-renderer-backgrounding")

        prefs = {
            "profile.managed_default_content_settings.images": 2,  # Disable images
            "profile.default_content_setting_values.notifications": 2,  # Disable notifications
            "profile.managed_default_content_settings.stylesheets": 2,  # Disable CSS
            "profile.managed_default_content_settings.cookies": 2,  # Disable cookies
            "profile.managed_default_content_settings.plugins": 2,  # Disable plugins
            "profile.managed_default_content_settings.popups": 2,  # Disable popups
            "profile.managed_default_content_settings.geolocation": 2,  # Disable geolocation
            "profile.managed_default_content_settings.media_stream": 2,  # Disable media stream
        }
        options.add_experimental_option("prefs", prefs)

        driver = Chrome(options=options)
        try:
            logger.info(f"Fetching URL: {url}")
            driver.get(url)
            logger.info("Successfully fetched URL")
            return driver.page_source
        except Exception as e:
            logger.error(f"Error occurred while fetching URL {url}: {str(e)}")
            return Response({"Message":f"Error occured: {str(e)}"})
        finally:
            driver.quit()

    def parse_product_details(self, html_content):
        logger.info("Parsing HTML content")
        soup = BeautifulSoup(html_content, 'html.parser')
        products = []

        product_grid = soup.find_all('div', class_='sh-dgr__gr-auto sh-dgr__grid-result')
        for product in product_grid:
            product_name = product.find('h3', class_='tAxDx').get_text(strip=True) if product.find('h3', class_='tAxDx') else None
            price_span = product.find('span', class_='a8Pemb OFFNJ')
            price = price_span.get_text(strip=True) if price_span else None
            website_span = product.find('div', class_='aULzUe IuHnof')
            website_name = website_span.get_text(strip=True) if website_span else None

            # Extract ratings
            rating_span = product.find('span', class_='Rsc7Yb')
            rating = rating_span.get_text(strip=True) if rating_span else None

            # Extract review count
            review_count_span = rating_span.find_next_sibling('div', class_='qSSQfd uqAnbd').next_sibling if rating_span else None
            review_count = review_count_span.get_text(strip=True) if review_count_span else None

            link_tag = product.find('a', class_='shntl')
            link = link_tag['href'] if link_tag else None

            if link and link.startswith('/url?url='):
                parsed_url = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
                link = parsed_url['url'][0] if 'url' in parsed_url else link
            
            products.append({
                'Product Name': product_name,
                'Price': price,
                'Website Name': website_name,
                'Link': link,
                "Rating": rating,
                "Review Counts": review_count
            })
        logger.info(f"Parsed {len(products)} products")
        return products
    
    


    
    # def extract_product_info(self, product):
    #     product_name = product.select_one('h3.tAxDx')
    #     product_name = product_name.get_text(strip=True) if product_name else None

    #     price_span = product.select_one('span.a8Pemb.OFFNJ')
    #     price = price_span.get_text(strip=True) if price_span else None

    #     website_span = product.select_one('div.aULzUe.IuHnof')
    #     website_name = website_span.get_text(strip=True) if website_span else None

    #     rating_span = product.select_one('span.Rsc7Yb')
    #     rating = rating_span.get_text(strip=True) if rating_span else None

    #     review_count_span = rating_span.find_next_sibling('div.qSSQfd.uqAnbd').next_sibling if rating_span and rating_span.find_next_sibling('div.qSSQfd.uqAnbd') else None
    #     review_count = review_count_span.get_text(strip=True) if review_count_span else None

    #     link_tag = product.select_one('a.shntl')
    #     link = link_tag['href'] if link_tag else None

    #     if link and link.startswith('/url?url='):
    #         parsed_url = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
    #         link = parsed_url['url'][0] if 'url' in parsed_url else link

    #     return {
    #         'Product Name': product_name,
    #         'Price': price,
    #         'Website Name': website_name,
    #         'Link': link,
    #         "Rating": rating,
    #         "Review Counts": review_count
    #     }

    # def parse_product_details(self, html_content):
    #     soup = BeautifulSoup(html_content, 'html.parser')
    #     product_grid = soup.select('div.sh-dgr__gr-auto.sh-dgr__grid-result')
    #     products = [self.extract_product_info(product) for product in product_grid]
    #     return products



    async def fetch_all_pages(self, urls):
        with ThreadPoolExecutor(max_workers=6) as executor:
            loop = asyncio.get_event_loop()
            tasks = [loop.run_in_executor(executor, self.fetch_html_content, url) for url in urls]
            return await asyncio.gather(*tasks)

    @sync_to_async
    def get_user(self, userid):
        return CustomUser.objects.filter(id=userid).first()

    async def async_post(self, request):
        start_time = time.time()
        userid = get_user_id_from_token(request)
        user = await self.get_user(userid)

        if not user:
            logger.error("User not found")
            return Response({"Message": "User not Found!!!!"})

        product = request.data.get('product_name')

        if not product:
            logger.warning("Product name not provided")
            return Response({'Message': 'Please provide product_name'}, status=status.HTTP_400_BAD_REQUEST)

        product_name = str(product).replace(' ', '+')

        # Get filter parameters from the request
        on_sale = request.data.get('on_sale')
        ppr_min = request.data.get('ppr_min')
        ppr_max = request.data.get('ppr_max')
        avg_rating = request.data.get('avg_rating')
        ship_speed = request.data.get('ship_speed')
        free_shipping = request.data.get('free_shipping')
        sort_order = request.data.get('sort_order')  # New parameter for sorting
        
        filters = []
        rating_mapping = {
            '5': '500',
            '4': '400',
            '3': '300',
            '2': '200',
            '1': '100'
        }

        if avg_rating in rating_mapping:
            filters.append(f'avg_rating:{rating_mapping[avg_rating]}')
        if on_sale:
            filters.append('sales:1')
        if ppr_min and ppr_max:
            filters.append(f'price:1,ppr_min:{ppr_min},ppr_max:{ppr_max}')
        # if avg_rating in rating_mapping:
        #     filters.append(f'avg_rating:{rating_mapping[avg_rating]}')
        if ship_speed:
            filters.append(f'shipspped:{ship_speed}')
        if free_shipping:
            filters.append('ship:1')

        # Add sort order to the filters
        sort_mapping = {
            'relevance': 'p_ord:r',
            'low_to_high': 'p_ord:p',
            'high_to_low': 'p_ord:pd',
            'rating': 'p_ord:rv'
        }

        if sort_order in sort_mapping:
            filters.append(sort_mapping[sort_order])


        filter_string = ','.join(filters)
        
        urls = [
            f"https://www.google.com/search?q={product_name}&sca_esv=9c8758eb10df77ff&sca_upv=1&hl=en-GB&psb=1&tbs=vw:d,{filter_string}&tbm=shop&ei=gc-UZr-xKtCN4-EP99WjoAU&start={pge}&sa=N&ved=0ahUKEwj_9bLawqiHAxXQxjgGHffqCFQQ8tMDCIMb&biw=1536&bih=730&dpr=1.25"
            # f"https://www.google.com/search?q={product_name}&sca_esv=0835a04e1987451a&sca_upv=1&hl=en-GB&psb=1&tbs=vw:d,{filter_string}&tbm=shop&ei=PtyLZqe-L52qseMP_e2qoAk&start={pge}&sa=N&ved=0ahUKEwin1bPLuZeHAxUdVWwGHf22CpQ4eBDy0wMI7w0&biw=1536&bih=730&dpr=1.25"
            for pge in range(0, 121, 60)  # Reduced to 3 pages
            
        ]
        logger.info(f"Generated URLs: {urls}")
        print(urls)
        retries = 3
        for attempt in range(retries):
            try:
                logger.info(f"Fetching HTML contents, attempt {attempt + 1}")
                html_contents = await self.fetch_all_pages(urls)

                all_products = []

                for html_content in html_contents:
                    if html_content:
                        products = self.parse_product_details(html_content)
                        all_products.extend(products)

                if all_products:
                    end_time = time.time()
                    duration = end_time - start_time
                    logger.info(f"Successfully fetched {len(all_products)} products")
                    logger.info(f"Time Taken: {duration}")
                    return Response({'Message': 'Fetch the Product data Successfully', "Product_data": all_products}, status=status.HTTP_200_OK)
                else:
                    logger.warning(f"Attempt {attempt + 1}: Products list is empty, retrying...")
                    print(f"Attempt {attempt + 1}: Products list is empty, retrying...")
                    await asyncio.sleep(3)  # Wait before retrying

            except Exception as e:
                logger.error(f"Attempt {attempt + 1}: Error occurred: {str(e)}")
                print(f"Attempt {attempt + 1}: Error occurred: {str(e)}")
                await asyncio.sleep(3)  # Wait before retrying

        logger.error("Failed to fetch product data after multiple attempts")
        return Response({'Message': 'Failed to fetch product data after multiple attempts'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        return asyncio.run(self.async_post(request))



logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s')

from django.db import transaction
import concurrent.futures

class OxylabSearchView(APIView):
    def post(self, request):
        logger = logging.getLogger(__name__)  # Get logger for this module

        # Log the incoming request details
        logger.info(f"Received POST request: {request.data}")

        query = request.data.get("product_name")
        ppr_min = request.data.get("ppr_min", None)
        ppr_max = request.data.get("ppr_max", None)
        sort_by = request.data.get("sort_by", 'relevance')  # Default to 'relevance'

        if not query:
            return Response({'Message': 'Please provide query to search'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            oxy_account = oxylab_account.objects.get(id=1)
            username = oxy_account.username
            password = oxy_account.password
        except oxylab_account.DoesNotExist:
            return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)

        query_main = str(query).replace(" ", "+")

        sort_mapping = {
            'relevance': 'r',
            'low_to_high': 'p',
            'high_to_low': 'pd',
            'rating': 'rv'
        }

        sort_key = sort_mapping.get(sort_by, 'r')  # Default to 'relevance' if sort_by is invalid

        # Build context dynamically based on provided filters
        context = [{'key': 'sort_by', 'value': sort_key}]
        
        if ppr_min is not None:
            context.append({'key': 'min_price', 'value': ppr_min})
        
        if ppr_max is not None:
            context.append({'key': 'max_price', 'value': ppr_max})

        def fetch_page(page_number):
            payload = {
                'source': 'google_shopping_search',
                'domain': 'co.in',
                'query': query_main,
                "start_page": page_number,
                'pages': 1,
                'parse': True,
                'locale': 'en',
                "geo_location": "India",
                'context': context,
            }
            try:
                response = requests.post(
                    'https://realtime.oxylabs.io/v1/queries',
                    auth=(username, password),
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                # print(data)
                return data.get('results', [])
            except requests.RequestException as e:
                logger.error(f"Error fetching page {page_number}: {e}")
                return []

        # Fetch data from 4 pages in parallel
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(fetch_page, page) for page in range(1, 8)]
            results = [future.result() for future in futures]

        shopping_data = []
        search_history_entries = []
        def generate_unique_product_id():
            # Generate a UUID and take the integer representation
            unique_id = uuid.uuid4().int
            
            # Convert the integer to a string and take the first 20 digits
            product_id = "NA_" + str(unique_id)[:30]
            
            return product_id

        for page_index, result_set in enumerate(results, start=1):
            logger.info(f"Processing results for page {page_index}")
            for result in result_set:
                organic_results = result.get('content', {}).get('results', {}).get('organic', [])
                for item in organic_results:
                    try:
                        if 'url' in item:
                            item['url'] = "https://www.google.com" + item['url']
                    except Exception as e:
                        logger.error(f"Error parsing URL for item: {e}")
                    try:
                        if 'merchant' in item and 'url' in item['merchant']:
                            item['merchant']['url'] = self.fix_url(item['merchant']['url'])
                    except Exception as e:
                        logger.error(f"Error parsing URL for item: {e}")
                    try:
                        print("THE ITEM IS HERE",item)
                        if 'product_id' not in item or not item['product_id']:
                            print("THE ITEM WITHOUT PRODUCTID IS HERE",item)
                            item['product_id'] = generate_unique_product_id()
                            print("AFTER COrrection THE ITEM WITHOUT PRODUCTID IS HERE",item)
                    except Exception as e:
                        logger.error(f"Error getting product_id for item: {e}")

                    shopping_data.append(item)

                    product_id = item.get('product_id')
                    if product_id is None or product_id == "":
                        logger.error(f"Invalid product_id: {product_id}")
                        continue

                    search_history_entries.append(
                        search_history(
                            query=query,
                            product_id=product_id,
                            google_url=item['url'],
                            seller_name=item['merchant']['name'],
                            seller_url=item['merchant']['url'],
                            price=item['price'],
                            product_title=item['title'],
                            delivery=item['delivery'],
                            currency=item['currency'],
                            rating=item.get('rating'),
                            reviews_count=item.get('reviews_count'),
                            product_pic=item.get('thumbnail')
                        )
                    )

        logger.info(f"Total search_history entries to create: {len(search_history_entries)}")

        with transaction.atomic():
            for entry in search_history_entries:
                try:
                    entry.save()
                except Exception as e:
                    logger.error(f"Error creating search_history entry: {e}")

        logger.info(f"Total products fetched: {len(shopping_data)}")
        return Response({'Message': 'Fetched the Product data Successfully', "Product_data": shopping_data}, status=status.HTTP_200_OK)

    @staticmethod
    def fix_url(encoded_url):
        parsed_url = urlparse(encoded_url)
        query_params = parse_qs(parsed_url.query)
        if 'url' in query_params:
            return query_params['url'][0]
        return encoded_url







# class OxylabSaleView(APIView):
#     def post(self, request):
#         logger = logging.getLogger(__name__)  # Get logger for this module

#         # Log the incoming request details
#         logger.info(f"Received POST request: {request.data}")

#         query = request.data.get("product_name")
#         ppr_min = request.data.get("ppr_min", None)
#         ppr_max = request.data.get("ppr_max", None)
#         sort_by = request.data.get("sort_by", 'relevance')  # Default to 'relevance'

#         if not query:
#             return Response({'Message': 'Please provide query to search'}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             oxy_account = oxylab_account.objects.get(id=1)
#             username = oxy_account.username
#             password = oxy_account.password
#         except oxylab_account.DoesNotExist:
#             return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)

#         query_main = str(query).replace(" ", "+")

#         sort_mapping = {
#             'relevance': 'r',
#             'low_to_high': 'p',
#             'high_to_low': 'pd',
#             'rating': 'rv'
#         }

#         sort_key = sort_mapping.get(sort_by, 'r')  # Default to 'relevance' if sort_by is invalid

#         # Build context dynamically based on provided filters
#         context = [{'key': 'sort_by', 'value': sort_key},{'key': 'tbs', 'value': 'sales:1'}]
        
#         if ppr_min is not None:
#             context.append({'key': 'min_price', 'value': ppr_min})
        
#         if ppr_max is not None:
#             context.append({'key': 'max_price', 'value': ppr_max})

#         def fetch_page(page_number):
#             payload = {
#                 'source': 'google_shopping_search',
#                 'domain': 'co.in',
#                 'query': query_main,
#                 "start_page": page_number,
#                 'pages': 1,
#                 'parse': True,
#                 'locale': 'en',
#                 "geo_location": "India",
#                 'context': context,
#             }
#             try:
#                 response = requests.post(
#                     'https://realtime.oxylabs.io/v1/queries',
#                     auth=(username, password),
#                     json=payload,
#                 )
#                 response.raise_for_status()
#                 data = response.json()
#                 print(data)
#                 return data.get('results', [])
#             except requests.RequestException as e:
#                 logger.error(f"Error fetching page {page_number}: {e}")
#                 return []

#         # Fetch data from 4 pages in parallel
#         with ThreadPoolExecutor(max_workers=4) as executor:
#             futures = [executor.submit(fetch_page, page) for page in range(1, 8)]
#             results = [future.result() for future in futures]

#         shopping_data = []
#         search_history_entries = []

#         for page_index, result_set in enumerate(results, start=1):
#             logger.info(f"Processing results for page {page_index}")
#             for result in result_set:
#                 organic_results = result.get('content', {}).get('results', {}).get('organic', [])
#                 for item in organic_results:
#                     try:
#                         if 'url' in item:
#                             item['url'] = "https://www.google.com" + item['url']
#                     except Exception as e:
#                         logger.error(f"Error parsing URL for item: {e}")

#                     try:
#                         if 'merchant' in item and 'url' in item['merchant']:
#                             item['merchant']['url'] = self.fix_url(item['merchant']['url'])
#                     except Exception as e:
#                         logger.error(f"Error parsing URL for item: {e}")

#                     shopping_data.append(item)

#                     product_id = item.get('product_id')
#                     if product_id is None or product_id == "":
#                         logger.error(f"Invalid product_id: {product_id}")
#                         continue

#                     search_history_entries.append(
#                         search_history(
#                             query=query,
#                             product_id=product_id,
#                             google_url=item['url'],
#                             seller_name=item['merchant']['name'],
#                             seller_url=item['merchant']['url'],
#                             price=item['price'],
#                             product_title=item['title'],
#                             rating=item.get('rating'),
#                             reviews_count=item.get('reviews_count'),
#                             product_pic=item.get('thumbnail')
#                         )
#                     )

#         logger.info(f"Total search_history entries to create: {len(search_history_entries)}")

#         with transaction.atomic():
#             for entry in search_history_entries:
#                 try:
#                     entry.save()
#                 except Exception as e:
#                     logger.error(f"Error creating search_history entry: {e}")

#         logger.info(f"Total products fetched: {len(shopping_data)}")
#         return Response({'Message': 'Fetched the Product data Successfully', "Product_data": shopping_data}, status=status.HTTP_200_OK)

#     @staticmethod
#     def fix_url(encoded_url):
#         parsed_url = urlparse(encoded_url)
#         query_params = parse_qs(parsed_url.query)
#         if 'url' in query_params:
#             return query_params['url'][0]
#         return encoded_url





# import requests, json
from pprint import pprint

class OxylabProductDetailView(APIView):
    def post(self,request):
        logger = logging.getLogger(__name__)  # Get logger for this module

        # Log the incoming request details
        logger.info(f"Received POST request: {request.data}")
        # userid = get_user_id_from_token(request)
        # user = CustomUser.objects.filter(id=userid)

        # if not user:
        #     logger.warning("User not found for userid: %s", userid)
        #     return Response({"Message": "User not Found!!!!"})

        def get_url_data(url):

            # Structure payload.
            payload = {
                'source': 'universal_ecommerce',
                "url" : url,
                'geo_location': 'India',
                'parse': True
            }
            
            # Get response.
            response = requests.request(
                'POST',
                'https://realtime.oxylabs.io/v1/queries',
                auth=(username, password),
                json=payload,timeout=120
            )
            print("Fetched json Succesfully")
            
            
            
            # Instead of response with job status and results url, this will return the
            # JSON response with results.
            # pprint(response.json())
            return response.json()
        

        def get_details(response_data,obj):

            # Product ID
            try:
                product_id = obj.product_id
            except:
                product_id = "not Available"
            # product_image
            try:
                if response_data['results'][0]['content']['image'] is not None:
                    product_image = response_data['results'][0]['content']['image']
                else:
                    product_image = obj.product_image
            except:
                product_image = obj.product_image
            # Product Name
            try:
                if response_data['results'][0]['content']['title'] is not None:
                    product_name = response_data['results'][0]['content']['title']
                else:
                    product_name = obj.title
            except:
                product_name = obj.title
            # Product Price
            try:
                if response_data['results'][0]['content']['price'] is not None:
                    product_price = response_data['results'][0]['content']['price']
                else:
                    product_price = obj.price
            except:
                product_price = obj.price
            # seller Link
            try:
                if response_data['results'][0]['content']['url'] is not None:
                    seller_link = response_data['results'][0]['content']['url']
                else:
                    seller_link = obj.seller_link
            except:
                seller_link = obj.seller_link
            # seller Name
            try:
                if response_data['results'][0]['content']['brand'] is not None:
                    seller_name = response_data['results'][0]['content']['brand']
                else:
                    seller_name = obj.seller_name
            except:
                seller_name = obj.seller_name
            # Google Shooping Link
            try:
                google_shopping_link = response_data['results'][0]['content']['url']
            except:
                google_shopping_link = "not Available"
            try:
                description = response_data['results'][0]['content']['description']
            except:
                description = "not Available"
            try:
                parse_status_code = response_data['results'][0]['content']['parse_status_code']
            except:
                parse_status_code ="not Available"


            tmp = {
                "url": seller_link,
                "title": product_name,
                "images": {
                    "full_size": [
                        product_image
                    ],
                    "thumbnails": []
                },
                "pricing": {
                    "online": [
                        {
                            "price": product_price,
                            "seller": seller_name,
                            "details": None,
                            "currency": "₹",
                            "condition": "New",
                            "price_total": product_price,
                            "seller_link": seller_link,
                            "price_shipping": 0
                        }
                    ]
                },
                "variants": None,
                "description": description,
                "related_items": None,
                # "title": "You might also like",
                "parse_status_code": parse_status_code
            }

            
            return tmp

        url_link = request.data.get("url_link")

        product_id = request.data.get("product_id")

        if not product_id and not url_link:
            return Response({'Message': 'Please provide product_id or url_link to search'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            oxy_account = oxylab_account.objects.get(id=1)
            username = oxy_account.username
            password = oxy_account.password
        except oxylab_account.DoesNotExist:
            return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)

        if str(product_id).startswith("NA_"):
            try:
                obj = prodid_mapping.objects.filter(product_id=product_id).first()
                try:
                    res = get_url_data(obj.seller_link)
                except:
                    print("Not able to get data from Url link")
                    res = {}
                res_all = get_details(res,obj)
                print(res_all)
                print("Before")
                if res_all['pricing']['online'][0]['seller_link'] =="":
                    logger.error(f'Unable to fetch the Product detail: {str(e)}')
                    return Response({'Message': f'Unable to fetch the Product detail: {str(e)}'}, status=status.HTTP_404_NOT_FOUND)
                print(res_all)
                print("After")
                return Response({'Message': 'Fetch the Product detail Successfully', "Product_detail": res_all}, status=status.HTTP_200_OK)
            except Exception as e:
                logger.error(f'Unable to fetch the Product detail: {str(e)}')
                return Response({'Message': f'Unable to fetch the Product detail: {str(e)}'}, status=status.HTTP_404_NOT_FOUND)

        
        else:
            # Structure payload.
            payload = {
                'source': 'google_shopping_product',
                'domain': 'co.in',
                'query': product_id, # Product ID
                'parse': True,
                'locale': 'en',
                "geo_location": "India",
                "results_language":"English"
            }

            try:

                # Get response.
                response = requests.request(
                    'POST',
                    'https://realtime.oxylabs.io/v1/queries',
                    auth=(username, password),
                    json=payload,
                )
                
                data =response.json()#['results'][0]['content']

                # print(data)

                # URL prefix to prepend
                url_prefix = 'https://www.google.com'

                def get_final_url(original_url):
                    response = requests.get(original_url, allow_redirects=True, timeout=3)
                    return response.url

                def filter_merchants(shopping_data):
                    # url_list = [
                    #     "amazon", "flipkart", "snapdeal", "myntra", "ajio", "paytmmall", "tatacliq", 
                    #     "shopclues", "pepperfry", "nykaa", "limeroad", "faballey", "zivame", "koovs", 
                    #     "clovia", "biba", "wforwoman", "bewakoof", "urbanladder", "croma", "reliancedigital", 
                    #     "vijaysales", "gadgets360", "poorvikamobile", "samsung", "oneplus", "mi", "dell", 
                    #     "apple", "bigbasket", "blinkit", "jiomart", "dunzo", "spencers", "naturesbasket", 
                    #     "zopnow", "shop", "starquik", "fabindia", "hometown", "woodenstreet", "thedecorkart", 
                    #     "chumbak", "livspace", "thesleepcompany", "firstcry", "healthkart", "netmeds", 
                    #     "1mg", "lenskart", "tanishq", "bluestone", "caratlane", "purplle", "crossword", 
                    #     "sapnaonline", "booksadda", "bookchor", "a1books", "scholastic", "headsupfortails", 
                    #     "petsworld", "dogspot", "petshop18", "pawsindia", "marshallspetzone", "petsglam", 
                    #     "petsy", "petnest", "justdogsstore", "infibeam", "shoppersstop", "craftsvilla", 
                    #     "naaptol", "saholic", "homeshop18", "futurebazaar", "ritukumar", "thelabellife", 
                    #     "andindia", "globaldesi", "sutastore", "nykaafashion", "jaypore", "amantelingerie", 
                    #     "happimobiles", "electronicscomp", "jio", "unboxindia", "gadgetbridge", "vlebazaar", 
                    #     "dmart", "supermart", "reliancefresh", "houseofpataudi", "ikea", "zarahome", 
                    #     "indigoliving", "goodearth", "westside", "godrejinterio", "fabfurnish", "pcjeweller", 
                    #     "kalyanjewellers", "candere", "voylla", "orra", "sencogoldanddiamonds", "bookishsanta", 
                    #     "pustakmandi", "wordery", "starmark", "bargainbooks", "bookdepository", "worldofbooks", 
                    #     "bookswagon", "kitabay", "pupkart", "whiskas", "petshop", "barksandmeows", 
                    #     "petophilia", "waggle", "themancompany", "beardo", "mamaearth", "plumgoodness", 
                    #     "buywow", "ustraa", "myglamm", "bombayshavingcompany", "khadinatural", "zomato", 
                    #     "swiggy", "freshmenu", "box8", "faasos", "dineout", "rebelfoods", "behrouzbiryani", 
                    #     "dominos", "pizzahut", "makemytrip", "goibibo", "yatra", "cleartrip", "oyorooms", 
                    #     "airbnb", "trivago", "booking", "agoda", "expedia", "urbanclap", "housejoy", 
                    #     "jeeves", "onsitego", "homecentre", "rentomojo", "furlenco", "nestaway", "tata"
                    # ]

                    try:
                        urls_ = URL_List.objects.values_list('name', flat=True)
                        url_list = list(urls_)
                    except URL_List.DoesNotExist:
                        print({'Message': f'Unable to Find URL List result'}) 
                        url_list=[]

                    try:
                        # Remove duplicates from the URL list
                        url_list = list(set(url_list))

                        # Convert URL list to lowercase for case-insensitive comparison
                        url_list = [url.lower() for url in url_list]

                        # Function to normalize the merchant name
                        def normalize_name(name):
                            # Remove domain extensions and symbols
                            name = re.sub(r'\.(com|in|org|net|co)\b', '', name, flags=re.IGNORECASE)
                            # name = re.sub(r'\W+', '', name)  # Remove all non-alphanumeric characters
                            return name.lower()
                        
                        # Check if any normalized merchant name is in the URL list
                        return any(
                            normalize_name(merchant.get('seller', '')) in url_list for merchant in shopping_data
                        )

                    except Exception as e:
                        print(f'Error: {str(e)}')
                        return False




                # Update seller links
                seller_lst = []
                if 'pricing' in data['results'][0]['content'] and 'online' in data['results'][0]['content']['pricing']:
                    # if data['results'][0]['content']['pricing']['online'] ==[]:
                    #     # Return a response indicating no pricing information was found
                    #     print("data['results'][0]['content']['pricing']['online']---------->",data['results'][0]['content']['pricing']['online'])
                    #     return Response({'Message': 'No pricing information found.'}, status=status.HTTP_404_NOT_FOUND)
                    for seller_info in data['results'][0]['content']['pricing']['online']: # -----> passed on fail  ---> 200 website check ---> Continue
                        # if "seller_link" not in seller_info or seller_info["seller_link"] == "":
                        #     logger.error(f'Unable to fetch the Product detail: {str(e)}')
                        #     # return Response({'Message': f'Unable to fetch the Product detail: {str(e)}'}, status=status.HTTP_404_NOT_FOUND)
                        #     del seller_info
                        #     continue
                        if filter_merchants([seller_info]) == False:
                            print("Falied Seller Type",seller_info)
                        else:
                            print("Passed Seller Type",seller_info)
                            seller_link = seller_info.get('seller_link')
                            if seller_link and seller_link.startswith('/'):
                                link_seller = url_prefix + seller_link
                                try:
                                    seller_info['seller_link'] = get_final_url(link_seller)
                                except:
                                    seller_info['seller_link'] = link_seller
                                seller_lst.append(seller_info)
                data['results'][0]['content']['pricing']['online'] = seller_lst
                                # get_final_url(link_seller)

                # Update review URLs for 1, 3, 4, and 5 stars
                if 'reviews' in data['results'][0]['content'] and 'reviews_by_stars' in data['results'][0]['content']['reviews']:
                    for rating in ['1', '3', '4', '5']:
                        reviews_data = data['results'][0]['content']['reviews']['reviews_by_stars'].get(rating)
                        if reviews_data:
                            review_url = reviews_data.get('url')
                            if review_url and review_url.startswith('/'):
                                reviews_data['url'] = url_prefix + review_url

                def extract_product_id(url):
                    # Define a regular expression pattern to match the product ID
                    pattern = r'/shopping/product/(\d+)'
                    # Use re.search to find the product ID
                    match = re.search(pattern, url)
                    if match:
                        return match.group(1)  # Return the product ID
                    else:
                        return None


                if 'related_items' in data['results'][0]['content']:
                    related_items = data['results'][0]['content']['related_items']
                    if related_items and isinstance(related_items, list):
                        updated_items = []
                        for seller_info in related_items[0]['items']:
                            seller_link = seller_info.get('url')
                            if seller_link and seller_link.startswith('/'):
                                seller_info['url'] = url_prefix + seller_link
                                seller_info['product_id'] = extract_product_id(seller_link)
                                del seller_info['url']
                                # Add to the list if product_id is not '1'
                                if seller_info['product_id'] != '1':
                                    updated_items.append(seller_info)
                        # Replace old list with updated list
                        related_items[0]['items'] = updated_items
                            # del seller_info['url']

                # Convert the updated data back to JSON format if needed
                # updated_json = json.dumps(data, indent=2,ensure_ascii=False)

                # Print prettified response to stdout.
                pprint(data)
                try:
                    # data = response.json()
                    prod_data = data['results'][0]['content']

                    if prod_data ['parse_status_code'] == 12009:    
                        return Response({'Message': 'Unable to fetch the Product detail'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                    # print(data)
                    # logger.debug(f"Received API response: {prod_data}")

                    return Response({'Message': 'Fetch the Product detail Successfully', "Product_detail": prod_data}, status=status.HTTP_200_OK)
                except Exception as e:
                    logger.error(f'Unable to fetch the Product detail: {str(e)}')
                    return Response({'Message': f'Unable to fetch the Product detail: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except Exception as e:
                    logger.error(f'Unable to fetch the Product detail: {str(e)}')
                    return Response({'Message': f'Unable to fetch the Product detail: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class AddtoCartView(APIView):
    def post(self,request):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()    

        if not user:
            # logger.warning("User not found for userid: %s", userid)
            return Response({"Message": "User not Found!!!!"})

        products_id = request.data.get('product_id')

        url_link = request.data.get('seller_link')

        def get_url_data(url):
            try:
                oxy_account = oxylab_account.objects.get(id=1)
                username = oxy_account.username
                password = oxy_account.password
            except oxylab_account.DoesNotExist:
                return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)

            # Structure payload.
            payload = {
                'source': 'universal_ecommerce',
                "url" : url,
                'geo_location': 'India',
                'parse': True
            }
            
            # Get response.
            response = requests.request(
                'POST',
                'https://realtime.oxylabs.io/v1/queries',
                auth=(username, password),
                json=payload,timeout=120
            )
            print("Fetched json Succesfully")
            
            return response.json()


        def get_details2(response_data,obj):

            # Product ID
            try:
                product_id = obj.product_id
            except:
                product_id = "not Available"
            # product_image
            try:
                if response_data['results'][0]['content']['image'] is not None:
                    product_image = response_data['results'][0]['content']['image']
                else:
                    product_image = obj.product_image
            except:
                product_image = obj.product_image
            # Product Name
            try:
                if response_data['results'][0]['content']['title'] is not None:
                    product_name = response_data['results'][0]['content']['title']
                else:
                    product_name = obj.title
            except:
                product_name = obj.title
            # Product Price
            try:
                if response_data['results'][0]['content']['price'] is not None:
                    product_price = response_data['results'][0]['content']['price']
                else:
                    product_price = obj.price
            except:
                product_price = obj.price
            # seller Link
            try:
                if response_data['results'][0]['content']['url'] is not None:
                    seller_link = response_data['results'][0]['content']['url']
                else:
                    seller_link = obj.seller_link
            except:
                seller_link = obj.seller_link
            # seller Name
            try:
                if response_data['results'][0]['content']['brand'] is not None:
                    seller_name = response_data['results'][0]['content']['brand']
                else:
                    seller_name = obj.seller_name
            except:
                seller_name = obj.seller_name
            # Google Shooping Link
            try:
                google_shopping_link = response_data['results'][0]['content']['url']
            except:
                google_shopping_link = "not Available"
            try:
                description = response_data['results'][0]['content']['description']
            except:
                description = "not Available"
            try:
                parse_status_code = response_data['results'][0]['content']['parse_status_code']
            except:
                parse_status_code ="not Available"
            return product_id, product_image, product_name, product_price, seller_link, seller_name, google_shopping_link

#==================================================== Add to cart Via Seller Link ==============================================
        
        def get_details(response_data):
            def generate_unique_product_id():
                # Generate a UUID and take the integer representation
                unique_id = uuid.uuid4().int
                
                # Convert the integer to a string and take the first 20 digits
                product_id = "NA_" + str(unique_id)[:30]
                
                return product_id
            

            # Product ID
            try:
                product_id = generate_unique_product_id()
            except:
                product_id = "not Available"
            # product_image
            try:
                product_image = response_data['results'][0]['content']['image']
            except:
                product_image = "not Available"
            # Product Name
            try:
                product_name = response_data['results'][0]['content']['title']
            except:
                product_name = "not Available"
            # Product Price
            try:
                product_price = response_data['results'][0]['content']['price']
            except:
                product_price = 0.0
            # seller Link
            try:
                seller_link = response_data['results'][0]['content']['url']
            except:
                seller_link = "not Available"
            # seller Name
            try:
                seller_name = response_data['results'][0]['content']['brand']
            except:
                seller_name = "not Available"
            # Google Shooping Link
            try:
                google_shopping_link = response_data['results'][0]['content']['url']
            except:
                google_shopping_link = "not Available"
            try:
                description = response_data['results'][0]['content']['description']
            except:
                description = "not Available"
            try:
                parse_status_code = response_data['results'][0]['content']['parse_status_code']
            except:
                parse_status_code ="not Available"
            
            return product_id, product_image, product_name, product_price, seller_link, seller_name, google_shopping_link
        
    
        if url_link:
            try:
                data_res = get_url_data(url_link) # NEW CODE UNIVERSAL SCRAPER
            except:
                return Response({"Message":"Unable to fetch details of product"},status=status.HTTP_404_NOT_FOUND)
            try:
                if data_res['message'] == "Your provided google shopping url is not supported":
                    return Response({"Message":"The given seller link is not valid"})
            except:
                pass
            
            product_id, product_image, product_name, product_price, seller_link, seller_name, google_shopping_link = get_details(data_res) # NEW CODE UNIVERSAL SCRAPER

            print(type(user),user)
            # print(type(quantity),quantity)
            print(type(product_id),product_id)
            print(type(google_shopping_link),google_shopping_link)
            print(type(product_name),product_name)
            print(type(product_image),product_image)
            print(type(product_price),product_price)
            print(type(seller_link),seller_link)
            print(type(seller_name),seller_name)

            try:

                cart.objects.create(
                user= user,
                # quantity = quantity, # IT SHOULD NOT BE ADDED TO CART AS WE DONT HAVE ACCESS TO SELLER WEBSITE WE ONLY AHVE LINK
                product_id = product_id,
                google_shopping_url = google_shopping_link,
                product_name = product_name,
                product_image = product_image,
                price = product_price,
                seller_link = seller_link,
                seller_name = seller_name
                )

                return Response({"Message":"Product added to cart"},status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({"Message":f"Failed to add product to cart: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)




#==================================================== Add to cart Via Seller Link ==============================================

        if not products_id or not request.data.get('product_id'):
            return Response({"Message":"Product not Found!!!"},status=status.HTTP_400_BAD_REQUEST)

        if str(products_id).startswith("NA_"):
            try:
                obj = prodid_mapping.objects.filter(product_id=products_id).first()
                try:
                    print("i am here")
                    res = get_url_data(obj.seller_link)
                    print("i was here")
                    print(res)
                except:
                    print("Not able to get data from Url link")
                    res = {}
                product_id, product_image, product_name, product_price, seller_link, seller_name, google_shopping_link = get_details2(res,obj)
                
                try:

                    cart.objects.create(
                    user= user,
                    # quantity = quantity, # IT SHOULD NOT BE ADDED TO CART AS WE DONT HAVE ACCESS TO SELLER WEBSITE WE ONLY AHVE LINK
                    product_id = product_id,
                    google_shopping_url = google_shopping_link,
                    product_name = product_name,
                    product_image = product_image,
                    price = product_price,
                    seller_link = seller_link,
                    seller_name = seller_name
                    )

                    return Response({"Message":"Product added to cart"},status=status.HTTP_201_CREATED)
                except Exception as e:
                    return Response({"Message":f"Failed to add product to cart: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)

            except Exception as e:
                logger.error(f'Unable to fetch the Product detail: {str(e)}')
                return Response({'Message': f'Unable to fetch the Product detail: {str(e)}'}, status=status.HTTP_404_NOT_FOUND)

        else:

            try:
                oxy_account = oxylab_account.objects.get(id=1)
                username = oxy_account.username
                password = oxy_account.password
            except oxylab_account.DoesNotExist:
                return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)



            payload = {
                'source': 'google_shopping_product',
                'domain': 'co.in',
                'query': products_id, # Product ID
                'parse': True,
                'locale': 'en'
            }

            try:

                # Get response.
                response = requests.request(
                    'POST',
                    'https://realtime.oxylabs.io/v1/queries',
                    auth=(username, password),
                    json=payload,
                )
                
                data =response.json()#['results'][0]['content']

                # print(data)
                def get_final_url(original_url):
                    response = requests.get(original_url, allow_redirects=True,timeout=5)
                    return response.url

                # URL prefix to prepend
                url_prefix = 'https://www.google.com'

                # Update seller links
                if 'pricing' in data['results'][0]['content'] and 'online' in data['results'][0]['content']['pricing']:
                    for seller_info in data['results'][0]['content']['pricing']['online']:
                        seller_link = seller_info.get('seller_link')
                        if seller_link and seller_link.startswith('/'):
                            link_seller = url_prefix + seller_link
                            seller_info['seller_link'] = get_final_url(link_seller)
                            # seller_info['seller_link'] = str(seller_link).replace("/url?q=",'')#url_prefix + seller_link

                # Update review URLs for 1, 3, 4, and 5 stars
                if 'reviews' in data['results'][0]['content'] and 'reviews_by_stars' in data['results'][0]['content']['reviews']:
                    for rating in ['1', '3', '4', '5']:
                        reviews_data = data['results'][0]['content']['reviews']['reviews_by_stars'].get(rating)
                        if reviews_data:
                            review_url = reviews_data.get('url')
                            if review_url and review_url.startswith('/'):
                                reviews_data['url'] = url_prefix + review_url

                # pprint(data)
                response_data = data['results'][0]['content']
                # response_data = data
            except Exception as e:
                    return Response({'Message': f'Unable to fetch the Product detail: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            print("Product data fetched Succesfully")

            try:
                quantity = request.data.get("quantity",1)
                # product_id = products_id
                google_shopping_url = response_data['url']
                product_name = response_data['title']
                product_image = response_data['images']['full_size'][0]
                price = response_data['pricing']['online'][0]['price']
                seller_link = response_data['pricing']['online'][0]['seller_link']
                # seller_logo = data['url']
                seller_name = response_data['pricing']['online'][0]['seller']
            except Exception as e:
                return Response({"Message":f"Error Occured: {str(e)}"})
            
            print("Product details fetched Succesfully")

            print(type(user),user)
            print(type(quantity),quantity)
            print(type(products_id),products_id)
            print(type(google_shopping_url),google_shopping_url)
            print(type(product_name),product_name)
            print(type(product_image),product_image)
            print(type(price),price)
            print(type(seller_link),seller_link)
            print(type(seller_name),seller_name)

            try:

                cart.objects.create(
                user= user,
                quantity = quantity, # IT SHOULD NOT BE ADDED TO CART AS WE DONT HAVE ACCESS TO SELLER WEBSITE WE ONLY AHVE LINK
                product_id = products_id,
                google_shopping_url = google_shopping_url,
                product_name = product_name,
                product_image = product_image,
                price = price,
                seller_link = seller_link,
                seller_name = seller_name
                )

                return Response({"Message":"Product added to cart"},status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({"Message":f"Failed to add product to cart: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)
        

class DeletefromCartView(APIView):
    def post(self,request):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()    

        if not user:
            # logger.warning("User not found for userid: %s", userid)
            return Response({"Message": "User not Found!!!!"})
        

        cart_id = request.data.get("cart_id")

        if not cart_id or not request.data.get("cart_id"):
            return Response({"Message": "Cart id not Found!!!!"})

        # try:

            # kart = cart.objects.get(
            # user= user,
            # id = cart_id
            # )
            # if not kart:
            #     return Response({"Message":"cart not found"},status=status.HTTP_404_NOT_FOUND)

            # kart.delete()

        try:
            kart = cart.objects.get(user=user, id=cart_id)
            kart.delete()
            return Response({"Message": "Product removed from cart"}, status=status.HTTP_204_NO_CONTENT)

        except ObjectDoesNotExist:
            return Response({"Message": "Cart item not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"Message":f"Failed to remove Cart item: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)
        

class UpdateproductCartView(APIView):
    def post(self,request):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()    

        if not user:
            # logger.warning("User not found for userid: %s", userid)
            return Response({"Message": "User not Found!!!!"})
        

        cart_id = request.data.get("cart_id")

        if not cart_id or not request.data.get("cart_id"):
            return Response({"Message": "Cart id not Found!!!!"})
        
        quantity = request.data.get("quantity")

        if not quantity or not request.data.get("quantity"):
            return Response({"Message": "quantity not Found!!!!"})

        try:

            kart = cart.objects.get(
            user= user,
            id = cart_id
            )

            # if not kart:
            #     return Response({"Message":"Cart item not found"},status=status.HTTP_404_NOT_FOUND)

            kart.quantity = quantity

            kart.save()
            return Response({"Message":"Cart item Updated Succesfully"},status=status.HTTP_201_CREATED)
        except ObjectDoesNotExist:
            return Response({"Message": "Cart item not found"}, status=status.HTTP_404_NOT_FOUND)
        except:
            return Response({"Message":"Failed to update Cart item"},status=status.HTTP_400_BAD_REQUEST)
        


class Addtosaveforlater(APIView):
    def post(self,request):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()    

        if not user:
            return Response({"Message": "User not Found!!!!"})
        

        cart_id = request.data.get("cart_id")

        products_id = request.data.get('product_id') 

        url_link = request.data.get('seller_link')

        def get_details2(response_data,obj):

            # Product ID
            try:
                product_id = obj.product_id
            except:
                product_id = "not Available"
            # product_image
            try:
                if response_data['results'][0]['content']['image'] is not None:
                    product_image = response_data['results'][0]['content']['image']
                else:
                    product_image = obj.product_image
            except:
                product_image = obj.product_image
            # Product Name
            try:
                if response_data['results'][0]['content']['title'] is not None:
                    product_name = response_data['results'][0]['content']['title']
                else:
                    product_name = obj.title
            except:
                product_name = obj.title
            # Product Price
            try:
                if response_data['results'][0]['content']['price'] is not None:
                    product_price = response_data['results'][0]['content']['price']
                else:
                    product_price = obj.price
            except:
                product_price = obj.price
            # seller Link
            try:
                if response_data['results'][0]['content']['url'] is not None:
                    seller_link = response_data['results'][0]['content']['url']
                else:
                    seller_link = obj.seller_link
            except:
                seller_link = obj.seller_link
            # seller Name
            try:
                if response_data['results'][0]['content']['brand'] is not None:
                    seller_name = response_data['results'][0]['content']['brand']
                else:
                    seller_name = obj.seller_name
            except:
                seller_name = obj.seller_name
            # Google Shooping Link
            try:
                google_shopping_link = response_data['results'][0]['content']['url']
            except:
                google_shopping_link = "not Available"
            try:
                description = response_data['results'][0]['content']['description']
            except:
                description = "not Available"
            try:
                parse_status_code = response_data['results'][0]['content']['parse_status_code']
            except:
                parse_status_code ="not Available"
            return product_id, product_image, product_name, product_price, seller_link, seller_name, google_shopping_link
#==================================================== Add to cart Via Seller Link ==============================================
        def get_url_data(url):
            try:
                oxy_account = oxylab_account.objects.get(id=1)
                username = oxy_account.username
                password = oxy_account.password
            except oxylab_account.DoesNotExist:
                return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)

            # Structure payload.
            payload = {
                'source': 'universal_ecommerce',
                "url" : url,
                'geo_location': 'India',
                'parse': True
            }
            
            # Get response.
            response = requests.request(
                'POST',
                'https://realtime.oxylabs.io/v1/queries',
                auth=(username, password),
                json=payload,timeout=120
            )
            print("Fetched json Succesfully")
            
            
            
            # Instead of response with job status and results url, this will return the
            # JSON response with results.
            # pprint(response.json())
            return response.json()
        

        def get_details(response_data):
            def generate_unique_product_id():
                # Generate a UUID and take the integer representation
                unique_id = uuid.uuid4().int
                
                # Convert the integer to a string and take the first 20 digits
                product_id = "NA_" + str(unique_id)[:30]
                
                return product_id
            

            # Product ID
            try:
                product_id = generate_unique_product_id()
            except:
                product_id = "not Available"
            # product_image
            try:
                product_image = response_data['results'][0]['content']['image']
            except:
                product_image = "not Available"
            # Product Name
            try:
                product_name = response_data['results'][0]['content']['title']
            except:
                product_name = "not Available"
            # Product Price
            try:
                product_price = response_data['results'][0]['content']['price']
            except:
                product_price = 0.0
            # seller Link
            try:
                seller_link = response_data['results'][0]['content']['url']
            except:
                seller_link = "not Available"
            # seller Name
            try:
                seller_name = response_data['results'][0]['content']['brand']
            except:
                seller_name = "not Available"
            # Google Shooping Link
            try:
                google_shopping_link = response_data['results'][0]['content']['url']
            except:
                google_shopping_link = "not Available"
            try:
                description = response_data['results'][0]['content']['description']
            except:
                description = "not Available"
            try:
                parse_status_code = response_data['results'][0]['content']['parse_status_code']
            except:
                parse_status_code ="not Available"
            
            return product_id, product_image, product_name, product_price, seller_link, seller_name, google_shopping_link
        
    
        if url_link:
            try:
                data_res = get_url_data(url_link) # NEW CODE UNIVERSAL SCRAPER
            except:
                return Response({"Message":"Unable to fetch details of product"},status=status.HTTP_404_NOT_FOUND)
            try:
                if data_res['message'] == "Your provided google shopping url is not supported":
                    return Response({"Message":"The given seller link is not valid"})
            except:
                pass
            
            product_id, product_image, product_name, product_price, seller_link, seller_name, google_shopping_link = get_details(data_res) # NEW CODE UNIVERSAL SCRAPER

            print(type(user),user)
            # print(type(quantity),quantity)
            print(type(product_id),product_id)
            print(type(google_shopping_link),google_shopping_link)
            print(type(product_name),product_name)
            print(type(product_image),product_image)
            print(type(product_price),product_price)
            print(type(seller_link),seller_link)
            print(type(seller_name),seller_name)

            try:

                saveforlater.objects.create(
                user= user,
                # quantity = quantity, # IT SHOULD NOT BE ADDED TO CART AS WE DONT HAVE ACCESS TO SELLER WEBSITE WE ONLY AHVE LINK
                product_id = product_id,
                google_shopping_url = google_shopping_link,
                product_name = product_name,
                product_image = product_image,
                price = product_price,
                seller_link = seller_link,
                seller_name = seller_name

                )
                return Response({"Message": "Product has been Saved For Later"}, status=status.HTTP_204_NO_CONTENT)

            except ObjectDoesNotExist:
                return Response({"Message": "Cart item not found"}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({"Message":f"Failed to move product to Saved For Later: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)




            # try:

            #     cart.objects.create(
            #     user= user,
            #     # quantity = quantity, # IT SHOULD NOT BE ADDED TO CART AS WE DONT HAVE ACCESS TO SELLER WEBSITE WE ONLY AHVE LINK
            #     product_id = product_id,
            #     google_shopping_url = google_shopping_link,
            #     product_name = product_name,
            #     product_image = product_image,
            #     price = product_price,
            #     seller_link = seller_link,
            #     seller_name = seller_name
            #     )

            #     return Response({"Message":"Product added to cart"},status=status.HTTP_201_CREATED)
            # except Exception as e:
            #     return Response({"Message":f"Failed to add product to cart: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)




#==================================================== Add to cart Via Seller Link ==============================================

        if not cart_id and not products_id:
            return Response({"Message": "Please Provide Product_id or Cart id!!!!"})
        
        if cart_id:

            try:
                # get the cart object
                kart = cart.objects.get(user=user, id=cart_id)

                # Create the saveforlater object with fields from cart
                save_for_later_data = {
                    'user': user,
                    'product_id': kart.product_id,
                    'quantity': kart.quantity,
                    'product_name': kart.product_name,
                    'product_image': kart.product_image,
                    'price': kart.price,
                    'google_shopping_url': kart.google_shopping_url,
                    'seller_link': kart.seller_link,
                    'seller_logo': kart.seller_logo,
                    'seller_name': kart.seller_name
                }

                # Create saveforlater object
                saveforlater.objects.create(**save_for_later_data)


                # Create the saveforlater object
                # saveforlater.objects.create(kart)
                # delete the cart object
                kart.delete()
                return Response({"Message": "Product has been Saved For Later"}, status=status.HTTP_204_NO_CONTENT)
            except ObjectDoesNotExist:
                return Response({"Message": "Cart item not found"}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({"Message":f"Failed to move product to Saved For Later: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)
            
        else: # Means Product Id is provide and not cart id
            if str(products_id).startswith("NA_"):
                try:
                    obj = prodid_mapping.objects.filter(product_id=products_id).first()
                    try:
                        print("i am here")
                        res = get_url_data(obj.seller_link)
                        print("i was here")
                        print(res)
                    except:
                        print("Not able to get data from Url link")
                        res = {}
                    product_id, product_image, product_name, product_price, seller_link, seller_name, google_shopping_link = get_details2(res,obj)
                    
                    try:

                        saveforlater.objects.create(
                        user= user,
                        # quantity = quantity, # IT SHOULD NOT BE ADDED TO CART AS WE DONT HAVE ACCESS TO SELLER WEBSITE WE ONLY AHVE LINK
                        product_id = product_id,
                        google_shopping_url = google_shopping_link,
                        product_name = product_name,
                        product_image = product_image,
                        price = product_price,
                        seller_link = seller_link,
                        seller_name = seller_name
                        )

                        return Response({"Message":"Product added to Save Later"},status=status.HTTP_201_CREATED)
                    except Exception as e:
                        return Response({"Message":f"Failed to add product to Save Later: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)

                except Exception as e:
                    logger.error(f'Unable to fetch the Product detail: {str(e)}')
                    return Response({'Message': f'Unable to fetch the Product detail: {str(e)}'}, status=status.HTTP_404_NOT_FOUND)


            else:
                # if not products_id or not request.data.get('product_id'):
                #     return Response({"Message":"Product not Found!!!"},status=status.HTTP_400_BAD_REQUEST)

                try:
                    oxy_account = oxylab_account.objects.get(id=1)
                    username = oxy_account.username
                    password = oxy_account.password
                except oxylab_account.DoesNotExist:
                    return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)


                payload = {
                    'source': 'google_shopping_product',
                    'domain': 'co.in',
                    'query': products_id, # Product ID
                    'parse': True,
                    'locale': 'en'
                }

                try:

                    # Get response.
                    response = requests.request(
                        'POST',
                        'https://realtime.oxylabs.io/v1/queries',
                        auth=(username, password),
                        json=payload,
                    )
                    
                    data =response.json()#['results'][0]['content']

                    # print(data)

                    def get_final_url(original_url):
                        response = requests.get(original_url, allow_redirects=True,timeout=5)
                        return response.url

                    # URL prefix to prepend
                    url_prefix = 'https://www.google.com'

                    # Update seller links
                    if 'pricing' in data['results'][0]['content'] and 'online' in data['results'][0]['content']['pricing']:
                        for seller_info in data['results'][0]['content']['pricing']['online']:
                            seller_link = seller_info.get('seller_link')
                            if seller_link and seller_link.startswith('/'):
                                link_seller = url_prefix + seller_link
                                seller_info['seller_link'] = get_final_url(link_seller)
                                # seller_info['seller_link'] = str(seller_link).replace("/url?q=",'')#url_prefix + seller_link

                    # Update review URLs for 1, 3, 4, and 5 stars
                    if 'reviews' in data['results'][0]['content'] and 'reviews_by_stars' in data['results'][0]['content']['reviews']:
                        for rating in ['1', '3', '4', '5']:
                            reviews_data = data['results'][0]['content']['reviews']['reviews_by_stars'].get(rating)
                            if reviews_data:
                                review_url = reviews_data.get('url')
                                if review_url and review_url.startswith('/'):
                                    reviews_data['url'] = url_prefix + review_url

                    # pprint(data)
                    response_data = data['results'][0]['content']
                    # response_data = data
                except Exception as e:
                        return Response({'Message': f'Unable to fetch the Product detail: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

                print("Product data fetched Succesfully")

                try:
                    quantity = request.data.get("quantity",1)
                    # product_id = products_id
                    google_shopping_url = response_data['url']
                    product_name = response_data['title']
                    product_image = response_data['images']['full_size'][0]
                    price = response_data['pricing']['online'][0]['price']
                    seller_link = response_data['pricing']['online'][0]['seller_link']
                    # seller_logo = data['url']
                    seller_name = response_data['pricing']['online'][0]['seller']
                except Exception as e:
                    return Response({"Message":f"Error Occured: {str(e)}"})
                
                print("Product details fetched Succesfully")

                try:

                    saveforlater.objects.create(
                    user= user,
                    quantity = quantity, # IT SHOULD NOT BE ADDED TO CART AS WE DONT HAVE ACCESS TO SELLER WEBSITE WE ONLY AHVE LINK
                    product_id = products_id,
                    google_shopping_url = google_shopping_url,
                    product_name = product_name,
                    product_image = product_image,
                    price = price,
                    seller_link = seller_link,
                    seller_name = seller_name
                    )
                    return Response({"Message": "Product has been Saved For Later"}, status=status.HTTP_204_NO_CONTENT)

                except ObjectDoesNotExist:
                    return Response({"Message": "Cart item not found"}, status=status.HTTP_404_NOT_FOUND)
                except Exception as e:
                    return Response({"Message":f"Failed to move product to Saved For Later: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)




        #     return Response({"Message": "Product has been Saved For Later"}, status=status.HTTP_204_NO_CONTENT)

        # except ObjectDoesNotExist:
        #     return Response({"Message": "Cart item not found"}, status=status.HTTP_404_NOT_FOUND)
        # except Exception as e:
        #     return Response({"Message":f"Failed to move product to Saved For Later: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)



class Deletefromsaveforlater(APIView):
    def post(self,request):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()    

        if not user:
            return Response({"Message": "User not Found!!!!"})
        
        savelater_id = request.data.get("savelater_id")
        products_id = request.data.get('product_id')

        if not savelater_id and not products_id:
            return Response({"Message": "Please provide savelater id or product id!!!!"})
        
        if savelater_id:

            try:
                item = saveforlater.objects.get(user=user, id=savelater_id)
                item.delete()
                return Response({"Message": "Product removed from Save for later"}, status=status.HTTP_204_NO_CONTENT)

            except ObjectDoesNotExist:
                return Response({"Message": "Save for later item not found"}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({"Message":f"Failed to remove item from Save for later: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)
        
        if products_id:

            try:
                item = saveforlater.objects.filter(user=user, product_id=products_id).first()
                item.delete()
                return Response({"Message": "Product removed from Save for later"}, status=status.HTTP_204_NO_CONTENT)

            except ObjectDoesNotExist:
                return Response({"Message": "Save for later item not found"}, status=status.HTTP_404_NOT_FOUND)
            except Exception as e:
                return Response({"Message":f"Failed to remove item from Save for later: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)


class MovetoCartfromsaveforlater(APIView):
    def post(self,request):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()    

        if not user:
            return Response({"Message": "User not Found!!!!"})
        

        savelater_id = request.data.get("savelater_id")

        if not savelater_id or not request.data.get("savelater_id"):
            return Response({"Message": "savelater id not Found!!!!"})

        try:
            # get the cart object
            save_for_later = saveforlater.objects.get(user=user, id=savelater_id)

            # Create the saveforlater object with fields from cart
            kart = {
                'user': user,
                'product_id': save_for_later.product_id,
                'quantity': save_for_later.quantity,
                'product_name': save_for_later.product_name,
                'product_image': save_for_later.product_image,
                'price': save_for_later.price,
                'google_shopping_url': save_for_later.google_shopping_url,
                'seller_link': save_for_later.seller_link,
                'seller_logo': save_for_later.seller_logo,
                'seller_name': save_for_later.seller_name
            }

            # Create saveforlater object
            cart.objects.create(**kart)


            # Create the saveforlater object
            # saveforlater.objects.create(kart)
            # delete the cart object
            save_for_later.delete()
            return Response({"Message": "Product Moved to Cart Successfully"}, status=status.HTTP_204_NO_CONTENT)

        except ObjectDoesNotExist:
            return Response({"Message": "saveforlater item not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"Message":f"Failed to move product to Cart: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)
        



class getallcartitems(APIView):
    def get(self,request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id = user_id).first()

        if not user:
            return Response({"Message": "User not Found!!!!"})
        
        try:
            all_cart = cart.objects.filter(user=user)

            allcart_data=[]

            for cart_item in all_cart:

                tmp = {
                        'id': cart_item.id,
                        'product_id': cart_item.product_id,
                        'quantity': cart_item.quantity,
                        'product_name': cart_item.product_name,
                        'product_image': cart_item.product_image,
                        'price': cart_item.price,
                        'google_shopping_url': cart_item.google_shopping_url,
                        'seller_link': cart_item.seller_link,
                        'seller_logo': cart_item.seller_logo,
                        'seller_name': cart_item.seller_name,
                        'clicks Count': cart_item.clicked,
                        'bought': cart_item.bought
                    }
                allcart_data.append(tmp)

            return Response({"Message": "All Cart item fetched Successfully","cart_data":allcart_data}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({"Message": "Cart items not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"Message":f"Failed to Fetch Cart items: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)


class getallsaveforlateritems(APIView):
    def get(self,request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id = user_id).first()

        if not user:
            return Response({"Message": "User not Found!!!!"})
        
        try:
            all_savelater = saveforlater.objects.filter(user=user)

            all_savelater_data=[]

            for savelater_item in all_savelater:

                tmp = {
                        'id': savelater_item.id,
                        'product_id': savelater_item.product_id,
                        'quantity': savelater_item.quantity,
                        'product_name': savelater_item.product_name,
                        'product_image': savelater_item.product_image,
                        'price': savelater_item.price,
                        'google_shopping_url': savelater_item.google_shopping_url,
                        'seller_link': savelater_item.seller_link,
                        'seller_logo': savelater_item.seller_logo,
                        'seller_name': savelater_item.seller_name
                    }
                all_savelater_data.append(tmp)

            return Response({"Message": "All save later item fetched Successfully","savelater_data":all_savelater_data}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({"Message": "Save later items not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"Message":f"Failed to Fetch Save later items: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)


class BuyProduct(APIView):
    def post(self, request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found!"}, status=status.HTTP_404_NOT_FOUND)
        
        cart_id = request.data.get('cart_id')
        if not cart_id:
            return Response({"Message": "cart_id not found!"}, status=status.HTTP_404_NOT_FOUND)

        try:
            cart_item = cart.objects.filter(id = cart_id, user=user).first()

            if not cart_item:
                return Response({"Message": "No Product Found"}, status=status.HTTP_404_NOT_FOUND)
            # cart_item = get_object_or_404(Cart, id=cart_id, user=user)
            cart_item.clicked += 1
            cart_item.save()
            # Store the cart_id in the session
            request.session['cart_id'] = cart_id
            return Response({'redirect_url': cart_item.seller_link}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({"Message": "No Product Found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"Message":f"Error Occured While pressing Buy Button: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)


class ConfirmPurchase(APIView):
    def post(self, request):
        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()

        if not user:
            return Response({"Message": "User not found!"}, status=status.HTTP_404_NOT_FOUND)

        cart_id = request.session.get('cart_id')
        if not cart_id:
            return Response({"Message": "No cart_id in session"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            cart_item = cart.objects.get(id=cart_id, user=user)
        except cart.DoesNotExist:
            return Response({"Message": "No Product Found"}, status=status.HTTP_404_NOT_FOUND)
        
        print(cart_item.id)
        print(cart_item.seller_link)
        print(cart_item.bought)
        print(cart_item.clicked)

        # Retrieve and validate 'bought' status
        bought_str = request.data.get('bought')

        if bought_str not in ['yes', 'no']:
            return Response({"Message": "Invalid value for 'bought'"}, status=status.HTTP_400_BAD_REQUEST)

        if bought_str in ['no']:
            del request.session['cart_id']
            return Response({"Message": "No Product Bought"}, status=status.HTTP_400_BAD_REQUEST)

        # Update the bought status
        cart_item.bought = (bought_str == 'yes')
        cart_item.save()

        # Store the cart item in OrderHistory
        tmp = {
            'product_id': cart_item.product_id,
            'quantity': cart_item.quantity,
            'product_name': cart_item.product_name,
            'product_image': cart_item.product_image,
            'price': cart_item.price,
            'google_shopping_url': cart_item.google_shopping_url,
            'seller_link': cart_item.seller_link,
            'seller_logo': cart_item.seller_logo,
            'seller_name': cart_item.seller_name,
            'clicked': cart_item.clicked,
            'bought': cart_item.bought
        }
        orderhistory.objects.create(**tmp, user=user)

        # If the product was bought, delete the cart item
        if cart_item.bought:
            cart_item.delete()

        # Clear cart_id from session
        del request.session['cart_id']

        return Response({'Message': 'Bought status updated'}, status=status.HTTP_200_OK)


class Admingetallcart(APIView):
    def post(self,request):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            cart_items = cart.objects.all()
            print(cart_items)

            all_data = []
            for item in cart_items:
                tmp = {
                    'id' : item.id,
                    'user': item.user.id,
                    'product_id': item.product_id,
                    'quantity': item.quantity,
                    'product_name': item.product_name,
                    'product_image': item.product_image,
                    'price': item.price,
                    'google_shopping_url': item.google_shopping_url,
                    'seller_link': item.seller_link,
                    'seller_logo': item.seller_logo,
                    'seller_name': item.seller_name,
                    'clicked': item.clicked,
                    'bought': item.bought
                }
                all_data.append(tmp)

            # serialized_cart_items = serializers.serialize('json', cart_items)
            # cart_data = json.loads(serialized_cart_items)
            # serialized_cart_items = serializers.serialize('json', cart_items)
            return JsonResponse({"Message": "All Cart items fetched Successfully", "cart_data": all_data}, status=status.HTTP_200_OK)
            # return Response({"Message": "All Cart item fetched Successfully","cart_data":cart_items}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({"Message": "Cart items not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"Message":f"Failed to Fetch Cart items: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)
        
class Admingetallsavelater(APIView):
    def post(self,request):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            savelater_items = saveforlater.objects.all()
            print(savelater_items)

            all_data = []
            for item in savelater_items:
                tmp = {
                    'id' : item.id,
                    'user': item.user.id,
                    'product_id': item.product_id,
                    'quantity': item.quantity,
                    'product_name': item.product_name,
                    'product_image': item.product_image,
                    'price': item.price,
                    'google_shopping_url': item.google_shopping_url,
                    'seller_link': item.seller_link,
                    'seller_logo': item.seller_logo,
                    'seller_name': item.seller_name
                }
                all_data.append(tmp)

            return JsonResponse({"Message": "All Cart items fetched Successfully", "cart_data": all_data}, status=status.HTTP_200_OK)
        except ObjectDoesNotExist:
            return Response({"Message": "Cart items not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"Message":f"Failed to Fetch Cart items: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)
        

class OxylabPricingView(APIView):
    def post(self,request):
        logger = logging.getLogger(__name__)  # Get logger for this module

        # Log the incoming request details
        logger.info(f"Received POST request: {request.data}")
        # userid = get_user_id_from_token(request)
        # user = CustomUser.objects.filter(id=userid)

        # if not user:
        #     logger.warning("User not found for userid: %s", userid)
        #     return Response({"Message": "User not Found!!!!"})

        product_id = request.data.get("product_id")

        if not product_id:
            return Response({'Message': 'Please provide product_id to search'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            oxy_account = oxylab_account.objects.get(id=1)
            username = oxy_account.username
            password = oxy_account.password
        except oxylab_account.DoesNotExist:
            return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)



        # Structure payload.
        payload = {
            'source': 'google_shopping_pricing',
            'domain': 'co.in',
            'query': product_id, # Product ID
            'parse': True,
            'locale': 'en',
        }

        try:

            # Get response.
            response = requests.request(
                'POST',
                'https://realtime.oxylabs.io/v1/queries',
                auth=(username, password),
                json=payload,
            )
            
            data =response.json()#['results'][0]['content']

            # print(data)

            # URL prefix to prepend
            # url_prefix = 'https://www.google.com'

            # Update seller links
            if 'pricing' in data['results'][0]['content']:
                for seller_info in data['results'][0]['content']['pricing']:
                    seller_link = seller_info.get('seller_link')
                    if seller_link and seller_link.startswith('/url?q='):
                        # seller_info['seller_link'] = url_prefix + seller_link
                        seller_info['seller_link'] = str(seller_link).replace("/url?q=",'')

            # Convert the updated data back to JSON format if needed
            # updated_json = json.dumps(data, indent=2,ensure_ascii=False)

            # Print prettified response to stdout.
            # pprint(data)
            try:
                # data = response.json()
                prod_data = data['results'][0]['content']

                if prod_data ['parse_status_code'] == 12009:    
                    return Response({'Message': 'Unable to fetch the Pricing detail'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                # print(data)
                logger.debug(f"Received API response: {prod_data}")

                return Response({'Message': 'Fetch the Product detail Successfully', "Product_detail": prod_data}, status=status.HTTP_200_OK)
            except Exception as e:
                logger.error(f'Unable to fetch the Product detail: {str(e)}')
                return Response({'Message': f'Unable to fetch the Product detail: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
                logger.error(f'Unable to fetch the Product detail: {str(e)}')
                return Response({'Message': f'Unable to fetch the Product detail: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        






class OxylabPageONSale(APIView):
    def post(self, request):
        logger = logging.getLogger(__name__)  # Get logger for this module

        # Log the incoming request details
        logger.info(f"Received POST request: {request.data}")

        query = request.data.get("product_name")
        ppr_min = request.data.get("ppr_min", None)
        ppr_max = request.data.get("ppr_max", None)
        filter_all = request.data.get("filter_all", None)
        sort_by = request.data.get("sort_by", 'relevance')  # Default to 'relevance'
        page_number = request.data.get("page_number", 1)  # Default to 1 if not provided

        if not query:
            return Response({'Message': 'Please provide query to search'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            oxy_account = oxylab_account.objects.get(id=1)
            username = oxy_account.username
            password = oxy_account.password
        except oxylab_account.DoesNotExist:
            return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)

        query_main = str(query).replace(" ", "+")

        sort_mapping = {
            'relevance': 'r',
            'low_to_high': 'p',
            'high_to_low': 'pd',
            'rating': 'rv'
        }

        sort_key = sort_mapping.get(sort_by, 'r')  # Default to 'relevance' if sort_by is invalid

        # Build context dynamically based on provided filters
        context = [{'key': 'sort_by', 'value': sort_key}]
        
        if ppr_min is not None:
            context.append({'key': 'min_price', 'value': ppr_min})
        
        if ppr_max is not None:
            context.append({'key': 'max_price', 'value': ppr_max})

        if filter_all is not None:
            context.append({'key': 'tbs', 'value': f"tbm=shop&q={query_main}&tbs=mr:1,sales:1,{filter_all}"})
        else:
            context.append({'key': 'tbs', 'value': f"tbm=shop&q={query_main}&tbs=mr:1,sales:1"})

        def get_final_url(original_url):
            response = requests.get(original_url, allow_redirects=True,timeout=5)
            return response.url
            
        def fetch_page(page_number):
            payload = {
                'source': 'google_shopping_search',
                'domain': 'co.in',
                'query': query_main,
                "start_page": page_number,
                'pages': 1,
                'parse': True,
                'locale': 'en',
                "geo_location": "India",
                'context': context,
            }
            try:
                response = requests.post(
                    'https://realtime.oxylabs.io/v1/queries',
                    auth=(username, password),
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                return data.get('results', [])
            except requests.RequestException as e:
                logger.error(f"Error fetching page {page_number}: {e}")
                return []
            
        try:
            # Fetch data for the specified page
            results = fetch_page(page_number)
            
            def generate_unique_product_id():
                # Generate a UUID and take the integer representation
                unique_id = uuid.uuid4().int
                
                # Convert the integer to a string and take the first 20 digits
                product_id = "NA_" + str(unique_id)[:30]
                
                return product_id

            shopping_data = []
            search_history_entries = []
            last_page_number = []
            current_page_number = []
            passed = []
            # url_list = [
            #     "amazon", "flipkart", "snapdeal", "myntra", "ajio", "paytmmall", "tatacliq", "shopclues",
            #     "pepperfry", "nykaa", "limeroad", "faballey", "zivame", "koovs", "clovia", "biba", 
            #     "wforwoman", "bewakoof", "urbanladder", "croma", "reliancedigital", "vijaysales", 
            #     "gadgets360", "poorvikamobile", "samsung", "oneplus", "mi", "dell", "apple", "bigbasket", 
            #     "blinkit", "jiomart", "dunzo", "spencers", "naturesbasket", "zopnow", "starquik", "fabindia", 
            #     "hometown", "woodenstreet", "thedecorkart", "chumbak", "livspace", "thesleepcompany", "firstcry", 
            #     "healthkart", "netmeds", "1mg", "lenskart", "tanishq", "bluestone", "caratlane", "purplle", 
            #     "crossword", "sapnaonline", "booksadda", "bookchor", "a1books", "scholastic", "headsupfortails", 
            #     "petsworld", "dogspot", "petshop18", "pawsindia", "marshallspetzone", "petsglam", "petsy", 
            #     "petnest", "justdogsstore", "infibeam", "shoppersstop", "craftsvilla", "naaptol", "saholic", 
            #     "homeshop18", "futurebazaar", "ritukumar", "thelabellife", "andindia", "globaldesi", "sutastore", 
            #     "nykaafashion", "jaypore", "amantelingerie", "happimobiles", "electronicscomp", "jio", 
            #     "unboxindia", "gadgetbridge", "vlebazaar", "dmart", "supermart", "moreretail", "easyday", 
            #     "reliancefresh", "houseofpataudi", "ikea", "zarahome", "indigoliving", "goodearth", "westside", 
            #     "godrejinterio", "fabfurnish", "limeroad", "pcjeweller", "kalyanjewellers", "candere", "voylla", 
            #     "orra", "sencogoldanddiamonds", "bookishsanta", "pustakmandi", "wordery", "starmark", 
            #     "bargainbooks", "bookdepository", "worldofbooks", "bookswagon", "kitabay", "pupkart", 
            #     "whiskas", "barksandmeows", "petophilia", "waggle", "themancompany", "beardo", "mamaearth", 
            #     "plumgoodness", "buywow", "ustraa", "myglamm", "bombayshavingcompany", "khadinatural", 
            #     "zomato", "swiggy", "freshmenu", "box8", "faasos", "dineout", "rebelfoods", "behrouzbiryani", 
            #     "dominos", "pizzahut", "makemytrip", "goibibo", "yatra", "cleartrip", "oyorooms", "airbnb", 
            #     "trivago", "booking", "agoda", "expedia", "urbanclap", "housejoy", "jeeves", "onsitego", 
            #     "homecentre", "rentomojo", "furlenco", "nestaway", "tata"
            # ]

            try:
                urls_ = URL_List.objects.values_list('name', flat=True)
                url_list = list(urls_)
            except URL_List.DoesNotExist:
                print({'Message': f'Unable to Find URL List result'}) 
                url_list=[]
            
            # Remove duplicates and convert to lowercase
            url_list = list(set([url.lower() for url in url_list]))

            # Function to normalize the merchant name
            def normalize_name(name):
                # Remove domain extensions and symbols
                name = re.sub(r'\.(com|in|org|net|co)\b', '', name, flags=re.IGNORECASE)
                return name.lower()

            # Normalize and filter merchants in shopping_data before processing
            for result in results:
                organic_results = result.get('content', {}).get('results', {}).get('organic', [])
                last_page_number.append(result.get('content', {})['last_visible_page'])
                current_page_number.append(result.get('content', {})['page'])

                for item in organic_results:
                    merchant_name = item.get('merchant', {}).get('name', '')
                    normalized_name = normalize_name(merchant_name)
                    
                    # Filter based on normalized merchant name
                    if normalized_name in url_list:
                        passed.append(item)
                    else:
                        print(f"Merchant name '{merchant_name}' not found in URL list.")
                        continue  # Skip the item if merchant name is not in the list

                    try:
                        if 'url' in item:
                            item['url'] = "https://www.google.com" + item['url']
                    except Exception as e:
                        logger.error(f"Error parsing URL for item: {e}")

                    try:
                        if 'merchant' in item and 'url' in item['merchant']:
                            item['merchant']['url'] = self.fix_url(item['merchant']['url'])
                    except Exception as e:
                        logger.error(f"Error parsing URL for item: {e}")

                    try:
                        if 'product_id' not in item or not item['product_id']:
                            new_url = get_final_url(item['merchant']['url'])
                            seller_link = new_url
                            
                            # Check if seller_link exists in prodid_mapping
                            existing_entry = prodid_mapping.objects.filter(seller_link=seller_link).first()
                            
                            if existing_entry:
                                # If entry exists, use the existing product_id
                                item['product_id'] = existing_entry.product_id
                            else:
                                # If entry does not exist, generate a new product_id and create a new entry
                                item['product_id'] = generate_unique_product_id()
                                prodid_mapping.objects.create(
                                    product_id=item['product_id'],
                                    seller_link=seller_link,
                                    price=item['price'],
                                    seller_name=item['merchant']['name'],
                                    title=item['title'],
                                    delivery=item['delivery'],
                                    product_image=item['thumbnail'],
                                )
                        
                    except Exception as e:
                        logger.error(f"Error getting product_id for item: {e}")
                    

                    shopping_data.append(item)

                    product_id = item.get('product_id')
                    if product_id is None or product_id == "":
                        logger.error(f"Invalid product_id: {product_id}")
                        continue

                    search_history_entries.append(
                        search_history(
                            query=query,
                            product_id=product_id,
                            google_url=item['url'],
                            seller_name=item['merchant']['name'],
                            seller_url=item['merchant']['url'],
                            price=item['price'],
                            product_title=item['title'],
                            delivery=item['delivery'],
                            currency=item['currency'],
                            rating=item.get('rating'),
                            reviews_count=item.get('reviews_count'),
                            product_pic=item.get('thumbnail')
                        )
                    )

            logger.info(f"Total search_history entries to create: {len(search_history_entries)}")

            with transaction.atomic():
                try:
                    search_history.objects.bulk_create(search_history_entries, ignore_conflicts=True)
                except Exception as e:
                    logger.error(f"Error creating search_history entries: {e}")

            logger.info(f"Total products fetched: {len(shopping_data)}")

            return Response({'Message': 'Fetched the Product data Successfully', "Product_data": passed, "Last Page": last_page_number, "Current Page": current_page_number}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'Message': f'Failed to Fetch the Product data: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        # def get_final_url(original_url):
        #     response = requests.get(original_url, allow_redirects=True,timeout=5)
        #     return response.url
            
        # def fetch_page(page_number):
        #     payload = {
        #         'source': 'google_shopping_search',
        #         'domain': 'co.in',
        #         'query': query_main,
        #         "start_page": page_number,
        #         'pages': 1,
        #         'parse': True,
        #         'locale': 'en',
        #         "geo_location": "India",
        #         'context': context,
        #     }
        #     try:
        #         response = requests.post(
        #             'https://realtime.oxylabs.io/v1/queries',
        #             auth=(username, password),
        #             json=payload,
        #         )
        #         response.raise_for_status()
        #         data = response.json()
        #         return data.get('results', [])
        #     except requests.RequestException as e:
        #         logger.error(f"Error fetching page {page_number}: {e}")
        #         return []

        # try:

        #     # Fetch data for the specified page
        #     results = fetch_page(page_number)

        #     shopping_data = []
        #     search_history_entries = []
        #     last_page_number = []
        #     current_page_number = []
        #     for result in results:
        #         organic_results = result.get('content', {}).get('results', {}).get('organic', [])
        #         last_page_number.append(result.get('content', {})['last_visible_page'])
        #         current_page_number.append(result.get('content', {})['page'])
        #         for item in organic_results:
        #             try:
        #                 if 'url' in item:
        #                     item['url'] = "https://www.google.com" + item['url']
        #             except Exception as e:
        #                 logger.error(f"Error parsing URL for item: {e}")

        #             try:
        #                 if 'merchant' in item and 'url' in item['merchant']:
        #                     item['merchant']['url'] = self.fix_url(item['merchant']['url'])
        #             except Exception as e:
        #                 logger.error(f"Error parsing URL for item: {e}")

        #             shopping_data.append(item)

        #             product_id = item.get('product_id')
        #             if product_id is None or product_id == "":
        #                 logger.error(f"Invalid product_id: {product_id}")
        #                 continue

        #             search_history_entries.append(
        #                 search_history(
        #                     query=query,
        #                     product_id=product_id,
        #                     google_url=item['url'],
        #                     seller_name=item['merchant']['name'],
        #                     seller_url=item['merchant']['url'],
        #                     price=item['price'],
        #                     product_title=item['title'],
        #                     delivery=item['delivery'],
        #                     currency=item['currency'],
        #                     rating=item.get('rating'),
        #                     reviews_count=item.get('reviews_count'),
        #                     product_pic=item.get('thumbnail')
        #                 )
        #             )

        #     logger.info(f"Total search_history entries to create: {len(search_history_entries)}")

        #     with transaction.atomic():
        #         try:
        #             search_history.objects.bulk_create(search_history_entries, ignore_conflicts=True)
        #         except Exception as e:
        #             logger.error(f"Error creating search_history entries: {e}")

        #     logger.info(f"Total products fetched: {len(shopping_data)}")
            
        #     return Response({'Message': 'Fetched the Product data Successfully', "Product_data": shopping_data, "Last Page": last_page_number, "Current Page":current_page_number}, status=status.HTTP_200_OK)

        # except Exception as e:
        #     return Response({'Message': f'Failed to Fetch the Product data : {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def fix_url(encoded_url):
        parsed_url = urlparse(encoded_url)
        query_params = parse_qs(parsed_url.query)
        if 'url' in query_params:
            return query_params['url'][0]
        return encoded_url
    





class OxylabPageSearchView(APIView):
    def post(self, request):
        logger = logging.getLogger(__name__)  # Get logger for this module

        # Log the incoming request details
        logger.info(f"Received POST request: {request.data}")

        query = request.data.get("product_name")
        ppr_min = request.data.get("ppr_min", None)
        ppr_max = request.data.get("ppr_max", None)
        filter_all = request.data.get("filter_all", None)
        sort_by = request.data.get("sort_by", 'relevance')  # Default to 'relevance'
        page_number = request.data.get("page_number", 1)  # Default to 1 if not provided

        if not query:
            return Response({'Message': 'Please provide query to search'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            oxy_account = oxylab_account.objects.get(id=1)
            username = oxy_account.username
            password = oxy_account.password
        except oxylab_account.DoesNotExist:
            return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)

        query_main = str(query).replace(" ", "+")

        sort_mapping = {
            'relevance': 'r',
            'low_to_high': 'p',
            'high_to_low': 'pd',
            'rating': 'rv'
        }

        sort_key = sort_mapping.get(sort_by, 'r')  # Default to 'relevance' if sort_by is invalid

        # Build context dynamically based on provided filters
        context = [{'key': 'sort_by', 'value': sort_key}]
        
        if ppr_min is not None:
            context.append({'key': 'min_price', 'value': ppr_min})
        
        if ppr_max is not None:
            context.append({'key': 'max_price', 'value': ppr_max})

        if filter_all is not None:
            context.append({'key': 'tbs', 'value': f"tbm=shop&q={query_main}&tbs=mr:1,{filter_all}"})

        def get_final_url(original_url):
            response = requests.get(original_url, allow_redirects=True,timeout=5)
            return response.url
            
        def fetch_page(page_number):
            payload = {
                'source': 'google_shopping_search',
                'domain': 'co.in',
                'query': query_main,
                "start_page": page_number,
                'pages': 1,
                'parse': True,
                'locale': 'en',
                "geo_location": "India",
                'context': context,
            }
            try:
                response = requests.post(
                    'https://realtime.oxylabs.io/v1/queries',
                    auth=(username, password),
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                return data.get('results', [])
            except requests.RequestException as e:
                logger.error(f"Error fetching page {page_number}: {e}")
                return []
            
        try:
            # Fetch data for the specified page
            results = fetch_page(page_number)
            
            def generate_unique_product_id():
                # Generate a UUID and take the integer representation
                unique_id = uuid.uuid4().int
                
                # Convert the integer to a string and take the first 20 digits
                product_id = "NA_" + str(unique_id)[:30]
                
                return product_id

            shopping_data = []
            search_history_entries = []
            last_page_number = []
            current_page_number = []
            passed = []
            # url_list = [
            #     "amazon", "flipkart", "snapdeal", "myntra", "ajio", "paytmmall", "tatacliq", "shopclues",
            #     "pepperfry", "nykaa", "limeroad", "faballey", "zivame", "koovs", "clovia", "biba", 
            #     "wforwoman", "bewakoof", "urbanladder", "croma", "reliancedigital", "vijaysales", 
            #     "gadgets360", "poorvikamobile", "samsung", "oneplus", "mi", "dell", "apple", "bigbasket", 
            #     "blinkit", "jiomart", "dunzo", "spencers", "naturesbasket", "zopnow", "starquik", "fabindia", 
            #     "hometown", "woodenstreet", "thedecorkart", "chumbak", "livspace", "thesleepcompany", "firstcry", 
            #     "healthkart", "netmeds", "1mg", "lenskart", "tanishq", "bluestone", "caratlane", "purplle", 
            #     "crossword", "sapnaonline", "booksadda", "bookchor", "a1books", "scholastic", "headsupfortails", 
            #     "petsworld", "dogspot", "petshop18", "pawsindia", "marshallspetzone", "petsglam", "petsy", 
            #     "petnest", "justdogsstore", "infibeam", "shoppersstop", "craftsvilla", "naaptol", "saholic", 
            #     "homeshop18", "futurebazaar", "ritukumar", "thelabellife", "andindia", "globaldesi", "sutastore", 
            #     "nykaafashion", "jaypore", "amantelingerie", "happimobiles", "electronicscomp", "jio", 
            #     "unboxindia", "gadgetbridge", "vlebazaar", "dmart", "supermart", "moreretail", "easyday", 
            #     "reliancefresh", "houseofpataudi", "ikea", "zarahome", "indigoliving", "goodearth", "westside", 
            #     "godrejinterio", "fabfurnish", "limeroad", "pcjeweller", "kalyanjewellers", "candere", "voylla", 
            #     "orra", "sencogoldanddiamonds", "bookishsanta", "pustakmandi", "wordery", "starmark", 
            #     "bargainbooks", "bookdepository", "worldofbooks", "bookswagon", "kitabay", "pupkart", 
            #     "whiskas", "barksandmeows", "petophilia", "waggle", "themancompany", "beardo", "mamaearth", 
            #     "plumgoodness", "buywow", "ustraa", "myglamm", "bombayshavingcompany", "khadinatural", 
            #     "zomato", "swiggy", "freshmenu", "box8", "faasos", "dineout", "rebelfoods", "behrouzbiryani", 
            #     "dominos", "pizzahut", "makemytrip", "goibibo", "yatra", "cleartrip", "oyorooms", "airbnb", 
            #     "trivago", "booking", "agoda", "expedia", "urbanclap", "housejoy", "jeeves", "onsitego", 
            #     "homecentre", "rentomojo", "furlenco", "nestaway", "tata"
            # ]
            
            try:
                urls_ = URL_List.objects.values_list('name', flat=True)
                url_list = list(urls_)
            except URL_List.DoesNotExist:
                print({'Message': f'Unable to Find URL List result'}) 
                url_list=[]

            # Remove duplicates and convert to lowercase
            url_list = list(set([url.lower() for url in url_list]))

            # Function to normalize the merchant name
            def normalize_name(name):
                # Remove domain extensions and symbols
                name = re.sub(r'\.(com|in|org|net|co)\b', '', name, flags=re.IGNORECASE)
                return name.lower()

            # Normalize and filter merchants in shopping_data before processing
            for result in results:
                organic_results = result.get('content', {}).get('results', {}).get('organic', [])
                last_page_number.append(result.get('content', {})['last_visible_page'])
                current_page_number.append(result.get('content', {})['page'])

                for item in organic_results:
                    merchant_name = item.get('merchant', {}).get('name', '')
                    normalized_name = normalize_name(merchant_name)
                    
                    # Filter based on normalized merchant name
                    if normalized_name in url_list:
                        passed.append(item)
                    else:
                        print(f"Merchant name '{merchant_name}' not found in URL list.")
                        continue  # Skip the item if merchant name is not in the list

                    try:
                        if 'url' in item:
                            item['url'] = "https://www.google.com" + item['url']
                    except Exception as e:
                        logger.error(f"Error parsing URL for item: {e}")

                    try:
                        if 'merchant' in item and 'url' in item['merchant']:
                            item['merchant']['url'] = self.fix_url(item['merchant']['url'])
                    except Exception as e:
                        logger.error(f"Error parsing URL for item: {e}")

                    try:
                        if 'product_id' not in item or not item['product_id']:
                            new_url = get_final_url(item['merchant']['url'])
                            seller_link = new_url
                            
                            # Check if seller_link exists in prodid_mapping
                            existing_entry = prodid_mapping.objects.filter(seller_link=seller_link).first()
                            
                            if existing_entry:
                                # If entry exists, use the existing product_id
                                item['product_id'] = existing_entry.product_id
                            else:
                                # If entry does not exist, generate a new product_id and create a new entry
                                item['product_id'] = generate_unique_product_id()
                                prodid_mapping.objects.create(
                                    product_id=item['product_id'],
                                    seller_link=seller_link,
                                    price=item['price'],
                                    seller_name=item['merchant']['name'],
                                    title=item['title'],
                                    delivery=item['delivery'],
                                    product_image=item['thumbnail'],
                                )
                        
                    except Exception as e:
                        logger.error(f"Error getting product_id for item: {e}")
                    

                    shopping_data.append(item)

                    product_id = item.get('product_id')
                    if product_id is None or product_id == "":
                        logger.error(f"Invalid product_id: {product_id}")
                        continue

                    search_history_entries.append(
                        search_history(
                            query=query,
                            product_id=product_id,
                            google_url=item['url'],
                            seller_name=item['merchant']['name'],
                            seller_url=item['merchant']['url'],
                            price=item['price'],
                            product_title=item['title'],
                            delivery=item['delivery'],
                            currency=item['currency'],
                            rating=item.get('rating'),
                            reviews_count=item.get('reviews_count'),
                            product_pic=item.get('thumbnail')
                        )
                    )

            logger.info(f"Total search_history entries to create: {len(search_history_entries)}")

            with transaction.atomic():
                try:
                    search_history.objects.bulk_create(search_history_entries, ignore_conflicts=True)
                except Exception as e:
                    logger.error(f"Error creating search_history entries: {e}")

            logger.info(f"Total products fetched: {len(shopping_data)}")

            return Response({'Message': 'Fetched the Product data Successfully', "Product_data": passed, "Last Page": last_page_number, "Current Page": current_page_number}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'Message': f'Failed to Fetch the Product data: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)


        # try:

        #     # Fetch data for the specified page
        #     results = fetch_page(page_number)
        #     def generate_unique_product_id():
        #         # Generate a UUID and take the integer representation
        #         unique_id = uuid.uuid4().int
                
        #         # Convert the integer to a string and take the first 20 digits
        #         product_id = "NA_" + str(unique_id)[:30]
                
        #         return product_id

        #     shopping_data = []
        #     search_history_entries = []
        #     last_page_number = []
        #     current_page_number = []
        #     for result in results:
        #         organic_results = result.get('content', {}).get('results', {}).get('organic', [])
        #         last_page_number.append(result.get('content', {})['last_visible_page'])
        #         current_page_number.append(result.get('content', {})['page'])
        #         for item in organic_results:
        #             try:
        #                 if 'url' in item:
        #                     item['url'] = "https://www.google.com" + item['url']
        #             except Exception as e:
        #                 logger.error(f"Error parsing URL for item: {e}")

        #             try:
        #                 if 'merchant' in item and 'url' in item['merchant']:
        #                     item['merchant']['url'] = self.fix_url(item['merchant']['url'])
        #             except Exception as e:
        #                 logger.error(f"Error parsing URL for item: {e}")

        #             try:
        #                 print("THE ITEM IS HERE",item)
        #                 if 'product_id' not in item or not item['product_id']:
        #                     print("THE ITEM WITHOUT PRODUCTID IS HERE",item)
        #                     item['product_id'] = generate_unique_product_id()
        #                     prodid_mapping.objects.create(
        #                         product_id = item['product_id'],
        #                         seller_link = item['merchant']['url'],
        #                         price = item['price'],
        #                     )
        #                     print("AFTER COrrection THE ITEM WITHOUT PRODUCTID IS HERE",item)
        #             except Exception as e:
        #                 logger.error(f"Error getting product_id for item: {e}")

        #             shopping_data.append(item)

        #             product_id = item.get('product_id')
        #             if product_id is None or product_id == "":
        #                 logger.error(f"Invalid product_id: {product_id}")
        #                 continue

        #             search_history_entries.append(
        #                 search_history(
        #                     query=query,
        #                     product_id=product_id,
        #                     google_url=item['url'],
        #                     seller_name=item['merchant']['name'],
        #                     seller_url=item['merchant']['url'],
        #                     price=item['price'],
        #                     product_title=item['title'],
        #                     delivery=item['delivery'],
        #                     currency=item['currency'],
        #                     rating=item.get('rating'),
        #                     reviews_count=item.get('reviews_count'),
        #                     product_pic=item.get('thumbnail')
        #                 )
        #             )

        #     logger.info(f"Total search_history entries to create: {len(search_history_entries)}")

        #     with transaction.atomic():
        #         try:
        #             search_history.objects.bulk_create(search_history_entries, ignore_conflicts=True)
        #         except Exception as e:
        #             logger.error(f"Error creating search_history entries: {e}")

        #     logger.info(f"Total products fetched: {len(shopping_data)}")

        #     try:
        #         passed= []
        #         url_list = ["amazon", "flipkart", "snapdeal", "myntra", "ajio", "paytmmall", "tatacliq", "shopclues", "myntra", "pepperfry", "nykaa", "limeroad", "faballey", "zivame", "koovs", "clovia", "biba", "wforwoman", "bewakoof", "urbanladder", "croma", "reliancedigital", "vijaysales", "gadgets360", "poorvikamobile", "samsung", "oneplus", "mi", "dell", "apple", "bigbasket", "blinkit", "amazon", "jiomart", "dunzo", "spencers", "naturesbasket", "zopnow", "shop", "starquik", "urbanladder", "pepperfry", "fabindia", "hometown", "woodenstreet", "thedecorkart", "chumbak", "hometown", "livspace", "thesleepcompany", "firstcry", "healthkart", "netmeds", "1mg", "lenskart", "tanishq", "bluestone", "caratlane", "zivame", "purplle", "amazon", "flipkart", "in", "crossword", "sapnaonline", "booksadda", "bookchor", "amazon", "a1books", "scholastic", "headsupfortails", "petsworld", "dogspot", "petshop18", "pawsindia", "marshallspetzone", "petsglam", "petsy", "petnest", "justdogsstore", "infibeam", "shoppersstop", "shopping", "craftsvilla", "naaptol", "shopping", "saholic", "flipkart", "homeshop18", "futurebazaar", "ritukumar", "shoppersstop", "thelabellife", "andindia", "globaldesi", "sutastore", "nykaafashion", "jaypore", "amantelingerie", "myntra", "happimobiles", "electronicscomp", "jio", "unboxindia", "samsung", "gadgetbridge", "store", "poorvikamobile", "happimobiles", "vlebazaar", "dmart", "amazon", "naturesbasket", "supermart", "naturesbasket", "spencers", "bigbasket", "moreretail", "easyday", "reliancefresh", "houseofpataudi", "urbanladder", "ikea", "zarahome", "indigoliving", "goodearth", "westside", "godrejinterio", "fabfurnish", "pepperfry", "limeroad", "tanishq", "pcjeweller", "kalyanjewellers", "candere", "caratlane", "bluestone", "voylla", "orra", "sencogoldanddiamonds", "bookishsanta", "pustakmandi", "wordery", "starmark", "bargainbooks", "bookdepository", "worldofbooks", "crossword", "bookswagon", "kitabay", "pupkart", "whiskas", "petshop", "petsy", "headsupfortails", "petsworld", "justdogs", "barksandmeows", "petophilia", "waggle", "themancompany", "beardo", "mamaearth", "in", "plumgoodness", "buywow", "ustraa", "myglamm", "bombayshavingcompany", "khadinatural", "zomato", "swiggy", "freshmenu", "box8", "faasos", "dineout", "rebelfoods", "behrouzbiryani", "dominos", "pizzahut", "makemytrip", "goibibo", "yatra", "cleartrip", "oyorooms", "airbnb", "trivago", "booking", "agoda", "expedia", "urbanclap", "housejoy", "jeeves", "onsitego", "urbanladder", "pepperfry", "homecentre", "rentomojo", "furlenco", "nestaway", "tata"]
                
        #         # Remove duplicates from the URL list
        #         url_list = list(set(url_list))


        #         # Convert URL list to lowercase for case-insensitive comparison
        #         url_list = [url.lower() for url in url_list]

        #         # Function to normalize the merchant name
        #         def normalize_name(name):
        #             # Remove domain extensions and symbols
        #             name = re.sub(r'\.(com|in|org|net|co)\b', '', name, flags=re.IGNORECASE)
        #             # name = re.sub(r'\W+', '', name)  # Remove all non-alphanumeric characters
        #             return name.lower()

        #         passed = []

        #         # try:
        #         for i in shopping_data:
        #             merchant_name = i.get('merchant', {}).get('name', '')
                    
        #             # Normalize the merchant name
        #             normalized_name = normalize_name(merchant_name)
                    
        #             # Check if the normalized merchant name is in the URL list
        #             if normalized_name in url_list:
        #                 passed.append(i)
        #             else:
        #                 print(f"Merchant name '{merchant_name}' not found in URL list.")
                
        #         print({"Message":"Filter out result on 200 website Successful","data":passed})
        #     except Exception as e:
        #         print({'Message': f'Unable to filter result: {str(e)}'})
            
        #     return Response({'Message': 'Fetched the Product data Successfully', "Product_data": passed, "Last Page": last_page_number, "Current Page":current_page_number}, status=status.HTTP_200_OK)

        # except Exception as e:
        #     return Response({'Message': f'Failed to Fetch the Product data : {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def fix_url(encoded_url):
        parsed_url = urlparse(encoded_url)
        query_params = parse_qs(parsed_url.query)
        if 'url' in query_params:
            return query_params['url'][0]
        return encoded_url
    




class GetFiltersView(APIView):
    def post(self, request):
        logger = logging.getLogger(__name__)  # Get logger for this module

        # Log the incoming request details
        logger.info(f"Received POST request: {request.data}")

        query = request.data.get("product_name")

        if not query:
            return Response({'Message': 'Please provide query to search'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            oxy_account = oxylab_account.objects.get(id=1)
            username = oxy_account.username
            password = oxy_account.password
        except oxylab_account.DoesNotExist:
            return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)

        query_main = str(query).replace(" ", "+")



        def process_filters(data):
            """
            Processes the filters from the given data and returns a dictionary with filter names and their values.

            Args:
                data (dict): The data containing the filters, typically from response.json()['results'][0].

            Returns:
                dict: A dictionary with filter names as keys and dictionaries of values as values.
            """
            dct = {}

            # Iterate through each filter in the data
            for i in data['content']['results']['filters']:
                filter_name = i["name"]
                tct = {}
                
                # Iterate through each value in the filter
                for j in i['values']:
                    # Clean the URL parameter and update the tct dictionary
                    # tct[j['value']] = j['url'].split("tbs=")[-1].split('&')[0].split(',')[-1]

                    if str(j['url'].split("tbs=")[-1].split('&')[0].split(',')[-1]).startswith('merchagg'):
                        tct[j['value']] = j['url'].split("tbs=")[-1].split('&')[0].split(',')[-1].split('%')[0]
                    else:
                        tct[j['value']] = str(j['url'].split("tbs=")[-1].split('&')[0].split(',')[-1]).replace("%7C","|")
                        
                # Update the dct dictionary with filter_name and its corresponding tct dictionary
                dct[filter_name] = tct

            return dct
            
        def fetch_page():
            payload = {
                'source': 'google_shopping_search',
                'domain': 'co.in',
                'query': query_main,
                "start_page": 1,
                'pages': 1,
                'parse': True,
                'locale': 'en',
                "geo_location": "India",
                # 'context': context,
            }
            try:
                response = requests.post(
                    'https://realtime.oxylabs.io/v1/queries',
                    auth=(username, password),
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                return data.get('results', [])
            except requests.RequestException as e:
                logger.error(f"Error fetching page {1}: {e}")
                return []

        try:

            # Fetch data for the specified page
            results = fetch_page()

            current_page_number = []
            for result in results:
                try:
                    filters = process_filters(result)
                except:
                    filters = None
                # organic_results = result.get('content', {}).get('results', {}).get('organic', [])
                current_page_number.append(result.get('content', {})['page'])


            filterss =[]

            if filters==None:
                filters_list=None
                filterss = None
                return Response({'Message': 'Failed to Fetch the Filters data', "filters":filterss}, status=status.HTTP_400_BAD_REQUEST)
            else:

                filters_list = [{key: value} for key, value in filters.items()]
                print(filters_list)

                for filter in filters_list:
                    for title, values in filter.items():
                        filterss.append({"title": title, "Value": values})

            return Response({'Message': 'Fetched the Filters data Successfully', "Current Page":current_page_number, "filters":filterss}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'Message': f'Failed to Fetch the Filters data: {str(e)}', "filters":None}, status=status.HTTP_400_BAD_REQUEST)

class OxylabCategoryPageView(APIView):

    cat_mapping = {
            'Animals & Pet Supplies': 'Mordern Animals & Pet Supplies',
            'Apparel & Accessories': 'Mordern Apparel & Accessories',
            'Arts & Entertainment': 'Mordern Arts & Entertainment',
            'Baby & Toddler': 'Mordern Baby & Toddler',
            'Business & Industrial': 'Mordern Business & Industrial',
            'Cameras & Optics': 'Mordern Cameras & Optics',
            'Electronics': 'Mordern Electronics',
            'Food, Beverages & Tobacco': 'Mordern Food, Beverages & Tobacco',
            'Furniture': 'Mordern Furniture',
            'Hardware': 'Mordern Hardware',
            'Health & Beauty': 'Mordern Health & Beauty',
            'Home & Garden': 'Mordern Home & Garden',
            'Luggage & Bags': 'Mordern Luggage & Bags',
            'Mature': 'Mordern Mature',
            'Media': 'Mordern Media',
            'Office Supplies': 'Mordern Office Supplies',
            'Religious & Ceremonial': 'Mordern Religious & Ceremonial',
            'Software': 'Mordern Software',
            'Sporting Goods': 'Mordern Sporting Goods',
            'Toys & Games': 'Mordern Toys & Games',
            'Vehicles & Parts': 'Mordern Vehicles & Parts',
            "Lights": "Modern Lighting Solutions"
        }


    def post(self, request):
        logger = logging.getLogger(__name__)  # Get logger for this module

        # Log the incoming request details
        logger.info(f"Received POST request: {request.data}")

        query = request.data.get("product_name")
        ppr_min = request.data.get("ppr_min", None)
        ppr_max = request.data.get("ppr_max", None)
        filter_all = request.data.get("filter_all", None)
        sort_by = request.data.get("sort_by", 'relevance')  # Default to 'relevance'
        page_number = request.data.get("page_number", 1)  # Default to 1 if not provided
        cat_id = request.data.get("cat_id")

        if cat_id:
            try:
                cat_model = category_model.objects.get(id = cat_id)
                mapped_query = cat_model.mapping_name
            except ObjectDoesNotExist:
                return Response({'Message': 'No Category Found'}, status=status.HTTP_400_BAD_REQUEST)
            if not mapped_query:
                return Response({'Message': 'Invalid query. Please use a valid category from category input_list.'}, status=status.HTTP_400_BAD_REQUEST)

        else:
            try:
                cat_model = category_model.objects.filter(category_name = query).first()
                mapped_query = cat_model.mapping_name
                print("USING CATEGORY MODEL")
            except:
                # Validate and map the query
                mapped_query = self.cat_mapping.get(query)
                print("USING QUERY LIST")
            if not mapped_query:
                return Response({'Message': 'Invalid query. Please use a valid category from category input_list.'}, status=status.HTTP_400_BAD_REQUEST)


        if not query and not cat_id:
            return Response({'Message': 'Please provide query or category_id to search'}, status=status.HTTP_400_BAD_REQUEST)

        # Get oxylabs credentials
        try:
            oxy_account = oxylab_account.objects.get(id=1)
            username = oxy_account.username
            password = oxy_account.password
        except oxylab_account.DoesNotExist:
            return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)

        query_main = str(mapped_query).replace(" ", "+")

        sort_mapping = {
            'relevance': 'r',
            'low_to_high': 'p',
            'high_to_low': 'pd',
            'rating': 'rv'
        }

        sort_key = sort_mapping.get(sort_by, 'r')  # Default to 'relevance' if sort_by is invalid

        # Build context dynamically based on provided filters
        context = [{'key': 'sort_by', 'value': sort_key}]
        
        if ppr_min is not None:
            context.append({'key': 'min_price', 'value': ppr_min})
        
        if ppr_max is not None:
            context.append({'key': 'max_price', 'value': ppr_max})

        if filter_all is not None:
            context.append({'key': 'tbs', 'value': f"tbm=shop&q={query_main}&tbs=mr:1,{filter_all}"})

        def get_final_url(original_url):
            response = requests.get(original_url, allow_redirects=True,timeout=5)
            return response.url
            
        def fetch_page(page_number):
            payload = {
                'source': 'google_shopping_search',
                'domain': 'co.in',
                'query': query_main,
                "start_page": page_number,
                'pages': 1,
                'parse': True,
                'locale': 'en',
                "geo_location": "India",
                'context': context,
            }
            try:
                response = requests.post(
                    'https://realtime.oxylabs.io/v1/queries',
                    auth=(username, password),
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                return data.get('results', [])
            except requests.RequestException as e:
                logger.error(f"Error fetching page {page_number}: {e}")
                return []
            
        try:
            # Fetch data for the specified page
            results = fetch_page(page_number)
            
            def generate_unique_product_id():
                # Generate a UUID and take the integer representation
                unique_id = uuid.uuid4().int
                
                # Convert the integer to a string and take the first 20 digits
                product_id = "NA_" + str(unique_id)[:30]
                
                return product_id

            shopping_data = []
            search_history_entries = []
            last_page_number = []
            current_page_number = []
            passed = []
            # url_list = [
            #     "amazon", "flipkart", "snapdeal", "myntra", "ajio", "paytmmall", "tatacliq", "shopclues",
            #     "pepperfry", "nykaa", "limeroad", "faballey", "zivame", "koovs", "clovia", "biba", 
            #     "wforwoman", "bewakoof", "urbanladder", "croma", "reliancedigital", "vijaysales", 
            #     "gadgets360", "poorvikamobile", "samsung", "oneplus", "mi", "dell", "apple", "bigbasket", 
            #     "blinkit", "jiomart", "dunzo", "spencers", "naturesbasket", "zopnow", "starquik", "fabindia", 
            #     "hometown", "woodenstreet", "thedecorkart", "chumbak", "livspace", "thesleepcompany", "firstcry", 
            #     "healthkart", "netmeds", "1mg", "lenskart", "tanishq", "bluestone", "caratlane", "purplle", 
            #     "crossword", "sapnaonline", "booksadda", "bookchor", "a1books", "scholastic", "headsupfortails", 
            #     "petsworld", "dogspot", "petshop18", "pawsindia", "marshallspetzone", "petsglam", "petsy", 
            #     "petnest", "justdogsstore", "infibeam", "shoppersstop", "craftsvilla", "naaptol", "saholic", 
            #     "homeshop18", "futurebazaar", "ritukumar", "thelabellife", "andindia", "globaldesi", "sutastore", 
            #     "nykaafashion", "jaypore", "amantelingerie", "happimobiles", "electronicscomp", "jio", 
            #     "unboxindia", "gadgetbridge", "vlebazaar", "dmart", "supermart", "moreretail", "easyday", 
            #     "reliancefresh", "houseofpataudi", "ikea", "zarahome", "indigoliving", "goodearth", "westside", 
            #     "godrejinterio", "fabfurnish", "limeroad", "pcjeweller", "kalyanjewellers", "candere", "voylla", 
            #     "orra", "sencogoldanddiamonds", "bookishsanta", "pustakmandi", "wordery", "starmark", 
            #     "bargainbooks", "bookdepository", "worldofbooks", "bookswagon", "kitabay", "pupkart", 
            #     "whiskas", "barksandmeows", "petophilia", "waggle", "themancompany", "beardo", "mamaearth", 
            #     "plumgoodness", "buywow", "ustraa", "myglamm", "bombayshavingcompany", "khadinatural", 
            #     "zomato", "swiggy", "freshmenu", "box8", "faasos", "dineout", "rebelfoods", "behrouzbiryani", 
            #     "dominos", "pizzahut", "makemytrip", "goibibo", "yatra", "cleartrip", "oyorooms", "airbnb", 
            #     "trivago", "booking", "agoda", "expedia", "urbanclap", "housejoy", "jeeves", "onsitego", 
            #     "homecentre", "rentomojo", "furlenco", "nestaway", "tata"
            # ]

            try:
                urls_ = URL_List.objects.values_list('name', flat=True)
                url_list = list(urls_)
            except URL_List.DoesNotExist:
                print({'Message': f'Unable to Find URL List result'}) 
                url_list=[]
            
            # Remove duplicates and convert to lowercase
            url_list = list(set([url.lower() for url in url_list]))

            # Function to normalize the merchant name
            def normalize_name(name):
                # Remove domain extensions and symbols
                name = re.sub(r'\.(com|in|org|net|co)\b', '', name, flags=re.IGNORECASE)
                return name.lower()

            # Normalize and filter merchants in shopping_data before processing
            for result in results:
                organic_results = result.get('content', {}).get('results', {}).get('organic', [])
                last_page_number.append(result.get('content', {})['last_visible_page'])
                current_page_number.append(result.get('content', {})['page'])

                for item in organic_results:
                    merchant_name = item.get('merchant', {}).get('name', '')
                    normalized_name = normalize_name(merchant_name)
                    
                    # Filter based on normalized merchant name
                    if normalized_name in url_list:
                        passed.append(item)
                    else:
                        print(f"Merchant name '{merchant_name}' not found in URL list.")
                        continue  # Skip the item if merchant name is not in the list

                    try:
                        if 'url' in item:
                            item['url'] = "https://www.google.com" + item['url']
                    except Exception as e:
                        logger.error(f"Error parsing URL for item: {e}")

                    try:
                        if 'merchant' in item and 'url' in item['merchant']:
                            item['merchant']['url'] = self.fix_url(item['merchant']['url'])
                    except Exception as e:
                        logger.error(f"Error parsing URL for item: {e}")

                    try:
                        if 'product_id' not in item or not item['product_id']:
                            new_url = get_final_url(item['merchant']['url'])
                            seller_link = new_url
                            
                            # Check if seller_link exists in prodid_mapping
                            existing_entry = prodid_mapping.objects.filter(seller_link=seller_link).first()
                            
                            if existing_entry:
                                # If entry exists, use the existing product_id
                                item['product_id'] = existing_entry.product_id
                            else:
                                # If entry does not exist, generate a new product_id and create a new entry
                                item['product_id'] = generate_unique_product_id()
                                prodid_mapping.objects.create(
                                    product_id=item['product_id'],
                                    seller_link=seller_link,
                                    price=item['price'],
                                    seller_name=item['merchant']['name'],
                                    title=item['title'],
                                    delivery=item['delivery'],
                                    product_image=item['thumbnail'],
                                )
                        
                    except Exception as e:
                        logger.error(f"Error getting product_id for item: {e}")
                    

                    shopping_data.append(item)

                    product_id = item.get('product_id')
                    if product_id is None or product_id == "":
                        logger.error(f"Invalid product_id: {product_id}")
                        continue

                    search_history_entries.append(
                        search_history(
                            query=query,
                            product_id=product_id,
                            google_url=item['url'],
                            seller_name=item['merchant']['name'],
                            seller_url=item['merchant']['url'],
                            price=item['price'],
                            product_title=item['title'],
                            delivery=item['delivery'],
                            currency=item['currency'],
                            rating=item.get('rating'),
                            reviews_count=item.get('reviews_count'),
                            product_pic=item.get('thumbnail')
                        )
                    )

            logger.info(f"Total search_history entries to create: {len(search_history_entries)}")

            with transaction.atomic():
                try:
                    search_history.objects.bulk_create(search_history_entries, ignore_conflicts=True)
                except Exception as e:
                    logger.error(f"Error creating search_history entries: {e}")

            logger.info(f"Total products fetched: {len(shopping_data)}")

            return Response({'Message': 'Fetched the Product data Successfully', "Product_data": passed, "Last Page": last_page_number, "Current Page": current_page_number}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'Message': f'Failed to Fetch the Product data: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)



        # try:
        #     # Fetch data for the specified page
        #     results = fetch_page(page_number)

        #     shopping_data = []
        #     search_history_entries = []
        #     last_page_number = []
        #     current_page_number = []
        #     for result in results:
        #         organic_results = result.get('content', {}).get('results', {}).get('organic', [])
        #         last_page_number.append(result.get('content', {})['last_visible_page'])
        #         current_page_number.append(result.get('content', {})['page'])
        #         for item in organic_results:
        #             try:
        #                 if 'url' in item:
        #                     item['url'] = "https://www.google.com" + item['url']
        #             except Exception as e:
        #                 logger.error(f"Error parsing URL for item: {e}")

        #             try:
        #                 if 'merchant' in item and 'url' in item['merchant']:
        #                     item['merchant']['url'] = self.fix_url(item['merchant']['url'])
        #             except Exception as e:
        #                 logger.error(f"Error parsing URL for item: {e}")

        #             shopping_data.append(item)

        #             product_id = item.get('product_id')
        #             if product_id is None or product_id == "":
        #                 logger.error(f"Invalid product_id: {product_id}")
        #                 continue

        #             search_history_entries.append(
        #                 search_history(
        #                     query=query,
        #                     product_id=product_id,
        #                     google_url=item['url'],
        #                     seller_name=item['merchant']['name'],
        #                     seller_url=item['merchant']['url'],
        #                     price=item['price'],
        #                     product_title=item['title'],
        #                     delivery=item['delivery'],
        #                     currency=item['currency'],
        #                     rating=item.get('rating'),
        #                     reviews_count=item.get('reviews_count'),
        #                     product_pic=item.get('thumbnail')
        #                 )
        #             )

        #     logger.info(f"Total search_history entries to create: {len(search_history_entries)}")

        #     with transaction.atomic():
        #         try:
        #             search_history.objects.bulk_create(search_history_entries, ignore_conflicts=True)
        #         except Exception as e:
        #             logger.error(f"Error creating search_history entries: {e}")

        #     logger.info(f"Total products fetched: {len(shopping_data)}")

        #     try:
        #         passed= []
        #         url_list = ["amazon", "flipkart", "snapdeal", "myntra", "ajio", "paytmmall", "tatacliq", "shopclues", "myntra", "pepperfry", "nykaa", "limeroad", "faballey", "zivame", "koovs", "clovia", "biba", "wforwoman", "bewakoof", "urbanladder", "croma", "reliancedigital", "vijaysales", "gadgets360", "poorvikamobile", "samsung", "oneplus", "mi", "dell", "apple", "bigbasket", "blinkit", "amazon", "jiomart", "dunzo", "spencers", "naturesbasket", "zopnow", "shop", "starquik", "urbanladder", "pepperfry", "fabindia", "hometown", "woodenstreet", "thedecorkart", "chumbak", "hometown", "livspace", "thesleepcompany", "firstcry", "healthkart", "netmeds", "1mg", "lenskart", "tanishq", "bluestone", "caratlane", "zivame", "purplle", "amazon", "flipkart", "in", "crossword", "sapnaonline", "booksadda", "bookchor", "amazon", "a1books", "scholastic", "headsupfortails", "petsworld", "dogspot", "petshop18", "pawsindia", "marshallspetzone", "petsglam", "petsy", "petnest", "justdogsstore", "infibeam", "shoppersstop", "shopping", "craftsvilla", "naaptol", "shopping", "saholic", "flipkart", "homeshop18", "futurebazaar", "ritukumar", "shoppersstop", "thelabellife", "andindia", "globaldesi", "sutastore", "nykaafashion", "jaypore", "amantelingerie", "myntra", "happimobiles", "electronicscomp", "jio", "unboxindia", "samsung", "gadgetbridge", "store", "poorvikamobile", "happimobiles", "vlebazaar", "dmart", "amazon", "naturesbasket", "supermart", "naturesbasket", "spencers", "bigbasket", "moreretail", "easyday", "reliancefresh", "houseofpataudi", "urbanladder", "ikea", "zarahome", "indigoliving", "goodearth", "westside", "godrejinterio", "fabfurnish", "pepperfry", "limeroad", "tanishq", "pcjeweller", "kalyanjewellers", "candere", "caratlane", "bluestone", "voylla", "orra", "sencogoldanddiamonds", "bookishsanta", "pustakmandi", "wordery", "starmark", "bargainbooks", "bookdepository", "worldofbooks", "crossword", "bookswagon", "kitabay", "pupkart", "whiskas", "petshop", "petsy", "headsupfortails", "petsworld", "justdogs", "barksandmeows", "petophilia", "waggle", "themancompany", "beardo", "mamaearth", "in", "plumgoodness", "buywow", "ustraa", "myglamm", "bombayshavingcompany", "khadinatural", "zomato", "swiggy", "freshmenu", "box8", "faasos", "dineout", "rebelfoods", "behrouzbiryani", "dominos", "pizzahut", "makemytrip", "goibibo", "yatra", "cleartrip", "oyorooms", "airbnb", "trivago", "booking", "agoda", "expedia", "urbanclap", "housejoy", "jeeves", "onsitego", "urbanladder", "pepperfry", "homecentre", "rentomojo", "furlenco", "nestaway", "tata"]
                
        #         # Remove duplicates from the URL list
        #         url_list = list(set(url_list))


        #         # Convert URL list to lowercase for case-insensitive comparison
        #         url_list = [url.lower() for url in url_list]

        #         # Function to normalize the merchant name
        #         def normalize_name(name):
        #             # Remove domain extensions and symbols
        #             name = re.sub(r'\.(com|in|org|net|co)\b', '', name, flags=re.IGNORECASE)
        #             # name = re.sub(r'\W+', '', name)  # Remove all non-alphanumeric characters
        #             return name.lower()

        #         passed = []

        #         # try:
        #         for i in shopping_data:
        #             merchant_name = i.get('merchant', {}).get('name', '')
                    
        #             # Normalize the merchant name
        #             normalized_name = normalize_name(merchant_name)
                    
        #             # Check if the normalized merchant name is in the URL list
        #             if normalized_name in url_list:
        #                 passed.append(i)
        #             else:
        #                 print(f"Merchant name '{merchant_name}' not found in URL list.")
                
        #         print({"Message":"Filter out result on 200 website Successful","data":passed})
        #     except Exception as e:
        #         print({'Message': f'Unable to filter result: {str(e)}'})
            
        #     return Response({'Message': 'Fetched the Product data Successfully', "Product_data": passed, "Last Page": last_page_number, "Current Page":current_page_number}, status=status.HTTP_200_OK)

        # except Exception as e:
        #     return Response({'Message': f'Failed to Fetch the Product data : {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def fix_url(encoded_url):
        parsed_url = urlparse(encoded_url)
        query_params = parse_qs(parsed_url.query)
        if 'url' in query_params:
            return query_params['url'][0]
        return encoded_url
    

class GetAllcategorytext(APIView):
    def post(self,request):
        all_cats=[]
        try:
            all_cat = category_model.objects.all()
            for cats in all_cat:
                tmp ={
                    "id":cats.id,
                    "name":cats.category_name,
                    "mapping_name":cats.mapping_name,
                    "title":cats.title,
                    "image":request.build_absolute_uri(cats.category_image.url) if cats.category_image else None,
                    "icon":request.build_absolute_uri(cats.icon.url) if cats.icon else None,
                    "offer_text":cats.offer_text,
                    "text1":cats.Cat_text1,
                    "text2":cats.Cat_text2 ,
                }
                all_cats.append(tmp)

            if len(all_cats) ==0:
                return Response({'Message': 'No Category data found'}, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({'Message': 'Fetched the Category data Successfully', "Category_data": all_cats}, status=status.HTTP_200_OK)

        except ObjectDoesNotExist:
            return Response({'Message': 'No Category model Exist'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'Message': f'Failed to Fetch the Category data : {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
        


class Getcategorytextwithimage(APIView):
    def post(self,request):
        all_cats=[]
        try:
            all_cat = category_model.objects.all()
            for cats in all_cat:
                if cats.category_image:
                    tmp ={
                        "id":cats.id,
                        "name":cats.category_name,
                        "mapping_name":cats.mapping_name,
                        "title":cats.title,
                        "image":request.build_absolute_uri(cats.category_image.url),
                        "icon":request.build_absolute_uri(cats.icon.url) if cats.icon else None,
                        "offer_text":cats.offer_text,
                        "text1":cats.Cat_text1,
                        "text2":cats.Cat_text2 ,
                    }
                    all_cats.append(tmp)

            if len(all_cats) ==0:
                return Response({'Message': 'No Category data found'}, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({'Message': 'Fetched the Category data Successfully', "Category_data": all_cats}, status=status.HTTP_200_OK)

        except ObjectDoesNotExist:
            return Response({'Message': 'No Category model Exist'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'Message': f'Failed to Fetch the Category data : {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
        





class CreateCategoryText(APIView):
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]  

    def post(self, request):
        # Extract data from request
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

        category_name = request.data.get('category_name')
        mapping_name = request.data.get('mapping_name')
        title = request.data.get('title')
        category_image = request.FILES.get('category_image') 
        icon = request.FILES.get('icon')
        offer_text = request.data.get('offer_text', '')
        Cat_text1 = request.data.get('Cat_text1', '')
        Cat_text2 = request.data.get('Cat_text2', '')

        if not category_name:
            return Response({'Message': 'Category name is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Create and save the category object
        category = category_model(
            category_name=category_name,
            mapping_name = mapping_name,
            title = title,
            category_image=category_image,
            icon = icon,
            offer_text = offer_text,
            Cat_text1=Cat_text1,
            Cat_text2=Cat_text2
        )
        category.save()

        return Response({'Message': 'Category created successfully', 'id': category.id}, status=status.HTTP_201_CREATED)



class EditCategoryText(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        cat_id = request.data.get('cat_id')
        if not cat_id:
            Response({'Message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND) 

        try:
            category = category_model.objects.get(id=cat_id)
        except category_model.DoesNotExist:
            return Response({'Message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Extract data from request
        category_name = request.data.get('category_name')
        mapping_name = request.data.get('mapping_name')
        title = request.data.get('title')
        category_image = request.FILES.get('category_image')
        icon = request.FILES.get('icon')
        offer_text = request.data.get('offer_text', '')
        Cat_text1 = request.data.get('Cat_text1')
        Cat_text2 = request.data.get('Cat_text2')

        if category_name:
            category.category_name = category_name
        if mapping_name:
            category.mapping_name = mapping_name
        if category_image:
            category.category_image = category_image
        if icon:
            category.icon = icon
        if title:
            category.title = title
        if Cat_text1 is not None:
            category.Cat_text1 = Cat_text1
        if Cat_text2 is not None:
            category.Cat_text2 = Cat_text2
        if offer_text is not None:
            category.offer_text = offer_text

        if not (category_name or category_image or Cat_text1 or Cat_text2 or title or icon or offer_text):
            return Response({'Message': 'No detail found to update'}, status=status.HTTP_400_BAD_REQUEST)

        category.save()

        return Response({'Message': 'Category updated successfully', 'id': category.id}, status=status.HTTP_200_OK)




class DeleteCategoryText(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

        cat_id = request.data.get('cat_id')
        if not cat_id:
            return Response({'Message': 'Category not found'}, status=status.HTTP_404_NOT_FOUND) 

        try:
            category = category_model.objects.get(id=cat_id)
            category.delete()
            return Response({'Message': 'Category Text deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except category_model.DoesNotExist:
            return Response({'Message': 'Category Text not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'Message': 'Failed to Delete the Category Text'}, status=status.HTTP_404_NOT_FOUND)



def url_to_cart(url):
    # Structure payload.
    payload = {
        'source': 'google_shopping',
        'url': f'{str(url)}',
        'geo_location': 'India',
        'parse': True,
        # 'locale':'en'
    }

    # Get oxylabs credentials
    try:
        oxy_account = oxylab_account.objects.get(id=1)
        username = oxy_account.username
        password = oxy_account.password
    except oxylab_account.DoesNotExist:
        return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)
    
    # Get response.
    response = requests.request(
        'POST',
        'https://realtime.oxylabs.io/v1/queries',
        auth=(username, password),
        json=payload,
    )
    
    return response.json()

def get_details(response_data):
    # Product ID
    try:
        product_id = [i['product_id'] for i in response_data['results'][0]['content']['variants'][0]['items'] if 'selected' in i and i['selected']==True][0]
    except:
        product_id = "not Available"
    # product_image
    try:
        product_image = response_data['results'][0]['content']['images']['full_size'][0]
    except:
        product_image = "not Available"
    # Product Name
    try:
        product_name = response_data['results'][0]['content']['title']
    except:
        product_name = "not Available"
    # Product Price
    try:
        product_price = response_data['results'][0]['content']['pricing']['online'][0]['price']
    except:
        product_price = "not Available"
    # seller Link
    try:
        seller_link = response_data['results'][0]['content']['pricing']['online'][0]['seller_link']
    except:
        seller_link = "not Available"
    # seller Name
    try:
        seller_name = response_data['results'][0]['content']['pricing']['online'][0]['seller']
    except:
        seller_name = "not Available"
    # Google Shooping Link
    try:
        google_shopping_link = response_data['results'][0]['content']['url']
    except:
        google_shopping_link = "not Available"
    return product_id, product_image, product_name, product_price, seller_link, seller_name, google_shopping_link



class filter_out_200(APIView):
    def post(self, request):

        data = request.data.get('data')
        if not data:
            return Response({'Message': 'Data not found'}, status=status.HTTP_404_NOT_FOUND) 
        try:
            passed= []
            # url_list = ["amazon", "flipkart", "snapdeal", "myntra", "ajio", "paytmmall", "tatacliq", "shopclues", "myntra", "pepperfry", "nykaa", "limeroad", "faballey", "zivame", "koovs", "clovia", "biba", "wforwoman", "bewakoof", "urbanladder", "croma", "reliancedigital", "vijaysales", "gadgets360", "poorvikamobile", "samsung", "oneplus", "mi", "dell", "apple", "bigbasket", "blinkit", "amazon", "jiomart", "dunzo", "spencers", "naturesbasket", "zopnow", "shop", "starquik", "urbanladder", "pepperfry", "fabindia", "hometown", "woodenstreet", "thedecorkart", "chumbak", "hometown", "livspace", "thesleepcompany", "firstcry", "healthkart", "netmeds", "1mg", "lenskart", "tanishq", "bluestone", "caratlane", "zivame", "purplle", "amazon", "flipkart", "in", "crossword", "sapnaonline", "booksadda", "bookchor", "amazon", "a1books", "scholastic", "headsupfortails", "petsworld", "dogspot", "petshop18", "pawsindia", "marshallspetzone", "petsglam", "petsy", "petnest", "justdogsstore", "infibeam", "shoppersstop", "shopping", "craftsvilla", "naaptol", "shopping", "saholic", "flipkart", "homeshop18", "futurebazaar", "ritukumar", "shoppersstop", "thelabellife", "andindia", "globaldesi", "sutastore", "nykaafashion", "jaypore", "amantelingerie", "myntra", "happimobiles", "electronicscomp", "jio", "unboxindia", "samsung", "gadgetbridge", "store", "poorvikamobile", "happimobiles", "vlebazaar", "dmart", "amazon", "naturesbasket", "supermart", "naturesbasket", "spencers", "bigbasket", "moreretail", "easyday", "reliancefresh", "houseofpataudi", "urbanladder", "ikea", "zarahome", "indigoliving", "goodearth", "westside", "godrejinterio", "fabfurnish", "pepperfry", "limeroad", "tanishq", "pcjeweller", "kalyanjewellers", "candere", "caratlane", "bluestone", "voylla", "orra", "sencogoldanddiamonds", "bookishsanta", "pustakmandi", "wordery", "starmark", "bargainbooks", "bookdepository", "worldofbooks", "crossword", "bookswagon", "kitabay", "pupkart", "whiskas", "petshop", "petsy", "headsupfortails", "petsworld", "justdogs", "barksandmeows", "petophilia", "waggle", "themancompany", "beardo", "mamaearth", "in", "plumgoodness", "buywow", "ustraa", "myglamm", "bombayshavingcompany", "khadinatural", "zomato", "swiggy", "freshmenu", "box8", "faasos", "dineout", "rebelfoods", "behrouzbiryani", "dominos", "pizzahut", "makemytrip", "goibibo", "yatra", "cleartrip", "oyorooms", "airbnb", "trivago", "booking", "agoda", "expedia", "urbanclap", "housejoy", "jeeves", "onsitego", "urbanladder", "pepperfry", "homecentre", "rentomojo", "furlenco", "nestaway", "tata"]
            try:
                urls_ = URL_List.objects.values_list('name', flat=True)
                url_list = list(urls_)
            except URL_List.DoesNotExist:
                return Response({'Message': f'Unable to Find URL List result'}, status=status.HTTP_404_NOT_FOUND) 
            for i in data:
                merchant_name = i.get('merchant', {}).get('name', '')
                url  = i.get('merchant', {}).get('url', '')
                
                # Check if the merchant name or a portion of it is in the URL list
                if any(url.lower() in merchant_name.lower() for url in url_list):
                    # print(f"Merchant name '{merchant_name}' found in URL list.")
                    passed.append(i)
                else:
                    print(url)
                    print(f"Merchant name '{merchant_name}' not found in URL list.")
                
            
            return Response({"Message":"Filter out result on 200 website Successful","data":passed}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'Message': f'Unable to filter result: {str(e)}'}, status=status.HTTP_404_NOT_FOUND) 



url_list = ["amazon", "flipkart", "snapdeal", "myntra", "ajio", "paytmmall", "tatacliq", "shopclues", "myntra", "pepperfry", "nykaa", "limeroad", "faballey", "zivame", "koovs", "clovia", "biba", "wforwoman", "bewakoof", "urbanladder", "croma", "reliancedigital", "vijaysales", "gadgets360", "poorvikamobile", "samsung", "oneplus", "mi", "dell", "apple", "bigbasket", "blinkit", "amazon", "jiomart", "dunzo", "spencers", "naturesbasket", "zopnow", "shop", "starquik", "urbanladder", "pepperfry", "fabindia", "hometown", "woodenstreet", "thedecorkart", "chumbak", "hometown", "livspace", "thesleepcompany", "firstcry", "healthkart", "netmeds", "1mg", "lenskart", "tanishq", "bluestone", "caratlane", "zivame", "purplle", "amazon", "flipkart", "in", "crossword", "sapnaonline", "booksadda", "bookchor", "amazon", "a1books", "scholastic", "headsupfortails", "petsworld", "dogspot", "petshop18", "pawsindia", "marshallspetzone", "petsglam", "petsy", "petnest", "justdogsstore", "infibeam", "shoppersstop", "shopping", "craftsvilla", "naaptol", "shopping", "saholic", "flipkart", "homeshop18", "futurebazaar", "ritukumar", "shoppersstop", "thelabellife", "andindia", "globaldesi", "sutastore", "nykaafashion", "jaypore", "amantelingerie", "myntra", "happimobiles", "electronicscomp", "jio", "unboxindia", "samsung", "gadgetbridge", "store", "poorvikamobile", "happimobiles", "vlebazaar", "dmart", "amazon", "naturesbasket", "supermart", "naturesbasket", "spencers", "bigbasket", "moreretail", "easyday", "reliancefresh", "houseofpataudi", "urbanladder", "ikea", "zarahome", "indigoliving", "goodearth", "westside", "godrejinterio", "fabfurnish", "pepperfry", "limeroad", "tanishq", "pcjeweller", "kalyanjewellers", "candere", "caratlane", "bluestone", "voylla", "orra", "sencogoldanddiamonds", "bookishsanta", "pustakmandi", "wordery", "starmark", "bargainbooks", "bookdepository", "worldofbooks", "crossword", "bookswagon", "kitabay", "pupkart", "whiskas", "petshop", "petsy", "headsupfortails", "petsworld", "justdogs", "barksandmeows", "petophilia", "waggle", "themancompany", "beardo", "mamaearth", "in", "plumgoodness", "buywow", "ustraa", "myglamm", "bombayshavingcompany", "khadinatural", "zomato", "swiggy", "freshmenu", "box8", "faasos", "dineout", "rebelfoods", "behrouzbiryani", "dominos", "pizzahut", "makemytrip", "goibibo", "yatra", "cleartrip", "oyorooms", "airbnb", "trivago", "booking", "agoda", "expedia", "urbanclap", "housejoy", "jeeves", "onsitego", "urbanladder", "pepperfry", "homecentre", "rentomojo", "furlenco", "nestaway", "tata"]

def get_200_sites(data,url_list):
    for i in data['results'][0]['content']['results']['organic']:
    # for i in data:        -----> if given Page search api Result
        merchant_name = i.get('merchant', {}).get('name', '')
        url  = i.get('merchant', {}).get('url', '')
        
        # Check if the merchant name or a portion of it is in the URL list
        if any(url.lower() in merchant_name.lower() for url in url_list):
            # print(f"Merchant name '{merchant_name}' found in URL list.")
            pass
        else:
            print(url)
            print(f"Merchant name '{merchant_name}' not found in URL list.")


#================================================= Search History =========================================================================


class ClearSearchHistoryView(APIView):
    def post(self, request):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            # Check if there are any records to delete
            if not search_history.objects.exists():
                return Response({'Message': 'No search history records found.'}, status=status.HTTP_404_NOT_FOUND)
            # Using transaction.atomic to ensure atomicity
            with transaction.atomic():
                batch_size = 1000  # Adjust batch size as necessary
                while search_history.objects.exists():
                    # Fetch a batch of records to delete
                    records_to_delete = search_history.objects.all()[:batch_size]
                    # Delete the batch of records
                    records_to_delete.delete()
            
            return Response({'Message': 'All search history records have been deleted.'}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({'Message': f"Unable to delete Search history: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class GetAllSearchHsitory(APIView):
    def post(self, request):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            try:
                history = search_history.objects.all().order_by('-id')
            except search_history.DoesNotExist:
                return Response({'Message': 'No search history records found.'}, status=status.HTTP_404_NOT_FOUND)

            serialize =historySerializer(history, many=True)

            return Response({"Message":"All search history records fetched Successully", "Search_history":serialize.data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'Message': 'Unable to get search history records.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class DeleteOneHistory(APIView):
    def post(self, request):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)
        
        history_id = request.data.get("id")

        try:
            try:
                history = search_history.objects.get(id=history_id)
            except search_history.DoesNotExist:
                return Response({'Message': 'No search history records found.'}, status=status.HTTP_404_NOT_FOUND)
            history.delete()

            return Response({"Message":"Search history records deleted Successully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'Message': 'Unable to deleted search history records.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#================================================= Search History =========================================================================


class GetALLCategoryList(APIView):
    def post(self, request):
        try:
            # Fetch only the category names in a more efficient way
            all_cat_names = category_model.objects.values_list('category_name', flat=True)
            
            return Response({
                'Message': 'Fetch all category names successfully',
                'Category List': list(all_cat_names)
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'Message': f"Unable to get Category List: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class CategoryPageWithProductIDFilter(APIView):

    cat_mapping = {
            'Animals & Pet Supplies': 'Mordern Animals & Pet Supplies',
            'Apparel & Accessories': 'Mordern Apparel & Accessories',
            'Arts & Entertainment': 'Mordern Arts & Entertainment',
            'Baby & Toddler': 'Mordern Baby & Toddler',
            'Business & Industrial': 'Mordern Business & Industrial',
            'Cameras & Optics': 'Mordern Cameras & Optics',
            'Electronics': 'Mordern Electronics',
            'Food, Beverages & Tobacco': 'Mordern Food, Beverages & Tobacco',
            'Furniture': 'Mordern Furniture',
            'Hardware': 'Mordern Hardware',
            'Health & Beauty': 'Mordern Health & Beauty',
            'Home & Garden': 'Mordern Home & Garden',
            'Luggage & Bags': 'Mordern Luggage & Bags',
            'Mature': 'Mordern Mature',
            'Media': 'Mordern Media',
            'Office Supplies': 'Mordern Office Supplies',
            'Religious & Ceremonial': 'Mordern Religious & Ceremonial',
            'Software': 'Mordern Software',
            'Sporting Goods': 'Mordern Sporting Goods',
            'Toys & Games': 'Mordern Toys & Games',
            'Vehicles & Parts': 'Mordern Vehicles & Parts',
            "Lights": "Modern Lighting Solutions"
        }


    def post(self, request):
        logger = logging.getLogger(__name__)  # Get logger for this module

        # Log the incoming request details
        logger.info(f"Received POST request: {request.data}")

        query = request.data.get("product_name")
        ppr_min = request.data.get("ppr_min", None)
        ppr_max = request.data.get("ppr_max", None)
        filter_all = request.data.get("filter_all", None)
        sort_by = request.data.get("sort_by", 'relevance')  # Default to 'relevance'
        page_number = request.data.get("page_number", 1)  # Default to 1 if not provided
        cat_id = request.data.get("cat_id")

        if cat_id:
            try:
                cat_model = category_model.objects.get(id = cat_id)
                mapped_query = cat_model.mapping_name
            except ObjectDoesNotExist:
                return Response({'Message': 'No Category Found'}, status=status.HTTP_400_BAD_REQUEST)
            if not mapped_query:
                return Response({'Message': 'Invalid query. Please use a valid category from category input_list.'}, status=status.HTTP_400_BAD_REQUEST)

        else:
            try:
                cat_model = category_model.objects.filter(category_name = query).first()
                mapped_query = cat_model.mapping_name
                print("USING CATEGORY MODEL")
            except:
                # Validate and map the query
                mapped_query = self.cat_mapping.get(query)
                print("USING QUERY LIST")
            if not mapped_query:
                return Response({'Message': 'Invalid query. Please use a valid category from category input_list.'}, status=status.HTTP_400_BAD_REQUEST)


        if not query and not cat_id:
            return Response({'Message': 'Please provide query or category_id to search'}, status=status.HTTP_400_BAD_REQUEST)

        # Get oxylabs credentials
        try:
            oxy_account = oxylab_account.objects.get(id=1)
            username = oxy_account.username
            password = oxy_account.password
        except oxylab_account.DoesNotExist:
            return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)

        query_main = str(mapped_query).replace(" ", "+")

        sort_mapping = {
            'relevance': 'r',
            'low_to_high': 'p',
            'high_to_low': 'pd',
            'rating': 'rv'
        }

        sort_key = sort_mapping.get(sort_by, 'r')  # Default to 'relevance' if sort_by is invalid

        # Build context dynamically based on provided filters
        context = [{'key': 'sort_by', 'value': sort_key}]
        
        if ppr_min is not None:
            context.append({'key': 'min_price', 'value': ppr_min})
        
        if ppr_max is not None:
            context.append({'key': 'max_price', 'value': ppr_max})

        if filter_all is not None:
            context.append({'key': 'tbs', 'value': f"tbm=shop&q={query_main}&tbs=mr:1,{filter_all}"})

        def get_final_url(original_url):
            response = requests.get(original_url, allow_redirects=True,timeout=5)
            return response.url
            
        def fetch_page(page_number):
            payload = {
                'source': 'google_shopping_search',
                'domain': 'co.in',
                'query': query_main,
                "start_page": page_number,
                'pages': 1,
                'parse': True,
                'locale': 'en',
                "geo_location": "India",
                'context': context,
            }
            try:
                response = requests.post(
                    'https://realtime.oxylabs.io/v1/queries',
                    auth=(username, password),
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                return data.get('results', [])
            except requests.RequestException as e:
                logger.error(f"Error fetching page {page_number}: {e}")
                return []

        try:
            # Fetch data for the specified page
            results = fetch_page(page_number)

            shopping_data = []
            search_history_entries = []
            last_page_number = []
            current_page_number = []
            for result in results:
                organic_results = result.get('content', {}).get('results', {}).get('organic', [])
                last_page_number.append(result.get('content', {})['last_visible_page'])
                current_page_number.append(result.get('content', {})['page'])
                for item in organic_results:
                    try:
                        if not "product_id" in item:
                            del item 
                            continue
                    except Exception as e:
                        logger.error(f"Error Removing item without Product_id: {e}")

                    try:
                        if 'url' in item:
                            item['url'] = "https://www.google.com" + item['url']
                    except Exception as e:
                        logger.error(f"Error parsing URL for item: {e}")

                    try:
                        if 'merchant' in item and 'url' in item['merchant']:
                            item['merchant']['url'] = self.fix_url(item['merchant']['url'])
                    except Exception as e:
                        logger.error(f"Error parsing URL for item: {e}")

                    shopping_data.append(item)

                    product_id = item.get('product_id')
                    if product_id is None or product_id == "":
                        logger.error(f"Invalid product_id: {product_id}")
                        continue

                    search_history_entries.append(
                        search_history(
                            query=query,
                            product_id=product_id,
                            google_url=item['url'],
                            seller_name=item['merchant']['name'],
                            seller_url=item['merchant']['url'],
                            price=item['price'],
                            product_title=item['title'],
                            delivery=item['delivery'],
                            currency=item['currency'],
                            rating=item.get('rating'),
                            reviews_count=item.get('reviews_count'),
                            product_pic=item.get('thumbnail')
                        )
                    )

            logger.info(f"Total search_history entries to create: {len(search_history_entries)}")

            with transaction.atomic():
                try:
                    search_history.objects.bulk_create(search_history_entries, ignore_conflicts=True)
                except Exception as e:
                    logger.error(f"Error creating search_history entries: {e}")

            logger.info(f"Total products fetched: {len(shopping_data)}")

            try:
                passed= []
                url_list = ["amazon", "flipkart", "snapdeal", "myntra", "ajio", "paytmmall", "tatacliq", "shopclues", "myntra", "pepperfry", "nykaa", "limeroad", "faballey", "zivame", "koovs", "clovia", "biba", "wforwoman", "bewakoof", "urbanladder", "croma", "reliancedigital", "vijaysales", "gadgets360", "poorvikamobile", "samsung", "oneplus", "mi", "dell", "apple", "bigbasket", "blinkit", "amazon", "jiomart", "dunzo", "spencers", "naturesbasket", "zopnow", "shop", "starquik", "urbanladder", "pepperfry", "fabindia", "hometown", "woodenstreet", "thedecorkart", "chumbak", "hometown", "livspace", "thesleepcompany", "firstcry", "healthkart", "netmeds", "1mg", "lenskart", "tanishq", "bluestone", "caratlane", "zivame", "purplle", "amazon", "flipkart", "in", "crossword", "sapnaonline", "booksadda", "bookchor", "amazon", "a1books", "scholastic", "headsupfortails", "petsworld", "dogspot", "petshop18", "pawsindia", "marshallspetzone", "petsglam", "petsy", "petnest", "justdogsstore", "infibeam", "shoppersstop", "shopping", "craftsvilla", "naaptol", "shopping", "saholic", "flipkart", "homeshop18", "futurebazaar", "ritukumar", "shoppersstop", "thelabellife", "andindia", "globaldesi", "sutastore", "nykaafashion", "jaypore", "amantelingerie", "myntra", "happimobiles", "electronicscomp", "jio", "unboxindia", "samsung", "gadgetbridge", "store", "poorvikamobile", "happimobiles", "vlebazaar", "dmart", "amazon", "naturesbasket", "supermart", "naturesbasket", "spencers", "bigbasket", "moreretail", "easyday", "reliancefresh", "houseofpataudi", "urbanladder", "ikea", "zarahome", "indigoliving", "goodearth", "westside", "godrejinterio", "fabfurnish", "pepperfry", "limeroad", "tanishq", "pcjeweller", "kalyanjewellers", "candere", "caratlane", "bluestone", "voylla", "orra", "sencogoldanddiamonds", "bookishsanta", "pustakmandi", "wordery", "starmark", "bargainbooks", "bookdepository", "worldofbooks", "crossword", "bookswagon", "kitabay", "pupkart", "whiskas", "petshop", "petsy", "headsupfortails", "petsworld", "justdogs", "barksandmeows", "petophilia", "waggle", "themancompany", "beardo", "mamaearth", "in", "plumgoodness", "buywow", "ustraa", "myglamm", "bombayshavingcompany", "khadinatural", "zomato", "swiggy", "freshmenu", "box8", "faasos", "dineout", "rebelfoods", "behrouzbiryani", "dominos", "pizzahut", "makemytrip", "goibibo", "yatra", "cleartrip", "oyorooms", "airbnb", "trivago", "booking", "agoda", "expedia", "urbanclap", "housejoy", "jeeves", "onsitego", "urbanladder", "pepperfry", "homecentre", "rentomojo", "furlenco", "nestaway", "tata"]
                for i in shopping_data:
                    merchant_name = i.get('merchant', {}).get('name', '')
                    url  = i.get('merchant', {}).get('url', '')
                    
                    # Check if the merchant name or a portion of it is in the URL list
                    if any(url.lower() in merchant_name.lower() for url in url_list):
                        # print(f"Merchant name '{merchant_name}' found in URL list.")
                        passed.append(i)
                    else:
                        print(url)
                        print(f"Merchant name '{merchant_name}' not found in URL list.")
                    
                
                print({"Message":"Filter out result on 200 website Successful","data":passed})
            except Exception as e:
                print({'Message': f'Unable to filter result: {str(e)}'})
            
            return Response({'Message': 'Fetched the Product data Successfully', "Product_data": passed, "Last Page": last_page_number, "Current Page":current_page_number}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'Message': f'Failed to Fetch the Product data : {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def fix_url(encoded_url):
        parsed_url = urlparse(encoded_url)
        query_params = parse_qs(parsed_url.query)
        if 'url' in query_params:
            return query_params['url'][0]
        return encoded_url
    
class SuggestionAPIView(APIView):
    def post(self, request):
        query = request.data.get("product_name")
        if not query:
            return Response({"error": "product_name is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        # Fetch the search history items matching the query
        history_items = search_history.objects.filter(query=query).order_by('-id')[:10]

        if not history_items:
            # No suggestions available
            return Response({'Message': 'No Suggestion Available'}, status=status.HTTP_404_NOT_FOUND)
        history_items = list(history_items.values())
        
        try:
            # Serialize the history items
            serializer = historySerializer(history_items, many=True)  # 'many=True' is used for serializing a queryset
            tmp = []
            print(serializer.data)
            print(serializer.data[0])

            for row in serializer.data:
                tmp.append(
                {
                # "pos": 1,
                "url": row.get("google_url"),
                "type": "grid",
                "price": row.get("price"),
                "title": row.get("product_title"),
                "rating": row.get("rating"),
                "currency": row.get("currency"),
                "delivery": row.get("delivery"),
                "merchant": {
                    "url": row.get("seller_url"),
                    "name": row.get("seller_name")
                },
                "price_str": f"₹{row.get("price")}",
                "thumbnail": row.get("product_pic"),
                "product_id": row.get("product_id"),
                # "pos_overall": 1,
                "reviews_count": row.get("reviews_count")})
                
            return Response({"Message":"Suggestion fetched Successfully","Suggestions": tmp}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"Message":f"Error Ocuured while fetching Suggestion: {str(e)}"}, status=status.HTTP_404_NOT_FOUND)
      

class add_to_URL_List(APIView):
    def post(self, request):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

        urls = request.data.get('url_list', [])
        # print(urls)

        # Fetch all existing URLs once
        existing_urls = list(set(url.name.lower() for url in URL_List.objects.all()))
        # print(existing_urls)
        
        # Find new URLs
        new_urls = [url.lower() for url in urls if url.lower() not in existing_urls]
        # print(new_urls)

        if new_urls:
            # Avoiding integrity error by creating URLs individually
            for url in new_urls:
                URL_List.objects.get_or_create(name=url)
            
            message = f'Successfully added {len(new_urls)} new URLs'
            return Response({'Message': message, 'new_urls': new_urls}, status=status.HTTP_201_CREATED)
        else:
            message = 'All URLs already exist in the list'
            return Response({'Message': message}, status=status.HTTP_200_OK)
    

class GetAllURLs(APIView):
    def post(self, request):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            urls = URL_List.objects.all().order_by('-created')
            serializer = URLListSerializer(urls, many=True)
        except URL_List.DoesNotExist:
            return Response({'Message': 'URL List not found'}, status=status.HTTP_404_NOT_FOUND)

        return Response({"Message":"URL List fetched Successfully","URL List": serializer.data}, status=status.HTTP_200_OK)

class EditURL(APIView):
    def post(self, request):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            url_id = request.data.get("url_id")
            if not url_id:
                return Response({'Message': 'URL id not provided'}, status=status.HTTP_404_NOT_FOUND)
            url = URL_List.objects.get(id=url_id)
        except URL_List.DoesNotExist:
            return Response({'Message': 'URL not found'}, status=status.HTTP_404_NOT_FOUND)
        
        new_name = request.data.get('name')
        if not new_name:
            return Response({'Message': 'New name is required'}, status=status.HTTP_400_BAD_REQUEST)

        url.name = new_name
        url.save()
        
        serializer = URLListSerializer(url)
        return Response(serializer.data)
    
class DeleteURL(APIView):
    def post(self, request):
        user_id = get_user_id_from_token(request)
        user, is_superuser = IsSuperUser(user_id)
        if not user or not is_superuser:
            msg = 'could not found the super user'
            return Response({"Message": msg}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            url_id = request.data.get("url_id")
            if not url_id:
                return Response({'Message': 'URL id not provided'}, status=status.HTTP_404_NOT_FOUND)
            url = URL_List.objects.get(id=url_id)
            name_=url.name
            id_ = url.id
        except URL_List.DoesNotExist:
            return Response({'Message': 'URL not found'}, status=status.HTTP_404_NOT_FOUND)
        url.delete()
        return Response({'Message': 'URL deleted successfully',"id":id_,'URL':name_}, status=status.HTTP_204_NO_CONTENT)
    

class SearchSuggestionsView(APIView):
    def post(self, request):
        keyword = request.data.get('product_name')
        if not keyword:
            return Response({'Message': 'Product_name not provided'}, status=status.HTTP_404_NOT_FOUND)

        try:
            suggestions = search_history.objects.filter(query__icontains=keyword).values_list('query', flat=True).distinct()[:10]
            if list(suggestions) ==[]:
                return Response({'Message': 'No Suggestions Available', 'Suggestions': list(suggestions)}, status=200)
            return Response({'Message': 'Suggestion Fetched Succesfully', 'Suggestions': list(suggestions)}, status=200)
        except Exception as e:
            return Response({"Message":f"Error Ocuured while fetching Suggestion: {str(e)}"}, status=status.HTTP_404_NOT_FOUND)