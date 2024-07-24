from django.shortcuts import render
from .models import *
from rest_framework.views import APIView
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from rest_framework.response import Response
from .email import send_otp_via_email
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import generate_random_string, get_user_id_from_token
from .serializers import  UserChangePasswordSerializer, UserLoginSerializer, UserProfileSerializer, UserRegistrationSerializer, UserChangePasswordSerializer, UserModifyPasswordSerializer
from rest_framework.permissions import BasePermission, IsAuthenticated, AllowAny
from .renderers import UserRenderer
from django.views import View
from django.http import JsonResponse, HttpResponse
import os
from django.conf import settings
from django.utils import timezone
# import pytz
import datetime
import requests
import random
from django.core.validators import validate_email
import threading
from queue import Queue
from django.contrib.sessions.models import Session
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
                                        'Sorry, your password was incorrect.'
                                    
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
import requests
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



# class ProductSearchView(APIView):
#     def fetch_html_content(self, url, options, queue):
#         try:
#             driver = Chrome(options=options)
#             driver.get(url)
#             data = driver.page_source
#             driver.quit()
#             queue.put(data)
#         except Exception as e:
#             queue.put(None)

#     def parse_product_details(self, html_content):
#         soup = BeautifulSoup(html_content, 'html.parser')
#         products = []

#         product_grid = soup.find_all('div', class_='sh-dgr__gr-auto sh-dgr__grid-result')
#         for product in product_grid:
#             product_name = product.find('h3', class_='tAxDx').get_text(strip=True) if product.find('h3', class_='tAxDx') else None
#             price_span = product.find('span', class_='a8Pemb OFFNJ')
#             price = price_span.get_text(strip=True) if price_span else None
#             website_span = product.find('div', class_='aULzUe IuHnof')
#             website_name = website_span.get_text(strip=True) if website_span else None

#             # Extract ratings
#             rating_span = product.find('span', class_='Rsc7Yb')
#             rating = rating_span.get_text(strip=True) if rating_span else None

#             # Extract review count
#             review_count_span = rating_span.find_next_sibling('div', class_='qSSQfd uqAnbd').next_sibling if rating_span else None
#             review_count = review_count_span.get_text(strip=True) if review_count_span else None

#             link_tag = product.find('a', class_='shntl')
#             link = link_tag['href'] if link_tag else None

#             if link and link.startswith('/url?url='):
#                 parsed_url = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
#                 link = parsed_url['url'][0] if 'url' in parsed_url else link
            
#             products.append({
#                 'Product Name': product_name,
#                 'Price': price,
#                 'Website Name': website_name,
#                 'Link': link,
#                 "Rating" : rating,
#                 "Review Counts" : review_count
#             })

#         return products

#     def post(self, request):
#         userid = get_user_id_from_token(request)
#         user = CustomUser.objects.filter(id=userid)

#         options = Options()
#         options.add_argument("--headless")
#         options.add_argument("window-size=1400,1500")
#         options.add_argument("--disable-gpu")
#         options.add_argument("--no-sandbox")
#         options.add_argument("start-maximized")
#         options.add_argument("enable-automation")
#         options.add_argument("--disable-infobars")
#         options.add_argument("--disable-dev-shm-usage")
#         options.add_argument("--disable-extensions")
#         options.add_argument("--disable-popup-blocking")
#         options.add_argument("--disable-notifications")
#         options.add_argument("--disable-background-timer-throttling")
#         options.add_argument("--disable-backgrounding-occluded-windows")
#         options.add_argument("--disable-renderer-backgrounding")

#         prefs = {
#             "profile.managed_default_content_settings.images": 2,  # Disable images
#             "profile.default_content_setting_values.notifications": 2,  # Disable notifications
#             "profile.managed_default_content_settings.stylesheets": 2,  # Disable CSS
#             "profile.managed_default_content_settings.cookies": 2,  # Disable cookies
#             "profile.managed_default_content_settings.plugins": 2,  # Disable plugins
#             "profile.managed_default_content_settings.popups": 2,  # Disable popups
#             "profile.managed_default_content_settings.geolocation": 2,  # Disable geolocation
#             "profile.managed_default_content_settings.media_stream": 2,  # Disable media stream
#         }
#         options.add_experimental_option("prefs", prefs)

#         if not user:
#             return Response({"Message": "User not Found!!!!"})

#         product = request.data.get('product_name')

#         if not product:
#             return Response({'Message': 'Please provide product_name'}, status=status.HTTP_400_BAD_REQUEST)

#         product_name = str(product).replace(' ', '+')

#         # Get filter parameters from the request
#         on_sale = request.data.get('on_sale')
#         ppr_min = request.data.get('ppr_min')
#         ppr_max = request.data.get('ppr_max')
#         avg_rating = request.data.get('avg_rating')
#         ship_speed = request.data.get('ship_speed')
#         free_shipping = request.data.get('free_shipping')
        
#         filters = []

#         if on_sale:
#             filters.append('sales:1')
#         if ppr_min and ppr_max:
#             filters.append(f'price:1,ppr_min:{ppr_min},ppr_max:{ppr_max}')
#         if avg_rating:
#             filters.append(f'avg_rating:{avg_rating}')
#         if ship_speed:
#             filters.append(f'shipspped:{ship_speed}')
#         if free_shipping:
#             filters.append('ship:1')

#         filter_string = ','.join(filters)
        
#         def fetch_page(pge, queue):
#             url = f"https://www.google.com/search?q={product_name}&sca_esv=0835a04e1987451a&sca_upv=1&hl=en-GB&psb=1&tbs=vw:d,{filter_string}&tbm=shop&ei=PtyLZqe-L52qseMP_e2qoAk&start={pge}&sa=N&ved=0ahUKEwin1bPLuZeHAxUdVWwGHf22CpQ4eBDy0wMI7w0&biw=1536&bih=730&dpr=1.25"
#             self.fetch_html_content(url, options, queue)

#         retries = 3
#         for attempt in range(retries):
#             try:
#                 all_products = []
#                 threads = []
#                 queue = Queue()

#                 for pge in range(0, 241, 60):
#                     thread = threading.Thread(target=fetch_page, args=(pge, queue))
#                     threads.append(thread)
#                     thread.start()

#                 for thread in threads:
#                     thread.join()

#                 while not queue.empty():
#                     html_content = queue.get()
#                     if html_content:
#                         products = self.parse_product_details(html_content)
#                         all_products.extend(products)

#                 if all_products:
#                     return Response({'Message': 'Fetch the Product data Successfully', "Product_data": all_products}, status=status.HTTP_200_OK)
#                 else:
#                     print(f"Attempt {attempt + 1}: Products list is empty, retrying...")
#                     time.sleep(3)  # Wait before retrying

#             except Exception as e:
#                 print(f"Attempt {attempt + 1}: Error occurred: {str(e)}")
#                 time.sleep(3)  # Wait before retrying

#         return Response({'Message': 'Failed to fetch product data after multiple attempts'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





# class ProductSearchView(APIView):
#     def fetch_html_content(self, url, options):
#         driver = Chrome(options=options)
#         driver.get(url)
#         data = driver.page_source
#         driver.quit()
#         return data

#     def parse_product_details(self, html_content):
#         soup = BeautifulSoup(html_content, 'html.parser')
#         products = []

#         product_grid = soup.find_all('div', class_='sh-dgr__gr-auto sh-dgr__grid-result')
#         for product in product_grid:
#             product_name = product.find('h3', class_='tAxDx').get_text(strip=True) if product.find('h3', class_='tAxDx') else None
#             price_span = product.find('span', class_='a8Pemb OFFNJ')
#             price = price_span.get_text(strip=True) if price_span else None
#             website_span = product.find('div', class_='aULzUe IuHnof')
#             website_name = website_span.get_text(strip=True) if website_span else None

#             # Extract ratings
#             rating_span = product.find('span', class_='Rsc7Yb')
#             rating = rating_span.get_text(strip=True) if rating_span else None

#             # Extract review count
#             review_count_span = rating_span.find_next_sibling('div', class_='qSSQfd uqAnbd').next_sibling if rating_span else None
#             review_count = review_count_span.get_text(strip=True) if review_count_span else None

#             link_tag = product.find('a', class_='shntl')
#             link = link_tag['href'] if link_tag else None

#             if link and link.startswith('/url?url='):
#                 parsed_url = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
#                 link = parsed_url['url'][0] if 'url' in parsed_url else link
            
#             products.append({
#                 'Product Name': product_name,
#                 'Price': price,
#                 'Website Name': website_name,
#                 'Link': link,
#                 "Rating" : rating,
#                 "Review Counts" : review_count
#             })

#         return products

#     def post(self, request):
#         userid = get_user_id_from_token(request)
#         user = CustomUser.objects.filter(id=userid)

#         options = Options()
#         options.add_argument("--headless")
#         options.add_argument("window-size=1400,1500")
#         options.add_argument("--disable-gpu")
#         options.add_argument("--no-sandbox")
#         options.add_argument("start-maximized")
#         options.add_argument("enable-automation")
#         options.add_argument("--disable-infobars")
#         options.add_argument("--disable-dev-shm-usage")

#         if not user:
#             return Response({"Message": "User not Found!!!!"})

#         product = request.data.get('product_name')

#         if not product:
#             return Response({'Message': 'Please provide product_name'}, status=status.HTTP_400_BAD_REQUEST)

#         product_name = str(product).replace(' ', '+')
        
#         # Get filter parameters from the request
#         on_sale = request.data.get('on_sale')
#         ppr_min = request.data.get('ppr_min')
#         ppr_max = request.data.get('ppr_max')
#         avg_rating = request.data.get('avg_rating')
#         ship_speed = request.data.get('ship_speed')
#         free_shipping = request.data.get('free_shipping')
        

#         filters = []

#         if on_sale:
#             filters.append('sales:1')
#         if ppr_min and ppr_max:
#             filters.append(f'price:1,ppr_min:{ppr_min},ppr_max:{ppr_max}')
#         if avg_rating:
#             filters.append(f'avg_rating:{avg_rating}')
#         if ship_speed:
#             filters.append(f'shipspeed:{ship_speed}')
#         if free_shipping:
#             filters.append('ship:1')

#         filter_string = ','.join(filters)

#         retries = 3
#         for attempt in range(retries):
#             try:
#                 all_products = []
#                 for pge in range(0, 241, 60):
#                     url = f"https://www.google.com/search?q={product_name}&sca_esv=0835a04e1987451a&sca_upv=1&hl=en-GB&psb=1&tbs=vw:d,{filter_string}&tbm=shop&ei=PtyLZqe-L52qseMP_e2qoAk&start={pge}&sa=N&ved=0ahUKEwin1bPLuZeHAxUdVWwGHf22CpQ4eBDy0wMI7w0&biw=1536&bih=730&dpr=1.25"
#                     html_content = self.fetch_html_content(url, options)
#                     products = self.parse_product_details(html_content)
#                     all_products.extend(products)

#                 if all_products:
#                     return Response({'Message': 'Fetch the Product data Successfully', "Product_data": all_products}, status=status.HTTP_200_OK)
#                 else:
#                     print(f"Attempt {attempt + 1}: Products list is empty, retrying...")
#                     time.sleep(3)  # Wait before retrying

#             except Exception as e:
#                 print(f"Attempt {attempt + 1}: Error occurred: {str(e)}")
#                 time.sleep(3)  # Wait before retrying

#         return Response({'Message': 'Failed to fetch product data after multiple attempts'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)





# class oxylabSearchView(APIView):   
#     def post(self, request):

#         userid = get_user_id_from_token(request)
#         user = CustomUser.objects.filter(id=userid)

#         if not user:
#             return Response({"Message":"User not Found!!!!"})

#         query = request.data.get("query")

#         if not query:
#             return Response({'Message': 'Please provide query to search'}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             oxy_account = oxylab_account.objects.get(id=1)
#             username = oxy_account.username
#             password = oxy_account.password
#         except oxylab_account.DoesNotExist:
#             return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)

#         query_main = str(query).replace(" ","+")

#         try:
#             # Structure payload.
#             payload = {
#                 'source': 'google_shopping_search',
#                 'domain': 'com',
#                 'query': query_main,
#                 'pages': 4,
#                 'parse': True,
#                 'context': [
#                     {'key': 'sort_by', 'value': 'pd'},
#                     {'key': 'min_price', 'value': 1},
#                 ],
#             }

#             # Get response.
#             response = requests.request(
#                 'POST',
#                 'https://realtime.oxylabs.io/v1/queries',
#                 auth=(f'{username}', f'{password}'),
#                 json=payload,
#             )

#             time.sleep(2)

#             # Print prettified response to stdout.
#             data =response.json()
#             shopping_data=[]


#             for i in range(len(data['results'])):
#                 organic_results = data['results'][i]['content']['results']['organic']
#                 for item in organic_results:
#                     try:
#                         # Fix the main URL
#                         # item['url'] = self.fix_url(item['url'])
#                         # Fix the merchant URL if it exists
#                         if 'merchant' in item and 'url' in item['merchant']:
#                             item['merchant']['url'] = self.fix_url(item['merchant']['url'])
#                     except Exception as e:
#                         print(f"Error parsing URL for item: {e}")
#                         # If there is an error, leave the URL as it is
#                     shopping_data.append(item)



#             # for i in range(len(data['results'])):
#             #     organic_results = data['results'][i]['content']['results']['organic']
#             #     for item in organic_results:
#             #         # Fix the main URL
#             #         # item['url'] = self.fix_url(item['url'])
#             #         # Fix the merchant URL if it exists
#             #         if 'merchant' in item and 'url' in item['merchant']:
#             #             item['merchant']['url'] = self.fix_url(item['merchant']['url'])
#             #         shopping_data.append(item)
#             print(response.text)
            
#             return Response({'Message': 'Fetch the Product data Successfully', "Product_data" : shopping_data}, status=status.HTTP_200_OK)
#         except Exception as e:
#             return Response({'Message': f'Unable to fetch the Product data: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

#     @staticmethod
#     def fix_url(encoded_url):
#         parsed_url = urlparse(encoded_url)
#         query_params = parse_qs(parsed_url.query)
#         if 'url' in query_params:
#             return query_params['url'][0]
#         return encoded_url
# Configure logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s')

from django.db import transaction

class OxylabSearchView(APIView):
    def post(self, request):
        logger = logging.getLogger(__name__)  # Get logger for this module

        # Log the incoming request details
        logger.info(f"Received POST request: {request.data}")
        # userid = get_user_id_from_token(request)
        # user = CustomUser.objects.filter(id=userid)

        # if not user:
        #     logger.warning("User not found for userid: %s", userid)
        #     return Response({"Message": "User not Found!!!!"})

        query = request.data.get("product_name")
        ppr_min = request.data.get("ppr_min", None)
        ppr_max = request.data.get("ppr_max", None)
        # avg_rating = request.data.get("avg_rating", None)
        sort_by = request.data.get("sort_by", 'relevance')  # Default to 'relevance'
        # location = request.data.get("location", "India")  # Default location is India

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

        try:
            # Structure payload.
            payload = {
                'source': 'google_shopping_search',
                'domain': 'co.in',
                'query': query_main,
                "start_page":1,
                'pages': 4,
                'parse': True,
                # "currency": "EUR",
                'context': context,
            }
            logger.debug(f"Sending API request with payload: {payload}")
            print(payload)

            # Get response.
            response = requests.request(
                'POST',
                'https://realtime.oxylabs.io/v1/queries',
                auth=(f'{username}', f'{password}'),
                json=payload,
            )

            time.sleep(2)

            # Print prettified response to stdout.
            data = response.json()
            shopping_data = []
            search_history_entries = []

            for i in range(len(data['results'])):
                organic_results = data['results'][i]['content']['results']['organic']
                for item in organic_results:
                    #-------------------Adding "https://www.google.com" to main url---------------------------------------
                    try:
                        # Fix the merchant URL if it exists
                        if 'url' in item:
                            item['url'] = "https://www.google.com" + item['url']
                    except Exception as e:
                        logger.error(f"Error parsing URL for item: {e}")
                        print(f"Error parsing URL for item: {e}")
                    #-------------------Adding "https://www.google.com" to main url---------------------------------------

                    try:
                        # Fix the merchant URL if it exists
                        if 'merchant' in item and 'url' in item['merchant']:
                            item['merchant']['url'] = self.fix_url(item['merchant']['url'])
                    except Exception as e:
                        logger.error(f"Error parsing URL for item: {e}")
                        print(f"Error parsing URL for item: {e}")
                        # If there is an error, leave the URL as it is
                    shopping_data.append(item)

                    # Check if product_id is within the 64-bit integer range
                    product_id = item.get('product_id')
                    if product_id is None or product_id =="":
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
                            rating=item.get('rating'),
                            reviews_count=item.get('reviews_count'),
                            product_pic=item.get('thumbnail')
                        )
                    )

            # with transaction.atomic():
            #     search_history.objects.bulk_create(search_history_entries)

             # Log the number of entries to be created
            logger.info(f"Total search_history entries to create: {len(search_history_entries)}")

            # Insert entries one by one with error handling
            with transaction.atomic():
                for entry in search_history_entries:
                    try:
                        entry.save()
                    except Exception as e:
                        logger.error(f"Error creating search_history entry: {e}")

            print(response.text)
            logger.debug(f"Received API response: {response.text}")

            # for row in shopping_data:
            #     search_history.objects.create(
            #         query = query,
            #         product_id = row['product_id'],
            #         google_url = row['url'],
            #         seller_name = row['merchant']['name'],
            #         seller_url = row['merchant']['url'],
            #         price = row['price'],
            #         product_title = row['title'],
            #         rating = row['rating'],
            #         reviews_count = row['reviews_count'],
            #         product_pic = row['thumbnail']
            #     )

            # for row in shopping_data:
            #     try:
            #         logger.debug(f"Creating search_history entry for product_id: {row['product_id']}")
            #         search_history.objects.create(
            #             query=query,
            #             product_id=row['product_id'],
            #             google_url=row['url'],
            #             seller_name=row['merchant']['name'],
            #             seller_url=row['merchant']['url'],
            #             price=row['price'],
            #             product_title=row['title'],
            #             rating=row.get('rating'),  # Use .get to handle missing keys
            #             reviews_count=row.get('reviews_count'),  # Use .get to handle missing keys
            #             product_pic=row.get('thumbnail')  # Use .get to handle missing keys
            #         )
            #     except Exception as e:
            #         logger.error(f"Error creating search_history entry: {e}")

            return Response({'Message': 'Fetch the Product data Successfully', "Product_data": shopping_data}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Unable to fetch the Product data: {str(e)}')
            return Response({'Message': f'Unable to fetch the Product data: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @staticmethod
    def fix_url(encoded_url):
        parsed_url = urlparse(encoded_url)
        query_params = parse_qs(parsed_url.query)
        if 'url' in query_params:
            return query_params['url'][0]
        return encoded_url
    
    # @staticmethod
    # def fix_main_url(encoded_url):
    #     parsed_url = urlparse(encoded_url)
    #     query_params = parse_qs(parsed_url.query)
    #     if 'url' in query_params:
    #         return "https://www.google.com"+query_params['url']
    #     return encoded_url


# "https://www.google.com"




import requests, json
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
            'source': 'google_shopping_product',
            'domain': 'co.in',
            'query': product_id, # Product ID
            'parse': True
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

            print(data)

            # URL prefix to prepend
            url_prefix = 'https://www.google.com'

            # Update seller links
            if 'pricing' in data['results'][0]['content'] and 'online' in data['results'][0]['content']['pricing']:
                for seller_info in data['results'][0]['content']['pricing']['online']:
                    seller_link = seller_info.get('seller_link')
                    if seller_link and seller_link.startswith('/'):
                        seller_info['seller_link'] = url_prefix + seller_link

            # Update review URLs for 1, 3, 4, and 5 stars
            if 'reviews' in data['results'][0]['content'] and 'reviews_by_stars' in data['results'][0]['content']['reviews']:
                for rating in ['1', '3', '4', '5']:
                    reviews_data = data['results'][0]['content']['reviews']['reviews_by_stars'].get(rating)
                    if reviews_data:
                        review_url = reviews_data.get('url')
                        if review_url and review_url.startswith('/'):
                            reviews_data['url'] = url_prefix + review_url

            # Convert the updated data back to JSON format if needed
            # updated_json = json.dumps(data, indent=2,ensure_ascii=False)

            # Print prettified response to stdout.
            pprint(data)
            try:
                # data = response.json()
                prod_data = data['results'][0]['content']
                # print(data)
                logger.debug(f"Received API response: {prod_data}")

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

        if not products_id or not request.data.get('product_id'):
            return Response({"Message":"Product not Found!!!"},status=status.HTTP_400_BAD_REQUEST)

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
            'parse': True
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

            # Update seller links
            if 'pricing' in data['results'][0]['content'] and 'online' in data['results'][0]['content']['pricing']:
                for seller_info in data['results'][0]['content']['pricing']['online']:
                    seller_link = seller_info.get('seller_link')
                    if seller_link and seller_link.startswith('/'):
                        seller_info['seller_link'] = str(seller_link).replace("/url?q=",'')#url_prefix + seller_link

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

        if not cart_id or not request.data.get("cart_id"):
            return Response({"Message": "Cart id not Found!!!!"})

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



class Deletefromsaveforlater(APIView):
    def post(self,request):

        user_id = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=user_id).first()    

        if not user:
            return Response({"Message": "User not Found!!!!"})
        
        savelater_id = request.data.get("savelater_id")
        if not savelater_id or not request.data.get("savelater_id"):
            return Response({"Message": "savelater id not Found!!!!"})

        try:
            item = saveforlater.objects.get(user=user, id=savelater_id)
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




# class ConfirmPurchase(APIView):
#     def post(self, request):
#         user_id = get_user_id_from_token(request)
#         user = CustomUser.objects.filter(id=user_id).first()

#         if not user:
#             return Response({"Message": "User not found!"}, status=status.HTTP_404_NOT_FOUND)

#         cart_id = request.session.get('cart_id')
#         if not cart_id:
#             return Response({"Message": "No cart_id in session"}, status=status.HTTP_400_BAD_REQUEST)
        
#         try:
#             try:
#                 cart_item = cart.objects.get(id=cart_id, user=user)
#             except cart.DoesNotExist:
#                 return Response({"Message": "No Product Found"}, status=status.HTTP_404_NOT_FOUND)

#             if cart_item:

#                 # cart_item = get_object_or_404(Cart, id=cart_id, user=user)
#                 bought_str = request.data.get('bought')

#                 if bought_str == 'yes':
#                     cart_item.bought = True
#                 else:
#                     cart_item.bought = False
#                     del request.session['cart_id']
#                     return Response({'Message': 'No Product Bought'}, status=status.HTTP_200_OK)

#                 # cart_item.bought = bought
#                 cart_item.save()
                
#                 tmp = {
#                             # 'id': cart_item.id,
#                             'product_id': cart_item.product_id,
#                             'quantity': cart_item.quantity,
#                             'product_name': cart_item.product_name,
#                             'product_image': cart_item.product_image,
#                             'price': cart_item.price,
#                             'google_shopping_url': cart_item.google_shopping_url,
#                             'seller_link': cart_item.seller_link,
#                             'seller_logo': cart_item.seller_logo,
#                             'seller_name': cart_item.seller_name,
#                             'clicked': cart_item.clicked,
#                             'bought': cart_item.bought
#                         }
#                 orderhistory.objects.create(**tmp,user=user)
#                 if cart_item.bought == True:
#                     cart_item.delete()
#                 # Clear cart_id from session
#                 del request.session['cart_id']


#                 return Response({'Message': 'Bought status updated'}, status=status.HTTP_200_OK)
#             else:
#                 return Response({"Message": "No Product Found"}, status=status.HTTP_404_NOT_FOUND)
#         except ObjectDoesNotExist:
#             return Response({"Message": "No Product Found"}, status=status.HTTP_404_NOT_FOUND)
#         except Exception as e:
#             return Response({"Message":f"Error Occured While updating Bought status: {str(e)}"},status=status.HTTP_400_BAD_REQUEST)



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

        # Retrieve and validate 'bought' status
        bought_str = request.data.get('bought')
        if bought_str not in ['yes', 'no']:
            return Response({"Message": "Invalid value for 'bought'"}, status=status.HTTP_400_BAD_REQUEST)

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