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
                return Response({'token':token,'verified' : user.is_user_verified, 'Message':'Email verified successfully.', "membership_id":None, "membership":None, "membership_expiry_date":None, "subscription_status":user.is_subscribed, "stripe_customer_id":user.stripe_customer_id}, status=status.HTTP_200_OK)
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


class OxylabSearchView(APIView):
    def post(self, request):
        logger = logging.getLogger(__name__)  # Get logger for this module

        # Log the incoming request details
        logger.info(f"Received POST request: {request.data}")
        userid = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=userid)

        if not user:
            logger.warning("User not found for userid: %s", userid)
            return Response({"Message": "User not Found!!!!"})

        query = request.data.get("query")
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

            for i in range(len(data['results'])):
                organic_results = data['results'][i]['content']['results']['organic']
                for item in organic_results:
                    try:
                        # Fix the merchant URL if it exists
                        if 'merchant' in item and 'url' in item['merchant']:
                            item['merchant']['url'] = self.fix_url(item['merchant']['url'])
                    except Exception as e:
                        logger.error(f"Error parsing URL for item: {e}")
                        print(f"Error parsing URL for item: {e}")
                        # If there is an error, leave the URL as it is
                    shopping_data.append(item)

            print(response.text)
            logger.debug(f"Received API response: {response.text}")

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
