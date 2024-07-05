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
        
        if not request.data.get('email'):
            # return Response({'Message': 'email field is required'}, status=status.HTTP_400_BAD_REQUEST)
            return Response(
                {"errors": {"email": ["This is required field*"]}},status=status.HTTP_400_BAD_REQUEST)
        email = request.data.get("email")
        

        if CustomUser.objects.filter(email=email).exists():
            return Response({'Message': "User with this email already exists. Please Sign-in"}, status=status.HTTP_400_BAD_REQUEST)

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

        if not request.data.get('email') or not email:
            return Response({"errors": {"email": ["This is required field*"]}},status=status.HTTP_400_BAD_REQUEST)

        if not verification_code:
            return Response({"errors": {"verification_code": ["This is required field*"]}}, status=status.HTTP_400_BAD_REQUEST)
        
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
                return Response({'Message': 'Entered Verification code is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            # If email is not in records, prompt user to register first
            return Response({'Message': 'You are not registered with us, please sign up.'}, status=status.HTTP_400_BAD_REQUEST)

#---------------------------------------------------------UserEmailVerification By Adil--------------------------------------------------------
 
#---------------------------------------------------------Resend OTP API by ADIL----------------------------------------------------------------

class ResendOTPView(APIView):
    def post(self, request):
        email = request.data.get('email')
        # if not email:
        #     return Response({'Message': 'Please provide an email address.'}, status=status.HTTP_400_BAD_REQUEST)
        if not email:
            return Response(
                {"errors": {"email": ["This is required field*"]}},
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
                                "errors": {
                                    "password": [
                                        'Password is not Valid.'
                                    ]
                                }
                            }, status=status.HTTP_404_NOT_FOUND)
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
                            "This is required field*"
                        ]
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
        
        if not new_password:
            return Response({
                    "errors": {
                        "new_password": [
                            "This is required field*"
                        ]
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
        
        if not verification_code:
            return Response({
                    "errors": {
                        "verification_code": [
                            "This is required field*"
                        ]
                    }
                }, status=status.HTTP_400_BAD_REQUEST)

        if not email or not verification_code or not new_password:
            return Response({'Message': 'Please provide the Email, Verification code and New Password'}, status=status.HTTP_400_BAD_REQUEST)

         # Check if verification code is a valid number
        if not verification_code.isdigit():
            return Response({'Message': 'Invalid Verification Code.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(email=email, verification_code=verification_code)
            verification_code = random.randint(100000, 999999)# Extra Code added to change the code after Process because same code will be used multiple times.
            user.verification_code = verification_code# Extra Code added to change the code after Process because same code will be used multiple times.
            user.save()# Extra Code added to change the code after Process because same code will be used multiple times.
        except CustomUser.DoesNotExist:
            return Response({'Message': 'Invalid email or verification code.'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserChangePasswordSerializer(instance=user, data={'password': new_password, 'password2': new_password})
        try:
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({'Message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        except ValidationError as e:
            # Handle validation errors
            return Response({'Message': e.detail}, status=status.HTTP_400_BAD_REQUEST)


#---------------------------------------------Change Password by Adil------------------------------------------------------------




from django.core.validators import validate_email


#---------------------------------Forgot Password by Adil--------------------------------------------------------------------

class ForgotPasswordView(APIView):
    def post(self, request):
        email = request.data.get('email')
        # if not email:
        #     return Response({'Message': 'Please provide the Email'}, status=status.HTTP_400_BAD_REQUEST)
        
        if not email:
            return Response(
                {"errors": {"email": ["This is required field*"]}},
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
            return Response({'Message': 'You are not registered with us, please sign up.'}, status=status.HTTP_400_BAD_REQUEST)

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

class ProductSearchView(APIView):   
    def post(self, request):

        userid = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=userid)

        options = Options()
        options.add_argument("--headless")
        options.add_argument("window-size=1400,1500")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("start-maximized")
        options.add_argument("enable-automation")
        options.add_argument("--disable-infobars")
        options.add_argument("--disable-dev-shm-usage")

        if not user:
            return Response({"Message":"User not Found!!!!"})

        product = request.data.get('product_name')

        if not product:
            return Response({'Message': 'Please provide product_name'}, status=status.HTTP_400_BAD_REQUEST)

        product_name = str(product).replace(' ','+')
        try:
            url = f"https://www.google.com/search?q={product_name}&sa=X&sca_esv=bb6fb22019ea88f6&sca_upv=1&hl=en&tbm=shop&ei=hBOEZvy0OoWavr0P8rqW6Ak&ved=0ahUKEwj8ht6WzYiHAxUFja8BHXKdBZ0Q4dUDCAg&uact=5&oq=chopping+knife&gs_lp=Egtwcm9kdWN0cy1jYyIOY2hvcHBpbmcga25pZmUyBRAAGIAEMgUQABiABDIFEAAYgAQyBhAAGBYYHjIGEAAYFhgeMgYQABgWGB4yBhAAGBYYHjIGEAAYFhgeMgYQABgWGB4yBhAAGBYYHkibHFCaBliOGnABeACQAQCYAa0BoAHWEKoBBDEuMTW4AQPIAQD4AQGYAhGgAoIRwgIKEAAYgAQYQxiKBZgDAIgGAZIHBDIuMTWgB_BL&sclient=products-cc#spd=14118574038044825156"
            driver = Chrome(options=options)
            driver.get(url)
            
            # time.sleep(3)
            data = driver.page_source
            driver.quit()
            
            html_content = data
            
            # Parse the HTML content
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Initialize a list to store the product details
            products = []
            
            # Extract product details
            product_grid = soup.find_all('div', class_='sh-dgr__gr-auto sh-dgr__grid-result')
            for product in product_grid:
                product_name = product.find('h3', class_='tAxDx').get_text(strip=True) if product.find('h3', class_='tAxDx') else None
                # product_title = product_name  # Assuming the name and title are the same
                
                price_span = product.find('span', class_='a8Pemb OFFNJ')
                price = price_span.get_text(strip=True) if price_span else None
                
                website_span = product.find('div', class_='aULzUe IuHnof')
                website_name = website_span.get_text(strip=True) if website_span else None
                
                link_tag = product.find('a', class_='shntl')
                link = link_tag['href'] if link_tag else None

                if link and link.startswith('/url?url='):
                    parsed_url = urllib.parse.parse_qs(urllib.parse.urlparse(link).query)
                    link = parsed_url['url'][0] if 'url' in parsed_url else link
            
                products.append({
                    'Product Name': product_name,
                    # 'Title': product_title,
                    'Price': price,
                    'Website Name': website_name,
                    'Link': link
                })
            # return products
        
            return Response({'Message': 'Fetch the Product data Successfully', "Product_data" : products}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'Message': f'Unable to fetch the Product data: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class oxylabSearchView(APIView):   
    def post(self, request):

        userid = get_user_id_from_token(request)
        user = CustomUser.objects.filter(id=userid)

        if not user:
            return Response({"Message":"User not Found!!!!"})

        query = request.data.get("query")

        if not query:
            return Response({'Message': 'Please provide query to search'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            oxy_account = oxylab_account.objects.get(id=1)
            username = oxy_account.username
            password = oxy_account.password
        except oxylab_account.DoesNotExist:
            return Response({'Message': 'Error in oxylabs credential '}, status=status.HTTP_400_BAD_REQUEST)

        query_main = str(query).replace(" ","+")

        try:
            # Structure payload.
            payload = {
                'source': 'google_shopping_search',
                'domain': 'com',
                'query': query_main,
                'pages': 4,
                'parse': True,
                'context': [
                    {'key': 'sort_by', 'value': 'pd'},
                    {'key': 'min_price', 'value': 1},
                ],
            }

            # Get response.
            response = requests.request(
                'POST',
                'https://realtime.oxylabs.io/v1/queries',
                auth=(f'{username}', f'{password}'),
                json=payload,
            )

            time.sleep(2)

            # Print prettified response to stdout.
            data =response.json()
            shopping_data=[]


            for i in range(len(data['results'])):
                organic_results = data['results'][i]['content']['results']['organic']
                for item in organic_results:
                    try:
                        # Fix the main URL
                        # item['url'] = self.fix_url(item['url'])
                        # Fix the merchant URL if it exists
                        if 'merchant' in item and 'url' in item['merchant']:
                            item['merchant']['url'] = self.fix_url(item['merchant']['url'])
                    except Exception as e:
                        print(f"Error parsing URL for item: {e}")
                        # If there is an error, leave the URL as it is
                    shopping_data.append(item)



            # for i in range(len(data['results'])):
            #     organic_results = data['results'][i]['content']['results']['organic']
            #     for item in organic_results:
            #         # Fix the main URL
            #         # item['url'] = self.fix_url(item['url'])
            #         # Fix the merchant URL if it exists
            #         if 'merchant' in item and 'url' in item['merchant']:
            #             item['merchant']['url'] = self.fix_url(item['merchant']['url'])
            #         shopping_data.append(item)
            print(response.text)
            
            return Response({'Message': 'Fetch the Product data Successfully', "Product_data" : shopping_data}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'Message': f'Unable to fetch the Product data: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

    @staticmethod
    def fix_url(encoded_url):
        parsed_url = urlparse(encoded_url)
        query_params = parse_qs(parsed_url.query)
        if 'url' in query_params:
            return query_params['url'][0]
        return encoded_url
