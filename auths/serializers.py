from rest_framework import serializers
from .models import CustomUser
import random, string
# from django.contrib.postgres.fields import JSONField
def generate_random_string(length=15):
    letters = string.ascii_letters  # includes uppercase and lowercase letters
    return ''.join(random.choice(letters) for _ in range(length))
  
class UserRegistrationSerializer(serializers.ModelSerializer):
      """ 
      This serializer will help to create new user's registration data and validate the password.
      """
      class Meta:
          model = CustomUser
          fields = (
                  '__all__'
              )

      def validate(self, attrs):
        password = attrs.get('password')
        #password2 = attrs.get('password2')
        if len(password) <= 8: 
            errors = "password length should be more than 8 characters."
            raise serializers.ValidationError({"password":[errors]})
        
        return attrs


      def create(self, validated_data):
        created_user =CustomUser.objects.create_user(
            username = generate_random_string(),
            email = validated_data.get('email'),
            name = validated_data.get('name'),
            password= validated_data.get('password')
          )
        return created_user

class UserLoginSerializer(serializers.ModelSerializer):
  """ 
  A serializer for login user
  """
  email = serializers.EmailField(max_length=255)
  class Meta:
      model = CustomUser
      fields = ['email', 'password']

class UserProfileSerializer(serializers.ModelSerializer):
    """ 
    Get a login user's data and send data
    """
    class Meta:
        model = CustomUser
        fields =['email','name','is_user_verified','credit','created']

        

# # --------------Code by ADIL---------------------------------------------------
class UserChangePasswordSerializer(serializers.Serializer):
    """ 
    Serializer for changing user password
    """
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')

        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password don't match")
        
        # Check if the new password is at least 8 characters long
        if len(password) <= 8:
            errors = "password length should be more than 8 characters."
            raise serializers.ValidationError({"password":[errors]})
        
        if len(password2) <= 8:
            errors = "password length should be more than 8 characters."
            raise serializers.ValidationError({"password":[errors]})

        return attrs

    def update(self, instance, validated_data):
        instance.set_password(validated_data['password'])
        instance.save()
        return instance        

# # --------------Code by ADIL---------------------------------------------------



class UserModifyPasswordSerializer(serializers.Serializer):
    """ 
    Serializer for changing user password.
    """
    old_password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    new_password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    def validate(self, attrs):
        old_password = attrs.get('old_password')
        new_password = attrs.get('new_password')

        # Check if both old and new passwords are provided
        # if not old_password:
        #     raise serializers.ValidationError("Old password is required.")
        # if not new_password:
        #     raise serializers.ValidationError("New password is required.")
        # errors = {}
        # # Check if the new password is at least 8 characters long
        # if len(new_password) < 8:
        #     raise serializers.ValidationError("password length must be minimum 8 characters.")

        # Check if both old and new passwords are provided
        errors=''
        if not old_password:
            errors = "Old password is required."
            raise serializers.ValidationError({"errors":{"password":errors}})
        if not new_password:
            errors = "New password is required."
            raise serializers.ValidationError({"errors":{"password":errors}})
        elif len(new_password) <= 8:
            errors= "password length should be more than 8 characters."
            raise serializers.ValidationError({"errors":{"password":[errors]}})

        # if errors:
        #     raise serializers.ValidationError({"errors":{"password":errors}})

        return attrs
    
    def update(self, instance, validated_data):
        instance.set_password(validated_data['new_password'])
        instance.save()
        return instance