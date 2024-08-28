from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.validators import MinValueValidator

# ------------------------copied from keywordlit project------------------------------------------------------------------------------

class TimeStampModel(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


# --------------------------------------------UserManager Code By Adil-------------------------------------------------------------
class UserManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        """ 
        Create a normal user instead of super user with his/ her personal details.
        """
        if not email:
            raise ValueError('User must have an email address')
        if not username:
            raise ValueError('User must have a username')

        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Superuser must have an email address')

        email = self.normalize_email(email)
        #user = self.model(email=email, username=email, is_staff=True, is_superuser=True, **extra_fields)
        user = self.model(email=email, is_staff=True, is_superuser=True, **extra_fields)
        #user = self.model(email=email, is_admin = True, is_staff=True, is_superuser=True, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    


#-----------------------------------------------------Code BY Adil-------------------------------------------------------------
class CustomUser(AbstractUser,TimeStampModel):
    """ 
    This models is create to store and edit the New registered User's Data and edit Django defualt User authentication 
    """

    id = models.BigAutoField(primary_key=True)
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=25)
    verification_code = models.BigIntegerField(null=True, blank=True)
    is_user_verified = models.BooleanField(default=False)
    credit = models.BigIntegerField(default=100)
    #Mobile_number = models.IntegerField(default=0)
    #gender = models.CharField(max_length=25, choices=GENDER, null=True, blank=True)
    # profile_photo = models.ImageField(upload_to='profile_pic/', blank=True, null=True) #default='default-user-profile.jpg')
    stripe_customer_id = models.CharField(max_length=255, blank=True, null=True)  # Added for Stripe
    is_subscribed = models.BooleanField(default=False)  # Added for Stripe
    #membership = models.ForeignKey(Membership, null=True, blank=True, on_delete=models.SET_NULL)  # Added for Stripe
    membership_expiry = models.DateTimeField(null=True, blank=True)  
    REQUIRED_FIELDS = ["email","is_user_verified"]

    objects = UserManager()

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_staff

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True 
    
class oxylab_account(TimeStampModel):
    STATUS = (
        ('ACTIVE','ACTIVE'),
        ('INACTIVE','INACTIVE'),
    )
    username = models.CharField(max_length=100)
    password = models.CharField(max_length=100)
    busy = models.BooleanField(default=False)
    status = models.CharField(max_length=25,choices=STATUS,default='ACTIVE')

class search_history(TimeStampModel):
    query = models.CharField(max_length=300)
    product_id = models.CharField(max_length=300)
    google_url = models.URLField()
    seller_name = models.CharField(max_length=250)
    seller_url = models.URLField()
    price = models.FloatField()
    product_title = models.TextField()
    rating = models.FloatField(null=True,blank=True)
    reviews_count = models.IntegerField(null=True,blank=True)
    product_pic = models.URLField(null=True,blank=True)
    currency = models.CharField(max_length=250, null=True, blank=True)
    delivery = models.CharField(max_length=250, null=True, blank=True)

class cart(TimeStampModel):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    product_id = models.CharField(max_length=300)
    quantity = models.IntegerField(default=1)
    product_name = models.TextField(null=True,blank=True)
    product_image = models.URLField(null=True,blank=True)
    price = models.FloatField(default=0.0)
    google_shopping_url = models.URLField(null=True,blank=True)
    seller_link = models.URLField(null=True,blank=True)
    seller_logo = models.URLField(null=True,blank=True)
    seller_name = models.CharField(max_length=250,null=True,blank=True)
    clicked = models.IntegerField(default=0)  # Field to track the number of clicks
    bought = models.BooleanField(default=False)  # Field to track if the product was bought

class saveforlater(TimeStampModel):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    product_id = models.CharField(max_length=300)
    quantity = models.IntegerField(default=1)
    product_name = models.TextField(null=True,blank=True)
    product_image = models.URLField(null=True,blank=True)
    price = models.FloatField(default=0.0)
    google_shopping_url = models.URLField(null=True,blank=True)
    seller_link = models.URLField(null=True,blank=True)
    seller_logo = models.URLField(null=True,blank=True)
    seller_name = models.CharField(max_length=250,null=True,blank=True)    

class orderhistory(TimeStampModel):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    product_id = models.CharField(max_length=300)
    quantity = models.IntegerField(default=1)
    product_name = models.TextField()
    product_image = models.URLField()
    price = models.FloatField()
    google_shopping_url = models.URLField()
    seller_link = models.URLField()
    seller_logo = models.URLField(null=True,blank=True)
    seller_name = models.CharField(max_length=250)
    clicked = models.IntegerField(default=0)  # Field to track the number of clicks
    bought = models.BooleanField(default=False)  # Field to track if the product was bought    



class category_model(TimeStampModel):
    category_name = models.CharField(max_length=250)
    mapping_name = models.CharField(max_length=600)
    title = models.TextField()
    category_image = models.ImageField(upload_to='category_images/',blank=True, null=True)
    icon = models.FileField(upload_to='category_icons/',blank=True, null=True)
    offer_text = models.TextField(blank=True, null=True)
    Cat_text1 = models.TextField(blank=True, null=True)
    Cat_text2 = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.category_name


    
#-----------------------------------------------------Code BY Adil-------------------------------------------------------------



# Specify unique related_name attributes for the reverse relationships
CustomUser._meta.get_field('groups').remote_field.related_name = 'customuser_groups'
CustomUser._meta.get_field('user_permissions').remote_field.related_name = 'customuser_user_permissions'