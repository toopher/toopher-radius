from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
import datetime
import pytz


class ToopherRadiusAdminSettings:
    
    toopher_consumer_key = models.CharField('Toopher Consumer Key', max_length=50, null=True)
    toopher_consumer_secret = models.CharField('Toopher Consumer Secret', max_length=50, null=True)
    toopher_api_address = models.CharField('Toopher API Endpoint', max_length=50, null=False, default="https://toopher-api.appspot.com")
    
    