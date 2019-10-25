from django.db import models

class files(models.Model):
    apache1 = models.FileField(null=True)
    envvars = models.FileField(null=True)
    security = models.FileField(null=True)