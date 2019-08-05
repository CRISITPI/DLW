from dlw.models import testc
from rest_framework import serializers

class testSerializer(serializers.ModelSerializer):
    class Meta:
        model=testc
        # fields=('id','subject','targetone','targettwo')
        fields = '__all__'