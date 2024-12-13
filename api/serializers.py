from rest_framework import serializers
from api.models import CustomUser, IYS, Vehicles, Receipt, MobileTransactionHistory, EndOfDay
from django.utils import timezone
from rest_framework.exceptions import NotAcceptable
from rest_framework import status


class IYSSerializer(serializers.ModelSerializer):
    class Meta:
        model = IYS
        fields = ('message_permission_by_phone',
                  'message_permission_by_email',
                  'message_permission_by_sms')


class VehiclesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Vehicles
        fields = ('plate',)


class UserRegisterSerializer(serializers.ModelSerializer):
    iys = IYSSerializer(required=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    phone = serializers.CharField(required=True, min_length=11, max_length=11)
    tckn = serializers.CharField(required=True, min_length=11, max_length=11)
    name = serializers.CharField(required=True)
    surname = serializers.CharField(required=True)
    kvkk = serializers.BooleanField(required=True)
    aydinlatma = serializers.BooleanField(required=True)
    password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)
    vehicles = VehiclesSerializer(required=True, many=True)

    class Meta:
        model = CustomUser
        fields = ('phone', 'email', 'tckn', 'name', 'surname', 'password', 'confirm_password', 'vehicles',
                  'kvkk', 'aydinlatma', 'iys')
        extra_kwargs = {'password': {'write_only': True}, 'confirm_password': {'write_only': True}}

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        confirm_password = validated_data.pop('confirm_password', None)
        if password != confirm_password:
            raise NotAcceptable(detail="Şifreler eşleşmiyor!")
        
        phone = validated_data['phone']
        iys_data = validated_data.pop('iys')
        vehicles_data = validated_data.pop('vehicles', None)

        if password is not None:
            iys_instance = IYS.objects.create(**iys_data, phone=phone)
            instance = CustomUser.objects.create(iys=iys_instance, **validated_data)
            instance.set_password(password)
            for vehicle in vehicles_data:
                plate = vehicle['plate']
                plate = str.upper(plate)
                vehicle_instance, created = Vehicles.objects.get_or_create(plate=plate)
                instance.vehicles.add(vehicle_instance)

            instance.save()
            iys_instance.phone = instance.phone
            iys_instance.save()
            return instance


class UserInfoSerializer(serializers.ModelSerializer):
    iys = IYSSerializer()

    class Meta:
        model = CustomUser
        fields = ('user_id', 'status', 'tckn', 'phone', 'email', 'name', 'surname',
                  'address', 'start_date', 'iys')


class MobileUserUpdateSerializer(serializers.ModelSerializer):
    iys = IYSSerializer()

    class Meta:
        model = CustomUser
        fields = ('email', 'name', 'surname', 'iys')

    def update(self, instance, validated_data):

        if "email" in validated_data:
            if CustomUser.objects.filter(email=validated_data['email']).exists():
                raise serializers.ValidationError("Bu e-posta ile bir hesap mevcut!")
            else:
                instance.email = validated_data['email']

        if "iys" in validated_data:
            iys_data = validated_data.pop('iys')
            for key, value in iys_data.items():
                if key == 'message_permission_by_phone':
                    if instance.iys.message_permission_by_phone != value:
                        instance.iys.message_permission_by_phone = value
                        instance.iys.message_permission_by_phone_timestamp = timezone.now()
                    else:
                        continue
                elif key == 'message_permission_by_email':
                    if instance.iys.message_permission_by_email != value:
                        instance.iys.message_permission_by_email = value
                        instance.iys.message_permission_by_email_timestamp = timezone.now()
                    else:
                        continue

                elif key == 'message_permission_by_sms':
                    if instance.iys.message_permission_by_sms != value:
                        instance.iys.message_permission_by_sms = value
                        instance.iys.message_permission_by_sms_timestamp = timezone.now()
                    else:
                        continue
            instance.iys.save()

        for key, value in validated_data.items():
            setattr(instance, key, value)

        instance.save()

        return instance


class DashboardUserUpdateSerializer(serializers.ModelSerializer):
    message_permission_by_phone = serializers.BooleanField(source="iys.message_permission_by_phone", required=False)
    message_permission_by_sms = serializers.BooleanField(source="iys.message_permission_by_sms", required=False)
    message_permission_by_email = serializers.BooleanField(source="iys.message_permission_by_email", required=False)
    message_permission_by_phone_timestamp = serializers.DateTimeField(source="iys.message_permission_by_phone_timestamp"
                                                                      , required=False)
    message_permission_by_sms_timestamp = serializers.DateTimeField(source="iys.message_permission_by_sms_timestamp",
                                                                    required=False)
    message_permission_by_email_timestamp = serializers.DateTimeField(source="iys.message_permission_by_email_timestamp"
                                                                      , required=False)

    class Meta:
        model = CustomUser
        fields = ('email', 'name', 'surname', 'calisma_ruhsat_no', 'address', 'kvkk', 'kvkk_timestamp', 'aydinlatma',
                  'aydinlatma_timestamp', 'tckn', 'message_permission_by_phone',
                  'message_permission_by_phone_timestamp',
                  'message_permission_by_email', 'message_permission_by_email_timestamp', 'message_permission_by_sms',
                  'message_permission_by_sms_timestamp')

    def update(self, instance, validated_data):
        print(validated_data)
        if "iys" in validated_data:
            iys_data = validated_data.pop('iys')
            for key, value in iys_data.items():
                if key == 'message_permission_by_phone':
                    if instance.iys.message_permission_by_phone != value:
                        instance.iys.message_permission_by_phone = value
                        instance.iys.message_permission_by_phone_timestamp = timezone.now()
                    else:
                        continue
                elif key == 'message_permission_by_email':
                    if instance.iys.message_permission_by_email != value:
                        instance.iys.message_permission_by_email = value
                        instance.iys.message_permission_by_email_timestamp = timezone.now()
                    else:
                        continue
                elif key == 'message_permission_by_sms':
                    if instance.iys.message_permission_by_sms != value:
                        instance.iys.message_permission_by_sms = value
                        instance.iys.message_permission_by_sms_timestamp = timezone.now()
                    else:
                        continue
            instance.iys.save()

        for key, value in validated_data.items():
            if key == 'kvkk':
                if instance.kvkk != value:
                    instance.kvkk_timestamp = timezone.now()
                else:
                    continue
            elif key == 'aydinlatma':
                if instance.aydinlatma != value:
                    instance.aydinlatma_timestamp = timezone.now()
                else:
                    continue

            setattr(instance, key, value)

        instance.save()
        return instance


class UserListSerializer(serializers.ModelSerializer):
    status = serializers.CharField(source="get_status_display")
    user_type = serializers.CharField(source='get_user_type_display')

    class Meta:
        model = CustomUser
        fields = ('user_id', 'phone', 'user_type', 'name', 'surname', 'status', 'last_login')


class UserDetailSerializer(serializers.ModelSerializer):
    user_type = serializers.CharField(source='get_user_type_display')
    status = serializers.CharField(source="get_status_display")
    message_permission_by_phone = serializers.BooleanField(source="iys.message_permission_by_phone")
    message_permission_by_sms = serializers.BooleanField(source="iys.message_permission_by_sms")
    message_permission_by_email = serializers.BooleanField(source="iys.message_permission_by_email")
    message_permission_by_phone_timestamp = serializers.DateTimeField(source="iys.message_permission_by_phone_timestamp"
                                                                      , required=False)
    message_permission_by_sms_timestamp = serializers.DateTimeField(source="iys.message_permission_by_sms_timestamp",
                                                                    required=False)
    message_permission_by_email_timestamp = serializers.DateTimeField(source="iys.message_permission_by_email_timestamp"
                                                                      , required=False)

    class Meta:
        model = CustomUser
        fields = ('user_id', 'phone', 'tckn', 'email', 'name', 'surname', 'status', 'user_type', 'calisma_ruhsat_no',
                  'sozlesme_no', 'address', 'balance', 'start_date', 'last_login',
                  'kvkk', 'kvkk_timestamp', 'aydinlatma', 'aydinlatma_timestamp', 'message_permission_by_phone',
                  'message_permission_by_phone_timestamp', 'message_permission_by_email',
                  'message_permission_by_email_timestamp', 'message_permission_by_sms',
                  'message_permission_by_sms_timestamp')


class ReceiptSerializer(serializers.ModelSerializer):
    class Meta:
        model = Receipt
        fields = ('MerchantID', 'TerminalID', 'CardNumber', 'AuthorizationCode', 'TransactionDate', 'OperationName',
                  'Status', 'Response', 'Message', 'RRN', 'ApplicationLabel', 'AID', 'DriverAmount', 'AdditionalAmount',
                  'plate')


# Plate ekle
class TransactionHistorySerializer(serializers.ModelSerializer):
    detail = ReceiptSerializer()

    class Meta:
        model = MobileTransactionHistory
        fields = ('OrderID', 'success', 'TransactionType', 'TransactionDate', 'DriverAmount', 'IsVoidable',
                  'IsRefundable', 'QRLink', 'detail')


class DashboardAllTransactionsSerializer(serializers.ModelSerializer):
    Status = serializers.CharField(source="deeplink.Status")
    start_time = serializers.DateTimeField(format="%d-%m-%Y %H:%M:%S")
    end_time = serializers.DateTimeField(format="%d-%m-%Y %H:%M:%S")

    class Meta:
        model = MobileTransactionHistory
        fields = ('phone', 'OrderID', 'name', 'surname', 'success', 'Status', 'DriverAmount',
                  'IsVoidable', 'IsRefundable', 'TransactionType', 'start_time', 'end_time', 'plate', 'Status')


class DashboardTransactionHistorySerializer(serializers.ModelSerializer):
    Status = serializers.CharField(source="deeplink.Status")
    start_time = serializers.DateTimeField(format="%d-%m-%Y %H:%M:%S")
    end_time = serializers.DateTimeField(format="%d-%m-%Y %H:%M:%S")

    class Meta:
        model = MobileTransactionHistory
        fields = ('OrderID', 'success', 'Status', 'DriverAmount', 'IsVoidable', 'IsRefundable', 'TransactionType',
                  'start_time', 'end_time', 'plate', 'Status')


class DashboardTransactionDetailSerializer(serializers.ModelSerializer):
    detail = ReceiptSerializer()
    Status = serializers.CharField(source="deeplink.Status")
    end_time = serializers.DateTimeField(format="%d-%m-%Y %H:%M:%S")

    class Meta:
        model = MobileTransactionHistory
        fields = ('OrderID', 'name', 'surname', 'success', 'DriverAmount', 'IsVoidable', 'IsRefundable', 'end_time',
                  'QRLink', 'detail', 'plate', 'Status')


class AllCashOutsSerializer(serializers.ModelSerializer):
    class Meta:
        model = EndOfDay
        fields = ('url', 'key', 'uploaded_at', 'expires_at')
