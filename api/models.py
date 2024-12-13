from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
import uuid
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from django.utils.crypto import get_random_string


class IYS(models.Model):
    phone = models.CharField(verbose_name="Telefon", max_length=11, default="99999999999", blank=True)
    message_permission_by_phone = models.BooleanField(default=False, verbose_name="Telefon İzni")
    message_permission_by_phone_timestamp = models.DateTimeField(default=timezone.now, blank=True, editable=True)
    message_permission_by_email = models.BooleanField(default=False, verbose_name="E-posta İzni")
    message_permission_by_email_timestamp = models.DateTimeField(default=timezone.now, blank=True, editable=True)
    message_permission_by_sms = models.BooleanField(default=False, verbose_name="Sms İzni")
    message_permission_by_sms_timestamp = models.DateTimeField(default=timezone.now, blank=True, editable=True)

    def __str__(self):
        return self.phone

    class Meta:
        verbose_name_plural = "IYS"


class CustomAccountManager(BaseUserManager):

    def create_superuser(self, phone, password, **other_fields):

        other_fields.setdefault('is_staff', True)
        other_fields.setdefault('is_superuser', True)
        other_fields.setdefault('is_active', True)

        if other_fields.get('is_staff') is not True:
            raise ValueError(
                'Superuser must be assigned to is_staff=True.')
        if other_fields.get('is_superuser') is not True:
            raise ValueError(
                'Superuser must be assigned to is_superuser=True.')

        return self.create_user(phone, password, **other_fields)

    def create_user(self, phone, password, **other_fields):

        user = self.model(phone=phone, **other_fields)
        user.set_password(password)
        user.save()
        return user


class Vehicles(models.Model):
    plate = models.CharField(max_length=8, blank=True, default="")
    phone = models.CharField(verbose_name="Telefon", max_length=11, default="99999999999", blank=True)
    timestamp = models.DateTimeField(default=timezone.now, verbose_name="Timestamp")
    picked_at = models.DateTimeField(verbose_name="Aracı Alma Zamanı", null=True, blank=True)

    def __str__(self):
        return self.plate

    class Meta:
        verbose_name_plural = "Vehicles"


class CustomUser(AbstractBaseUser, PermissionsMixin):
    user_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tckn = models.CharField(verbose_name="TC No", max_length=11, default="11111111111")
    phone = models.CharField(verbose_name="Telefon", max_length=11, unique=True)
    email = models.EmailField(_('email address'), blank=True, default='')
    name = models.CharField(max_length=50, blank=True, default='')
    surname = models.CharField(max_length=50, blank=True, default='')
    address = models.TextField(verbose_name="Adres", blank=True, default="")
    iys = models.ForeignKey(IYS, verbose_name="IYS",
                            on_delete=models.CASCADE, blank=True, null=True)
    start_date = models.DateTimeField(default=timezone.now, blank=True, verbose_name="Kayıt Tarihi")
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    status = models.CharField(max_length=1, choices=[('1', 'Active'), ('2', 'Inactive'), ('3', 'Passive'),
                                                     ('4', 'Pending')], default="4", blank=True)
    user_type = models.CharField(max_length=1, choices=[('1', 'Şoför'), ('2', 'Admin'),
                                                        ('3', 'Saha Operasyon')], default="1")
    kvkk = models.BooleanField(default=False)
    kvkk_timestamp = models.DateTimeField(default=timezone.now, blank=True, editable=True,
                                          verbose_name="KVKK Timestamp")
    aydinlatma = models.BooleanField(default=False)
    aydinlatma_timestamp = models.DateTimeField(default=timezone.now, blank=True, editable=True,
                                                verbose_name="Aydınlatma Timestamp")
    calisma_ruhsat_no = models.CharField(verbose_name="Çalışma Ruhsat No",
                                         max_length=6, default="111111")
    sozlesme_no = models.CharField(verbose_name="Sözleşme No",
                                   max_length=8, blank=True, null=True)
    balance = models.DecimalField(blank=True, max_digits=8, decimal_places=2,
                                  default=0, verbose_name='Bakiye')
    vehicles = models.ManyToManyField(Vehicles, blank=True)

    objects = CustomAccountManager()

    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = ['tckn']

    def __str__(self):
        return self.phone

    @staticmethod
    def create_random_alphanumeric():
        rnd = get_random_string(8, 'abcdefghijklmnoprstuvyz0123456789')
        stop = False
        while not stop:
            if CustomUser.objects.filter(sozlesme_no=rnd).exists():
                rnd = get_random_string(8, 'abcdefghijklmnoprstuvyz0123456789')
            else:
                return rnd

    def save(self, *args, **kwargs):
        if self.sozlesme_no is None or self.sozlesme_no == "":
            self.sozlesme_no = self.create_random_alphanumeric()
        super(CustomUser, self).save(*args, **kwargs)


class DailyBalanceInfo(models.Model):
    phone = models.CharField(verbose_name="Telefon", max_length=11, default="99999999999", blank=True)
    tckn = models.CharField(verbose_name="TC No", max_length=11, default="11111111111")
    balance = models.DecimalField(max_length=50, blank=True, max_digits=8, decimal_places=2,
                                  default=0.00, verbose_name='Bakiye')
    timestamp = models.DateTimeField(default=timezone.now, verbose_name="Timestamp")


class EndOfDay(models.Model):
    uploaded_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(default=timezone.now)
    url = models.TextField(blank=True, default='', verbose_name="URL")
    key = models.CharField(blank=True, default='', max_length=30)

    def save(self, *args, **kwargs):
        self.expires_at = self.uploaded_at + timezone.timedelta(days=7)
        super(EndOfDay, self).save(*args, **kwargs)


class OtpPassword(models.Model):
    related_user = models.ForeignKey("api.CustomUser", verbose_name="Kullanıcı",
                                     on_delete=models.CASCADE, blank=True, null=True)
    verification_code = models.CharField(max_length=50, verbose_name="OTP Şifresi")
    is_used = models.BooleanField(blank=True, verbose_name="is_used", default=False)
    timestamp = models.DateTimeField(default=timezone.now, verbose_name="Timestamp")


class PaymentSession(models.Model):
    OrderID = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=True)
    UserHash = models.ForeignKey(CustomUser, verbose_name="Kullanıcı",
                                 on_delete=models.CASCADE, blank=True, null=True)
    PaymentSessionToken = models.CharField(max_length=16, verbose_name="PaymentSessionToken",
                                           blank=True, default="")
    Amount = models.DecimalField(blank=True, null=True, max_digits=6, decimal_places=2, verbose_name='Toplam Tutar')
    CurrencyCode = models.CharField(max_length=5, blank=True, default='TRY')
    TransactionType = models.CharField(max_length=10, choices=[('Sale', 'Sale')], blank=True, default='Sale')
    is_used = models.BooleanField(blank=True, verbose_name="is_used", default=False)
    timestamp = models.DateTimeField(default=timezone.now, verbose_name="Timestamp")
    plate = models.CharField(max_length=8, blank=True, default="")

    def __str__(self):
        return str(self.OrderID) + f"({self.PaymentSessionToken})"


class VoidRefundSession(models.Model):
    payment_session = models.ForeignKey(PaymentSession, verbose_name="Payment Session",
                                        on_delete=models.CASCADE, blank=True, null=True)
    OrderID = models.CharField(blank=True, default="", editable=True, max_length=40)
    PaymentSessionToken = models.CharField(max_length=16, verbose_name="PaymentSessionToken",
                                           blank=True, default="")
    TransactionType = models.CharField(max_length=10, choices=[('Void', 'Void'), ('Refund', 'Refund')],
                                       blank=True, default='Void')
    is_used = models.BooleanField(blank=True, verbose_name="is_used", default=False)
    timestamp = models.DateTimeField(default=timezone.now, verbose_name="Timestamp")
    plate = models.CharField(max_length=8, blank=True, default="")

    def __str__(self):
        return str(self.OrderID) + f"({self.PaymentSessionToken})"


class AdditionalAmounts(models.Model):
    payment_session = models.ForeignKey(PaymentSession, verbose_name="Payment Session",
                                        on_delete=models.CASCADE, blank=True, null=True)
    Amount = models.DecimalField(verbose_name="Hizmet Bedeli",
                                 max_digits=6, decimal_places=2, default=0, blank=True)
    Caption = models.CharField(max_length=50, blank=True, null=True)
    IntegrationKey = models.CharField(max_length=50, blank=True, default='Key')

    class Meta:
        verbose_name_plural = "Additional amounts"


class Deeplink(models.Model):
    payment_session = models.ForeignKey(PaymentSession, verbose_name="İlgili Payment Session",
                                        on_delete=models.CASCADE, blank=True, null=True)
    void_refund_session = models.ForeignKey(VoidRefundSession, verbose_name="İlgili Void Session",
                                            on_delete=models.CASCADE, blank=True, null=True)
    data = models.JSONField(verbose_name="data", null=True, blank=True)
    Approved = models.BooleanField(null=True, blank=True, verbose_name="Onaylandı")
    IsVoidable = models.BooleanField(null=True, blank=True, verbose_name="IsVoidable")
    IsRefundable = models.BooleanField(null=True, blank=True, verbose_name="IsRefundable")
    Status = models.CharField(max_length=2, blank=True, default='')
    timestamp = models.DateTimeField(default=timezone.now, verbose_name="Timestamp")
    TransactionType = models.CharField(max_length=10, choices=[('Sale', 'Sale'), ('Void', 'Void'),
                                                               ('Refund', 'Refund')], blank=True, default='Sale')
    hashData = models.TextField(blank=True, default='', verbose_name="hashData")

    def __str__(self):
        if self.TransactionType == 'Sale':
            return str(self.payment_session)
        else:
            return str(self.void_refund_session)


class WebhookData(models.Model):
    payment_session = models.ForeignKey(PaymentSession, verbose_name="İlgili Payment Session",
                                        on_delete=models.CASCADE, blank=True, null=True)
    void_refund_session = models.ForeignKey(VoidRefundSession, verbose_name="İlgili Void Session",
                                            on_delete=models.CASCADE, blank=True, null=True)
    data = models.JSONField(verbose_name="data", null=True, blank=True)
    Approved = models.BooleanField(null=True, blank=True, verbose_name="Onaylandı")
    IsVoidable = models.BooleanField(null=True, blank=True, verbose_name="IsVoidable")
    IsRefundable = models.BooleanField(null=True, blank=True, verbose_name="IsRefundable")
    Status = models.CharField(max_length=2, blank=True, default='3')
    timestamp = models.DateTimeField(default=timezone.now, verbose_name="Timestamp")
    TransactionType = models.CharField(max_length=10, choices=[('Sale', 'Sale'), ('Void', 'Void'),
                                                               ('Refund', 'Refund')], blank=True, default='Sale')
    hashData = models.TextField(blank=True, default='', verbose_name="hashData")

    # def __str__(self):
    #     if self.TransactionType == 'Sale':
    #         return str(self.payment_session.OrderID)
    #     else:
    #         return str(self.void_refund_session.OrderID)


class PosAuthorize(models.Model):
    Token = models.TextField(blank=True, default='', verbose_name="Token")
    timestamp = models.DateTimeField(default=timezone.now, verbose_name="Timestamp")


class PortalAuthorize(models.Model):
    access_token = models.TextField(blank=True, default='', verbose_name="access_token")
    timestamp = models.DateTimeField(default=timezone.now, verbose_name="Timestamp")


class ServerStatus(models.Model):
    version = models.CharField(max_length=8, blank=True, default='', verbose_name="Versiyon")
    message = models.CharField(max_length=150, blank=True, default='', verbose_name="Mesaj")
    status = models.CharField(max_length=5, choices=[('200', '200'), ('300', '300')], blank=True,
                              default='200', verbose_name="Status")
    timestamp = models.DateTimeField(default=timezone.now, verbose_name="Timestamp")

    class Meta:
        verbose_name_plural = "Server statuses"


class Receipt(models.Model):
    OrderID = models.CharField(blank=True, default="", editable=False, max_length=40)
    MerchantID = models.CharField(max_length=20, blank=True, default='', verbose_name="MerchantID")
    TerminalID = models.CharField(max_length=20, blank=True, default='', verbose_name="TerminalID")
    CardNumber = models.CharField(max_length=16, blank=True, default='', verbose_name="CardNumber")
    AuthorizationCode = models.CharField(max_length=16, blank=True, default='', verbose_name="AuthorizationCode")
    OperationName = models.CharField(max_length=16, blank=True, default='', verbose_name="OperationName")
    Status = models.CharField(max_length=16, blank=True, default='', verbose_name="Status")
    Response = models.CharField(max_length=16, blank=True, default='', verbose_name="Response")
    Message = models.CharField(max_length=50, blank=True, default='', verbose_name="Message")
    RRN = models.CharField(max_length=16, blank=True, default='', verbose_name="RRN")
    ApplicationLabel = models.CharField(max_length=25, blank=True, default='', verbose_name="ApplicationLabel")
    AID = models.CharField(max_length=16, blank=True, default='', verbose_name="AID")
    DriverAmount = models.DecimalField(blank=True, max_digits=6, decimal_places=2, verbose_name='Taksimetre Tutarı',
                                       default=0)
    AdditionalAmount = models.DecimalField(verbose_name="İşlem Ücreti",
                                           max_digits=6, decimal_places=2, default=0, blank=True)
    TransactionDate = models.CharField(max_length=25, blank=True, default='', verbose_name="TransactionDate")
    plate = models.CharField(max_length=8, blank=True, default="")

    def __str__(self):
        return self.OrderID


class MobileTransactionHistory(models.Model):
    phone = models.CharField(verbose_name="Telefon", max_length=11, default="99999999999", blank=True)
    name = models.CharField(max_length=50, blank=True, default='')
    surname = models.CharField(max_length=50, blank=True, default='')
    deeplink = models.ForeignKey(Deeplink, verbose_name="Deeplink Data",
                                 on_delete=models.CASCADE, blank=True, null=True)
    webhook = models.ForeignKey(WebhookData, verbose_name="Webhook Data",
                                on_delete=models.CASCADE, blank=True, null=True)
    OrderID = models.CharField(blank=True, default="", editable=False, max_length=40)
    success = models.BooleanField(null=True, blank=True, verbose_name="Success")
    TransactionDate = models.CharField(max_length=26, blank=True, default='', verbose_name="TransactionDate")
    DriverAmount = models.DecimalField(blank=True, max_digits=6, decimal_places=2, verbose_name='Taksimetre Tutarı',
                                       default=0)
    IsVoidable = models.BooleanField(null=True, blank=True, verbose_name="IsVoidable")
    IsRefundable = models.BooleanField(null=True, blank=True, verbose_name="IsRefundable")
    detail = models.ForeignKey(Receipt, verbose_name="Receipt",
                               on_delete=models.CASCADE, blank=True, null=True)
    QRLink = models.URLField(verbose_name="QRLink", blank=True, default="https://banapos.com/qr/?")
    start_time = models.DateTimeField(blank=True, null=True, verbose_name="Başlangıç")
    end_time = models.DateTimeField(blank=True, null=True, verbose_name="Bitiş")
    TransactionType = models.CharField(max_length=10, blank=True, null=True)
    ProcessType = models.CharField(max_length=10, blank=True, null=True,
                                   choices=[('Online', 'Online'), ('Offline', 'Offline')])
    plate = models.CharField(max_length=8, blank=True, default="")

    class Meta:
        verbose_name_plural = "Mobile Transaction Histories"


class PaymentLocation(models.Model):
    payment_session = models.ForeignKey(PaymentSession, verbose_name="Payment Session",
                                        on_delete=models.CASCADE, blank=True, null=True)
    void_refund_session = models.ForeignKey(VoidRefundSession, verbose_name="İlgili Void Session",
                                            on_delete=models.CASCADE, blank=True, null=True)
    lat = models.CharField(max_length=15, blank=True, default='', verbose_name="lat")
    lon = models.CharField(max_length=15, blank=True, default='', verbose_name="lon")
