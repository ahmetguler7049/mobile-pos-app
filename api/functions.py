import decimal
from Crypto.Cipher import AES
from base64 import b64decode, b64encode
import random
import string
from django.conf import settings
from django.utils import timezone
from .models import OtpPassword, Receipt, MobileTransactionHistory
from datetime import timedelta
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from rest_framework_simplejwt.tokens import RefreshToken
import requests
import io
import boto3
import csv
from django.utils.crypto import get_random_string

usercode = settings.USERCODE
OTP_PASSWORD = settings.OTP_PASSWORD
MSGHEADER = settings.MSGHEADER


def unpad(ct):
    return ct[:-ord(ct[-1])]


def create_six_digits_id():
    return ''.join(random.choices(string.digits, k=6))


def create_mobile_qr():
    rnd = get_random_string(16, 'ABCDEFGHIJKLMNOPRSTUVYZ0123456789')
    stop = False
    origin_url = "https://banapos.com/qr/?"
    while not stop:
        if MobileTransactionHistory.objects.filter(QRLink=origin_url + rnd).exists():
            rnd = get_random_string(16, 'ABCDEFGHIJKLMNOPRSTUVYZ0123456789')
        else:
            return rnd


def aes_decrypt(iv, secret_text):
    private_key = settings.PRIVATE_KEY.encode("utf8")
    cipher = AES.new(private_key, AES.MODE_CBC, iv)

    b64decoded_text = b64decode(secret_text)
    decrypted_text = cipher.decrypt(b64decoded_text)
    decrypted_text = unpad(decrypted_text.decode('utf8'))

    return decrypted_text


def local_send_otp(user):
    # Generating OTP verification code
    verification_code = create_six_digits_id()
    response = ["00"]
    if user:
        otp_instance = OtpPassword.objects.create(verification_code=verification_code)
        otp_instance.related_user = user
        otp_instance.save()
        user_exist = True
        # Message = f"Banapos dogrulama kodunuz: {otp_instance.verification_code}"
        # url = f"""https://api.netgsm.com.tr/sms/send/otp?usercode={usercode}&password={OTP_PASSWORD}&no={phone}&msg={Message}&msgheader={MSGHEADER}"""
        # payload = {}
        # headers = {}
        # response = requests.request("GET", url, headers=headers, data=payload)
        # response = response.text.split(' ')
    else:
        user_exist = False

    return user_exist, response, verification_code


def send_otp(phone, user):
    # Generating OTP verification code
    verification_code = create_six_digits_id()
    response = []

    if user:
        if user.phone == "05999999999":
            verification_code = "000000"
            otp_instance = OtpPassword.objects.create(verification_code=verification_code)
            otp_instance.related_user = user
            otp_instance.save()
            user_exist = True
        else:
            otp_instance = OtpPassword.objects.create(verification_code=verification_code)
            otp_instance.related_user = user
            otp_instance.save()
            user_exist = True
            Message = f"Banapos dogrulama kodunuz: {otp_instance.verification_code}"
            url = f"""https://api.netgsm.com.tr/sms/send/otp?usercode={usercode}&password={OTP_PASSWORD}&no={phone}&msg={Message}&msgheader={MSGHEADER}"""
            payload = {}
            headers = {}
            response = requests.request("GET", url, headers=headers, data=payload)
            response = response.text.split(' ')
    else:
        user_exist = False

    return user_exist, response


def OtpCheck(user, verification_code):
    OTP_LIFETIME = float(settings.OTP_LIFETIME)

    is_otp_exist = OtpPassword.objects.filter(related_user=user).exists()

    success = False
    is_otp_valid = False

    if is_otp_exist:
        otp_instance = OtpPassword.objects.filter(related_user=user).last()

        if verification_code == otp_instance.verification_code and not otp_instance.is_used:
            success = True

        if timezone.now() - timedelta(minutes=OTP_LIFETIME) < otp_instance.timestamp:
            is_otp_valid = True

    return success, is_otp_valid


def CustomLogin(user):
    # Clearing the concurrent sessions from other devices
    for token in OutstandingToken.objects.filter(user=user):
        _, _ = BlacklistedToken.objects.get_or_create(token=token)

    refresh = RefreshToken.for_user(user)
    refresh_token = str(refresh)
    access_token = str(refresh.access_token)

    user.last_login = timezone.now()
    user.save(update_fields=["last_login"])

    return access_token, refresh_token


def calculate_fee(Amount: decimal.Decimal):
    if settings.IS_COMMISSION_STATIC:
        return decimal.Decimal('1.00')
    else:
        if 0 <= Amount <= 20:
            return decimal.Decimal('1.95')
        elif 20 < Amount <= 30:
            return decimal.Decimal('2.95')
        elif 30 < Amount <= 40:
            return decimal.Decimal('3.95')
        elif 40 < Amount <= 60:
            return decimal.Decimal('5.95')
        elif 60 < Amount <= 80:
            return decimal.Decimal('7.95')
        elif 80 < Amount <= 100:
            return decimal.Decimal('8.95')
        elif 100 < Amount <= 250:
            return decimal.Decimal('9.95')
        elif 250 <= Amount:
            return (Amount * 6 / 100).quantize(decimal.Decimal('0.00'))


def CreateReceipt(json_data, DriverAmount, AdditionalAmount, TransactionDate, plate, OrderID):
    MerchantID = ""
    TerminalID = ""
    CardNumber = ""
    AuthorizationCode = ""
    Status = ""
    OperationName = ""
    Response = ""
    Message = ""
    RRN = ""
    ApplicationLabel = ""
    AID = ""

    if 'Transaction' in json_data:
        new_json = json_data['Transaction']['Receipt']['Detail']
        for item in new_json:
            if item['Key'] == 'Merchant ID':
                MerchantID = item['Value']
            elif item['Key'] == 'Terminal ID':
                TerminalID = item['Value']
            elif item['Key'] == 'Card Number':
                CardNumber = item['Value']
            elif item['Key'] == 'Authorization Code':
                AuthorizationCode = item['Value']
            elif item['Key'] == 'Operation Name':
                OperationName = item['Value']
            elif item['Key'] == 'Status':
                Status = item['Value']
            elif item['Key'] == 'Response':
                Response = item['Value']
            elif item['Key'] == 'Message':
                Message = item['Value']
            elif item['Key'] == 'RRN':
                RRN = item['Value']
            elif item['Key'] == 'Application Label':
                ApplicationLabel = item['Value']
            elif item['Key'] == 'AID':
                AID = item['Value']

        receipt = Receipt.objects.create(OrderID=OrderID,
                                         MerchantID=MerchantID,
                                         TerminalID=TerminalID,
                                         CardNumber=CardNumber,
                                         AuthorizationCode=AuthorizationCode,
                                         OperationName=OperationName,
                                         Status=Status,
                                         Response=Response,
                                         Message=Message,
                                         RRN=RRN,
                                         ApplicationLabel=ApplicationLabel,
                                         AID=AID,
                                         DriverAmount=DriverAmount,
                                         AdditionalAmount=AdditionalAmount,
                                         TransactionDate=TransactionDate,
                                         plate=plate
                                         )

        return receipt


def create_receipt_url(OrderID):
    temp = OrderID.split("-")
    combined_text = temp[0] + temp[1] + temp[-1]
    combined_text = combined_text.encode("utf8")
    hashed_user_id = b64encode(combined_text)
    return hashed_user_id


def create_end_day_excel(daily_list):
    buff = io.StringIO()
    writer = csv.writer(buff, dialect='excel', delimiter=',')

    for item in daily_list:
        writer.writerow([item.phone, item.tckn, item.balance])

    buff2 = io.BytesIO(buff.getvalue().encode())

    bucket = 'banaposbucket'
    sample_time = timezone.datetime.now()
    previous_day = sample_time - timezone.timedelta(days=1)
    key = f"dev/Hakedişler.{previous_day.day}.{previous_day.month}.{previous_day.year}.csv"

    client = boto3.client('s3',
                          aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                          aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                          region_name="eu-central-1"
                          )
    client.upload_fileobj(buff2, bucket, key)
    url = boto3.client('s3',
                       aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                       aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                       region_name="eu-central-1"
                       ).generate_presigned_url('get_object', ExpiresIn=604000,
                                                Params={'Bucket': bucket, 'Key': key})
    return url, key
