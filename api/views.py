import datetime
import decimal
import json
from django.utils import timezone
import boto3
# ---------------------------- Django Standards ----------------------------

from .models import ServerStatus, PosAuthorize, PaymentLocation, VoidRefundSession, OtpPassword, CustomUser, \
    PaymentSession, MobileTransactionHistory, AdditionalAmounts, Deeplink, PortalAuthorize, EndOfDay, \
    WebhookData, Vehicles, DailyBalanceInfo
from .serializers import UserDetailSerializer, UserRegisterSerializer, DashboardUserUpdateSerializer, \
    UserInfoSerializer, UserListSerializer, MobileUserUpdateSerializer, DashboardTransactionHistorySerializer, \
    DashboardTransactionDetailSerializer, DashboardAllTransactionsSerializer, ReceiptSerializer, \
    AllCashOutsSerializer, VehiclesSerializer, TransactionHistorySerializer
import requests
from django.conf import settings
from django.contrib import auth
# ---------------------------- Rest Framework ----------------------------
from rest_framework import mixins
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import NotAcceptable
# ---------------------------- Custom ----------------------------
from .functions import aes_decrypt, OtpCheck, send_otp, local_send_otp, calculate_fee, CreateReceipt, \
    CustomLogin, create_mobile_qr
from .paginations import MobileTransactionHistoryPagination, DashboardUserListPagination, \
    DashboardTransactionHistoryPagination
from .permissions import MobileAccessPermission, AuthorityPermission, WebhookAccessPermission
from .throttles import OTPThrottle


class ServerStatusView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            server_status = ServerStatus.objects.latest("timestamp")

            return Response(data={'status': server_status.status,
                                  'version': server_status.version,
                                  'message': server_status.message,
                                  },
                            status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class CustomUserCreate(APIView):
    permission_classes = [AllowAny]

    def post(self, request):

        try:
            data = request.data

            if 'email' in data:
                if CustomUser.objects.filter(email=data['email']).exists() and not data['email'] == "":
                    return Response(status=status.HTTP_409_CONFLICT,
                                    data={'message': 'Bu email ile bir hesap zaten mevcut!'})

            if CustomUser.objects.filter(phone=data['phone']).exists():
                return Response(status=status.HTTP_409_CONFLICT,
                                data={'message': 'Bu telefon numarası ile bir hesap zaten mevcut!'})

            serializer = UserRegisterSerializer(data=data)
            if serializer.is_valid():
                try:
                    user = serializer.save()
                    if user:
                        return Response(data={'message': "Hesap başarıyla oluşturuldu!"}, status=status.HTTP_201_CREATED)
                except NotAcceptable as e:
                    return Response(data={'message': str(e.detail)}, status=status.HTTP_406_NOT_ACCEPTABLE)
            else:
                return Response(data={'message': serializer.errors}, status=status.HTTP_406_NOT_ACCEPTABLE)

        except Exception as e:
            return Response(data={'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ForgetPasswordStart(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPThrottle]

    def post(self, request):
        try:
            phone = request.data['phone']
            user = CustomUser.objects.filter(phone=phone).last()

            user_exist, response = send_otp(phone, user)
            if user_exist:
                if response[0] == "00":
                    return Response(data={'message': 'Sms başarıyla gönderildi'},
                                    status=status.HTTP_200_OK)
                else:
                    return Response(data={'message': 'Mesaj gönderilmedi!'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response(data={'message': 'Hesap bulunamadı!'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class ForgetPasswordFinish(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            data = request.data
            phone = data['phone']
            password = data['password']
            confirm_password = request.data["confirm_password"]
            verification_code = data['verification_code']

            if password != confirm_password:
                msg = "Şifreler eşleşmiyor!"
                return Response(status=status.HTTP_400_BAD_REQUEST, data={'detail': msg})

            user = CustomUser.objects.filter(phone=phone).last()

            if user:
                success, is_otp_valid = OtpCheck(user, verification_code)

                if not success:
                    return Response({'message': 'Sms onaylaması geçersiz!'},
                                    status=status.HTTP_406_NOT_ACCEPTABLE)

                if not is_otp_valid:
                    return Response({'message': 'Sms şifresi zaman aşımına uğradı!'},
                                    status=status.HTTP_408_REQUEST_TIMEOUT)

                otp_instance = OtpPassword.objects.filter(related_user=user).last()
                otp_instance.is_used = True
                user.set_password(raw_password=password)
                user.save()
                msg = 'Şifreniz başarıyla değiştirildi, yeni şifrenizi kullanabilirsiniz.'
                return Response(status=status.HTTP_200_OK, data={'detail': msg})

            else:
                return Response({'message': 'Geçersiz telefon numarası veya şifre!'},
                                status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class ResetPassword(APIView):
    permission_classes = [IsAuthenticated, MobileAccessPermission]

    def post(self, request):
        try:
            user = request.user
            data = request.data

            old_password = data['old_password']
            password = data['password']
            confirm_password = request.data["confirm_password"]

            try:
                phone = user.phone
                user = auth.authenticate(phone=phone, password=old_password)
                if user:
                    if password != confirm_password:
                        msg = "Şifreler eşleşmiyor!"
                        return Response(status=status.HTTP_400_BAD_REQUEST, data={'detail': msg})

                    user.set_password(raw_password=password)
                    user.save()
                    msg = 'Şifreniz başarıyla değiştirildi, yeni şifrenizi kullanabilirsiniz.'
                    return Response(status=status.HTTP_200_OK, data={'detail': msg})

                else:
                    return Response(status=status.HTTP_400_BAD_REQUEST,
                                    data={'detail': "Şifrenizi doğru girdiğinizden emin olun!"})

            except Exception as e:
                return Response(data={'message': str(e)},
                                status=status.HTTP_403_FORBIDDEN)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class MobileLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            data = request.data
            phone = data['phone']
            password = data['password']
            verification_code = data['verification_code']
            user = auth.authenticate(phone=phone, password=password)

            if user:
                success, is_otp_valid = OtpCheck(user=user, verification_code=verification_code)

                if not success:
                    return Response({'message': 'Sms onaylaması geçersiz!'},
                                    status=status.HTTP_406_NOT_ACCEPTABLE)

                if not is_otp_valid:
                    return Response({'message': 'Sms şifresi zaman aşımına uğradı!'},
                                    status=status.HTTP_408_REQUEST_TIMEOUT)

                access_token, refresh_token = CustomLogin(user=user)
                otp_instance = OtpPassword.objects.filter(related_user=user).last()
                otp_instance.is_used = True
                otp_instance.save(update_fields=["is_used"])

                data = {'access': access_token, 'refresh': refresh_token}
                return Response(data, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'Geçersiz telefon numarası veya şifre!'},
                                status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class GetUserInfo(APIView):
    permission_classes = [IsAuthenticated, MobileAccessPermission]

    def get(self, request):
        try:
            user = request.user
            serializer = UserInfoSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class GetUserList(mixins.ListModelMixin, GenericAPIView):
    queryset = CustomUser.objects.all().order_by('-start_date')
    serializer_class = UserListSerializer
    permission_classes = [IsAuthenticated, AuthorityPermission]
    pagination_class = DashboardUserListPagination

    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)


class GetUserDetail(APIView):
    permission_classes = [IsAuthenticated, AuthorityPermission]

    def post(self, request):
        try:
            user = CustomUser.objects.filter(phone=request.data['phone']).last()
            serializer = UserDetailSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class UpdateUserProfile(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user = request.user

            serializer = MobileUserUpdateSerializer(instance=user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)

            else:
                return Response(data={'message': serializer.errors}, status=status.HTTP_406_NOT_ACCEPTABLE)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class MobileSendOTPView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPThrottle]

    def post(self, request):
        try:
            phone = request.data['phone']
            password = request.data['password']
            user = auth.authenticate(phone=phone, password=password)

            if settings.SEND_OTP:
                user_exist, response = send_otp(phone, user)
                if user_exist:
                    if response[0] == "00":
                        data = {'message': 'Sms başarıyla gönderildi.'}

                        return Response(data=data, status=status.HTTP_200_OK)
                    else:
                        return Response(data={'message': 'Mesaj gönderilmedi'}, status=status.HTTP_406_NOT_ACCEPTABLE)
                else:
                    return Response(data={'message': 'Hesap bulunamadı!'}, status=status.HTTP_404_NOT_FOUND)

            else:
                user_exist, response, verification_code = local_send_otp(user)
                if user_exist:
                    if response[0] == "00":
                        data = {'message': 'Sms başarıyla gönderildi.',
                                'verification_code': verification_code}
                        return Response(data=data, status=status.HTTP_200_OK)
                    else:
                        return Response(data={'message': 'Mesaj gönderilmedi!'}, status=status.HTTP_406_NOT_ACCEPTABLE)
                else:
                    return Response(data={'message': 'Hesap bulunamadı!'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response(data={'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class DashboardSendOTPView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPThrottle]

    def post(self, request):
        try:
            phone = request.data['phone']
            password = request.data['password']
            user = auth.authenticate(phone=phone, password=password)

            if user:
                if not (user.user_type == '2' or user.user_type == '3'):
                    return Response({'message': 'Geçersiz telefon numarası veya şifre!'},
                                    status=status.HTTP_404_NOT_FOUND)

            if settings.SEND_OTP:
                user_exist, response = send_otp(phone, user)
                if user_exist:
                    if response[0] == "00":
                        data = {'message': 'Sms başarıyla gönderildi.'}

                        return Response(data=data, status=status.HTTP_200_OK)
                    else:
                        return Response(data={'message': 'Mesaj gönderilmedi!'}, status=status.HTTP_406_NOT_ACCEPTABLE)
                else:
                    return Response(data={'message': 'Hesap bulunamadı!'}, status=status.HTTP_404_NOT_FOUND)

            else:
                user_exist, response, verification_code = local_send_otp(user)
                if user_exist:
                    if response[0] == "00":
                        data = {'message': 'Sms başarıyla gönderildi.',
                                'verification_code': verification_code}
                        return Response(data=data, status=status.HTTP_200_OK)
                    else:
                        return Response(data={'message': 'Mesaj gönderilmedi!'}, status=status.HTTP_406_NOT_ACCEPTABLE)
                else:
                    return Response(data={'message': 'Hesap bulunamadı!'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response(data={'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ResetPhone(APIView):
    permission_classes = [IsAuthenticated, AuthorityPermission]
    throttle_classes = [OTPThrottle]

    def post(self, request):
        try:
            old_phone = request.data['old_phone']
            new_phone = request.data['new_phone']
            user = CustomUser.objects.filter(phone=old_phone).last()

            if CustomUser.objects.filter(phone=new_phone).exists():
                return Response(data={'message': 'Bu telefon numarasıyla bir kullanıcı mevcut!'},
                                status=status.HTTP_403_FORBIDDEN)

            if settings.SEND_OTP:
                user_exist, response = send_otp(old_phone, user)
                if user_exist:
                    if response[0] == "00":
                        data = {'message': 'Sms başarıyla gönderildi.'}

                        return Response(data=data, status=status.HTTP_200_OK)
                    else:
                        return Response(data={'message': 'Mesaj gönderilmedi!'}, status=status.HTTP_406_NOT_ACCEPTABLE)
                else:
                    return Response(data={'message': 'Hesap bulunamadı!'}, status=status.HTTP_404_NOT_FOUND)

            else:
                user_exist, response, verification_code = local_send_otp(user)
                if user_exist:
                    if response[0] == "00":
                        data = {'message': 'Sms başarıyla gönderildi.',
                                'verification_code': verification_code}
                        return Response(data=data, status=status.HTTP_200_OK)
                    else:
                        return Response(data={'message': 'Mesaj gönderilmedi!'}, status=status.HTTP_406_NOT_ACCEPTABLE)
                else:
                    return Response(data={'message': 'Hesap bulunamadı!'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response(data={'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ResetPhoneOTP(APIView):
    permission_classes = [IsAuthenticated, AuthorityPermission]

    def post(self, request):
        try:
            data = request.data
            old_phone = data['old_phone']
            new_phone = data['new_phone']
            verification_code = data['verification_code']

            user = CustomUser.objects.filter(phone=old_phone).last()

            if user:
                success, is_otp_valid = OtpCheck(user=user, verification_code=verification_code)

                if not success:
                    return Response({'message': 'Sms onaylaması geçersiz!'},
                                    status=status.HTTP_406_NOT_ACCEPTABLE)

                if not is_otp_valid:
                    return Response({'message': 'Sms şifresi zaman aşımına uğradı!'},
                                    status=status.HTTP_408_REQUEST_TIMEOUT)

                otp_instance = OtpPassword.objects.filter(related_user=user).last()
                otp_instance.is_used = True
                user.phone = new_phone
                user.save()

                return Response({'message': 'Telefon numarası başarıyla değiştirildi.'}, status=status.HTTP_200_OK)

            else:
                return Response({'message': 'Geçersiz telefon numarası veya şifre!'},
                                status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class DashboardLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            data = request.data
            phone = data['phone']
            password = data['password']
            verification_code = data['verification_code']
            user = auth.authenticate(phone=phone, password=password)

            if user:
                if not (user.user_type == '2' or user.user_type == '3'):
                    return Response({'message': 'Geçersiz telefon numarası veya şifre!'},
                                    status=status.HTTP_404_NOT_FOUND)

                success, is_otp_valid = OtpCheck(user=user, verification_code=verification_code)

                if not success:
                    return Response({'message': 'Sms onaylaması geçersiz!'},
                                    status=status.HTTP_406_NOT_ACCEPTABLE)

                if not is_otp_valid:
                    return Response({'message': 'Sms şifresi zaman aşımına uğradı!'},
                                    status=status.HTTP_408_REQUEST_TIMEOUT)

                access_token, refresh_token = CustomLogin(user=user)

                serializer = UserInfoSerializer(user)
                data = {'access': access_token, 'refresh': refresh_token, "user-info": serializer.data}
                return Response(data, status=status.HTTP_200_OK)

            else:
                return Response({'message': 'Geçersiz telefon numarası veya şifre!'},
                                status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)

        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST, data=str(e))


class RefreshTokenView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # Refresh Token exp check
        try:
            refresh_token = request.data["refresh"]
            user = OutstandingToken.objects.filter(token=refresh_token).last().user
            old_token = RefreshToken(refresh_token)

            try:
                if user.user_type == "1" and user.status != "1":
                    old_token.blacklist()
                    return Response(data={"status": user.get_status_display()}, status=status.HTTP_403_FORBIDDEN)

                old_token.blacklist()
                new_token = RefreshToken.for_user(user)
                refresh_token = str(new_token)
                access_token = str(new_token.access_token)
                data = {'access': access_token, 'refresh': refresh_token}

                return Response(data, status=status.HTTP_200_OK)

            except Exception as e:
                old_token.blacklist()
                return Response(data=str(e), status=status.HTTP_403_FORBIDDEN)

        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST, data={str(e)})


class PaymentStart(APIView):
    permission_classes = [IsAuthenticated, MobileAccessPermission]

    def post(self, request):
        try:
            user = request.user
            data = request.data
            if data['Amount'] > 2500 or data['Amount'] < 1:
                return Response(data={"message": "Tutar 1 ile 2500 TL aralığında olmalıdır"},
                                status=status.HTTP_403_FORBIDDEN)

            DriverAmount = decimal.Decimal(str(data['Amount']))
            AdditionalAmount = calculate_fee(DriverAmount)
            Amount = DriverAmount + AdditionalAmount

            payment_session = PaymentSession.objects.create(Amount=Amount, UserHash=user, plate=request.data['plate'])
            taximeter = AdditionalAmounts.objects.create(payment_session=payment_session,
                                                         Amount=DriverAmount, Caption="Taksimetre Tutarı",
                                                         IntegrationKey="TAXIMETER")
            comission = AdditionalAmounts.objects.create(payment_session=payment_session,
                                                         Amount=AdditionalAmount, Caption="İşlem Ücreti",
                                                         IntegrationKey="COMMISSION")
            url = settings.PAYMENT_START_URL
            # if settings.ENV:
            auth_token = PosAuthorize.objects.latest("timestamp").Token
            header = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0',
                'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive',
                'Authorization': 'Bearer ' + auth_token
            }

            payload = {
                "UserHash": str(user.user_id),
                "Amount": str(payment_session.Amount),
                "OrderID": str(payment_session.OrderID),
                "CurrencyCode": payment_session.CurrencyCode,
                "TransactionType": payment_session.TransactionType,
                "CallBackURL": settings.CALLBACK_URL,
                "AdditionalAmounts": [
                    {
                        "Amount": str(taximeter.Amount),
                        "Caption": taximeter.Caption,
                        "IntegrationKey": taximeter.IntegrationKey
                    },
                    {
                        "Amount": str(comission.Amount),
                        "Caption": comission.Caption,
                        "IntegrationKey": comission.IntegrationKey
                    }
                ]
            }

            response = requests.post(url, json=payload, headers=header)
            if response.ok:
                json_response = response.json()
                payment_session.PaymentSessionToken = json_response['PaymentSessionToken']
                payment_session.save()
                PaymentLocation.objects.create(payment_session=payment_session, lat=data['lat'], lon=data['lon'])
                return Response(data={
                    "PaymentSessionToken": payment_session.PaymentSessionToken,
                    "OrderID": payment_session.OrderID
                }, status=status.HTTP_200_OK)
            else:
                return Response(data=response.text, status=status.HTTP_406_NOT_ACCEPTABLE)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class PaymentFinish(APIView):
    permission_classes = [IsAuthenticated, MobileAccessPermission]

    def post(self, request):
        try:
            user = request.user
            payment_session_token = request.data['PaymentSessionToken']
            payment_session = PaymentSession.objects.filter(PaymentSessionToken=payment_session_token,
                                                            UserHash__user_id=user.user_id).last()

            if payment_session.UserHash != user or not payment_session:
                return Response(data={"message": "Bu işlemi yapma izniniz yok!"},
                                status=status.HTTP_403_FORBIDDEN)

            if payment_session.is_used:
                return Response(data={"message": "Payment Session Token is already used!"},
                                status=status.HTTP_403_FORBIDDEN)

            secret_text = request.data['hashData']

            iv = payment_session_token.encode("utf8")
            decrypted_text = aes_decrypt(iv, secret_text)

            json_data = json.loads(decrypted_text)

            deeplink = Deeplink.objects.create(payment_session=payment_session, hashData=secret_text,
                                               Status=str(json_data['Status']), data=json_data, TransactionType="Sale",
                                               Approved=False, IsVoidable=False, IsRefundable=False)

            TransactionDate = str(deeplink.timestamp.strftime("%d-%m-%Y %H:%M:%S"))

            # Commission
            additional_amount = AdditionalAmounts.objects.filter(payment_session=payment_session,
                                                                 IntegrationKey="COMMISSION").last()
            AdditionalAmount = additional_amount.Amount
            DriverAmount = payment_session.Amount - AdditionalAmount

            plate = payment_session.plate

            success = False
            Status = deeplink.Status

            if Status == "3":
                if 'Transaction' in json_data:
                    TransactionDate = json_data['Transaction']['TransactionDate']
                    IsVoidable = json_data['Transaction']['IsVoidable']
                    IsRefundable = json_data['Transaction']['IsRefundable']

                    success = json_data['Transaction']['Receipt']['Approved']

                    deeplink.IsVoidable = IsVoidable
                    deeplink.IsRefundable = IsRefundable
                    deeplink.Approved = success
                    deeplink.save()

                # PaymentFailedResult as response
                else:
                    deeplink.Status = "7"
                    Status = "7"
                    deeplink.save()

            elif Status == "5":
                json_data['message'] = "Status:5(CancelPayment) - Ödemeyi iptal ettiniz."
            elif Status == "1":
                json_data['message'] = "Status:1(ActivationNotFound) - BANAPOS ekibiyle iletişime geçiniz."
            elif Status == "2":
                json_data['message'] = "Status:2(TerminalNotFound) - BANAPOS ekibiyle iletişime geçiniz."
            elif Status == "4":
                json_data['message'] = "Status:4(InvalidCallback) - BANAPOS ekibiyle iletişime geçiniz."
            elif Status == "6":
                json_data['message'] = "Status:6(UserHashNotFound) - BANAPOS ekibiyle iletişime geçiniz."

            qr_id = create_mobile_qr()
            QRLink = "https://banapos.com/qr/?" + qr_id
            TransactionType = deeplink.TransactionType
            OrderID = payment_session.OrderID

            if Status == "3":
                if not MobileTransactionHistory.objects.filter(OrderID=OrderID, TransactionType="Sale").exists():
                    MobileTransactionHistory.objects.create(
                        QRLink=QRLink,
                        OrderID=OrderID,
                        TransactionType=TransactionType
                    )
                else:
                    transaction = MobileTransactionHistory.objects.filter(OrderID=OrderID,
                                                                          TransactionType="Sale").last()
                    QRLink = transaction.QRLink
            else:
                receipt = CreateReceipt(json_data, DriverAmount, AdditionalAmount, TransactionDate,
                                        plate, OrderID)

                MobileTransactionHistory.objects.create(phone=user.phone,
                                                        name=user.name,
                                                        surname=user.surname,
                                                        deeplink=deeplink,
                                                        OrderID=OrderID,
                                                        success=success,
                                                        TransactionType=TransactionType,
                                                        TransactionDate=TransactionDate,
                                                        DriverAmount=DriverAmount,
                                                        IsVoidable=deeplink.IsVoidable,
                                                        IsRefundable=deeplink.IsRefundable,
                                                        QRLink=QRLink,
                                                        detail=receipt,
                                                        start_time=payment_session.timestamp,
                                                        end_time=deeplink.timestamp,
                                                        plate=plate
                                                        )

            return Response(data={"data": json_data, "QRLink": QRLink,
                                  "DriverAmount": DriverAmount, "AdditionalAmount": AdditionalAmount,
                                  "TransactionType": TransactionType,
                                  "success": success, "Status": Status},
                            status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class VoidRefundStart(APIView):
    permission_classes = [IsAuthenticated, MobileAccessPermission]

    def post(self, request):
        try:
            user = request.user
            data = request.data

            OrderID = data['OrderID']
            TransactionType = data['TransactionType']

            payment_session = PaymentSession.objects.filter(OrderID=OrderID).last()

            if user.user_id != payment_session.UserHash_id or not payment_session:
                return Response(data={"message": "Bu işlemi yapma izniniz yok!"},
                                status=status.HTTP_403_FORBIDDEN)

            transaction = MobileTransactionHistory.objects.filter(OrderID=payment_session.OrderID).last()

            if TransactionType == "Void" or TransactionType == "Refund":
                if TransactionType == "Void" and not transaction.IsVoidable:
                    return Response(data={"message": "İptal işlemi yapılamaz!"},
                                    status=status.HTTP_403_FORBIDDEN)

                elif TransactionType == "Refund" and not transaction.IsRefundable:
                    return Response(data={"message": "İade işlemi yapılamaz!"},
                                    status=status.HTTP_403_FORBIDDEN)

            else:
                return Response(data={"message": "İptal veya iade seçimi yapınız!"},
                                status=status.HTTP_403_FORBIDDEN)

            void_refund_session = VoidRefundSession.objects.create(OrderID=OrderID,
                                                                   TransactionType=TransactionType,
                                                                   payment_session=payment_session,
                                                                   plate=request.data['plate'])
            auth_token = PosAuthorize.objects.filter().last().Token
            url = settings.PAYMENT_START_URL
            header = {'Authorization': 'Bearer ' + str(auth_token)}

            payload = {
                "OrderID": void_refund_session.OrderID,
                "TransactionType": void_refund_session.TransactionType,
                "CallBackURL": settings.CALLBACK_URL,
                "UserHash": str(user.user_id)
            }

            response = requests.post(url, json=payload, headers=header)

            if response.ok:
                json_response = response.json()
                void_refund_session.PaymentSessionToken = json_response['PaymentSessionToken']
                void_refund_session.save()
                PaymentLocation.objects.create(void_refund_session=void_refund_session, lat=data['lat'],
                                               lon=data['lon'])

                # There is no more than one void or refund process for an order

                return Response(data={
                    "PaymentSessionToken": void_refund_session.PaymentSessionToken,
                    "OrderID": void_refund_session.OrderID
                }, status=status.HTTP_200_OK)
            else:
                return Response(data=response.text, status=status.HTTP_406_NOT_ACCEPTABLE)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class VoidRefundFinish(APIView):
    permission_classes = [IsAuthenticated, MobileAccessPermission]

    def post(self, request):
        try:
            user = request.user
            payment_session_token = request.data['PaymentSessionToken']
            void_refund_session = VoidRefundSession.objects.filter(PaymentSessionToken=payment_session_token).last()

            if void_refund_session.payment_session.UserHash != user or not void_refund_session.payment_session:
                return Response(data={"message": "Bu işlemi yapma izniniz yok!"},
                                status=status.HTTP_403_FORBIDDEN)

            if void_refund_session.is_used:
                return Response(data={"message": "Payment Session Token is already used!"},
                                status=status.HTTP_403_FORBIDDEN)

            iv = payment_session_token.encode("utf8")
            secret_text = request.data['hashData']
            decrypted_text = aes_decrypt(iv, secret_text)
            json_data = json.loads(decrypted_text)
            deeplink = Deeplink.objects.create(void_refund_session=void_refund_session, hashData=secret_text,
                                               Status=json_data['Status'], data=json_data, TransactionType="Void",
                                               Approved=False, IsVoidable=False, IsRefundable=False)

            TransactionDate = str(deeplink.timestamp.strftime("%d-%m-%Y %H:%M:%S"))

            # Commission
            additional_amount = AdditionalAmounts.objects.filter(payment_session=void_refund_session.payment_session,
                                                                 IntegrationKey="COMMISSION").last()
            AdditionalAmount = additional_amount.Amount
            DriverAmount = void_refund_session.payment_session.Amount - AdditionalAmount

            plate = void_refund_session.plate

            success = False

            Status = json_data['Status']

            if Status == 3:
                if 'Transaction' in json_data:
                    if json_data['Transaction']['BankResponseCodeValue'] == '00' and \
                            json_data['Transaction']['ResponseCodeValue'] == '00':
                        TransactionDate = json_data['Transaction']['TransactionDate']

                        success = True

                        deeplink.Approved = success
                        deeplink.save()

                # PaymentFailedResult as response
                else:
                    deeplink.Status = "7"
                    deeplink.save()

            elif Status == 5:
                json_data['message'] = "Status:5(CancelPayment) - Ödemeyi iptal ettiniz."
            elif Status == 1:
                json_data['message'] = "Status:1(ActivationNotFound) - BANAPOS ekibiyle iletişime geçiniz."
            elif Status == 2:
                json_data['message'] = "Status:2(TerminalNotFound) - BANAPOS ekibiyle iletişime geçiniz."
            elif Status == 4:
                json_data['message'] = "Status:4(InvalidCallback) - BANAPOS ekibiyle iletişime geçiniz."
            elif Status == 6:
                json_data['message'] = "Status:6(UserHashNotFound) - BANAPOS ekibiyle iletişime geçiniz."

            OrderID = void_refund_session.OrderID
            qr_id = create_mobile_qr()
            QRLink = "https://banapos.com/qr/?" + qr_id
            TransactionType = deeplink.TransactionType

            if Status == 3:
                if not MobileTransactionHistory.objects.filter(OrderID=OrderID, TransactionType="Void").exists():
                    MobileTransactionHistory.objects.create(
                        QRLink=QRLink,
                        OrderID=OrderID,
                        TransactionType=TransactionType
                    )
                else:
                    transaction = MobileTransactionHistory.objects.filter(OrderID=OrderID,
                                                                          TransactionType="Void").last()
                    QRLink = transaction.QRLink
            else:
                receipt = CreateReceipt(json_data, DriverAmount, AdditionalAmount, TransactionDate, plate, OrderID)

                MobileTransactionHistory.objects.create(phone=user.phone,
                                                        name=user.name,
                                                        surname=user.surname,
                                                        deeplink=deeplink,
                                                        OrderID=OrderID,
                                                        success=success,
                                                        TransactionType=TransactionType,
                                                        TransactionDate=TransactionDate,
                                                        DriverAmount=DriverAmount,
                                                        IsVoidable=deeplink.IsVoidable,
                                                        IsRefundable=deeplink.IsRefundable,
                                                        QRLink=QRLink,
                                                        detail=receipt,
                                                        start_time=void_refund_session.timestamp,
                                                        end_time=deeplink.timestamp,
                                                        plate=plate
                                                        )

            return Response(data={"data": json_data, "QRLink": QRLink,
                                  "DriverAmount": DriverAmount, "AdditionalAmount": AdditionalAmount,
                                  "TransactionType": TransactionType,
                                  "success": success, "Status": deeplink.Status},
                            status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class TransactionHistoryView(mixins.ListModelMixin, GenericAPIView):
    serializer_class = TransactionHistorySerializer
    permission_classes = [IsAuthenticated, MobileAccessPermission]
    pagination_class = MobileTransactionHistoryPagination

    def get(self, request, *args, **kwargs):
        try:
            today = timezone.datetime.today().date()
            self.queryset = MobileTransactionHistory.objects.filter(phone=request.user.phone,
                                                                    IsRefundable__isnull=False,
                                                                    end_time__date=today).order_by(
                '-webhook__timestamp')
            response = self.list(request, *args, **kwargs)
            balance = request.user.balance
            response.data['balance'] = balance
            return response

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class TransactionHistoryByDate(mixins.ListModelMixin, GenericAPIView):
    serializer_class = TransactionHistorySerializer
    permission_classes = [IsAuthenticated, MobileAccessPermission]
    pagination_class = MobileTransactionHistoryPagination

    def get(self, request, *args, **kwargs):
        try:
            date_str = str(request.GET.get('date'))
            today = timezone.datetime.today().strftime('%d-%m-%Y')
            date = timezone.datetime.strptime(date_str, '%d-%m-%Y').date()
            is_today = date_str == today

            if not is_today:
                self.queryset = MobileTransactionHistory.objects.filter(phone=request.user.phone,
                                                                        IsRefundable__isnull=False,
                                                                        end_time__date=date).order_by(
                    '-webhook__timestamp')
                response = self.list(request, *args, **kwargs)
                balance_info = DailyBalanceInfo.objects.filter(phone=request.user.phone,
                                                               timestamp__date=date + timezone.timedelta(days=1)).last()
                balance = balance_info.balance
                response.data['balance'] = balance
                return response

            else:
                if MobileTransactionHistory.objects.filter(phone=request.user.phone,
                                                           IsRefundable__isnull=False,
                                                           end_time__date=date).exists():
                    self.queryset = MobileTransactionHistory.objects.filter(phone=request.user.phone,
                                                                            IsRefundable__isnull=False,
                                                                            end_time__date=date).order_by(
                        '-webhook__timestamp')
                    response = self.list(request, *args, **kwargs)
                    balance = request.user.balance
                    response.data['balance'] = balance
                    return response

                else:
                    return Response(data={'message': "Bu tarihe ait işlem geçmişi bulunamadı!"},
                                    status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class DashboardAllTransactions(mixins.ListModelMixin, GenericAPIView):
    queryset = MobileTransactionHistory.objects.all().order_by('-webhook__timestamp')
    serializer_class = DashboardAllTransactionsSerializer
    permission_classes = [IsAuthenticated, AuthorityPermission]
    pagination_class = DashboardTransactionHistoryPagination

    def get(self, request, *args, **kwargs):
        try:
            response = self.list(request, *args, **kwargs)
            return response

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class DashboardUserTransactionHistory(mixins.ListModelMixin, GenericAPIView):
    serializer_class = DashboardTransactionHistorySerializer
    permission_classes = [IsAuthenticated, AuthorityPermission]
    pagination_class = DashboardTransactionHistoryPagination

    def get(self, request, *args, **kwargs):
        try:
            phone = request.GET.get('phone')
            if CustomUser.objects.filter(phone=phone).exists():
                user = CustomUser.objects.filter(phone=phone).last()
                self.queryset = MobileTransactionHistory.objects.filter(webhook__payment_session__UserHash=user,
                                                                        IsRefundable__isnull=False). \
                    order_by('-webhook__timestamp')
                response = self.list(request, *args, **kwargs)
                return response
            else:
                Response(data={'message': "Kullanıcı bulunamadı!"},
                         status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response(data={'message': "Parametreleri kontrol ediniz!"},
                            status=status.HTTP_400_BAD_REQUEST)


class DashboardUserTransactionDetail(APIView):
    permission_classes = [IsAuthenticated, AuthorityPermission]

    def post(self, request):
        try:
            OrderID = request.data['OrderID']
            transaction_detail = MobileTransactionHistory.objects.filter(OrderID=OrderID).last()
            serializer = DashboardTransactionDetailSerializer(transaction_detail)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class WebhookRemoteView(APIView):
    permission_classes = [WebhookAccessPermission]

    def post(self, request):
        try:
            payment_session_token = request.headers['X-Payment-Session-Token']

            secret_text = request.data['data']
            iv = payment_session_token.encode("utf8")
            decrypted_text = aes_decrypt(iv, secret_text)

            json_data = json.loads(decrypted_text)

            operation_name = json_data['TransactionType']

            user = CustomUser.objects.filter(user_id=json_data['PaymentSession']['UserHash']).last()
            if not user:
                Response(data={'message': "Kullanıcı bulunamadı!"},
                         status=status.HTTP_400_BAD_REQUEST)

            TransactionDate = json_data['Transaction']['TransactionDate']
            IsVoidable = json_data['Transaction']['IsVoidable']
            IsRefundable = json_data['Transaction']['IsRefundable']

            if operation_name == 'TRANSACTION_SALE':
                payment_session = PaymentSession.objects.filter(PaymentSessionToken=payment_session_token).last()

                webhook_data = WebhookData.objects.create(payment_session=payment_session, hashData=secret_text,
                                                          data=json_data, TransactionType="Sale",
                                                          Approved=json_data['Transaction']['Receipt']['Approved'],
                                                          IsVoidable=IsVoidable, IsRefundable=IsRefundable)

                # Commission adding
                additional_amount = AdditionalAmounts.objects.filter(payment_session=payment_session,
                                                                     IntegrationKey="COMMISSION").last()
                AdditionalAmount = additional_amount.Amount
                DriverAmount = payment_session.Amount - AdditionalAmount
                plate = payment_session.plate

                OrderID = payment_session.OrderID

                qr_id = create_mobile_qr()
                QRLink = "https://banapos.com/qr/?" + qr_id
                TransactionType = webhook_data.TransactionType
                success = webhook_data.Approved

                if MobileTransactionHistory.objects.filter(OrderID=OrderID, TransactionType=TransactionType).exists():
                    transaction = MobileTransactionHistory.objects.filter(OrderID=OrderID,
                                                                          TransactionType=TransactionType).last()
                    receipt = CreateReceipt(json_data, DriverAmount, AdditionalAmount,
                                            TransactionDate, plate, OrderID)
                    transaction.phone = user.phone
                    transaction.name = user.name
                    transaction.surname = user.surname
                    transaction.webhook = webhook_data
                    transaction.success = success
                    transaction.TransactionDate = TransactionDate
                    transaction.DriverAmount = DriverAmount
                    transaction.IsVoidable = IsVoidable
                    transaction.IsRefundable = IsRefundable
                    transaction.detail = receipt
                    transaction.start_time = payment_session.timestamp
                    transaction.end_time = webhook_data.timestamp
                    transaction.plate = plate
                    transaction.save()

                else:
                    receipt = CreateReceipt(json_data, DriverAmount, AdditionalAmount,
                                            TransactionDate, plate, OrderID)

                    MobileTransactionHistory.objects.create(phone=user.phone,
                                                            name=user.name,
                                                            surname=user.surname,
                                                            webhook=webhook_data,
                                                            OrderID=OrderID,
                                                            success=success,
                                                            TransactionType=TransactionType,
                                                            TransactionDate=TransactionDate,
                                                            DriverAmount=DriverAmount,
                                                            IsVoidable=webhook_data.IsVoidable,
                                                            IsRefundable=webhook_data.IsRefundable,
                                                            QRLink=QRLink,
                                                            detail=receipt,
                                                            start_time=payment_session.timestamp,
                                                            end_time=webhook_data.timestamp,
                                                            plate=plate
                                                            )

                if success:
                    user.balance += DriverAmount
                    user.save()

            # Void Operation
            else:
                success = False
                void_refund_session = VoidRefundSession.objects.filter(PaymentSessionToken=payment_session_token).last()
                webhook_data = WebhookData.objects.create(void_refund_session=void_refund_session, hashData=secret_text,
                                                          Approved=success, data=json_data, IsVoidable=IsVoidable,
                                                          IsRefundable=IsRefundable, TransactionType="Void")

                additional_amount = AdditionalAmounts.objects.filter(payment_session=
                                                                     void_refund_session.payment_session,
                                                                     IntegrationKey="COMMISSION").last()
                AdditionalAmount = additional_amount.Amount
                DriverAmount = void_refund_session.payment_session.Amount - AdditionalAmount

                plate = void_refund_session.plate
                OrderID = void_refund_session.OrderID
                receipt = CreateReceipt(json_data, DriverAmount, AdditionalAmount, TransactionDate,
                                        plate, OrderID)
                qr_id = create_mobile_qr()
                QRLink = "https://banapos.com/qr/?" + qr_id

                if json_data['Transaction']['BankResponseCodeValue'] == '00' and \
                        json_data['Transaction']['ResponseCodeValue'] == '00':
                    sale_transaction = MobileTransactionHistory.objects.filter(OrderID=OrderID,
                                                                               TransactionType="Sale").last()
                    sale_transaction.IsVoidable = False
                    sale_transaction.IsRefundable = False
                    sale_transaction.save()

                    success = True
                    webhook_data.Approved = success
                    webhook_data.save()

                    user.balance -= DriverAmount
                    user.save()

                MobileTransactionHistory.objects.create(phone=user.phone,
                                                        name=user.name,
                                                        surname=user.surname,
                                                        webhook=webhook_data,
                                                        OrderID=void_refund_session.OrderID,
                                                        success=success,
                                                        TransactionType=webhook_data.TransactionType,
                                                        TransactionDate=TransactionDate,
                                                        DriverAmount=DriverAmount,
                                                        IsVoidable=webhook_data.IsVoidable,
                                                        IsRefundable=webhook_data.IsRefundable,
                                                        QRLink="https://banapos.com/qr/?" + QRLink,
                                                        detail=receipt,
                                                        start_time=void_refund_session.timestamp,
                                                        end_time=webhook_data.timestamp,
                                                        plate=plate
                                                        )

            if webhook_data:
                return Response(data={"ok": True}, status=status.HTTP_200_OK, headers={
                    "X-API-KEY": settings.ACCESS_KEY,
                    "X-Payment-Session-Token": payment_session_token,
                    "Content-Type": "application/json"
                })
            else:
                return Response(data={'message': "Webhook verisi oluşturulamadı!"}, status=status.HTTP_403_FORBIDDEN)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class UserStatusUpdate(APIView):
    permission_classes = [IsAuthenticated, AuthorityPermission]

    def post(self, request):

        try:
            data = request.data
            access_token = PortalAuthorize.objects.filter().last().access_token
            UserID = data['UserID']

            user = CustomUser.objects.filter(user_id=UserID).last()

            if user:
                phone = user.phone
                if data['status'] == "1":
                    if user.status == "1":
                        return Response(data={"message": "Kullanıcı durumu Aktif olarak güncellendi."},
                                        status=status.HTTP_200_OK)

                    ENROLL_USER_URL = settings.ENROLL_USER_URL

                    header = {'Authorization': 'Bearer ' + str(access_token)}
                    payload = {
                        "WspTenantId": settings.WSP_TENANT_ID,
                        "UserId": UserID,
                        "MobileNumber": phone,
                        "PackageId": settings.PACKAGE_ID
                    }

                    response = requests.post(ENROLL_USER_URL, json=payload, headers=header)

                    if response.ok:
                        user.status = '1'
                        user.save()

                        return Response(data={"message": "Kullanıcı durumu Aktif olarak güncellendi."},
                                        status=status.HTTP_200_OK)

                    else:
                        return Response(data=response.text, status=status.HTTP_406_NOT_ACCEPTABLE)

                elif data['status'] == "2" or data['status'] == "3" or data['status'] == "4":
                    INACTIVE_USER_URL = settings.INACTIVE_USER_URL

                    header = {'Authorization': 'Bearer ' + str(access_token)}
                    payload = {
                        "WspTenantId": settings.WSP_TENANT_ID,
                        "UserId": UserID,
                    }

                    response = requests.post(INACTIVE_USER_URL, json=payload, headers=header)

                    if response.ok:
                        if data['status'] == "2":
                            user.status = '2'
                            user.save()
                            return Response(data={"message": "Kullanıcı durumu İnaktif olarak güncellendi."},
                                            status=status.HTTP_200_OK)

                        elif data['status'] == "3":
                            user.status = '3'
                            user.save()
                            return Response(data={"message": "Kullanıcı durumu Pasif olarak güncellendi."},
                                            status=status.HTTP_200_OK)

                        elif data['status'] == "4":
                            user.status = '4'
                            user.save()
                            return Response(data={"message": "Kullanıcı durumu Beklemede olarak güncellendi."},
                                            status=status.HTTP_200_OK)
                    # yorum
                    else:
                        return Response(data=response.text, status=status.HTTP_406_NOT_ACCEPTABLE)
                else:
                    return Response(data={"message": "Alanları doğru belirttiğinizden emin olun!"},
                                    status=status.HTTP_403_FORBIDDEN)
            else:
                return Response(data={'message': 'Hesap bulunamadı!'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class DashboardUserUpdate(APIView):
    permission_classes = [IsAuthenticated, AuthorityPermission]

    def post(self, request):
        try:
            data = request.data
            user = CustomUser.objects.filter(phone=data['phone']).last()

            email = data['data']['email']
            if CustomUser.objects.filter(email=email).exists() and not user.email == email:
                return Response(status=status.HTTP_409_CONFLICT,
                                data={'message': 'Bu email ile bir hesap zaten mevcut!'})

            serializer = DashboardUserUpdateSerializer(instance=user, data=data['data'])
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_200_OK)

            else:
                return Response(data={'message': serializer.errors}, status=status.HTTP_406_NOT_ACCEPTABLE)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class TransactionReceipt(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            data = request.data
            QRLink = data['url']
            transaction = MobileTransactionHistory.objects.filter(QRLink=QRLink).last()

            serializer = ReceiptSerializer(transaction.detail)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class AllCashOuts(mixins.ListModelMixin, GenericAPIView):
    queryset = EndOfDay.objects.all().order_by('-uploaded_at')
    serializer_class = AllCashOutsSerializer
    permission_classes = [IsAuthenticated, AuthorityPermission]
    pagination_class = DashboardTransactionHistoryPagination

    def get(self, request, *args, **kwargs):
        try:
            return self.list(request, *args, **kwargs)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class RegenerateExcelURL(APIView):
    permission_classes = [IsAuthenticated, AuthorityPermission]

    def post(self, request):
        try:
            data = request.data
            key = data['key']

            bucket = 'banaposbucket'
            new_url = boto3.client('s3',
                                   aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                                   aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                                   region_name="eu-central-1"
                                   ).generate_presigned_url('get_object', ExpiresIn=604000,
                                                            Params={'Bucket': bucket, 'Key': key})

            cashout = EndOfDay.objects.filter(key=key).last()
            cashout.uploaded_at = timezone.datetime.now()
            cashout.url = new_url
            cashout.save()

            return Response(data={'new_url': cashout.url}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class MobileAddPlateAPI(APIView):
    permission_classes = [IsAuthenticated, MobileAccessPermission]

    def post(self, request):
        try:
            user = request.user
            plate = request.data['plate']
            plate = str.upper(plate)
            vehicle_instance, created = Vehicles.objects.get_or_create(plate=plate)
            user.vehicles.add(vehicle_instance)
            return Response(data={'message': "Yeni plaka eklendi."}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class MobileRemovePlateAPI(APIView):
    permission_classes = [IsAuthenticated, MobileAccessPermission]

    def post(self, request):
        try:
            user = request.user
            data = request.data
            vehicle_instance = user.vehicles.get(plate=data['plate'])
            user.vehicles.remove(vehicle_instance)
            return Response(data={'message': "Plaka kaldırıldı."}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class DashboardAddPlateAPI(APIView):
    permission_classes = [IsAuthenticated, AuthorityPermission]

    def post(self, request):
        try:
            data = request.data
            user = CustomUser.objects.filter(user_id=data['UserID']).last()

            vehicle_instance, created = Vehicles.objects.get_or_create(plate=data['plate'])
            user.vehicles.add(vehicle_instance)
            return Response(data={'message': "Yeni plaka eklendi."}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class DashboardRemovePlateAPI(APIView):
    permission_classes = [IsAuthenticated, AuthorityPermission]

    def post(self, request):
        try:
            data = request.data
            user = CustomUser.objects.filter(user_id=data['UserID']).last()
            vehicle_instance = user.vehicles.get(plate=data['plate'])
            user.vehicles.remove(vehicle_instance)
            return Response(data={'message': "Plaka kaldırıldı."}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class MobilePlateList(mixins.ListModelMixin, GenericAPIView):
    serializer_class = VehiclesSerializer
    permission_classes = [IsAuthenticated, MobileAccessPermission]

    def get(self, request, *args, **kwargs):
        try:
            user = request.user
            self.queryset = user.vehicles.all()
            response = self.list(request, *args, **kwargs)
            return Response(data={'plates': response.data}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class DashboardPlateList(mixins.ListModelMixin, GenericAPIView):
    serializer_class = VehiclesSerializer
    permission_classes = [IsAuthenticated, AuthorityPermission]

    def post(self, request, *args, **kwargs):
        try:
            UserID = request.data['UserID']
            if CustomUser.objects.filter(user_id=UserID).exists():
                user = CustomUser.objects.filter(user_id=UserID).last()
                self.queryset = user.vehicles.all()
                response = self.list(request, *args, **kwargs)
                return Response(data={'plates': response.data}, status=status.HTTP_200_OK)

            else:
                Response(data={'message': "Kullanıcı bulunamadı!"},
                         status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response(data={'message': "Parametreleri kontrol ediniz!"},
                            status=status.HTTP_400_BAD_REQUEST)


class SetVehicleAPI(APIView):
    permission_classes = [IsAuthenticated, MobileAccessPermission]

    def post(self, request):
        try:
            user = request.user
            data = request.data
            vehicle_instance = user.vehicles.filter(plate=data['plate']).last()
            if not vehicle_instance:
                return Response(data={'message': "Plakalarınız arasında bulamadım!", 'is_available': False},
                                status=status.HTTP_406_NOT_ACCEPTABLE)

            if vehicle_instance.phone == user.phone:
                return Response(data={'message': "Plaka seçildi.", 'is_available': True}, status=status.HTTP_200_OK)

            picked_at = vehicle_instance.picked_at

            # Araç ilk defa alınıyorsa
            if picked_at is None:
                if Vehicles.objects.filter(phone=user.phone).exists():
                    old_vehicle = Vehicles.objects.filter(phone=user.phone).last()
                    old_vehicle.phone = ""
                    old_vehicle.save()

                vehicle_instance.phone = user.phone
                vehicle_instance.picked_at = timezone.localtime(timezone.now())
                vehicle_instance.save()
                return Response(data={'message': "Plaka seçildi.", 'is_available': True}, status=status.HTTP_200_OK)

            # Araç müsait ise ve 30 dk içinde alınmadıysa
            elif timezone.localtime(timezone.now()) > picked_at + \
                    timezone.timedelta(minutes=int(settings.VEHICLE_TIME)) or vehicle_instance.phone == "":

                if Vehicles.objects.filter(phone=user.phone).exists():
                    old_vehicle = Vehicles.objects.filter(phone=user.phone).last()
                    old_vehicle.phone = ""
                    old_vehicle.save()

                vehicle_instance.phone = user.phone
                vehicle_instance.picked_at = timezone.localtime(timezone.now())
                vehicle_instance.save()
                return Response(data={'message': "Plaka seçildi.", 'is_available': True}, status=status.HTTP_200_OK)

            else:
                elapsed_time = timezone.localtime(timezone.now()) - picked_at
                seconds = elapsed_time.seconds
                remaining_time = int(settings.VEHICLE_TIME) * 60 - seconds
                minutes = remaining_time // 60
                seconds = remaining_time % 60

                return Response(data={'message': f"Bu plakayı almak için {minutes} dakika {seconds} "
                                                 f"saniye beklemelisiniz.",
                                      'is_available': False},
                                status=status.HTTP_403_FORBIDDEN)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class CheckVehicleAPI(APIView):
    permission_classes = [IsAuthenticated, MobileAccessPermission]

    def post(self, request):
        try:
            user = request.user
            data = request.data
            vehicle_instance = user.vehicles.filter(plate=data['plate']).last()
            if not vehicle_instance:
                return Response(data={'message': "Plakalarınız arasında bulamadım!", 'is_available': False},
                                status=status.HTTP_406_NOT_ACCEPTABLE)

            # If the vehicle is wanted to be taken for first time
            if vehicle_instance.phone == user.phone:
                is_available = True
                message = "Bu plaka kullanıma uygundur."
            else:
                is_available = False
                message = "Bu plaka başka bir şoför tarafından kullanılmaktadır."

            return Response(data={'message': message, 'is_available': is_available}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class ClearAuthorizationTokens(APIView):
    permission_classes = [IsAuthenticated, AuthorityPermission]

    def post(self, request):
        try:
            PosAuthorize.objects.filter(
                pk__in=PosAuthorize.objects.all().order_by('timestamp').values('pk')[:50]
            ).delete()
            PortalAuthorize.objects.filter(
                pk__in=PosAuthorize.objects.all().order_by('timestamp').values('pk')[:50]
            ).delete()

            return Response(data={'message': "data silindi!"}, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message': str(e)},
                            status=status.HTTP_400_BAD_REQUEST)


class TimezoneTestAPI(APIView):
    def post(self, request):
        sample_time = timezone.now()
        TransactionDate = str(sample_time.strftime("%d-%m-%Y %H:%M:%S"))
        return Response(data={'sample_time': sample_time, 'TransactionDate': TransactionDate},
                        status=status.HTTP_200_OK)
