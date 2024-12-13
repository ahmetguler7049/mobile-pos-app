from django.contrib import admin
from django.urls import path

from api.views import CustomUserCreate, GetUserInfo, MobileLoginView, LogoutView, DashboardLoginView, \
    DashboardSendOTPView, ForgetPasswordStart, ForgetPasswordFinish, MobileSendOTPView, ServerStatusView, \
    PaymentStart, RefreshTokenView, GetUserList, GetUserDetail, UpdateUserProfile, \
    WebhookRemoteView, PaymentFinish, TransactionHistoryView, ResetPassword, VoidRefundStart, VoidRefundFinish, \
    UserStatusUpdate, ResetPhone, ResetPhoneOTP, DashboardUserUpdate, DashboardAllTransactions, \
    DashboardUserTransactionHistory, DashboardUserTransactionDetail, TransactionReceipt, AllCashOuts, \
    RegenerateExcelURL, MobileAddPlateAPI, MobileRemovePlateAPI, MobilePlateList, DashboardAddPlateAPI, \
    DashboardRemovePlateAPI, DashboardPlateList, SetVehicleAPI, CheckVehicleAPI, TransactionHistoryByDate, \
    ClearAuthorizationTokens

urlpatterns = [
    path('admin/', admin.site.urls),
    path('app/status/', ServerStatusView.as_view(), name='server_status'),
    path('app/user-register/', CustomUserCreate.as_view(), name='user_create'),
    path('app/user-GetUserInfo/', GetUserInfo.as_view(), name='get_user_filtered'),
    path('app/login-otp-verification/', MobileSendOTPView.as_view(), name='send_otp'),
    path('app/user-login/', MobileLoginView.as_view(), name='LoginView'),
    path('app/user-profile-update/', UpdateUserProfile.as_view(), name='UpdateUserProfile'),
    path('app/user-logout/', LogoutView.as_view(), name='UserLogout'),
    path('app/forget-password-otp/', ForgetPasswordStart.as_view(), name='ForgetPasswordStart'),
    path('app/forget-password/', ForgetPasswordFinish.as_view(), name='ForgetPasswordFinish'),
    path('app/reset-password/', ResetPassword.as_view(), name='ResetPassword'),
    path('app/payment-start/', PaymentStart.as_view(), name='PaymentStart'),
    path('app/payment-finish/', PaymentFinish.as_view(), name='PaymentFinish'),
    path('app/payment-void-refund/', VoidRefundStart.as_view(), name='VoidRefundStart'),
    path('app/payment-void-refund-finish/', VoidRefundFinish.as_view(), name='VoidRefundFinish'),
    path('app/payment-transaction-history/', TransactionHistoryView.as_view(), name='TransactionHistoryView'),
    path('app/payment-transaction-history-by-date/', TransactionHistoryByDate.as_view(),
         name='TransactionHistoryByDate'),
    path('app/refresh-token/', RefreshTokenView.as_view(), name='RefreshToken'),
    path('app/add-plate/', MobileAddPlateAPI.as_view(), name='MobileAddPlateAPI'),
    path('app/remove-plate/', MobileRemovePlateAPI.as_view(), name='MobileRemovePlateAPI'),
    path('app/vehicle-set/', SetVehicleAPI.as_view(), name='AllocateVehicleAPI'),
    path('app/vehicle-check/', CheckVehicleAPI.as_view(), name='CheckVehicleAPI'),
    path('app/plate-list/', MobilePlateList.as_view(), name='MobilePlateList'),
    path('dashboard/otp-verification/', DashboardSendOTPView.as_view(), name='dashboard_send_otp'),
    path('dashboard/login/', DashboardLoginView.as_view(), name='DashboardLoginView'),
    path('dashboard/user-logout/', LogoutView.as_view(), name='DashboardLogout'),
    path('dashboard/user-list/', GetUserList.as_view(), name='GetUserList'),
    path('dashboard/user-detail/', GetUserDetail.as_view(), name='GetUserDetail'),
    path('dashboard/user-status-update/', UserStatusUpdate.as_view(), name='UserStatusUpdate'),
    path('dashboard/user-phone-update/', ResetPhone.as_view(), name='ResetPhone'),
    path('dashboard/user-phone-update-otp/', ResetPhoneOTP.as_view(), name='ResetPhoneOTP'),
    path('dashboard/user-update/', DashboardUserUpdate.as_view(), name='DashboardUserUpdate'),
    path('dashboard/all-transactions/', DashboardAllTransactions.as_view(), name='DashboardAllTransactions'),
    path('dashboard/all-cashouts/', AllCashOuts.as_view(), name='AllCashOuts'),
    path('dashboard/regenerate-excel-url/', RegenerateExcelURL.as_view(), name='RegenerateExcelURL'),
    path('dashboard/user-transaction-history/', DashboardUserTransactionHistory.as_view(),
         name='DashboardUserTransactionHistory'),
    path('dashboard/user-transaction-detail/', DashboardUserTransactionDetail.as_view(),
         name='DashboardUserTransactionDetail'),
    path('dashboard/add-plate/', DashboardAddPlateAPI.as_view(), name='DashboardAddPlateAPI'),
    path('dashboard/remove-plate/', DashboardRemovePlateAPI.as_view(), name='DashboardRemovePlateAPI'),
    path('dashboard/plate-list/', DashboardPlateList.as_view(), name='DashboardPlateList'),
    path('webhook/remote/', WebhookRemoteView.as_view(), name='WebhookRemoteView'),
    path('transaction/receipt/', TransactionReceipt.as_view(), name='TransactionReceipt'),
    path('clear/tokens/', ClearAuthorizationTokens.as_view(), name='ClearAuthorizationTokens'),
]
