from celery import shared_task
from api.models import PosAuthorize, PortalAuthorize, CustomUser, MobileTransactionHistory, DailyBalanceInfo, EndOfDay
import requests
from django.conf import settings
from api.functions import create_end_day_excel
from django.utils import timezone
import decimal

pos_authorize_url = settings.POS_AUTHORIZE_URL
pos_authorize_payload = {
    "ApplicationLoginID": settings.APPLICATIONLOGINID,
    "Password": settings.PASSWORD
}

web_portal_url = settings.WEB_PORTAL_URL
web_portal_payload = {
    "grant_type": "password",
    "scope": "https://everest/spos/portal",
    "user_id": "ahmetg1",
    "password": settings.WEB_PORTAL_PASSWORD,
    "client_id": "backoffice",
    "client_secret": "1234"
}


@shared_task
def EndDayTask():
    users = CustomUser.objects.filter(user_type="1", status="1")
    # Creation of excel
    daily_list = []
    for user in users:
        daily_list.append(DailyBalanceInfo(phone=user.phone, tckn=user.tckn, balance=user.balance,
                                           timestamp=timezone.now()))
    DailyBalanceInfo.objects.bulk_create(daily_list)

    # Excel url and key(file_name) of the day
    url, key = create_end_day_excel(daily_list)
    EndOfDay.objects.create(url=url, key=key)

    # End of the day
    sample_time = timezone.datetime.now()
    previous_day = sample_time - timezone.timedelta(days=1)

    transactions = MobileTransactionHistory.objects.filter(end_time__lte=previous_day,
                                                           end_time__gte=sample_time)
    transaction_list = []
    for transaction in transactions:
        transaction.IsVoidable = False
        transaction.IsRefundable = True
        transaction_list.append(transaction)

    MobileTransactionHistory.objects.bulk_update(transaction_list, ['IsVoidable', 'IsRefundable'])

    # Reset all balances
    user_list = []
    for user in users:
        user.balance = decimal.Decimal(0.00)
        user_list.append(user)

    CustomUser.objects.bulk_update(user_list, ['balance'])


@shared_task
def RenewAuthorization():

    pos_response = requests.post(pos_authorize_url, json=pos_authorize_payload)
    if pos_response.ok:
        pos_response = pos_response.json()

    portal_response = requests.post(web_portal_url, json=web_portal_payload)

    if portal_response.ok:
        portal_response = portal_response.json()

    PosAuthorize.objects.create(Token=pos_response['Token'])
    PortalAuthorize.objects.create(access_token=portal_response['access_token'])

    # if PosAuthorize.objects.all().count() > 1500:
    #     date = timezone.datetime.today()
    #     timestamp = date - timezone.timedelta(days=15)
    #
    #     PosAuthorize.objects.filter(
    #         pk__in=PosAuthorize.objects.filter(timestamp__lt=timestamp).values('pk')
    #     ).delete()
    #     PortalAuthorize.objects.filter(
    #         pk__in=PortalAuthorize.objects.filter(timestamp__lt=timestamp).values('pk')
    #     ).delete()
