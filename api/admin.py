from django.contrib import admin
from api.models import CustomUser, OtpPassword, PosAuthorize, AdditionalAmounts, \
    PaymentSession, ServerStatus, IYS, Vehicles, Deeplink, PortalAuthorize, MobileTransactionHistory, \
    VoidRefundSession, DailyBalanceInfo, EndOfDay, Receipt, WebhookData, PaymentLocation
from django.contrib.auth.admin import UserAdmin


class UserAdminConfig(UserAdmin):
    model = CustomUser
    search_fields = ('user_id', 'email', 'phone', 'tckn', 'name', 'surname')
    list_filter = ('user_id', 'email', 'phone', 'name', 'surname', 'status', 'is_active', 'is_staff', 'last_login')
    ordering = ('-start_date',)
    filter_horizontal = ('vehicles', 'groups')
    list_display = ('user_id', 'phone', 'tckn', 'name', 'surname', 'status',
                    'is_active', 'is_staff', 'last_login')
    list_display_links = ('phone', 'user_id')
    readonly_fields = ('user_id',)
    fieldsets = (
        (None, {'fields': ('user_id', 'phone', 'tckn', 'password', 'email', 'name', 'surname', 'address', 'vehicles',
                           'status', 'user_type', 'balance', 'start_date', 'sozlesme_no', 'last_login',
                           'kvkk', 'kvkk_timestamp', 'aydinlatma', 'aydinlatma_timestamp', 'iys')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'groups')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('phone', 'password1', 'password2', 'email', 'name', 'surname', 'address', 'user_type',
                       'vehicles', 'is_staff', 'is_active', 'iys')}
         ),
    )


class OtpAdmin(admin.ModelAdmin):
    model = OtpPassword
    list_display = ('related_user', 'verification_code', 'timestamp')
    list_display_links = ('related_user',)
    fieldsets = (
        (None, {'fields': ('related_user', 'verification_code', 'timestamp')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('related_user', 'verification_code', 'timestamp')}
         ),
    )


class PosAuthorizeAdmin(admin.ModelAdmin):
    model = PosAuthorize
    list_display = ('timestamp',)
    list_display_links = ('timestamp',)
    fieldsets = (
        (None, {'fields': ('Token', 'timestamp')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('Token',)}
         ),
    )


class PortalAuthorizeAdmin(admin.ModelAdmin):
    model = PortalAuthorize
    list_display = ('timestamp',)
    list_display_links = ('timestamp',)
    ordering = ('-timestamp',)
    fieldsets = (
        (None, {'fields': ('access_token', 'timestamp')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('access_token',)}
         ),
    )


class VehiclesAdmin(admin.ModelAdmin):
    model = Vehicles
    list_display = ('plate', 'timestamp', 'phone', 'picked_at')
    list_display_links = ('plate',)
    fieldsets = (
        (None, {'fields': ('plate', 'timestamp', 'phone', 'picked_at')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('plate', 'timestamp', 'phone', 'picked_at')}
         ),
    )


class IYSAdmin(admin.ModelAdmin):
    model = IYS
    list_display = ('phone', 'message_permission_by_phone', 'message_permission_by_phone_timestamp',
                    'message_permission_by_email', 'message_permission_by_email_timestamp',
                    'message_permission_by_sms', 'message_permission_by_sms_timestamp')
    list_display_links = ('phone',)
    fieldsets = (
        (None, {'fields': ('phone', 'message_permission_by_phone', 'message_permission_by_phone_timestamp',
                           'message_permission_by_email', 'message_permission_by_email_timestamp',
                           'message_permission_by_sms', 'message_permission_by_sms_timestamp')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('message_permission_by_phone', 'message_permission_by_phone_timestamp',
                       'message_permission_by_email', 'message_permission_by_email_timestamp',
                       'message_permission_by_sms', 'message_permission_by_sms_timestamp')}
         ),
    )


class PaymentSessionAdmin(admin.ModelAdmin):
    model = PaymentSession
    list_display = ('OrderID', 'UserHash', 'Amount', 'PaymentSessionToken', 'TransactionType', 'timestamp')
    list_display_links = ('OrderID',)
    # readonly_fields = ('OrderID', 'UserHash')
    fieldsets = (
        (None, {'fields': ('OrderID', 'UserHash', 'Amount', 'PaymentSessionToken', 'is_used',
                           'TransactionType', 'timestamp')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('UserHash', 'Amount', 'TransactionType', 'CurrencyCode')}
         ),
    )


class VoidRefundSessionAdmin(admin.ModelAdmin):
    model = VoidRefundSession
    list_display = ('OrderID', 'PaymentSessionToken', 'TransactionType', 'timestamp')
    list_display_links = ('OrderID', 'PaymentSessionToken')
    # readonly_fields = ('OrderID',)
    fieldsets = (
        (None, {'fields': ('OrderID', 'payment_session', 'PaymentSessionToken', 'is_used',
                           'TransactionType', 'timestamp')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('OrderID', 'payment_session', 'PaymentSessionToken', 'is_used',
                       'TransactionType', 'timestamp')}
         ),
    )


class DeeplinkAdmin(admin.ModelAdmin):
    model = Deeplink
    list_display = ('payment_session', 'void_refund_session', 'TransactionType', 'Status',
                    'Approved', 'timestamp')
    list_display_links = ('payment_session', 'void_refund_session',)
    search_fields = ('OrderID',)
    ordering = ('-timestamp',)
    fieldsets = (
        (None, {'fields': ('payment_session', 'void_refund_session', 'data', 'hashData', 'TransactionType', 'Status',
                           'Approved', 'IsVoidable', 'IsRefundable', 'timestamp')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('payment_session', 'void_refund_session', 'data', 'Approved')}
         ),
    )


class WebhookDataAdmin(admin.ModelAdmin):
    model = WebhookData
    list_display = ('payment_session', 'void_refund_session', 'TransactionType', 'Approved', 'timestamp')
    list_display_links = ('payment_session', 'void_refund_session')
    ordering = ('-timestamp',)
    fieldsets = (
        (None, {'fields': ('payment_session', 'void_refund_session', 'data', 'hashData', 'TransactionType', 'Approved',
                           'IsVoidable', 'IsRefundable', 'timestamp')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('payment_session', 'void_refund_session', 'data', 'Approved')}
         ),
    )


class DailyBalanceInfoAdmin(admin.ModelAdmin):
    model = DailyBalanceInfo
    list_display = ('phone', 'tckn', 'balance', 'timestamp')
    list_display_links = ('phone',)
    ordering = ('-timestamp',)
    fieldsets = (
        (None, {'fields': ('phone', 'tckn', 'balance', 'timestamp')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('phone', 'tckn', 'balance', 'timestamp')}
         ),
    )


class EndOfDayAdmin(admin.ModelAdmin):
    model = EndOfDay
    list_display = ('url', 'key', 'uploaded_at', 'expires_at')
    list_display_links = ('key',)
    ordering = ('-uploaded_at',)
    fieldsets = (
        (None, {'fields': ('url', 'key', 'uploaded_at', 'expires_at')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('url', 'key', 'uploaded_at')}
         ),
    )


class MobileTransactionHistoryAdmin(admin.ModelAdmin):
    model = MobileTransactionHistory
    list_display = ('phone', 'OrderID', 'success', 'TransactionType', 'TransactionDate',
                    'DriverAmount', 'start_time', 'end_time')
    list_display_links = ('phone', 'OrderID')
    search_fields = ('phone', 'OrderID', 'DriverAmount')
    readonly_fields = ('phone', 'OrderID',)
    ordering = ('-deeplink__timestamp',)
    fieldsets = (
        (None, {'fields': ('phone', 'name', 'surname', 'OrderID', 'success', 'TransactionType', 'QRLink',
                           'IsVoidable', 'IsRefundable', 'TransactionDate', 'DriverAmount', 'detail',
                           'start_time', 'end_time')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('phone', 'OrderID', 'success', 'QRLink', 'IsVoidable', 'IsRefundable', 'TransactionDate',
                       'DriverAmount', 'detail')}
         )

    )


admin.site.register(CustomUser, UserAdminConfig)
admin.site.register(OtpPassword, OtpAdmin)
admin.site.register(IYS, IYSAdmin)
admin.site.register(Vehicles, VehiclesAdmin)
admin.site.register(PosAuthorize, PosAuthorizeAdmin)
admin.site.register(PortalAuthorize, PortalAuthorizeAdmin)
admin.site.register(Deeplink, DeeplinkAdmin)
admin.site.register(WebhookData, WebhookDataAdmin)
admin.site.register(PaymentSession, PaymentSessionAdmin)
admin.site.register(VoidRefundSession, VoidRefundSessionAdmin)
admin.site.register(DailyBalanceInfo, DailyBalanceInfoAdmin)
admin.site.register(EndOfDay, EndOfDayAdmin)
admin.site.register(MobileTransactionHistory, MobileTransactionHistoryAdmin)
admin.site.register(AdditionalAmounts)
admin.site.register(Receipt)
admin.site.register(ServerStatus)
admin.site.register(PaymentLocation)
