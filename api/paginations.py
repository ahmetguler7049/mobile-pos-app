from rest_framework.pagination import PageNumberPagination


class MobileTransactionHistoryPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'


class DashboardTransactionHistoryPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'


class DashboardUserListPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
