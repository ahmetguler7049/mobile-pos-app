from rest_framework.throttling import AnonRateThrottle


class OTPThrottle(AnonRateThrottle):
    rate = '6/hour'

