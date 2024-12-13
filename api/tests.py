from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from .models import CustomUser, IYS


class CustomUserCreateTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('user_create')
        
        self.iys_data = {
            'message_permission_by_phone': True,
            'message_permission_by_email': True,
            'message_permission_by_sms': True
        }
        
        self.existing_iys = IYS.objects.create(
            message_permission_by_phone=True,
            message_permission_by_email=True,
            message_permission_by_sms=True,
            phone="05551112233"
        )
        
        self.existing_user = CustomUser.objects.create_user(
            phone="05551112233",
            email="existing@test.com",
            name="Existing",
            surname="User",
            tckn="12345678901",
            iys=self.existing_iys,
            password="testpass123"
        )
        
        self.valid_payload = {
            'phone': '05559998877',
            'email': 'test@test.com',
            'name': 'Test',
            'surname': 'User',
            'password': 'testpass123',
            'confirm_password': 'testpass123',
            'tckn': '98765432109',
            'kvkk': True,
            'aydinlatma': True,
            'iys': self.iys_data,
            'vehicles': [{'plate': '34ABC123'}]
        }

    def test_create_valid_user(self):
        response = self.client.post(
            self.url,
            self.valid_payload,
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['message'], "Hesap başarıyla oluşturuldu!")

    def test_create_user_with_existing_phone(self):
        payload = self.valid_payload.copy()
        payload['phone'] = self.existing_user.phone
        
        response = self.client.post(
            self.url,
            payload,
            format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(
            response.data['message'],
            'Bu telefon numarası ile bir hesap zaten mevcut!'
        )

    def test_create_user_with_existing_email(self):
        payload = self.valid_payload.copy()
        payload['email'] = self.existing_user.email
        
        response = self.client.post(
            self.url,
            payload,
            format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(
            response.data['message'],
            'Bu email ile bir hesap zaten mevcut!'
        )

    def test_create_user_password_mismatch(self):
        payload = self.valid_payload.copy()
        payload['confirm_password'] = 'differentpass'
        
        response = self.client.post(
            self.url,
            payload,
            format='json'
        )
        self.assertEqual(response.status_code, status.HTTP_406_NOT_ACCEPTABLE)


class MobileLoginTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.login_url = reverse('LoginView')
        self.send_otp_url = reverse('send_otp')
        
        self.existing_iys = IYS.objects.create(
            message_permission_by_phone=True,
            message_permission_by_email=True,
            message_permission_by_sms=True,
            phone="05551112233"
        )
        
        self.existing_user = CustomUser.objects.create_user(
            phone="05551112233",
            email="existing@test.com",
            name="Existing",
            surname="User",
            tckn="12345678901",
            iys=self.existing_iys,
            password="testpass123"
        )
        
        self.otp_payload = {
            'phone': '05551112233',
            'password': 'testpass123'
        }
        
        self.login_payload = {
            'phone': '05551112233',
            'password': 'testpass123',
            'verification_code': '123456'
        }

    @override_settings(SEND_OTP=False)
    def test_login_success(self):
        otp_response = self.client.post(
            self.send_otp_url,
            self.otp_payload,
            format='json'
        )

        self.assertEqual(otp_response.status_code, status.HTTP_200_OK)
        verification_code = otp_response.data.get('verification_code')
        self.login_payload['verification_code'] = verification_code
        
        response = self.client.post(
            self.login_url,
            self.login_payload,
            format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)


class UpdateUserProfileTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = reverse('UpdateUserProfile')
        
        self.iys = IYS.objects.create(
            message_permission_by_phone=True,
            message_permission_by_email=True,
            message_permission_by_sms=True,
            phone="05551112233"
        )
        
        self.user = CustomUser.objects.create_user(
            phone="05551112233",
            email="test@test.com",
            password="testpass123",
            name="Test",
            surname="User",
            tckn="12345678901",
            iys=self.iys,
            user_type="1"
        )

        other_iys = IYS.objects.create(
            message_permission_by_phone=True,
            message_permission_by_email=True,
            message_permission_by_sms=True,
            phone="05559998877"
        )
        
        self.other_user = CustomUser.objects.create_user(
            phone="05559998877",
            email="other@test.com",
            password="testpass123",
            name="Other",
            surname="User",
            tckn="98765432109",
            iys=other_iys,
            user_type="1"
        )
        
        self.client.force_authenticate(user=self.user)
        
        self.valid_payload = {
            'name': 'Updated Name',
            'surname': 'Updated Surname',
            'email': 'updated@test.com',
            'iys': {
                'message_permission_by_phone': False,
                'message_permission_by_email': True,
                'message_permission_by_sms': True
            }
        }

    def test_update_profile_success(self):
        response = self.client.post(
            self.url,
            self.valid_payload,
            format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'Updated Name')
        self.assertEqual(response.data['surname'], 'Updated Surname')
        self.assertEqual(response.data['email'], 'updated@test.com')
        
        self.user.refresh_from_db()
        self.assertFalse(self.user.iys.message_permission_by_phone)
        self.assertTrue(self.user.iys.message_permission_by_email)
        self.assertTrue(self.user.iys.message_permission_by_sms)

    def test_update_profile_partial(self):
        partial_payload = {
            'name': 'Only Name Updated'
        }
        
        response = self.client.post(
            self.url,
            partial_payload,
            format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'Only Name Updated')
        self.assertEqual(response.data['surname'], self.user.surname)
        self.assertEqual(response.data['email'], self.user.email)


    def test_update_profile_iys_timestamp(self):
        old_phone_timestamp = self.user.iys.message_permission_by_phone_timestamp
        
        payload = {
            'iys': {
                'message_permission_by_phone': False
            }
        }
        
        response = self.client.post(
            self.url,
            payload,
            format='json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.iys.refresh_from_db()
        self.assertNotEqual(
            old_phone_timestamp,
            self.user.iys.message_permission_by_phone_timestamp
        )
