import unittest

from otp import OTPService


class OTPServiceTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.sent = []
        self.service = OTPService(
            self.sent.append,
            clock=lambda: self.now,
            make_code=lambda: "123456",
        )

    def test_success_is_single_use(self):
        self.assertTrue(self.service.send_code("session")[0])
        self.assertEqual(self.sent, ["123456"])
        self.assertTrue(self.service.verify_code("session", "123456")[0])
        self.assertFalse(self.service.verify_code("session", "123456")[0])

    def test_expiration_and_attempt_limit(self):
        self.service.send_code("session")
        self.now += 300
        self.assertIn("expired", self.service.verify_code("session", "123456")[1])
        self.now += 30
        self.service.send_code("session")
        for _ in range(4):
            self.assertIn("Incorrect", self.service.verify_code("session", "000000")[1])
        self.assertIn("Too many", self.service.verify_code("session", "000000")[1])
        self.assertFalse(self.service.verify_code("session", "123456")[0])

    def test_cooldown_applies_across_sessions(self):
        self.service.send_code("first")
        self.assertIn("Wait", self.service.send_code("second")[1])
        self.assertEqual(len(self.sent), 1)
        self.now += 30
        self.assertTrue(self.service.send_code("second")[0])

    def test_failed_send_keeps_existing_code_and_does_not_start_cooldown(self):
        self.service.send_code("session")
        self.now += 30
        self.service.send_email = lambda code: (_ for _ in ()).throw(OSError("offline"))
        with self.assertRaises(OSError):
            self.service.send_code("session")
        self.assertTrue(self.service.verify_code("session", "123456")[0])
        self.service.send_email = self.sent.append
        self.assertTrue(self.service.send_code("session")[0])


if __name__ == "__main__":
    unittest.main()
