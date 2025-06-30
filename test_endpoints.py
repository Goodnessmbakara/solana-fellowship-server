#!/usr/bin/env python3
"""
Solana Fellowship Server Test Script
Tests all endpoints with realistic data and proper error handling
"""

import base64
import json
import time
from typing import Any, Dict, Optional

import requests


class SolanaServerTester:

    def __init__(self, base_url: str = "https://69fr8x3c-3000.uks1.devtunnels.ms"):
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = []

    def log_test(
        self,
        endpoint: str,
        success: bool,
        response: Optional[Dict] = None,
        error: Optional[str] = None,
    ):
        """Log test results with timestamp"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        result = {
            "timestamp": timestamp,
            "endpoint": endpoint,
            "success": success,
            "response": response,
            "error": error,
        }
        self.test_results.append(result)

        status = "✅ PASS" if success else "❌ FAIL"
        print(f"[{timestamp}] {status} {endpoint}")
        if error:
            print(f"   Error: {error}")
        if response:
            print(f"   Response: {json.dumps(response, indent=2)}")
        print()

    def test_health_check(self) -> bool:
        """Test basic health check endpoint"""
        try:
            response = self.session.get(f"{self.base_url}/health")
            if response.status_code == 200:
                self.log_test("/health", True, response.json())
                return True
            else:
                self.log_test(
                    "/health", False, error=f"Status code: {response.status_code}"
                )
                return False
        except Exception as e:
            self.log_test("/health", False, error=str(e))
            return False

    def test_generate_keypair(self) -> Optional[Dict]:
        """Test keypair generation endpoint"""
        try:
            response = self.session.post(f"{self.base_url}/keypair")
            if response.status_code == 200:
                data = response.json()
                if data.get("success", False):
                    self.log_test("/keypair", True, data)
                    return data
                else:
                    self.log_test(
                        "/keypair", False, error=data.get("error", "Unknown error")
                    )
                    return None
            else:
                self.log_test(
                    "/keypair", False, error=f"Status code: {response.status_code}"
                )
                return None
        except Exception as e:
            self.log_test("/keypair", False, error=str(e))
            return None

    def test_create_token(
        self, mint_authority_pubkey: str, mint_pubkey: str
    ) -> Optional[Dict]:
        """Test SPL token creation endpoint"""
        payload = {
            "mint_authority": mint_authority_pubkey,
            "mint": mint_pubkey,
            "decimals": 9,
        }

        try:
            response = self.session.post(
                f"{self.base_url}/token/create",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("success", False):
                    self.log_test("/token/create", True, data)
                    return data
                else:
                    self.log_test(
                        "/token/create", False, error=data.get("error", "Unknown error")
                    )
                    return None
            else:
                self.log_test(
                    "/token/create",
                    False,
                    error=f"Status code: {response.status_code}, Response: {response.text}",
                )
                return None
        except Exception as e:
            self.log_test("/token/create", False, error=str(e))
            return None

    def test_mint_tokens(
        self,
        mint_pubkey: str,
        mint_authority_pubkey: str,
        recipient_address: str,
        amount: int,
    ) -> Optional[Dict]:
        """Test token minting endpoint"""
        payload = {
            "mint": mint_pubkey,
            "destination": recipient_address,
            "authority": mint_authority_pubkey,
            "amount": amount,
        }

        try:
            response = self.session.post(
                f"{self.base_url}/token/mint",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("success", False):
                    self.log_test("/token/mint", True, data)
                    return data
                else:
                    self.log_test(
                        "/token/mint", False, error=data.get("error", "Unknown error")
                    )
                    return None
            else:
                self.log_test(
                    "/token/mint",
                    False,
                    error=f"Status code: {response.status_code}, Response: {response.text}",
                )
                return None
        except Exception as e:
            self.log_test("/token/mint", False, error=str(e))
            return None

    def test_token_mint_negative_cases(self, mint_pubkey, destination_pubkey, authority_pubkey):
        """Test /token/mint endpoint with negative and edge cases"""
        print("\n4b. Testing /token/mint negative and edge cases...")
        cases = [
            # Missing fields
            ({"destination": destination_pubkey, "authority": authority_pubkey, "amount": 1000000}, "missing mint"),
            ({"mint": mint_pubkey, "authority": authority_pubkey, "amount": 1000000}, "missing destination"),
            ({"mint": mint_pubkey, "destination": destination_pubkey, "amount": 1000000}, "missing authority"),
            ({"mint": mint_pubkey, "destination": destination_pubkey, "authority": authority_pubkey}, "missing amount"),
            # Empty strings
            ({"mint": "", "destination": destination_pubkey, "authority": authority_pubkey, "amount": 1000000}, "empty mint"),
            ({"mint": mint_pubkey, "destination": "", "authority": authority_pubkey, "amount": 1000000}, "empty destination"),
            ({"mint": mint_pubkey, "destination": destination_pubkey, "authority": "", "amount": 1000000}, "empty authority"),
            # Invalid base58
            ({"mint": "invalid!base58", "destination": destination_pubkey, "authority": authority_pubkey, "amount": 1000000}, "invalid base58 mint"),
            ({"mint": mint_pubkey, "destination": "invalid!base58", "authority": authority_pubkey, "amount": 1000000}, "invalid base58 destination"),
            ({"mint": mint_pubkey, "destination": destination_pubkey, "authority": "invalid!base58", "amount": 1000000}, "invalid base58 authority"),
            # Zero/negative/large amounts
            ({"mint": mint_pubkey, "destination": destination_pubkey, "authority": authority_pubkey, "amount": 0}, "zero amount"),
            ({"mint": mint_pubkey, "destination": destination_pubkey, "authority": authority_pubkey, "amount": -1}, "negative amount"),
            ({"mint": mint_pubkey, "destination": destination_pubkey, "authority": authority_pubkey, "amount": 2**64-1}, "very large amount"),
            # Extra/unexpected fields
            ({"mint": mint_pubkey, "destination": destination_pubkey, "authority": authority_pubkey, "amount": 1000000, "extra": "field"}, "extra field"),
        ]
        for payload, desc in cases:
            try:
                response = self.session.post(f"{self.base_url}/token/mint", json=payload)
                data = response.json()
                if not (response.status_code == 200 and data.get("success") is False and "error" in data):
                    self.log_test("/token/mint (neg) - " + desc, False, response=data, error=f"Expected error, got: {data}")
                else:
                    self.log_test("/token/mint (neg) - " + desc, True, response=data)
            except Exception as e:
                self.log_test("/token/mint (neg) - " + desc, False, error=str(e))

    def test_sign_message(self, private_key: str, message: str) -> Optional[Dict]:
        """Test message signing endpoint"""
        payload = {"message": message, "secret": private_key}

        try:
            response = self.session.post(
                f"{self.base_url}/message/sign",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("success", False):
                    self.log_test("/message/sign", True, data)
                    return data
                else:
                    self.log_test(
                        "/message/sign", False, error=data.get("error", "Unknown error")
                    )
                    return None
            else:
                self.log_test(
                    "/message/sign",
                    False,
                    error=f"Status code: {response.status_code}, Response: {response.text}",
                )
                return None
        except Exception as e:
            self.log_test("/message/sign", False, error=str(e))
            return None

    def test_verify_message(
        self, public_key: str, message: str, signature: str
    ) -> bool:
        """Test message verification endpoint"""
        payload = {"message": message, "signature": signature, "pubkey": public_key}

        try:
            response = self.session.post(
                f"{self.base_url}/message/verify",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("success", False):
                    success = data.get("data", {}).get("valid", False)
                    self.log_test("/message/verify", success, data)
                    return success
                else:
                    self.log_test(
                        "/message/verify",
                        False,
                        error=data.get("error", "Unknown error"),
                    )
                    return False
            else:
                self.log_test(
                    "/message/verify",
                    False,
                    error=f"Status code: {response.status_code}, Response: {response.text}",
                )
                return False
        except Exception as e:
            self.log_test("/message/verify", False, error=str(e))
            return False

    def test_send_sol(self, from_keypair, to_keypair):
        """Test SOL transfer instruction creation"""
        print("7. Testing SOL transfer instruction...")

        # Use public keys, not private keys - access nested data structure
        from_pubkey = from_keypair["data"]["pubkey"]
        to_pubkey = to_keypair["data"]["pubkey"]

        payload = {
            "from": from_pubkey,
            "to": to_pubkey,
            "lamports": 100000  # 0.0001 SOL
        }

        try:
            response = self.session.post(f"{self.base_url}/send/sol", json=payload)
            data = response.json()

            if response.status_code == 200 and data.get("success"):
                # Check new response format: accounts should be array of strings
                accounts = data["data"]["accounts"]
                if isinstance(accounts, list) and all(isinstance(acc, str) for acc in accounts):
                    self.log_test("/send/sol", True, data)
                    return data
                else:
                    self.log_test(
                        "/send/sol", False, error="Invalid accounts format - expected array of strings"
                    )
                    return None
            else:
                self.log_test(
                    "/send/sol", False, error=data.get("error", "Unknown error")
                )
                return None
        except Exception as e:
            self.log_test("/send/sol", False, error=str(e))
            return None

    def test_send_token(self, token_data, owner_keypair):
        """Test token transfer instruction creation"""
        print("8. Testing token transfer instruction...")

        # Use public keys, not private keys - access nested data structure
        owner_pubkey = owner_keypair["data"]["pubkey"]

        payload = {
            "destination": owner_pubkey,  # destination address
            "mint": token_data["mint_pubkey"],  # mint address
            "owner": owner_pubkey,  # owner address
            "amount": 1000000  # 1 token (assuming 6 decimals)
        }

        try:
            response = self.session.post(f"{self.base_url}/send/token", json=payload)
            data = response.json()

            if response.status_code == 200 and data.get("success"):
                # Check new response format: accounts should have isSigner (camelCase)
                accounts = data["data"]["accounts"]
                if isinstance(accounts, list) and all("isSigner" in acc for acc in accounts):
                    self.log_test("/send/token", True, data)
                    return data
                else:
                    self.log_test(
                        "/send/token", False, error="Invalid accounts format - expected isSigner field"
                    )
                    return None
            else:
                self.log_test(
                    "/send/token", False, error=data.get("error", "Unknown error")
                )
                return None
        except Exception as e:
            self.log_test("/send/token", False, error=str(e))
            return None

    def test_keypair_negative_cases(self):
        print("\n2b. Testing /keypair negative and edge cases...")
        # /keypair takes no input, so test wrong method and extra fields
        cases = [
            ("GET", None, "wrong method"),
            ("POST", {"extra": "field"}, "extra field"),
        ]
        for method, payload, desc in cases:
            try:
                if method == "POST":
                    response = self.session.post(f"{self.base_url}/keypair", json=payload)
                else:
                    response = self.session.get(f"{self.base_url}/keypair")
                data = response.json()
                if not (response.status_code == 200 and data.get("success") is False and "error" in data):
                    self.log_test("/keypair (neg) - " + desc, False, response=data, error=f"Expected error, got: {data}")
                else:
                    self.log_test("/keypair (neg) - " + desc, True, response=data)
            except Exception as e:
                self.log_test("/keypair (neg) - " + desc, False, error=str(e))

    def test_create_token_negative_cases(self, mint_authority_pubkey, mint_pubkey):
        print("\n3b. Testing /token/create negative and edge cases...")
        cases = [
            # Missing fields
            ({"mint": mint_pubkey, "decimals": 6}, "missing mint_authority"),
            ({"mint_authority": mint_authority_pubkey, "decimals": 6}, "missing mint"),
            ({"mint_authority": mint_authority_pubkey, "mint": mint_pubkey}, "missing decimals"),
            # Empty strings
            ({"mint_authority": "", "mint": mint_pubkey, "decimals": 6}, "empty mint_authority"),
            ({"mint_authority": mint_authority_pubkey, "mint": "", "decimals": 6}, "empty mint"),
            # Invalid base58
            ({"mint_authority": "invalid!base58", "mint": mint_pubkey, "decimals": 6}, "invalid base58 mint_authority"),
            ({"mint_authority": mint_authority_pubkey, "mint": "invalid!base58", "decimals": 6}, "invalid base58 mint"),
            # Decimals out of range
            ({"mint_authority": mint_authority_pubkey, "mint": mint_pubkey, "decimals": 10}, "decimals too high"),
            ({"mint_authority": mint_authority_pubkey, "mint": mint_pubkey, "decimals": -1}, "decimals negative"),
            # Extra field
            ({"mint_authority": mint_authority_pubkey, "mint": mint_pubkey, "decimals": 6, "extra": "field"}, "extra field"),
        ]
        for payload, desc in cases:
            try:
                response = self.session.post(f"{self.base_url}/token/create", json=payload)
                data = response.json()
                if not (response.status_code == 200 and data.get("success") is False and "error" in data):
                    self.log_test("/token/create (neg) - " + desc, False, response=data, error=f"Expected error, got: {data}")
                else:
                    self.log_test("/token/create (neg) - " + desc, True, response=data)
            except Exception as e:
                self.log_test("/token/create (neg) - " + desc, False, error=str(e))

    def test_sign_message_negative_cases(self, secret):
        print("\n5b. Testing /message/sign negative and edge cases...")
        cases = [
            # Missing fields
            ({"message": "Hello"}, "missing secret"),
            ({"secret": secret}, "missing message"),
            # Empty strings
            ({"message": "", "secret": secret}, "empty message"),
            ({"message": "Hello", "secret": ""}, "empty secret"),
            # Invalid base58
            ({"message": "Hello", "secret": "invalid!base58"}, "invalid base58 secret"),
            # Extra field
            ({"message": "Hello", "secret": secret, "extra": "field"}, "extra field"),
        ]
        for payload, desc in cases:
            try:
                response = self.session.post(f"{self.base_url}/message/sign", json=payload)
                data = response.json()
                if not (response.status_code == 200 and data.get("success") is False and "error" in data):
                    self.log_test("/message/sign (neg) - " + desc, False, response=data, error=f"Expected error, got: {data}")
                else:
                    self.log_test("/message/sign (neg) - " + desc, True, response=data)
            except Exception as e:
                self.log_test("/message/sign (neg) - " + desc, False, error=str(e))

    def test_verify_message_negative_cases(self, pubkey, signature):
        print("\n6b. Testing /message/verify negative and edge cases...")
        cases = [
            # Missing fields
            ({"message": "Hello", "signature": signature}, "missing pubkey"),
            ({"message": "Hello", "pubkey": pubkey}, "missing signature"),
            ({"signature": signature, "pubkey": pubkey}, "missing message"),
            # Empty strings
            ({"message": "", "signature": signature, "pubkey": pubkey}, "empty message"),
            ({"message": "Hello", "signature": "", "pubkey": pubkey}, "empty signature"),
            ({"message": "Hello", "signature": signature, "pubkey": ""}, "empty pubkey"),
            # Invalid base58/base64
            ({"message": "Hello", "signature": "invalid!base64", "pubkey": pubkey}, "invalid base64 signature"),
            ({"message": "Hello", "signature": signature, "pubkey": "invalid!base58"}, "invalid base58 pubkey"),
            # Extra field
            ({"message": "Hello", "signature": signature, "pubkey": pubkey, "extra": "field"}, "extra field"),
        ]
        for payload, desc in cases:
            try:
                response = self.session.post(f"{self.base_url}/message/verify", json=payload)
                data = response.json()
                if not (response.status_code == 200 and data.get("success") is False and "error" in data):
                    self.log_test("/message/verify (neg) - " + desc, False, response=data, error=f"Expected error, got: {data}")
                else:
                    self.log_test("/message/verify (neg) - " + desc, True, response=data)
            except Exception as e:
                self.log_test("/message/verify (neg) - " + desc, False, error=str(e))

    def test_send_sol_negative_cases(self, from_pubkey, to_pubkey):
        print("\n7b. Testing /send/sol negative and edge cases...")
        cases = [
            # Missing fields
            ({"to": to_pubkey, "lamports": 100000}, "missing from"),
            ({"from": from_pubkey, "lamports": 100000}, "missing to"),
            ({"from": from_pubkey, "to": to_pubkey}, "missing lamports"),
            # Empty strings
            ({"from": "", "to": to_pubkey, "lamports": 100000}, "empty from"),
            ({"from": from_pubkey, "to": "", "lamports": 100000}, "empty to"),
            # Invalid base58
            ({"from": "invalid!base58", "to": to_pubkey, "lamports": 100000}, "invalid base58 from"),
            ({"from": from_pubkey, "to": "invalid!base58", "lamports": 100000}, "invalid base58 to"),
            # Zero/negative/large lamports
            ({"from": from_pubkey, "to": to_pubkey, "lamports": 0}, "zero lamports"),
            ({"from": from_pubkey, "to": to_pubkey, "lamports": -1}, "negative lamports"),
            ({"from": from_pubkey, "to": to_pubkey, "lamports": 2**64-1}, "very large lamports"),
            # Same address
            ({"from": from_pubkey, "to": from_pubkey, "lamports": 100000}, "same from and to"),
            # Extra field
            ({"from": from_pubkey, "to": to_pubkey, "lamports": 100000, "extra": "field"}, "extra field"),
        ]
        for payload, desc in cases:
            try:
                response = self.session.post(f"{self.base_url}/send/sol", json=payload)
                data = response.json()
                if not (response.status_code == 200 and data.get("success") is False and "error" in data):
                    self.log_test("/send/sol (neg) - " + desc, False, response=data, error=f"Expected error, got: {data}")
                else:
                    self.log_test("/send/sol (neg) - " + desc, True, response=data)
            except Exception as e:
                self.log_test("/send/sol (neg) - " + desc, False, error=str(e))

    def test_send_token_negative_cases(self, destination, mint, owner):
        print("\n8b. Testing /send/token negative and edge cases...")
        cases = [
            # Missing fields
            ({"mint": mint, "owner": owner, "amount": 100000}, "missing destination"),
            ({"destination": destination, "owner": owner, "amount": 100000}, "missing mint"),
            ({"destination": destination, "mint": mint, "amount": 100000}, "missing owner"),
            ({"destination": destination, "mint": mint, "owner": owner}, "missing amount"),
            # Empty strings
            ({"destination": "", "mint": mint, "owner": owner, "amount": 100000}, "empty destination"),
            ({"destination": destination, "mint": "", "owner": owner, "amount": 100000}, "empty mint"),
            ({"destination": destination, "mint": mint, "owner": "", "amount": 100000}, "empty owner"),
            # Invalid base58
            ({"destination": "invalid!base58", "mint": mint, "owner": owner, "amount": 100000}, "invalid base58 destination"),
            ({"destination": destination, "mint": "invalid!base58", "owner": owner, "amount": 100000}, "invalid base58 mint"),
            ({"destination": destination, "mint": mint, "owner": "invalid!base58", "amount": 100000}, "invalid base58 owner"),
            # Zero/negative/large amount
            ({"destination": destination, "mint": mint, "owner": owner, "amount": 0}, "zero amount"),
            ({"destination": destination, "mint": mint, "owner": owner, "amount": -1}, "negative amount"),
            ({"destination": destination, "mint": mint, "owner": owner, "amount": 2**64-1}, "very large amount"),
            # Extra field
            ({"destination": destination, "mint": mint, "owner": owner, "amount": 100000, "extra": "field"}, "extra field"),
        ]
        for payload, desc in cases:
            try:
                response = self.session.post(f"{self.base_url}/send/token", json=payload)
                data = response.json()
                if not (response.status_code == 200 and data.get("success") is False and "error" in data):
                    self.log_test("/send/token (neg) - " + desc, False, response=data, error=f"Expected error, got: {data}")
                else:
                    self.log_test("/send/token (neg) - " + desc, True, response=data)
            except Exception as e:
                self.log_test("/send/token (neg) - " + desc, False, error=str(e))

    def run_all_tests(self):
        """Run comprehensive test suite"""
        print("🚀 Starting Solana Fellowship Server Test Suite")
        print("=" * 60)

        # Test 1: Health check
        print("\n1. Testing health check...")
        self.test_health_check()

        # Test 2: Generate keypairs for testing
        print("\n2. Generating test keypairs...")
        keypair1 = self.test_generate_keypair()
        keypair2 = self.test_generate_keypair()

        if not keypair1 or not keypair2:
            print("❌ Failed to generate keypairs. Stopping tests.")
            return

        # Test 3: Create SPL token (using public keys, not private keys)
        print("\n3. Testing SPL token creation...")
        token_data = self.test_create_token(
            keypair1["data"]["pubkey"],  # mint_authority (public key)
            keypair2["data"]["pubkey"],  # mint (public key)
        )

        # Test 4: Mint tokens (only if token creation was successful)
        print("\n4. Testing token minting...")
        if token_data:
            self.test_mint_tokens(
                keypair2["data"]["pubkey"],  # mint (public key)
                keypair1["data"]["pubkey"],  # authority (public key)
                keypair1["data"]["pubkey"],  # destination (public key)
                1000000000,  # 1 token with 9 decimals
            )
            self.test_token_mint_negative_cases(
                keypair2["data"]["pubkey"],
                keypair1["data"]["pubkey"],
                keypair1["data"]["pubkey"]
            )

        # Test 5: Sign message
        print("\n5. Testing message signing...")
        sign_data = self.test_sign_message(
            keypair1["data"]["secret"],
            "Hello Solana Fellowship! This is a test message.",
        )

        # Test 6: Verify message
        print("\n6. Testing message verification...")
        if sign_data:
            self.test_verify_message(
                keypair1["data"]["pubkey"],
                "Hello Solana Fellowship! This is a test message.",
                sign_data["data"]["signature"],
            )

        # Test 7: Create SOL transfer instruction
        self.test_send_sol(keypair1, keypair2)

        # Test 8: Create token transfer instruction (only if token creation was successful)
        if token_data:
            # Create a mock token data structure for testing
            mock_token_data = {
                "mint_pubkey": keypair2["data"]["pubkey"]  # Use the mint public key
            }
            self.test_send_token(mock_token_data, keypair1)
        else:
            print("8. Testing token transfer instruction...")
            self.log_test("/send/token", False, error="Token creation failed, skipping token transfer test")

        # Print summary
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)

        passed = sum(1 for result in self.test_results if result["success"])
        total = len(self.test_results)

        print(f"Total tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Success rate: {(passed/total)*100:.1f}%")

        # Save results to file
        with open("test_results.json", "w") as f:
            json.dump(self.test_results, f, indent=2)
        print(f"\n📄 Detailed results saved to: test_results.json")


def main():
    """Main test runner"""
    import sys

    # Allow custom base URL
    base_url = (
        sys.argv[1] if len(sys.argv) > 1 else "https://69fr8x3c-3000.uks1.devtunnels.ms"
    )

    print(f"🎯 Testing server at: {base_url}")

    tester = SolanaServerTester(base_url)
    tester.run_all_tests()


if __name__ == "__main__":
    main()
