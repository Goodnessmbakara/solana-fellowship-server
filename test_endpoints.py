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
    def __init__(self, base_url: str = "http://localhost:3000"):
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
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"

    print(f"🎯 Testing server at: {base_url}")

    tester = SolanaServerTester(base_url)
    tester.run_all_tests()


if __name__ == "__main__":
    main()
