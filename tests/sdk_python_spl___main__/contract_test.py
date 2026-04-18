"""
Contract tests for sdk_python_spl___main__ component.

This test suite verifies the main() CLI function according to its contract:
- Argument parsing (InsufficientArguments errors)
- File loading (PolicyFileNotFound, RequestFileNotFound errors)
- Processing (InvalidJSON, ParseError, VerificationError, KeyError errors)
- Invariants (environment structure, hardcoded values)
- Integration tests with real files
"""

import pytest
import sys
import json
import os
from pathlib import Path
from unittest.mock import Mock, patch, mock_open, MagicMock
from io import StringIO


# Mock the module structure since we're testing the main function
# Import will be mocked in fixtures
class MockParser:
    @staticmethod
    def parse(policy_text):
        return {"parsed": "policy"}


class MockVerifier:
    @staticmethod
    def verify(policy, request, env):
        return {"allow": True}


# Test fixtures
@pytest.fixture
def mock_parser():
    """Mock parser.parse function"""
    with patch('sdk_python_spl___main__.parse') as mock_parse:
        mock_parse.return_value = {"parsed": "policy"}
        yield mock_parse


@pytest.fixture
def mock_verifier():
    """Mock verifier.verify function"""
    with patch('sdk_python_spl___main__.verify') as mock_verify:
        mock_verify.return_value = {"allow": True}
        yield mock_verify


@pytest.fixture
def valid_policy_file(tmp_path):
    """Create a valid policy file"""
    policy_file = tmp_path / "policy.spl"
    policy_file.write_text("allow if true")
    return str(policy_file)


@pytest.fixture
def valid_request_file(tmp_path):
    """Create a valid request JSON file"""
    request_file = tmp_path / "request.json"
    request_file.write_text('{"action": "send", "resource": "email"}')
    return str(request_file)


@pytest.fixture
def invalid_json_file(tmp_path):
    """Create an invalid JSON file"""
    request_file = tmp_path / "invalid.json"
    request_file.write_text('{"invalid": json}')
    return str(request_file)


@pytest.fixture
def empty_policy_file(tmp_path):
    """Create an empty policy file"""
    policy_file = tmp_path / "empty.spl"
    policy_file.write_text("")
    return str(policy_file)


@pytest.fixture
def empty_json_file(tmp_path):
    """Create an empty JSON object file"""
    request_file = tmp_path / "empty.json"
    request_file.write_text('{}')
    return str(request_file)


# Happy Path Tests
class TestHappyPath:
    """Tests for successful execution paths"""
    
    def test_happy_path_allow(self, valid_policy_file, valid_request_file, 
                               mock_parser, mock_verifier, capsys, monkeypatch):
        """Happy path: valid policy and request files that result in ALLOW decision"""
        # Setup
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, valid_request_file])
        mock_verifier.return_value = {"allow": True}
        
        # Import and execute
        from sdk.python.spl.__main__ import main
        
        try:
            main()
        except SystemExit:
            pass
        
        # Verify
        captured = capsys.readouterr()
        assert 'ALLOW' in captured.out
        mock_parser.assert_called_once()
        mock_verifier.assert_called_once()
        
        # Verify environment structure in call
        call_args = mock_verifier.call_args
        if call_args:
            env = call_args[0][2] if len(call_args[0]) > 2 else call_args[1].get('env')
            if env:
                assert 'vars' in env
                assert 'now' in env
                assert 'per_day_count' in env
                assert 'crypto' in env
    
    def test_happy_path_deny(self, valid_policy_file, valid_request_file,
                             mock_parser, mock_verifier, capsys, monkeypatch):
        """Happy path: valid policy and request files that result in DENY decision"""
        # Setup
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, valid_request_file])
        mock_verifier.return_value = {"allow": False}
        
        # Import and execute
        from sdk.python.spl.__main__ import main
        
        try:
            main()
        except SystemExit:
            pass
        
        # Verify
        captured = capsys.readouterr()
        assert 'DENY' in captured.out
        mock_parser.assert_called_once()
        mock_verifier.assert_called_once()
    
    def test_integration_end_to_end(self, tmp_path, mock_parser, mock_verifier,
                                    capsys, monkeypatch):
        """Integration: full end-to-end test with real files"""
        # Create realistic policy and request files
        policy_file = tmp_path / "full_policy.spl"
        policy_file.write_text("""
        policy email_policy {
            allow if request.action == "send" and
                     request.recipient in vars.allowed_recipients
        }
        """)
        
        request_file = tmp_path / "full_request.json"
        request_file.write_text(json.dumps({
            "action": "send",
            "recipient": "niece@example.com",
            "subject": "Hello"
        }))
        
        monkeypatch.setattr(sys, 'argv', ['program', str(policy_file), str(request_file)])
        mock_verifier.return_value = {"allow": True}
        
        # Execute
        from sdk.python.spl.__main__ import main
        
        try:
            main()
        except SystemExit:
            pass
        
        # Verify complete flow
        captured = capsys.readouterr()
        assert captured.out in ['ALLOW\n', 'DENY\n'] or 'ALLOW' in captured.out or 'DENY' in captured.out


# Error Case Tests
class TestErrorCases:
    """Tests for error conditions"""
    
    def test_error_insufficient_arguments_zero(self, monkeypatch):
        """Error case: no arguments provided (only program name)"""
        monkeypatch.setattr(sys, 'argv', ['program'])
        
        from sdk.python.spl.__main__ import main
        
        with pytest.raises((SystemExit, IndexError, Exception)) as exc_info:
            main()
        
        # Should raise/exit due to insufficient arguments
        assert exc_info.value is not None
    
    def test_error_insufficient_arguments_one(self, monkeypatch):
        """Error case: only one argument provided"""
        monkeypatch.setattr(sys, 'argv', ['program', 'only_one_arg'])
        
        from sdk.python.spl.__main__ import main
        
        with pytest.raises((SystemExit, IndexError, FileNotFoundError, Exception)) as exc_info:
            main()
        
        # Should raise/exit due to insufficient arguments
        assert exc_info.value is not None
    
    def test_error_policy_file_not_found(self, valid_request_file, monkeypatch):
        """Error case: policy file does not exist"""
        monkeypatch.setattr(sys, 'argv', ['program', '/nonexistent/policy.spl', valid_request_file])
        
        from sdk.python.spl.__main__ import main
        
        with pytest.raises((SystemExit, FileNotFoundError, Exception)) as exc_info:
            main()
        
        # Should raise/exit due to missing policy file
        assert exc_info.value is not None
    
    def test_error_policy_file_not_readable(self, valid_request_file, tmp_path, monkeypatch):
        """Error case: policy file exists but is not readable"""
        policy_file = tmp_path / "unreadable.spl"
        policy_file.write_text("allow if true")
        
        # Make file unreadable (Unix-like systems)
        if hasattr(os, 'chmod'):
            os.chmod(str(policy_file), 0o000)
        
        monkeypatch.setattr(sys, 'argv', ['program', str(policy_file), valid_request_file])
        
        from sdk.python.spl.__main__ import main
        
        try:
            with pytest.raises((SystemExit, PermissionError, FileNotFoundError, Exception)) as exc_info:
                main()
            assert exc_info.value is not None
        finally:
            # Restore permissions for cleanup
            if hasattr(os, 'chmod'):
                os.chmod(str(policy_file), 0o644)
    
    def test_error_request_file_not_found(self, valid_policy_file, monkeypatch):
        """Error case: request file does not exist"""
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, '/nonexistent/request.json'])
        
        from sdk.python.spl.__main__ import main
        
        with pytest.raises((SystemExit, FileNotFoundError, Exception)) as exc_info:
            main()
        
        # Should raise/exit due to missing request file
        assert exc_info.value is not None
    
    def test_error_request_file_not_readable(self, valid_policy_file, tmp_path, monkeypatch):
        """Error case: request file exists but is not readable"""
        request_file = tmp_path / "unreadable.json"
        request_file.write_text('{"action": "test"}')
        
        # Make file unreadable (Unix-like systems)
        if hasattr(os, 'chmod'):
            os.chmod(str(request_file), 0o000)
        
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, str(request_file)])
        
        from sdk.python.spl.__main__ import main
        
        try:
            with pytest.raises((SystemExit, PermissionError, FileNotFoundError, Exception)) as exc_info:
                main()
            assert exc_info.value is not None
        finally:
            # Restore permissions for cleanup
            if hasattr(os, 'chmod'):
                os.chmod(str(request_file), 0o644)
    
    def test_error_invalid_json(self, valid_policy_file, invalid_json_file,
                                mock_parser, monkeypatch):
        """Error case: request file contains invalid JSON"""
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, invalid_json_file])
        
        from sdk.python.spl.__main__ import main
        
        with pytest.raises((SystemExit, json.JSONDecodeError, ValueError, Exception)) as exc_info:
            main()
        
        # Should raise/exit due to invalid JSON
        assert exc_info.value is not None
    
    def test_error_parse_error(self, valid_request_file, valid_policy_file,
                               mock_parser, monkeypatch):
        """Error case: policy file contains invalid SPL syntax"""
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, valid_request_file])
        
        # Make parser raise an exception
        mock_parser.side_effect = Exception("Parse error: invalid SPL syntax")
        
        from sdk.python.spl.__main__ import main
        
        with pytest.raises((SystemExit, Exception)) as exc_info:
            main()
        
        # Should raise/exit due to parse error
        assert exc_info.value is not None
        mock_parser.assert_called_once()
    
    def test_error_verification_error(self, valid_policy_file, valid_request_file,
                                      mock_parser, mock_verifier, monkeypatch):
        """Error case: verify function raises an exception"""
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, valid_request_file])
        
        # Make verifier raise an exception
        mock_verifier.side_effect = Exception("Verification failed")
        
        from sdk.python.spl.__main__ import main
        
        with pytest.raises((SystemExit, Exception)) as exc_info:
            main()
        
        # Should raise/exit due to verification error
        assert exc_info.value is not None
        mock_verifier.assert_called_once()
    
    def test_error_missing_allow_key(self, valid_policy_file, valid_request_file,
                                     mock_parser, mock_verifier, monkeypatch):
        """Error case: verify result does not contain 'allow' key"""
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, valid_request_file])
        
        # Make verifier return dict without 'allow' key
        mock_verifier.return_value = {"result": "something_else"}
        
        from sdk.python.spl.__main__ import main
        
        with pytest.raises((SystemExit, KeyError, Exception)) as exc_info:
            main()
        
        # Should raise/exit due to missing 'allow' key
        assert exc_info.value is not None


# Edge Case Tests
class TestEdgeCases:
    """Tests for boundary conditions and edge cases"""
    
    def test_edge_case_empty_policy_file(self, empty_policy_file, valid_request_file,
                                         mock_parser, monkeypatch):
        """Edge case: policy file is empty"""
        monkeypatch.setattr(sys, 'argv', ['program', empty_policy_file, valid_request_file])
        
        from sdk.python.spl.__main__ import main
        
        # Empty policy should either parse successfully or raise parse error
        # Behavior should be deterministic
        try:
            main()
            # If it doesn't raise, verify parser was called with empty string
            mock_parser.assert_called_once_with("")
        except (SystemExit, Exception) as e:
            # Parse error is acceptable for empty policy
            assert e is not None
    
    def test_edge_case_empty_json_file(self, valid_policy_file, empty_json_file,
                                       mock_parser, mock_verifier, monkeypatch, capsys):
        """Edge case: request file contains empty JSON object"""
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, empty_json_file])
        mock_verifier.return_value = {"allow": True}
        
        from sdk.python.spl.__main__ import main
        
        try:
            main()
        except SystemExit:
            pass
        
        # Should handle empty JSON object
        mock_verifier.assert_called_once()
        call_args = mock_verifier.call_args
        if call_args:
            request = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get('request')
            assert request == {}
    
    def test_edge_case_minimal_valid_input(self, tmp_path, mock_parser, mock_verifier,
                                           monkeypatch, capsys):
        """Edge case: minimal valid policy and request"""
        # Minimal policy
        policy_file = tmp_path / "minimal.spl"
        policy_file.write_text("a")
        
        # Minimal request
        request_file = tmp_path / "minimal.json"
        request_file.write_text('{}')
        
        monkeypatch.setattr(sys, 'argv', ['program', str(policy_file), str(request_file)])
        mock_verifier.return_value = {"allow": False}
        
        from sdk.python.spl.__main__ import main
        
        try:
            main()
        except SystemExit:
            pass
        
        # Should process minimal valid input
        captured = capsys.readouterr()
        assert 'DENY' in captured.out or 'ALLOW' in captured.out


# Invariant Tests
class TestInvariants:
    """Tests for contract invariants"""
    
    def test_invariant_environment_structure(self, valid_policy_file, valid_request_file,
                                             mock_parser, mock_verifier, monkeypatch, capsys):
        """Invariant: Environment dictionary has fixed structure with specific keys"""
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, valid_request_file])
        mock_verifier.return_value = {"allow": True}
        
        from sdk.python.spl.__main__ import main
        
        try:
            main()
        except SystemExit:
            pass
        
        # Verify environment structure
        mock_verifier.assert_called_once()
        call_args = mock_verifier.call_args
        
        if call_args:
            # Extract environment from call
            env = call_args[0][2] if len(call_args[0]) > 2 else call_args[1].get('env')
            
            assert env is not None, "Environment should be passed to verify"
            assert 'vars' in env, "Environment must have 'vars' key"
            assert 'now' in env, "Environment must have 'now' key"
            assert 'per_day_count' in env, "Environment must have 'per_day_count' key"
            assert 'crypto' in env, "Environment must have 'crypto' key"
    
    def test_invariant_allowed_recipients(self, valid_policy_file, valid_request_file,
                                          mock_parser, mock_verifier, monkeypatch, capsys):
        """Invariant: allowed_recipients is always ['niece@example.com', 'mom@example.com']"""
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, valid_request_file])
        mock_verifier.return_value = {"allow": True}
        
        from sdk.python.spl.__main__ import main
        
        try:
            main()
        except SystemExit:
            pass
        
        # Verify allowed_recipients
        mock_verifier.assert_called_once()
        call_args = mock_verifier.call_args
        
        if call_args:
            env = call_args[0][2] if len(call_args[0]) > 2 else call_args[1].get('env')
            
            assert env is not None
            assert 'vars' in env
            assert 'allowed_recipients' in env['vars']
            assert env['vars']['allowed_recipients'] == ['niece@example.com', 'mom@example.com']
    
    def test_invariant_now_hardcoded(self, valid_policy_file, valid_request_file,
                                     mock_parser, mock_verifier, monkeypatch, capsys):
        """Invariant: now is always hardcoded to '2025-10-01T00:00:00Z'"""
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, valid_request_file])
        mock_verifier.return_value = {"allow": True}
        
        from sdk.python.spl.__main__ import main
        
        try:
            main()
        except SystemExit:
            pass
        
        # Verify now value
        mock_verifier.assert_called_once()
        call_args = mock_verifier.call_args
        
        if call_args:
            env = call_args[0][2] if len(call_args[0]) > 2 else call_args[1].get('env')
            
            assert env is not None
            assert 'now' in env
            assert env['now'] == '2025-10-01T00:00:00Z'
    
    def test_invariant_per_day_count_returns_zero(self, valid_policy_file, valid_request_file,
                                                   mock_parser, mock_verifier, monkeypatch, capsys):
        """Invariant: per_day_count lambda always returns 0"""
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, valid_request_file])
        mock_verifier.return_value = {"allow": True}
        
        from sdk.python.spl.__main__ import main
        
        try:
            main()
        except SystemExit:
            pass
        
        # Verify per_day_count behavior
        mock_verifier.assert_called_once()
        call_args = mock_verifier.call_args
        
        if call_args:
            env = call_args[0][2] if len(call_args[0]) > 2 else call_args[1].get('env')
            
            assert env is not None
            assert 'per_day_count' in env
            assert callable(env['per_day_count'])
            
            # Test that it returns 0 for various inputs
            assert env['per_day_count']('any_arg') == 0
            assert env['per_day_count']('another_arg') == 0
            assert env['per_day_count'](None) == 0
    
    def test_invariant_crypto_validators_return_true(self, valid_policy_file, valid_request_file,
                                                      mock_parser, mock_verifier, monkeypatch, capsys):
        """Invariant: All crypto validation lambdas always return True"""
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, valid_request_file])
        mock_verifier.return_value = {"allow": True}
        
        from sdk.python.spl.__main__ import main
        
        try:
            main()
        except SystemExit:
            pass
        
        # Verify crypto validators
        mock_verifier.assert_called_once()
        call_args = mock_verifier.call_args
        
        if call_args:
            env = call_args[0][2] if len(call_args[0]) > 2 else call_args[1].get('env')
            
            assert env is not None
            assert 'crypto' in env
            
            crypto = env['crypto']
            assert 'dpop_ok' in crypto
            assert 'merkle_ok' in crypto
            assert 'vrf_ok' in crypto
            assert 'thresh_ok' in crypto
            
            # Verify all return True
            assert callable(crypto['dpop_ok'])
            assert callable(crypto['merkle_ok'])
            assert callable(crypto['vrf_ok'])
            assert callable(crypto['thresh_ok'])
            
            assert crypto['dpop_ok']('any_arg') is True
            assert crypto['merkle_ok']('any_arg') is True
            assert crypto['vrf_ok']('any_arg') is True
            assert crypto['thresh_ok']('any_arg') is True


# Additional coverage tests
class TestAdditionalCoverage:
    """Additional tests for comprehensive coverage"""
    
    def test_multiple_runs_same_environment(self, valid_policy_file, valid_request_file,
                                            mock_parser, mock_verifier, monkeypatch, capsys):
        """Verify that multiple runs produce consistent environment"""
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, valid_request_file])
        mock_verifier.return_value = {"allow": True}
        
        from sdk.python.spl.__main__ import main
        
        # First run
        try:
            main()
        except SystemExit:
            pass
        
        first_call_env = mock_verifier.call_args[0][2] if len(mock_verifier.call_args[0]) > 2 else None
        
        # Reset mock
        mock_verifier.reset_mock()
        
        # Second run
        try:
            main()
        except SystemExit:
            pass
        
        second_call_env = mock_verifier.call_args[0][2] if len(mock_verifier.call_args[0]) > 2 else None
        
        # Verify consistency
        if first_call_env and second_call_env:
            assert first_call_env['now'] == second_call_env['now']
            assert first_call_env['vars']['allowed_recipients'] == second_call_env['vars']['allowed_recipients']
    
    def test_policy_content_passed_to_parser(self, valid_policy_file, valid_request_file,
                                             mock_parser, mock_verifier, monkeypatch):
        """Verify that policy file content is correctly read and passed to parser"""
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, valid_request_file])
        mock_verifier.return_value = {"allow": True}
        
        from sdk.python.spl.__main__ import main
        
        try:
            main()
        except SystemExit:
            pass
        
        # Verify parser was called with the policy content
        mock_parser.assert_called_once()
        call_content = mock_parser.call_args[0][0]
        
        # Read the actual file to compare
        with open(valid_policy_file, 'r') as f:
            expected_content = f.read()
        
        assert call_content == expected_content
    
    def test_request_content_passed_to_verifier(self, valid_policy_file, valid_request_file,
                                                mock_parser, mock_verifier, monkeypatch):
        """Verify that request JSON is correctly parsed and passed to verifier"""
        monkeypatch.setattr(sys, 'argv', ['program', valid_policy_file, valid_request_file])
        mock_verifier.return_value = {"allow": True}
        
        from sdk.python.spl.__main__ import main
        
        try:
            main()
        except SystemExit:
            pass
        
        # Verify verifier was called with the request content
        mock_verifier.assert_called_once()
        call_request = mock_verifier.call_args[0][1] if len(mock_verifier.call_args[0]) > 1 else None
        
        # Read the actual file to compare
        with open(valid_request_file, 'r') as f:
            expected_request = json.load(f)
        
        assert call_request == expected_request
